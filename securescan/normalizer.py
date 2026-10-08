"""Convert raw output of every tool into the shared Finding schema and de-duplicate."""
from __future__ import annotations

import re
from pathlib import Path

from .models import Finding, Severity
from .scanners import ScanOutput
from .security import redact

_CWE_RE = re.compile(r"CWE-\d+")


def _rel(path_str: str, root: Path) -> str:
    if path_str and not Path(path_str).is_absolute():
        return Path(path_str).as_posix().removeprefix("./")
    try:
        return Path(path_str).resolve().relative_to(root.resolve()).as_posix()
    except (ValueError, OSError):
        return Path(path_str).as_posix()


def _snippet(root: Path, rel_file: str, line: int, context: int = 2) -> str:
    """Read the vulnerable lines ourselves (semgrep hides them without login); always redacted."""
    if not rel_file or line <= 0:
        return ""
    try:
        f = (root / rel_file).resolve()
        if root.resolve() not in f.parents:
            return ""
        lines = f.read_text(encoding="utf-8", errors="replace").splitlines()
        lo, hi = max(0, line - 1 - context), min(len(lines), line + context)
        return redact("\n".join(f"{i + 1:>4} | {lines[i][:300]}" for i in range(lo, hi)))
    except OSError:
        return ""


def from_semgrep(raw: dict, root: Path) -> list[Finding]:
    out = []
    for r in (raw or {}).get("results", []):
        extra = r.get("extra", {})
        meta = extra.get("metadata", {}) or {}
        cwe = meta.get("cwe", [])
        cwe = [cwe] if isinstance(cwe, str) else cwe
        sev = Severity.parse(meta.get("impact") or extra.get("severity"))
        if extra.get("severity") == "ERROR" and meta.get("impact") == "HIGH":
            sev = Severity.HIGH
        rel = _rel(r.get("path", ""), root)
        line = r.get("start", {}).get("line", 0)
        refs = meta.get("references", [])
        check_id = r.get("check_id", "semgrep")
        if "rules.semgrep." in check_id:  # local rule ids are prefixed with their file-system path
            check_id = "securescan." + check_id.split("rules.semgrep.")[-1]
        out.append(Finding(
            tool="semgrep", category="SAST", rule_id=check_id,
            title=check_id.split(".")[-1].replace("-", " ").capitalize(),
            description=redact(extra.get("message", ""))[:2000], severity=sev, file=rel, line=line,
            snippet=_snippet(root, rel, line, context=4),
            cwe=sorted({m for c in cwe for m in _CWE_RE.findall(str(c))}),
            references=refs if isinstance(refs, list) else [refs],
        ))
    return out


def from_pip_audit(raw: dict, root: Path) -> list[Finding]:
    out = []
    for dep in (raw or {}).get("dependencies", []):
        for v in dep.get("vulns", []):
            ids = [v.get("id", "")] + v.get("aliases", [])
            cves = sorted({i for i in ids if i.startswith("CVE-")})
            fixes = v.get("fix_versions", [])
            out.append(Finding(
                tool="pip-audit", category="SCA", rule_id=v.get("id", "pip-audit"),
                title=f"Vulnerable dependency {dep.get('name')} {dep.get('version')}",
                description=redact(v.get("description", ""))[:2000],
                # pip-audit has no severity; enriched later from trivy when the same CVE matches.
                severity=Severity.HIGH if fixes else Severity.MEDIUM,
                file=dep.get("_file", "requirements.txt"), package=dep.get("name", ""),
                installed_version=dep.get("version", ""), fixed_version=", ".join(fixes), cve=cves,
                references=[f"https://osv.dev/vulnerability/{v.get('id')}"],
            ))
    return out


def from_trivy(raw: dict, root: Path) -> list[Finding]:
    out = []
    for result in (raw or {}).get("Results", []) or []:
        target = result.get("Target", "")
        for v in result.get("Vulnerabilities", []) or []:
            cvss = None
            for src in (v.get("CVSS") or {}).values():
                score = src.get("V3Score") or src.get("V40Score")
                if score:
                    cvss = max(cvss or 0, float(score))
            vid = v.get("VulnerabilityID", "")
            out.append(Finding(
                tool="trivy", category="SCA", rule_id=vid,
                title=v.get("Title") or f"Vulnerable dependency {v.get('PkgName')}",
                description=redact(v.get("Description", ""))[:2000],
                severity=Severity.parse(v.get("Severity")), file=target, package=v.get("PkgName", ""),
                installed_version=v.get("InstalledVersion", ""), fixed_version=v.get("FixedVersion", ""),
                cve=[vid] if vid.startswith("CVE-") else [], cwe=v.get("CweIDs", []) or [], cvss=cvss,
                references=(v.get("References") or [])[:5],
            ))
    return out


def from_gitleaks(raw: list, root: Path) -> list[Finding]:
    out = []
    for leak in raw or []:
        rel = _rel(leak.get("File", ""), root)
        line = leak.get("StartLine", 0)
        out.append(Finding(
            tool="gitleaks", category="SECRET", rule_id=leak.get("RuleID", "secret"),
            title=f"Hard-coded secret ({leak.get('RuleID', 'secret')})",
            description=f"{leak.get('Description') or 'A credential'} appears to be committed to source "
                        "control. The value has been redacted from this report.",
            severity=Severity.CRITICAL if leak.get("Entropy", 0) > 3.5 else Severity.HIGH,
            file=rel, line=line, snippet=_snippet(root, rel, line, context=0), cwe=["CWE-798"],
        ))
    return out


PARSERS = {"semgrep": from_semgrep, "pip-audit": from_pip_audit, "trivy": from_trivy, "gitleaks": from_gitleaks}


def normalize(outputs: list[ScanOutput], root: Path) -> list[Finding]:
    merged: dict[str, Finding] = {}
    for o in outputs:
        if o.raw is None or o.tool not in PARSERS:
            continue
        for f in PARSERS[o.tool](o.raw, root):
            key = f.dedup_key()
            if key in merged:
                existing = merged[key]
                # Merge evidence from multiple tools: keep the worst severity and richest data.
                # pip-audit severity is a heuristic, so a real rating from trivy wins.
                if existing.tool == "pip-audit" and f.tool != "pip-audit":
                    existing.severity = f.severity
                elif f.tool != "pip-audit" and f.severity.rank > existing.severity.rank:
                    existing.severity = f.severity
                existing.cvss = existing.cvss or f.cvss
                existing.fixed_version = existing.fixed_version or f.fixed_version
                existing.cwe = sorted(set(existing.cwe) | set(f.cwe))
                existing.references = list(dict.fromkeys(existing.references + f.references))[:8]
                if f.tool not in existing.detected_by:
                    existing.detected_by.append(f.tool)
            else:
                f.detected_by = [f.tool]
                f.compute_id()
                merged[key] = f
    return list(merged.values())
