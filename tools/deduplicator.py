"""
tools/deduplicator.py
----------------------
Deduplicates overlapping security findings from different scanners (Semgrep, Bandit, Gitleaks).
Merges findings flagging the same file and overlapping line locations.
"""

from __future__ import annotations

from core.logging import get_logger
from core.state import Finding, Severity

logger = get_logger(__name__)

SEVERITY_ORDER = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}


def deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    """
    Deduplicate overlapping findings across scanners:
    - Same file
    - Overlapping line range (within 3 lines)
    - Merges sources (e.g. 'bandit+semgrep'), keeps higher severity, preserves CWE.
    """
    if not findings or len(findings) <= 1:
        return list(findings)

    deduped: list[Finding] = []

    for f in findings:
        matched = False
        for idx, existing in enumerate(deduped):
            # Check if same file and nearby line
            if (
                existing.file
                and f.file
                and existing.file.strip("/\\").lower() == f.file.strip("/\\").lower()
                and existing.line is not None
                and f.line is not None
                and abs(existing.line - f.line) <= 3
            ):
                matched = True
                # Merge into existing:
                # 1. Higher severity
                f_sev_val = SEVERITY_ORDER.get(f.severity, 0)
                ex_sev_val = SEVERITY_ORDER.get(existing.severity, 0)
                if f_sev_val > ex_sev_val:
                    existing.severity = f.severity

                # 2. Merge source_tool
                tools = set(existing.source_tool.split("+"))
                tools.add(f.source_tool)
                existing.source_tool = "+".join(sorted(tools))

                # 3. Preserve CWE if missing
                if not existing.cwe and f.cwe:
                    existing.cwe = f.cwe

                # 4. Code snippet
                if not existing.code_snippet and f.code_snippet:
                    existing.code_snippet = f.code_snippet

                # 5. Explanations & rule IDs
                if f.rule_id and f.rule_id not in (existing.rule_id or ""):
                    existing.rule_id = f"{existing.rule_id or ''}, {f.rule_id}".strip(", ")

                break

        if not matched:
            deduped.append(f)

    logger.debug("findings_deduplicated", before=len(findings), after=len(deduped))
    return deduped
