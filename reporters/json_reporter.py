"""JSON Reporter for WebSecAudit.
Exports machine-readable audit deliverables for CI/CD pipelines and SIEM systems.
"""

import json
from typing import Optional
from core.models import AuditResult


def export_json_report(result: AuditResult, file_path: Optional[str] = None) -> str:
    """Serialize AuditResult to JSON and optionally save to file."""
    data = result.to_dict()
    json_str = json.dumps(data, indent=2)

    if file_path:
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(json_str)

    return json_str
