from dataclasses import dataclass


@dataclass
class SecurityFinding:
    resource_id: str
    issue: str
    severity: str
    description: str