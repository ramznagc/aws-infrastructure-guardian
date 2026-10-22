
from dataclasses import dataclass


VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}


@dataclass
class SecurityFinding:
    resource_id: str
    issue: str
    severity: str
    description: str

    def __post_init__(self):
        self.severity = self.severity.upper()

        if self.severity not in VALID_SEVERITIES:
            raise ValueError(
                f"Invalid severity: {self.severity}"
            )

        if not self.resource_id.strip():
            raise ValueError("resource_id cannot be empty")

        if not self.issue.strip():
            raise ValueError("issue cannot be empty")
