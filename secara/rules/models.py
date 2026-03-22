from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

@dataclass
class Rule:
    """Represents a single vulnerability detection rule loaded from YAML."""
    id: str
    name: str
    severity: str
    description: str
    fix: str
    languages: List[str]
    pattern_type: str
    pattern: Dict[str, Any]
    cwe: Optional[str] = None                    # e.g. "CWE-89"
    references: List[str] = field(default_factory=list)  # URLs
