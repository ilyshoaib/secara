from dataclasses import dataclass
from typing import Any, Dict, List

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
