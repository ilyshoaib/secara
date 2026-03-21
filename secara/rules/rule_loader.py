import os
from pathlib import Path
import yaml
from typing import Dict, List, Optional
from secara.rules.models import Rule

_RULES_CACHE: Dict[str, List[Rule]] = {}

def load_builtin_rules() -> None:
    """Load all YAML rules from the builtin directory into memory."""
    if _RULES_CACHE:
        return

    builtin_dir = Path(__file__).parent / "builtin"
    if not builtin_dir.exists():
        return
        
    for yaml_file in builtin_dir.glob("*.yaml"):
        with open(yaml_file, "r", encoding="utf-8") as f:
            try:
                data = yaml.safe_load(f)
                if not data or not isinstance(data, dict) or "rules" not in data:
                    continue
                    
                for rule_dict in data["rules"]:
                    rule = Rule(
                        id=rule_dict.get("id", "UNKNOWN"),
                        name=rule_dict.get("name", "Unknown Rule"),
                        severity=rule_dict.get("severity", "LOW"),
                        description=rule_dict.get("description", ""),
                        fix=rule_dict.get("fix", ""),
                        languages=rule_dict.get("languages", []),
                        pattern_type=rule_dict.get("pattern_type") or rule_dict.get("pattern", {}).get("type", "unknown"),
                        pattern=rule_dict.get("pattern", {})
                    )
                    
                    # Store by language
                    for lang in rule.languages:
                        if lang not in _RULES_CACHE:
                            _RULES_CACHE[lang] = []
                        _RULES_CACHE[lang].append(rule)
            except yaml.YAMLError:
                continue

def get_rules_for_language(language: str) -> List[Rule]:
    """Return all rules applicable to a specific language (or 'any')."""
    if not _RULES_CACHE:
        load_builtin_rules()
        
    rules = []
    if language in _RULES_CACHE:
        rules.extend(_RULES_CACHE[language])
    if language != "any" and "any" in _RULES_CACHE:
        rules.extend(_RULES_CACHE["any"])
        
    return rules
