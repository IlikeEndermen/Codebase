import yaml
import logging
import operator
import re
from typing import Dict, List, Any, Optional
from pathlib import Path
from dataclasses import dataclass, field


logger = logging.getLogger(__name__)


@dataclass
class RuleStep:
    """Represents a single step in a rule."""
    tool: str
    output_key: Optional[str] = None
    condition: Optional[str] = None
    args: Optional[List[str]] = field(default_factory=list)


@dataclass
class Rule:
    """Represents a complete forensic rule."""
    name: str
    trigger: Dict[str, Any]
    steps: List[RuleStep]
    priority: str = "medium"


class RuleEngine:
    """Loads and manages YAML-based forensic rules."""

    PRIORITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    VALID_PRIORITIES = set(PRIORITY_ORDER.keys())

    ARTIFACT_TYPES = {
       # Images
    "image/png":                    "image",
    "image/jpeg":                   "image",
    "image/gif":                    "image",
    "image/bmp":                    "image",
    "image/webp":                   "image",

    # PCAP
    "application/pcap":             "pcap",

    # Archives
    "application/zip":              "archive",
    "application/x-rar":            "archive",
    "application/x-7z-compressed":  "archive",
    "application/gzip":             "archive",
    "application/x-bzip2":          "archive",
    "application/x-tar":            "archive",

    # Binary — this was the missing entry
    "binary":                       "binary",
    "application/octet-stream":     "binary",
    "application/x-executable":     "binary",
    "application/x-sharedlib":      "binary",
    "application/x-object":         "binary",
    "application/x-dosexec":        "binary",
    }

    def __init__(self, rules_dir: str = "src/rules/definitions"):
        # Make the path absolute relative to this file's location
        if not Path(rules_dir).is_absolute():
            # Get the directory where this file is located (src/rules/)
            base_dir = Path(__file__).parent.parent  # goes up to src/
            rules_dir = str(base_dir / "rules" / "definitions")
        
        self.rules_dir = Path(rules_dir)
        self.rules: List[Rule] = []
        self.load_rules()

    # ------------------------------------------------------------------ #
    #  Loading                                                             #
    # ------------------------------------------------------------------ #

    def load_rules(self) -> None:
        """Load all YAML rules from the rules directory."""
        if not self.rules_dir.exists():
            logger.warning(f"Rules directory not found: {self.rules_dir}")
            return

        for rule_file in self.rules_dir.glob("*.yaml"):
            try:
                with open(rule_file, "r") as f:
                    data = yaml.safe_load(f)

                if not data or "rules" not in data:
                    logger.warning(f"No 'rules' key found in {rule_file}, skipping.")
                    continue

                for rule_data in data["rules"]:
                    try:
                        rule = self._parse_rule(rule_data)
                        self.rules.append(rule)
                        logger.info(f"Loaded rule: {rule.name}")
                    except ValueError as e:
                        logger.error(f"Skipping invalid rule in {rule_file}: {e}")

            except yaml.YAMLError as e:
                logger.error(f"YAML parse error in {rule_file}: {e}")
            except OSError as e:
                logger.error(f"Could not read rule file {rule_file}: {e}")

    # ------------------------------------------------------------------ #
    #  Parsing & validation                                                #
    # ------------------------------------------------------------------ #

    def _parse_rule(self, rule_data: Dict) -> Rule:
        """Parse and validate a rule from YAML data."""
        name = rule_data.get("name")
        if not name:
            raise ValueError("Rule is missing required field: 'name'")

        if "trigger" not in rule_data:
            raise ValueError(f"Rule '{name}' is missing required field: 'trigger'")

        raw_steps = rule_data.get("steps")
        if not raw_steps:
            raise ValueError(f"Rule '{name}' has no steps defined")

        priority = rule_data.get("priority", "medium")
        if priority not in self.VALID_PRIORITIES:
            logger.warning(
                f"Rule '{name}' has unknown priority '{priority}', defaulting to 'medium'."
            )
            priority = "medium"

        steps = [self._parse_step(s, i, name) for i, s in enumerate(raw_steps)]

        return Rule(
            name=name,
            trigger=rule_data["trigger"],
            steps=steps,
            priority=priority,
        )

    @staticmethod
    def _parse_step(step_data: Dict, index: int, rule_name: str) -> RuleStep:
        """Parse and validate a single step."""
        tool = step_data.get("tool")
        if not tool:
            raise ValueError(
                f"Step {index} in rule '{rule_name}' is missing required field: 'tool'"
            )

        args = step_data.get("args", [])
        if not isinstance(args, list):
            raise ValueError(
                f"Step {index} in rule '{rule_name}': 'args' must be a list, "
                f"got {type(args).__name__}"
            )

        return RuleStep(
            tool=tool,
            output_key=step_data.get("output_key"),
            condition=step_data.get("condition"),
            args=args,
        )

    # ------------------------------------------------------------------ #
    #  Rule matching                                                       #
    # ------------------------------------------------------------------ #

    def get_applicable_rules(self, mime_type: str) -> List[Rule]:
        """Return all rules that match the given MIME type, sorted by priority."""
        applicable: List[Rule] = []
        artifact = self.ARTIFACT_TYPES.get(mime_type)

        for rule in self.rules:
            trigger = rule.trigger

            if "file_type" in trigger:
                if trigger["file_type"] == mime_type:
                    applicable.append(rule)
            elif "artifact_type" in trigger:
                if artifact and artifact == trigger["artifact_type"]:
                    applicable.append(rule)

        applicable.sort(key=lambda r: self.PRIORITY_ORDER.get(r.priority, 2))
        return applicable

    # ------------------------------------------------------------------ #
    #  Condition evaluation                                                #
    # ------------------------------------------------------------------ #

    _CONDITION_PATTERN = re.compile(
        r'^([\w.]+)\s*(==|!=|>=|<=|>|<)\s*(.+)$'
    )

    _OPERATORS = {
        "==": operator.eq,
        "!=": operator.ne,
        ">":  operator.gt,
        ">=": operator.ge,
        "<":  operator.lt,
        "<=": operator.le,
    }

    def evaluate_condition(self, condition: str, context: Dict[str, Any]) -> bool:
        """
        Evaluate a structured condition string against the current pipeline context.

        Supports dotted key paths and the operators ==, !=, >, >=, <, <=.
        Example: "metadata.color_depth == 8"
        """
        if not condition:
            return True

        match = self._CONDITION_PATTERN.match(condition.strip())
        if not match:
            logger.error(
                f"Condition '{condition}' does not match expected format "
                "'key.path operator value'"
            )
            return False

        key_path, op_str, raw_value = match.groups()

        try:
            # Resolve dotted key path from context dict
            resolved = context
            for part in key_path.split("."):
                if not isinstance(resolved, dict):
                    raise KeyError(
                        f"Expected dict at '{part}', got {type(resolved).__name__}"
                    )
                resolved = resolved[part]

            # Use yaml.safe_load to cast the literal to int, float, bool, or str
            expected = yaml.safe_load(raw_value.strip())

            return self._OPERATORS[op_str](resolved, expected)

        except KeyError as e:
            logger.error(f"Condition key not found in context: {e}")
            return False
        except Exception as e:
            logger.error(f"Failed to evaluate condition '{condition}': {e}")
            return False
