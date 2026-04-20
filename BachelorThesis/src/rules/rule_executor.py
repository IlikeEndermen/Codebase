"""
rules/rule_executor.py

Executes a single Rule against a target file, walking each RuleStep
in order while respecting conditions and building a shared context dict.
"""

import logging
import shutil
import subprocess
from typing import Any, Dict, List, Optional

from rules.rule_engine import Rule, RuleStep, RuleEngine

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Tool registry
# Maps the tool name used in YAML rules to the actual CLI executable.
# Extend this dict as you add more tools.
# ---------------------------------------------------------------------------
TOOL_REGISTRY: Dict[str, str] = {
    "exiftool":  "exiftool",
    "zsteg":     "zsteg",
    "steghide":  "steghide",
    "binwalk":   "binwalk",
    "tshark":    "tshark",
    "strings":   "strings",
    "foremost":  "foremost",
    "unzip":     "unzip",
    "7z":        "7z",
    "file":      "file",
    "xxd":       "xxd",
}

TOOL_TIMEOUT = 30  # seconds per tool call


class ToolNotFoundError(RuntimeError):
    pass


class RuleExecutor:
    """Execute a Rule step-by-step, collecting output into a context dict."""

    def __init__(self, timeout: int = TOOL_TIMEOUT) -> None:
        self.timeout = timeout
        self._rule_engine = RuleEngine.__new__(RuleEngine)  # reuse helpers only

    # ------------------------------------------------------------------ #

    def execute_rule(
        self,
        file_path: str,
        rule: Rule,
        existing_context: Optional[Dict[str, Any]] = None,
        verbose: bool = False,
    ) -> Dict[str, Any]:
        """
        Run all steps of *rule* against *file_path*.

        Parameters
        ----------
        file_path       : path to the artifact being analysed
        rule            : the Rule object to execute
        existing_context: results accumulated by previously executed rules
        verbose         : if True, print raw tool output to stdout

        Returns
        -------
        context dict with all output_key → value pairs collected this run.
        """
        context: Dict[str, Any] = dict(existing_context or {})

        for i, step in enumerate(rule.steps):
            step_label = f"[{rule.name}] step {i + 1}/{len(rule.steps)} ({step.tool})"

            # --- evaluate condition -------------------------------------------
            if step.condition:
                if not self._evaluate(step.condition, context):
                    logger.info(f"{step_label}: condition '{step.condition}' not met — skipping")
                    if verbose:
                        print(f"    ↳ skipped (condition not met: {step.condition})")
                    continue

            # --- resolve tool -------------------------------------------------
            try:
                executable = self._resolve_tool(step.tool)
            except ToolNotFoundError as exc:
                logger.warning(f"{step_label}: {exc} — skipping")
                if verbose:
                    print(f"    ↳ skipped ({exc})")
                continue

            # --- build command ------------------------------------------------
            cmd = self._build_command(executable, file_path, step.args or [])
            if verbose:
                print(f"    ↳ running: {' '.join(cmd)}")

            # --- execute ------------------------------------------------------
            output = self._run(cmd, step_label)

            if verbose and output:
                print(f"    ↳ output ({len(output)} chars):")
                for line in output.splitlines()[:20]:   # cap preview at 20 lines
                    print(f"       {line}")

            # --- store output -------------------------------------------------
            if step.output_key:
                context[step.output_key] = self._parse_output(output)
                logger.debug(f"{step_label}: stored under '{step.output_key}'")

        return context

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def _resolve_tool(tool_name: str) -> str:
        """Return the resolved executable path or raise ToolNotFoundError."""
        cli = TOOL_REGISTRY.get(tool_name, tool_name)
        if shutil.which(cli) is None:
            raise ToolNotFoundError(f"Tool '{cli}' not found on PATH")
        return cli

    @staticmethod
    def _build_command(executable: str, file_path: str, args: List[str]) -> List[str]:
        """Assemble the command list, substituting {file} placeholder in args."""
        resolved_args = [
            arg.replace("{file}", file_path) if isinstance(arg, str) else arg
            for arg in args
        ]
        
        # Special handling for steghide and zsteg
        if executable == "steghide":
            # steghide info -p <pass> <file>
            return ["steghide"] + resolved_args + [file_path]
        elif executable == "zsteg":
            # zsteg <args> <file>
            return [executable] + resolved_args + [file_path]
        
        # Default: command + args + file
        return [executable] + resolved_args + [file_path]

    def _run(self, cmd: List[str], label: str) -> str:
        """Run *cmd*, return stdout+stderr as a single string."""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                input="\n"  # Feed newline to steghide to avoid interactive prompt
            )
            output = result.stdout + result.stderr
            if result.returncode != 0:
                logger.debug(f"{label}: exited with code {result.returncode}")
            return output
        except subprocess.TimeoutExpired:
            logger.warning(f"{label}: timed out after {self.timeout}s")
            return ""
        except Exception as exc:
            logger.error(f"{label}: unexpected error: {exc}")
            return ""

    @staticmethod
    def _parse_output(raw: str) -> Any:
        """
        Light-weight output parser.
        Returns a dict when the output looks like 'key: value' pairs,
        otherwise returns the raw string.
        """
        lines = [l.strip() for l in raw.splitlines() if l.strip()]
        parsed: Dict[str, str] = {}
        for line in lines:
            if ": " in line:
                key, _, value = line.partition(": ")
                parsed[key.strip()] = value.strip()
        return parsed if parsed else raw

    def _evaluate(self, condition: str, context: Dict[str, Any]) -> bool:
        """Delegate condition evaluation to RuleEngine logic."""
        return RuleEngine.evaluate_condition(self._rule_engine, condition, context)
