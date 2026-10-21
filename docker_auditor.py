#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DockShield - Automated Dockerfile Security Auditor & Misconfiguration Scanner

Statically analyses a Dockerfile against a JSON rule set (aligned with CIS
Docker Benchmark recommendations), prints a colorized report and writes a
machine-readable JSON report.

Intended for defensive security analysis and auditing of your own images.

Exit codes:
    0  scan finished, no finding at or above the --fail-on threshold
    1  scan finished, at least one finding at or above the threshold
    2  usage / input / rules / I/O error
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import IntEnum
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

try:
    from colorama import Fore, Style, init as colorama_init
except ImportError:  # graceful fallback: run without colors
    class _NoColor:
        def __getattr__(self, name: str) -> str:
            return ""

    Fore = Style = _NoColor()  # type: ignore[assignment]

    def colorama_init(*args, **kwargs) -> None:  # type: ignore[no-redef]
        return None


VERSION = "1.0.0"
TOOL_NAME = "DockShield"
MAX_DOCKERFILE_BYTES = 5 * 1024 * 1024  # 5 MB safety limit
MAX_EVIDENCE_LENGTH = 120

BANNER = r"""
    ____             __   _____ __    _      __    __
   / __ \____  _____/ /__/ ___// /_  (_)__  / /___/ /
  / / / / __ \/ ___/ //_/\__ \/ __ \/ / _ \/ / __  /
 / /_/ / /_/ / /__/ ,<  ___/ / / / / /  __/ / /_/ /
/_____/\____/\___/_/|_|/____/_/ /_/_/\___/_/\__,_/
"""


# --------------------------------------------------------------------------- #
# Exceptions
# --------------------------------------------------------------------------- #
class AuditorError(Exception):
    """Base class for all expected DockShield errors."""


class RulesError(AuditorError):
    """Raised when the rules file is missing or invalid."""


class DockerfileError(AuditorError):
    """Raised when the target Dockerfile cannot be read or parsed."""


# --------------------------------------------------------------------------- #
# Data models
# --------------------------------------------------------------------------- #
class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: object) -> "Severity":
        try:
            return cls[str(value).strip().upper()]
        except KeyError:
            valid = ", ".join(s.name for s in cls)
            raise RulesError(f"Invalid severity '{value}'. Valid values: {valid}")


@dataclass(frozen=True)
class Instruction:
    """A logical Dockerfile instruction (continuation lines already merged)."""

    line: int
    keyword: str
    arguments: str

    @property
    def raw(self) -> str:
        return f"{self.keyword} {self.arguments}".strip()


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    description: str
    severity: Severity
    type: str
    remediation: str
    cis_reference: str
    pattern: Optional["re.Pattern[str]"] = None
    exclude_pattern: Optional["re.Pattern[str]"] = None
    applies_to: Tuple[str, ...] = ()
    scope: str = "file"  # "file" or "final_stage"
    redact: bool = False
    params: Dict[str, object] = field(default_factory=dict)


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: Severity
    line: Optional[int]
    evidence: str
    detail: str
    remediation: str
    cis_reference: str

    def to_dict(self) -> Dict[str, object]:
        return {
            "line": self.line,
            "evidence": self.evidence,
            "detail": self.detail,
            "remediation": self.remediation,
        }


@dataclass
class RuleResult:
    rule: Rule
    findings: List[Finding] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return not self.findings

    def to_dict(self) -> Dict[str, object]:
        return {
            "rule_id": self.rule.id,
            "title": self.rule.title,
            "severity": self.rule.severity.name,
            "cis_reference": self.rule.cis_reference,
            "status": "PASS" if self.passed else "FAIL",
            "findings": [f.to_dict() for f in self.findings],
        }


# --------------------------------------------------------------------------- #
# Rule loading
# --------------------------------------------------------------------------- #
class RuleLoader:
    """Loads and validates the JSON rule set."""

    REQUIRED_FIELDS = ("id", "title", "severity", "type", "remediation")
    SUPPORTED_TYPES = (
        "forbid_pattern",
        "require_pattern",
        "user_check",
        "base_image_check",
    )
    PATTERN_TYPES = ("forbid_pattern", "require_pattern", "user_check")
    VALID_SCOPES = ("file", "final_stage")

    @classmethod
    def load(cls, path: Path) -> Tuple[str, List[Rule]]:
        if not path.is_file():
            raise RulesError(f"Rules file not found: {path}")
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise RulesError(f"Rules file is not valid JSON ({path}): {exc}")
        except (OSError, UnicodeDecodeError) as exc:
            raise RulesError(f"Cannot read rules file ({path}): {exc}")

        if not isinstance(data, dict) or not isinstance(data.get("rules"), list):
            raise RulesError("Rules file must be an object with a 'rules' list.")
        if not data["rules"]:
            raise RulesError("Rules file contains no rules.")

        rules: List[Rule] = []
        seen_ids = set()
        for index, entry in enumerate(data["rules"], start=1):
            rule = cls._build_rule(entry, index)
            if rule.id in seen_ids:
                raise RulesError(f"Duplicate rule id '{rule.id}'.")
            seen_ids.add(rule.id)
            rules.append(rule)

        return str(data.get("ruleset", "Unnamed ruleset")), rules

    @classmethod
    def _build_rule(cls, entry: object, index: int) -> Rule:
        if not isinstance(entry, dict):
            raise RulesError(f"Rule #{index} must be a JSON object.")
        for key in cls.REQUIRED_FIELDS:
            if not entry.get(key):
                raise RulesError(f"Rule #{index} is missing required field '{key}'.")

        rule_id = str(entry["id"])
        rule_type = str(entry["type"])
        if rule_type not in cls.SUPPORTED_TYPES:
            raise RulesError(
                f"Rule {rule_id}: unsupported type '{rule_type}'. "
                f"Supported: {', '.join(cls.SUPPORTED_TYPES)}"
            )

        scope = str(entry.get("scope", "file"))
        if scope not in cls.VALID_SCOPES:
            raise RulesError(f"Rule {rule_id}: invalid scope '{scope}'.")

        pattern = cls._compile(entry.get("pattern"), rule_id, "pattern")
        exclude = cls._compile(entry.get("exclude_pattern"), rule_id, "exclude_pattern")
        if rule_type in cls.PATTERN_TYPES and pattern is None:
            raise RulesError(f"Rule {rule_id}: type '{rule_type}' requires a 'pattern'.")

        applies_to = entry.get("applies_to", [])
        if not isinstance(applies_to, list):
            raise RulesError(f"Rule {rule_id}: 'applies_to' must be a list.")

        params = entry.get("params", {})
        if not isinstance(params, dict):
            raise RulesError(f"Rule {rule_id}: 'params' must be an object.")

        return Rule(
            id=rule_id,
            title=str(entry["title"]),
            description=str(entry.get("description", entry["title"])),
            severity=Severity.parse(entry["severity"]),
            type=rule_type,
            remediation=str(entry["remediation"]),
            cis_reference=str(entry.get("cis_reference", "N/A")),
            pattern=pattern,
            exclude_pattern=exclude,
            applies_to=tuple(str(k).upper() for k in applies_to),
            scope=scope,
            redact=bool(entry.get("redact", False)),
            params=params,
        )

    @staticmethod
    def _compile(value: object, rule_id: str, name: str) -> Optional["re.Pattern[str]"]:
        if value is None:
            return None
        try:
            return re.compile(str(value), re.IGNORECASE)
        except re.error as exc:
            raise RulesError(f"Rule {rule_id}: invalid regex in '{name}': {exc}")


# --------------------------------------------------------------------------- #
# Dockerfile parsing
# --------------------------------------------------------------------------- #
class DockerfileParser:
    """Reads a Dockerfile line by line into logical instructions."""

    def parse(self, path: Path) -> List[Instruction]:
        text = self._read(path)
        instructions = self._tokenize(text)
        if not instructions:
            raise DockerfileError("The Dockerfile contains no instructions.")
        if not any(i.keyword == "FROM" for i in instructions):
            raise DockerfileError("No FROM instruction found: not a valid Dockerfile.")
        return instructions

    @staticmethod
    def _read(path: Path) -> str:
        if not path.exists():
            raise DockerfileError(f"File not found: {path}")
        if not path.is_file():
            raise DockerfileError(f"Not a regular file: {path}")
        try:
            if path.stat().st_size > MAX_DOCKERFILE_BYTES:
                raise DockerfileError(
                    f"File is larger than {MAX_DOCKERFILE_BYTES // (1024 * 1024)} MB limit."
                )
            return path.read_text(encoding="utf-8-sig", errors="replace")
        except PermissionError:
            raise DockerfileError(f"Permission denied while reading: {path}")
        except OSError as exc:
            raise DockerfileError(f"Cannot read file ({path}): {exc}")

    def _tokenize(self, text: str) -> List[Instruction]:
        instructions: List[Instruction] = []
        buffer: List[str] = []
        start_line = 0

        for number, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()

            if not buffer:
                if not stripped or stripped.startswith("#"):
                    continue
                start_line = number
            elif not stripped or stripped.startswith("#"):
                # Docker ignores blank/comment lines inside a continuation.
                continue

            if stripped.endswith("\\"):
                buffer.append(stripped[:-1].rstrip())
                continue

            buffer.append(stripped)
            instructions.append(self._build(start_line, buffer))
            buffer = []

        if buffer:  # file ended while a continuation was still open
            instructions.append(self._build(start_line, buffer))
        return instructions

    @staticmethod
    def _build(line: int, parts: List[str]) -> Instruction:
        joined = " ".join(p for p in parts if p)
        pieces = joined.split(None, 1)
        keyword = pieces[0].upper()
        arguments = pieces[1] if len(pieces) > 1 else ""
        return Instruction(line=line, keyword=keyword, arguments=arguments)


# --------------------------------------------------------------------------- #
# Auditing engine
# --------------------------------------------------------------------------- #
class DockerfileAuditor:
    """Matches parsed instructions against the loaded rules."""

    def __init__(self, rules: List[Rule]) -> None:
        self.rules = rules
        self._handlers: Dict[str, Callable[..., List[Finding]]] = {
            "forbid_pattern": self._check_forbid_pattern,
            "require_pattern": self._check_require_pattern,
            "user_check": self._check_user,
            "base_image_check": self._check_base_image,
        }

    def audit(self, instructions: List[Instruction]) -> List[RuleResult]:
        stages = self._split_stages(instructions)
        results: List[RuleResult] = []
        for rule in self.rules:
            handler = self._handlers[rule.type]
            results.append(RuleResult(rule, handler(rule, instructions, stages)))
        return results

    # -- helpers ----------------------------------------------------------- #
    @staticmethod
    def _split_stages(instructions: List[Instruction]) -> List[List[Instruction]]:
        stages: List[List[Instruction]] = []
        for ins in instructions:
            if ins.keyword == "FROM":
                stages.append([ins])
            elif stages:
                stages[-1].append(ins)
        return stages

    @staticmethod
    def _scope(rule: Rule, instructions: List[Instruction],
               stages: List[List[Instruction]]) -> List[Instruction]:
        if rule.scope == "final_stage" and stages:
            return stages[-1]
        return instructions

    @staticmethod
    def _applies(rule: Rule, ins: Instruction) -> bool:
        return not rule.applies_to or ins.keyword in rule.applies_to

    @staticmethod
    def _redact(text: str) -> str:
        if "=" in text:
            return re.sub(r"=(?:\"[^\"]*\"|'[^']*'|\S*)", "=********", text)
        parts = text.split(None, 2)
        return " ".join(parts[:2] + ["********"]) if len(parts) > 2 else text

    def _evidence(self, rule: Rule, ins: Instruction) -> str:
        text = self._redact(ins.raw) if rule.redact else ins.raw
        if len(text) > MAX_EVIDENCE_LENGTH:
            text = text[: MAX_EVIDENCE_LENGTH - 3] + "..."
        return text

    def _finding(self, rule: Rule, line: Optional[int], evidence: str,
                 detail: Optional[str] = None) -> Finding:
        return Finding(
            rule_id=rule.id,
            title=rule.title,
            severity=rule.severity,
            line=line,
            evidence=evidence,
            detail=detail or rule.description,
            remediation=rule.remediation,
            cis_reference=rule.cis_reference,
        )

    # -- rule type handlers ------------------------------------------------ #
    def _check_forbid_pattern(self, rule, instructions, stages) -> List[Finding]:
        findings: List[Finding] = []
        for ins in self._scope(rule, instructions, stages):
            if not self._applies(rule, ins):
                continue
            if not rule.pattern.search(ins.raw):
                continue
            if rule.exclude_pattern and rule.exclude_pattern.search(ins.raw):
                continue
            findings.append(self._finding(rule, ins.line, self._evidence(rule, ins)))
        return findings

    def _check_require_pattern(self, rule, instructions, stages) -> List[Finding]:
        for ins in self._scope(rule, instructions, stages):
            if self._applies(rule, ins) and rule.pattern.search(ins.raw):
                return []
        return [self._finding(rule, None, "(no matching instruction found)")]

    def _check_user(self, rule, instructions, stages) -> List[Finding]:
        final_stage = stages[-1]
        users = [i for i in final_stage if i.keyword == "USER"]
        if not users:
            first = final_stage[0]
            return [self._finding(
                rule, first.line, self._evidence(rule, first),
                "No USER instruction in the final build stage; "
                "the container runs as root by default.",
            )]
        last_user = users[-1]
        if rule.pattern.search(last_user.raw):
            return [self._finding(
                rule, last_user.line, self._evidence(rule, last_user),
                "The final USER instruction sets root; "
                "the container process runs with full privileges.",
            )]
        return []

    def _check_base_image(self, rule, instructions, stages) -> List[Finding]:
        forbidden = {str(t).lower() for t in rule.params.get("forbidden_tags", ["latest"])}
        stage_names: set = set()
        findings: List[Finding] = []

        for ins in instructions:
            if ins.keyword != "FROM":
                continue
            tokens = [t for t in ins.arguments.split() if not t.startswith("--")]
            if not tokens:
                continue
            image = tokens[0]
            alias = tokens[2].lower() if len(tokens) >= 3 and tokens[1].upper() == "AS" else None

            skip = (
                image.lower() == "scratch"
                or image.lower() in stage_names   # reference to an earlier stage
                or "$" in image                   # unresolved build-arg
                or "@sha256:" in image.lower()    # immutable digest: OK
            )
            if not skip:
                last_segment = image.rsplit("/", 1)[-1]
                tag = last_segment.split(":", 1)[1] if ":" in last_segment else None
                if tag is None:
                    findings.append(self._finding(
                        rule, ins.line, self._evidence(rule, ins),
                        f"Base image '{image}' has no tag or digest; "
                        "Docker resolves it to ':latest'.",
                    ))
                elif tag.lower() in forbidden:
                    findings.append(self._finding(
                        rule, ins.line, self._evidence(rule, ins),
                        f"Base image '{image}' uses the mutable ':{tag}' tag.",
                    ))
            if alias:
                stage_names.add(alias)
        return findings


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #
SEVERITY_COLORS = {
    Severity.CRITICAL: Fore.RED + Style.BRIGHT,
    Severity.HIGH: Fore.RED,
    Severity.MEDIUM: Fore.YELLOW,
    Severity.LOW: Fore.YELLOW,
}


def should_fail(results: List[RuleResult], threshold: Optional[Severity]) -> bool:
    if threshold is None:
        return False
    return any(f.severity >= threshold for r in results for f in r.findings)


class ReportBuilder:
    """Builds the JSON-serialisable report."""

    @staticmethod
    def build(target: Path, rules_path: Path, ruleset: str, instruction_count: int,
              results: List[RuleResult], threshold: Optional[Severity]) -> Dict[str, object]:
        findings = [f for r in results for f in r.findings]
        by_severity = {s.name: 0 for s in sorted(Severity, reverse=True)}
        for finding in findings:
            by_severity[finding.severity.name] += 1

        return {
            "tool": {"name": TOOL_NAME, "version": VERSION},
            "scan": {
                "target": str(target),
                "timestamp_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "rules_file": str(rules_path),
                "ruleset": ruleset,
                "instructions_analyzed": instruction_count,
            },
            "summary": {
                "rules_evaluated": len(results),
                "rules_passed": sum(1 for r in results if r.passed),
                "rules_failed": sum(1 for r in results if not r.passed),
                "findings_total": len(findings),
                "findings_by_severity": by_severity,
                "fail_threshold": threshold.name if threshold else "NONE",
                "verdict": "FAIL" if should_fail(results, threshold) else "PASS",
            },
            "results": [r.to_dict() for r in results],
        }

    @staticmethod
    def write(report: Dict[str, object], path: Path) -> None:
        try:
            if path.parent and not path.parent.exists():
                path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
            )
        except OSError as exc:
            raise AuditorError(f"Cannot write report to {path}: {exc}")


class ConsoleReporter:
    """Prints the colorized report to the terminal."""

    @staticmethod
    def banner() -> None:
        print(Fore.CYAN + Style.BRIGHT + BANNER + Style.RESET_ALL)
        print(Fore.CYAN + f"  {TOOL_NAME} v{VERSION} - Dockerfile Security Auditor "
              "& Misconfiguration Scanner" + Style.RESET_ALL)
        print(Style.DIM + "  For defensive analysis and authorized auditing only."
              + Style.RESET_ALL + "\n")

    @staticmethod
    def print_report(report: Dict[str, object], results: List[RuleResult]) -> None:
        scan, summary = report["scan"], report["summary"]
        print(f"[*] Target : {scan['target']}")
        print(f"[*] Ruleset: {scan['ruleset']} ({summary['rules_evaluated']} rules)")
        print(f"[*] Parsed : {scan['instructions_analyzed']} instructions\n")

        for result in results:
            rule = result.rule
            if result.passed:
                print(f"{Fore.GREEN}[PASS    ]{Style.RESET_ALL} "
                      f"{rule.id}  {rule.title}")
                continue

            color = SEVERITY_COLORS[rule.severity]
            print(f"{color}[{rule.severity.name:<8}]{Style.RESET_ALL} "
                  f"{rule.id}  {rule.title}  ({rule.cis_reference})")
            for finding in result.findings:
                where = f"Line {finding.line}" if finding.line else "File"
                print(f"    {color}{where:<8}{Style.RESET_ALL}: {finding.evidence}")
                print(f"    Issue   : {finding.detail}")
                print(f"    {Fore.GREEN}Fix{Style.RESET_ALL}     : {finding.remediation}")
            print()

        counts = summary["findings_by_severity"]
        print("-" * 64)
        print(f"Rules passed : {Fore.GREEN}{summary['rules_passed']}{Style.RESET_ALL}"
              f" / {summary['rules_evaluated']}")
        print(f"Findings     : {Fore.RED}CRITICAL {counts['CRITICAL']}{Style.RESET_ALL} | "
              f"{Fore.RED}HIGH {counts['HIGH']}{Style.RESET_ALL} | "
              f"{Fore.YELLOW}MEDIUM {counts['MEDIUM']}{Style.RESET_ALL} | "
              f"{Fore.YELLOW}LOW {counts['LOW']}{Style.RESET_ALL}")
        verdict_color = Fore.RED if summary["verdict"] == "FAIL" else Fore.GREEN
        print(f"Verdict      : {verdict_color}{Style.BRIGHT}{summary['verdict']}"
              f"{Style.RESET_ALL} (fail threshold: {summary['fail_threshold']})")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def build_arg_parser() -> argparse.ArgumentParser:
    default_rules = Path(__file__).resolve().parent / "security_rules.json"
    parser = argparse.ArgumentParser(
        prog="docker_auditor.py",
        description=f"{TOOL_NAME}: audit a Dockerfile for common security misconfigurations.",
    )
    parser.add_argument("dockerfile", help="path to the Dockerfile to audit")
    parser.add_argument("-r", "--rules", default=str(default_rules),
                        help="path to the JSON rules file (default: security_rules.json "
                             "next to the script)")
    parser.add_argument("-o", "--output", default="audit_report.json",
                        help="path of the JSON report (default: audit_report.json)")
    parser.add_argument("--fail-on", default="high",
                        choices=["critical", "high", "medium", "low", "none"],
                        help="exit with code 1 if a finding at/above this severity "
                             "exists (default: high)")
    parser.add_argument("--no-color", action="store_true", help="disable colored output")
    parser.add_argument("--version", action="version", version=f"{TOOL_NAME} {VERSION}")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)

    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(errors="replace")
            except (ValueError, OSError):
                pass
    colorama_init(autoreset=False, strip=True if args.no_color else None)

    reporter = ConsoleReporter()
    reporter.banner()

    threshold = None if args.fail_on == "none" else Severity.parse(args.fail_on)
    target = Path(args.dockerfile)
    rules_path = Path(args.rules)
    output_path = Path(args.output)

    try:
        ruleset, rules = RuleLoader.load(rules_path)
        instructions = DockerfileParser().parse(target)
        results = DockerfileAuditor(rules).audit(instructions)

        report = ReportBuilder.build(target, rules_path, ruleset, len(instructions),
                                     results, threshold)
        reporter.print_report(report, results)
        ReportBuilder.write(report, output_path)
        print(f"\n[+] JSON report saved to: {output_path}")
        return 1 if should_fail(results, threshold) else 0

    except AuditorError as exc:
        print(f"{Fore.RED}[!] Error: {exc}{Style.RESET_ALL}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Interrupted by user.{Style.RESET_ALL}", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())