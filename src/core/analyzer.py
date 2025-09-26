"""
Core security analyzer module
"""

import os
import json
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime

from parsers.terraform import TerraformParser
from parsers.cloudformation import CloudFormationParser
from parsers.arm import ARMParser
from rules.aws_rules import AWSRules
from rules.azure_rules import AzureRules
from rules.gcp_rules import GCPRules
from core.rule_engine import RuleEngine
from core.remediation import RemediationEngine


class SecurityAnalyzer:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.rule_engine = RuleEngine()
        self.remediation_engine = RemediationEngine()

        # Initialize parsers
        self.parsers = {
            "terraform": TerraformParser(),
            "cloudformation": CloudFormationParser(),
            "arm": ARMParser(),
        }

        # Initialize rule sets
        self.rule_sets = {
            "aws": AWSRules(),
            "azure": AzureRules(),
            "gcp": GCPRules(),
        }

    def analyze_path(
        self,
        path: Path,
        format: str,
        cloud_provider: str = "all",
        min_severity: str = "medium",
    ) -> Dict[str, Any]:
        """Analyze all files in a path"""
        results = {
            "timestamp": datetime.now().isoformat(),
            "summary": {
                "files_analyzed": 0,
                "total_issues": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
            },
            "findings": [],
        }

        parser = self.parsers.get(format)
        if not parser:
            raise ValueError(f"Unsupported format: {format}")

        files = self._get_files(path, format)

        for file_path in files:
            try:
                file_results = self._analyze_file(
                    file_path, parser, cloud_provider, min_severity
                )
                results["findings"].extend(file_results)
                results["summary"]["files_analyzed"] += 1

            except Exception as e:
                results["findings"].append(
                    {"file": str(file_path), "error": f"Failed to analyze: {str(e)}"}
                )

        # Update summary counts
        for finding in results["findings"]:
            if "severity" in finding:
                severity = finding["severity"].lower()
                results["summary"]["total_issues"] += 1
                results["summary"][severity] = results["summary"].get(severity, 0) + 1

        return results

    def _analyze_file(
        self, file_path: Path, parser, cloud_provider: str, min_severity: str
    ) -> List[Dict[str, Any]]:
        """Analyze a single file"""
        findings = []

        try:
            # Parse the file
            parsed_content = parser.parse(file_path)

            # Get applicable rules based on cloud provider
            applicable_rules = self._get_applicable_rules(cloud_provider, parsed_content)

            # Run rules against parsed content
            for rule in applicable_rules:
                rule_findings = self.rule_engine.evaluate_rule(
                    rule, parsed_content, file_path
                )

                # Filter by severity
                filtered_findings = [
                    f
                    for f in rule_findings
                    if self._severity_meets_threshold(f.get("severity"), min_severity)
                ]

                findings.extend(filtered_findings)

        except Exception as e:
            findings.append(
                {
                    "file": str(file_path),
                    "rule": "parse_error",
                    "severity": "high",
                    "message": f"Failed to parse file: {str(e)}",
                    "line": 1,
                    "column": 1,
                }
            )

        return findings

    def _get_files(self, path: Path, format: str) -> List[Path]:
        """Get all files of specified format from path"""
        extensions = {
            "terraform": [".tf", ".tfvars"],
            "cloudformation": [".yaml", ".yml", ".json"],
            "arm": [".json"],
        }

        target_extensions = extensions.get(format, [])
        files = []

        if path.is_file():
            if path.suffix in target_extensions:
                files.append(path)
        else:
            for ext in target_extensions:
                files.extend(path.rglob(f"*{ext}"))

        return files

    def _get_applicable_rules(self, cloud_provider: str, parsed_content: Dict) -> List:
        """Get rules applicable to the cloud provider and content"""
        rules = []

        if cloud_provider == "all":
            for rule_set in self.rule_sets.values():
                rules.extend(rule_set.get_rules(parsed_content))
        else:
            rule_set = self.rule_sets.get(cloud_provider)
            if rule_set:
                rules.extend(rule_set.get_rules(parsed_content))

        return rules

    def _severity_meets_threshold(self, severity: str, threshold: str) -> bool:
        """Check if severity meets minimum threshold"""
        severity_levels = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        return severity_levels.get(severity, 0) >= severity_levels.get(threshold, 2)

    def remediate_path(
        self,
        path: Path,
        format: str,
        apply_fixes: bool = False,
        create_backup: bool = True,
    ) -> Dict[str, Any]:
        """Remediate issues in a path"""
        # First, analyze to find issues
        analysis_results = self.analyze_path(path, format)

        remediation_results = {
            "total_issues": len(analysis_results["findings"]),
            "auto_fixable": 0,
            "fixed": 0,
            "manual_review": 0,
            "fixes_applied": [],
        }

        for finding in analysis_results["findings"]:
            if self.remediation_engine.can_auto_fix(finding):
                remediation_results["auto_fixable"] += 1

                if apply_fixes:
                    try:
                        fix_result = self.remediation_engine.apply_fix(
                            finding, create_backup
                        )
                        if fix_result["success"]:
                            remediation_results["fixed"] += 1
                            remediation_results["fixes_applied"].append(fix_result)
                    except Exception as e:
                        finding["fix_error"] = str(e)
            else:
                remediation_results["manual_review"] += 1

        return remediation_results
