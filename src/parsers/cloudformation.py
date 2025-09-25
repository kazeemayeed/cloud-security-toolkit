"""
CloudFormation template parser
"""

import json
from pathlib import Path
from typing import Any, Dict

import yaml


class CloudFormationParser:
    def parse(self, file_path: Path) -> Dict[str, Any]:
        """Parse CloudFormation template"""
        try:
            content = file_path.read_text(encoding="utf-8")

            if file_path.suffix.lower() == ".json":
                return json.loads(content)
            else:
                # Try to parse as YAML
                return yaml.safe_load(content)

        except Exception as e:
            raise ValueError(
                f"Failed to parse CloudFormation file {file_path}: {str(e)}"
            )

    def get_resources(self, parsed_content: Dict[str, Any]) -> Dict[str, Any]:
        """Extract resources from parsed content"""
        return parsed_content.get("Resources", {})

    def get_parameters(self, parsed_content: Dict[str, Any]) -> Dict[str, Any]:
        """Extract parameters from parsed content"""
        return parsed_content.get("Parameters", {})

    def get_outputs(self, parsed_content: Dict[str, Any]) -> Dict[str, Any]:
        """Extract outputs from parsed content"""
        return parsed_content.get("Outputs", {})

    def get_mappings(self, parsed_content: Dict[str, Any]) -> Dict[str, Any]:
        """Extract mappings from parsed content"""
        return parsed_content.get("Mappings", {})
