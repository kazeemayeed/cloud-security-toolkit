"""
Azure Resource Manager (ARM) template parser
"""

import json
from pathlib import Path
from typing import Dict, Any


class ARMParser:
    def parse(self, file_path: Path) -> Dict[str, Any]:
        """Parse ARM template"""
        try:
            content = file_path.read_text(encoding="utf-8")
            return json.loads(content)

        except Exception as e:
            raise ValueError(f"Failed to parse ARM template {file_path}: {str(e)}")

    def get_resources(self, parsed_content: Dict[str, Any]) -> Dict[str, Any]:
        """Extract resources from parsed content"""
        resources = parsed_content.get("resources", [])
        # Convert list to dict for easier processing
        resource_dict = {}
        for i, resource in enumerate(resources):
            resource_name = resource.get("name", f"resource_{i}")
            resource_dict[resource_name] = resource
        return resource_dict

    def get_parameters(self, parsed_content: Dict[str, Any]) -> Dict[str, Any]:
        """Extract parameters from parsed content"""
        return parsed_content.get("parameters", {})

    def get_variables(self, parsed_content: Dict[str, Any]) -> Dict[str, Any]:
        """Extract variables from parsed content"""
        return parsed_content.get("variables", {})

    def get_outputs(self, parsed_content: Dict[str, Any]) -> Dict[str, Any]:
        """Extract outputs from parsed content"""
        return parsed_content.get("outputs", {})
