"""
Terraform configuration parser
"""

import hcl2
import json
from pathlib import Path
from typing import Dict, Any


class TerraformParser:
    def parse(self, file_path: Path) -> Dict[str, Any]:
        """Parse Terraform configuration file"""
        try:
            content = file_path.read_text(encoding='utf-8')
            
            if file_path.suffix == '.json':
                # Parse JSON format Terraform
                return json.loads(content)
            else:
                # Parse HCL format Terraform
                return hcl2.loads(content)
                
        except Exception as e:
            raise ValueError(f"Failed to parse Terraform file {file_path}: {str(e)}")
    
    def get_resources(self, parsed_content: Dict[str, Any]) -> Dict[str, Any]:
        """Extract resources from parsed content"""
        return parsed_content.get('resource', {})
    
    def get_data_sources(self, parsed_content: Dict[str, Any]) -> Dict[str, Any]:
        """Extract data sources from parsed content"""
        return parsed_content.get('data', {})
    
    def get_variables(self, parsed_content: Dict[str, Any]) -> Dict[str, Any]:
        """Extract variables from parsed content"""
        return parsed_content.get('variable', {})
    
    def get_outputs(self, parsed_content: Dict[str, Any]) -> Dict[str, Any]:
        """Extract outputs from parsed content"""
        return parsed_content.get('output', {})
