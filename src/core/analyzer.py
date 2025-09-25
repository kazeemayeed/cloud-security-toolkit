"""
Core security analyzer module
"""

import os
import json
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime

from ..parsers.terraform import TerraformParser
from ..parsers.cloudformation import CloudFormationParser
from ..parsers.arm import ARMParser
from ..rules.aws_rules import AWSRules
from ..rules.azure_rules import AzureRules
from ..rules.gcp_rules import GCPRules
from .rule_engine import RuleEngine
from .remediation import RemediationEngine


class SecurityAnalyzer:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.rule_engine = RuleEngine()
        self.remediation_engine = RemediationEngine()
        
        # Initialize parsers
        self.parsers = {
            'terraform': TerraformParser(),
            'cloudformation': CloudFormationParser(),
            'arm': ARMParser()
        }
        
        # Initialize rule sets
        self.rule_sets = {
            'aws': AWSRules(),
            'azure': AzureRules(),
            'gcp': GCPRules()
        }
        
    def analyze_path(self, path: Path, format: str, cloud_provider: str = 'all', 
                    min_severity: str = 'medium') -> Dict[str, Any]:
        """Analyze all files in a path"""
        results = {
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'files_analyzed': 0,
                'total_issues': 0,
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0
            },
            'findings': []
        }
        
        parser = self.parsers.get(format)
        if not parser:
            raise ValueError(f"Unsupported format: {format}")
        
        files = self._get_files(path, format)
        
        for file_path in files:
            try:
                file_results = self._analyze_file(file_path, parser, cloud_provider, min_severity)
                results['findings'].extend(file_results)
                results['summary']['files_analyzed'] += 1
                
            except Exception as e:
                results['findings'].append({
                    'file': str(file_path),
                    'error': f"Failed to analyze: {str(e)}"
                })
        
        # Update summary counts
        for finding in results['findings']:
            if 'severity' in finding:
                severity = finding['severity'].lower()
                results['summary']['total_issues'] += 1
                results['summary'][severity] = results['summary'].get(severity, 0) + 1
        
        return violations
    
    def _check_security_group_open(self, content: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for security groups open to the world"""
        violations = []
        
        if 'resource' in content:
            for resource_type, resources in content['resource'].items():
                if resource_type == 'aws_security_group':
                    for resource_name, resource_config in resources.items():
                        ingress_rules = resource_config.get('ingress', [])
                        if not isinstance(ingress_rules, list):
                            ingress_rules = [ingress_rules]
                        
                        for rule in ingress_rules:
                            cidr_blocks = rule.get('cidr_blocks', [])
                            if '0.0.0.0/0' in cidr_blocks:
                                violations.append({
                                    'message': f'Security group {resource_name} allows inbound traffic from anywhere',
                                    'resource': f'{resource_type}.{resource_name}',
                                    'line': resource_config.get('__line__', 1)
                                })
        
        return violations
    
    def _check_rds_public_access(self, content: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for RDS instances with public access"""
        violations = []
        
        if 'resource' in content:
            for resource_type, resources in content['resource'].items():
                if resource_type == 'aws_db_instance':
                    for resource_name, resource_config in resources.items():
                        publicly_accessible = resource_config.get('publicly_accessible', False)
                        if publicly_accessible:
                            violations.append({
                                'message': f'RDS instance {resource_name} is publicly accessible',
                                'resource': f'{resource_type}.{resource_name}',
                                'line': resource_config.get('__line__', 1)
                            })
        
        return violations
    
    def _check_iam_wildcard_policy(self, content: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for IAM policies with wildcard actions"""
        violations = []
        
        if 'resource' in content:
            for resource_type, resources in content['resource'].items():
                if resource_type in ['aws_iam_policy', 'aws_iam_role_policy']:
                    for resource_name, resource_config in resources.items():
                        policy = resource_config.get('policy', '')
                        if isinstance(policy, str) and '"*"' in policy:
                            violations.append({
                                'message': f'IAM policy {resource_name} contains wildcard actions',
                                'resource': f'{resource_type}.{resource_name}',
                                'line': resource_config.get('__line__', 1)
                            })
        
        return violations
    
    def _is_s3_bucket_public(self, config: Dict[str, Any]) -> bool:
        """Check if S3 bucket configuration allows public access"""
        # Check various ways a bucket can be made public
        acl = config.get('acl', '')
        if acl in ['public-read', 'public-read-write']:
            return True
        
        # Check for public access block settings
        public_access_block = config.get('public_access_block', {})
        if public_access_block:
            block_public_acls = public_access_block.get('block_public_acls', True)
            block_public_policy = public_access_block.get('block_public_policy', True)
            ignore_public_acls = public_access_block.get('ignore_public_acls', True)
            restrict_public_buckets = public_access_block.get('restrict_public_buckets', True)
            
            if not (block_public_acls and block_public_policy and 
                   ignore_public_acls and restrict_public_buckets):
                return True
        
        return False
