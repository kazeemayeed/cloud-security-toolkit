"""
AWS Security Rules
"""

import re
from typing import Any, Dict, List


class AWSRules:
    def __init__(self):
        self.rules = [
            {
                "id": "aws_s3_public_bucket",
                "name": "S3 Bucket Public Access",
                "category": "storage",
                "severity": "high",
                "description": "S3 bucket allows public read or write access",
                "fix_suggestion": "Set bucket ACL to private and use bucket policies for controlled access",
                "references": [
                    "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"
                ],
                "evaluate": self._check_s3_public_bucket,
            },
            {
                "id": "aws_security_group_open",
                "name": "Security Group Open to World",
                "category": "network",
                "severity": "critical",
                "description": "Security group allows inbound traffic from 0.0.0.0/0",
                "fix_suggestion": "Restrict CIDR blocks to specific IP ranges",
                "references": [
                    "https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html"
                ],
                "evaluate": self._check_security_group_open,
            },
            {
                "id": "aws_rds_public_access",
                "name": "RDS Instance Public Access",
                "category": "database",
                "severity": "high",
                "description": "RDS instance is publicly accessible",
                "fix_suggestion": "Set publicly_accessible to false",
                "references": [
                    "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.RDSSecurityGroups.html"
                ],
                "evaluate": self._check_rds_public_access,
            },
            {
                "id": "aws_iam_wildcard_policy",
                "name": "IAM Policy with Wildcard Actions",
                "category": "identity",
                "severity": "medium",
                "description": "IAM policy contains wildcard (*) actions",
                "fix_suggestion": "Use specific actions instead of wildcards",
                "references": [
                    "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html"
                ],
                "evaluate": self._check_iam_wildcard_policy,
            },
        ]

    def get_rules(self, content: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Get rules applicable to the content"""
        return self.rules

    def _check_s3_public_bucket(self, content: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for S3 buckets with public access"""
        violations = []

        # Check Terraform resources
        if "resource" in content:
            for resource_type, resources in content["resource"].items():
                if resource_type == "aws_s3_bucket":
                    for resource_name, resource_config in resources.items():
                        if self._is_s3_bucket_public(resource_config):
                            violations.append(
                                {
                                    "message": f"S3 bucket {resource_name} allows public access",
                                    "resource": f"{resource_type}.{resource_name}",
                                    "line": resource_config.get("__line__", 1),
                                }
                            )

                elif resource_type == "aws_s3_bucket_acl":
                    for resource_name, resource_config in resources.items():
                        acl = resource_config.get("acl", "")
                        if acl in ["public-read", "public-read-write"]:
                            violations.append(
                                {
                                    "message": f"S3 bucket ACL {resource_name} is public",
                                    "resource": f"{resource_type}.{resource_name}",
                                    "line": resource_config.get("__line__", 1),
                                }
                            )

        return violations

    def _check_security_group_open(
        self, content: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Check for security groups open to the world"""
        violations = []

        if "resource" in content:
            for resource_type, resources in content["resource"].items():
                if resource_type == "aws_security_group":
                    for resource_name, resource_config in resources.items():
                        ingress_rules = resource_config.get("ingress", [])
                        if not isinstance(ingress_rules, list):
                            ingress_rules = [ingress_rules]

                        for rule in ingress_rules:
                            cidr_blocks = rule.get("cidr_blocks", [])
                            if "0.0.0.0/0" in cidr_blocks:
                                violations.append(
                                    {
                                        "message": f"Security group {resource_name} allows inbound traffic from anywhere",
                                        "resource": f"{resource_type}.{resource_name}",
                                        "line": resource_config.get("__line__", 1),
                                    }
                                )

        return violations

    def _check_rds_public_access(self, content: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for RDS instances with public access"""
        violations = []

        if "resource" in content:
            for resource_type, resources in content["resource"].items():
                if resource_type == "aws_db_instance":
                    for resource_name, resource_config in resources.items():
                        publicly_accessible = resource_config.get(
                            "publicly_accessible", False
                        )
                        if publicly_accessible:
                            violations.append(
                                {
                                    "message": f"RDS instance {resource_name} is publicly accessible",
                                    "resource": f"{resource_type}.{resource_name}",
                                    "line": resource_config.get("__line__", 1),
                                }
                            )

        return violations

    def _check_iam_wildcard_policy(
        self, content: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Check for IAM policies with wildcard actions"""
        violations = []

        if "resource" in content:
            for resource_type, resources in content["resource"].items():
                if resource_type in ["aws_iam_policy", "aws_iam_role_policy"]:
                    for resource_name, resource_config in resources.items():
                        policy = resource_config.get("policy", "")
                        if isinstance(policy, str) and '"*"' in policy:
                            violations.append(
                                {
                                    "message": f"IAM policy {resource_name} contains wildcard actions",
                                    "resource": f"{resource_type}.{resource_name}",
                                    "line": resource_config.get("__line__", 1),
                                }
                            )

        return violations

    def _is_s3_bucket_public(self, config: Dict[str, Any]) -> bool:
        """Check if S3 bucket configuration allows public access"""
        # Check various ways a bucket can be made public
        acl = config.get("acl", "")
        if acl in ["public-read", "public-read-write"]:
            return True

        # Check for public access block settings
        if public_access_block := config.get("public_access_block", {}):
            block_public_acls = public_access_block.get("block_public_acls", True)
            block_public_policy = public_access_block.get("block_public_policy", True)
            ignore_public_acls = public_access_block.get("ignore_public_acls", True)
            restrict_public_buckets = public_access_block.get(
                "restrict_public_buckets", True
            )

            if not (
                block_public_acls
                and block_public_policy
                and ignore_public_acls
                and restrict_public_buckets
            ):
                return True

        return False
