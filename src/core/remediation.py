"""
Auto-remediation engine
"""

import shutil
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime


class RemediationEngine:
    def __init__(self):
        self.auto_fixable_rules = {
            "aws_s3_public_bucket": self._fix_s3_public_bucket,
            "aws_security_group_open": self._fix_security_group_open,
            "azure_storage_public": self._fix_azure_storage_public,
            "gcp_compute_public_ip": self._fix_gcp_compute_public_ip,
        }

    def can_auto_fix(self, finding: Dict[str, Any]) -> bool:
        """Check if a finding can be automatically fixed"""
        rule_id = finding.get("rule_id")
        return rule_id in self.auto_fixable_rules

    def apply_fix(
        self, finding: Dict[str, Any], create_backup: bool = True
    ) -> Dict[str, Any]:
        """Apply automatic fix to a finding"""
        rule_id = finding.get("rule_id")
        fix_func = self.auto_fixable_rules.get(rule_id)

        if not fix_func:
            return {
                "success": False,
                "error": f"No auto-fix available for rule: {rule_id}",
            }

        file_path = Path(finding["file"])

        try:
            # Create backup if requested
            if create_backup:
                backup_path = self._create_backup(file_path)
            else:
                backup_path = None

            # Apply the fix
            fix_result = fix_func(finding, file_path)

            return {
                "success": True,
                "rule_id": rule_id,
                "file": str(file_path),
                "backup_path": str(backup_path) if backup_path else None,
                "fix_applied": fix_result,
                "timestamp": datetime.now().isoformat(),
            }

        except Exception as e:
            return {"success": False, "rule_id": rule_id, "file": str(file_path), "error": str(e)}

    def _create_backup(self, file_path: Path) -> Path:
        """Create a backup of the file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = file_path.with_suffix(f".backup_{timestamp}{file_path.suffix}")
        shutil.copy2(file_path, backup_path)
        return backup_path

    def _fix_s3_public_bucket(self, finding: Dict[str, Any], file_path: Path) -> str:
        """Fix S3 bucket public access"""
        # Read file content
        content = file_path.read_text()

        # Simple text replacement for common cases
        # This is a simplified example - real implementation would use proper parsing
        fixes = [
            ('acl = "public-read"', 'acl = "private"'),
            ('acl = "public-read-write"', 'acl = "private"'),
            ('"PublicRead"', '"Private"'),
            ('"PublicReadWrite"', '"Private"'),
        ]

        original_content = content
        for old, new in fixes:
            content = content.replace(old, new)

        if content != original_content:
            file_path.write_text(content)
            return "Removed public ACL from S3 bucket"

        return "No changes needed"

    def _fix_security_group_open(self, finding: Dict[str, Any], file_path: Path) -> str:
        """Fix overly permissive security group rules"""
        content = file_path.read_text()

        # Replace 0.0.0.0/0 with more restrictive CIDR
        fixes = [
            ('cidr_blocks = ["0.0.0.0/0"]', 'cidr_blocks = ["10.0.0.0/8"]'),
            ('"0.0.0.0/0"', '"10.0.0.0/8"'),
        ]

        original_content = content
        for old, new in fixes:
            content = content.replace(old, new)

        if content != original_content:
            file_path.write_text(content)
            return "Restricted security group CIDR blocks"

        return "No changes needed"

    def _fix_azure_storage_public(self, finding: Dict[str, Any], file_path: Path) -> str:
        """Fix Azure storage public access"""
        content = file_path.read_text()

        fixes = [
            ("allow_blob_public_access = true", "allow_blob_public_access = false"),
            ('"publicAccess": "blob"', '"publicAccess": "none"'),
            ('"publicAccess": "container"', '"publicAccess": "none"'),
        ]

        original_content = content
        for old, new in fixes:
            content = content.replace(old, new)

        if content != original_content:
            file_path.write_text(content)
            return "Disabled public access on Azure storage"

        return "No changes needed"

    def _fix_gcp_compute_public_ip(self, finding: Dict[str, Any], file_path: Path) -> str:
        """Fix GCP compute instance public IP"""
        content = file_path.read_text()

        # This is a simplified fix - real implementation would be more sophisticated
        if "access_config" in content and "nat_ip" in content:
            # Remove or comment out public IP configuration
            lines = content.split("\n")
            fixed_lines = []
            skip_block = False

            for line in lines:
                if "access_config" in line and "{" in line:
                    skip_block = True
                    fixed_lines.append("  # " + line + " # Removed public IP for security")
                    continue

                if skip_block and "}" in line:
                    skip_block = False
                    fixed_lines.append("  # " + line)
                    continue

                if skip_block:
                    fixed_lines.append("  # " + line)
                else:
                    fixed_lines.append(line)

            content = "\n".join(fixed_lines)
            file_path.write_text(content)
            return "Removed public IP from GCP compute instance"

        return "No changes needed"
