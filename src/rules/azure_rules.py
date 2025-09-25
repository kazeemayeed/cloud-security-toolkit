"""
Azure Security Rules
"""

from typing import Any, Dict, List


class AzureRules:
    def __init__(self):
        self.rules = [
            {
                "id": "azure_storage_public",
                "name": "Azure Storage Public Access",
                "category": "storage",
                "severity": "high",
                "description": "Storage account allows public blob access",
                "fix_suggestion": "Set allow_blob_public_access to false",
                "references": [
                    "https://docs.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-prevent"
                ],
                "evaluate": self._check_storage_public_access,
            },
            {
                "id": "azure_nsg_open",
                "name": "Network Security Group Open Rules",
                "category": "network",
                "severity": "critical",
                "description": "NSG rule allows inbound traffic from any source",
                "fix_suggestion": "Restrict source address prefixes to specific ranges",
                "references": [
                    "https://docs.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview"
                ],
                "evaluate": self._check_nsg_open_rules,
            },
            {
                "id": "azure_sql_public",
                "name": "Azure SQL Public Access",
                "category": "database",
                "severity": "high",
                "description": "Azure SQL server allows connections from any Azure service",
                "fix_suggestion": "Configure specific firewall rules instead of allowing all Azure services",
                "references": [
                    "https://docs.microsoft.com/en-us/azure/azure-sql/database/firewall-configure"
                ],
                "evaluate": self._check_sql_public_access,
            },
            {
                "id": "azure_vm_no_encryption",
                "name": "Virtual Machine Disk Encryption",
                "category": "compute",
                "severity": "medium",
                "description": "Virtual machine does not have disk encryption enabled",
                "fix_suggestion": "Enable Azure Disk Encryption for VM disks",
                "references": [
                    "https://docs.microsoft.com/en-us/azure/virtual-machines/disk-encryption-overview"
                ],
                "evaluate": self._check_vm_disk_encryption,
            },
        ]

    def get_rules(self, content: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Get rules applicable to the content"""
        return self.rules

    def _check_storage_public_access(
        self, content: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Check for storage accounts with public access"""
        violations = []

        # Check Terraform resources
        if "resource" in content:
            for resource_type, resources in content["resource"].items():
                if resource_type == "azurerm_storage_account":
                    for resource_name, resource_config in resources.items():
                        allow_public_access = resource_config.get(
                            "allow_blob_public_access", True
                        )
                        if allow_public_access:
                            violations.append(
                                {
                                    "message": f"Storage account {resource_name} allows public blob access",
                                    "resource": f"{resource_type}.{resource_name}",
                                    "line": resource_config.get("__line__", 1),
                                }
                            )

        # Check ARM templates
        if "resources" in content:
            for resource in content["resources"]:
                if resource.get("type") == "Microsoft.Storage/storageAccounts":
                    properties = resource.get("properties", {})
                    allow_public_access = properties.get("allowBlobPublicAccess", True)
                    if allow_public_access:
                        violations.append(
                            {
                                "message": f'Storage account {resource.get("name", "unknown")} allows public blob access',
                                "resource": resource.get("name", "unknown"),
                                "line": 1,
                            }
                        )

        return violations

    def _check_nsg_open_rules(self, content: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for NSG rules that are too open"""
        violations = []

        if "resource" in content:
            for resource_type, resources in content["resource"].items():
                if resource_type == "azurerm_network_security_rule":
                    for resource_name, resource_config in resources.items():
                        source_address_prefix = resource_config.get(
                            "source_address_prefix", ""
                        )
                        if source_address_prefix in ["*", "0.0.0.0/0", "Internet"]:
                            access = resource_config.get("access", "")
                            if access.lower() == "allow":
                                violations.append(
                                    {
                                        "message": f"NSG rule {resource_name} allows traffic from any source",
                                        "resource": f"{resource_type}.{resource_name}",
                                        "line": resource_config.get("__line__", 1),
                                    }
                                )

        return violations

    def _check_sql_public_access(self, content: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for Azure SQL with overly permissive firewall rules"""
        violations = []

        if "resource" in content:
            for resource_type, resources in content["resource"].items():
                if resource_type == "azurerm_sql_firewall_rule":
                    for resource_name, resource_config in resources.items():
                        start_ip = resource_config.get("start_ip_address", "")
                        end_ip = resource_config.get("end_ip_address", "")

                        # Check for rules that allow all Azure services (0.0.0.0)
                        # or all internet traffic
                        if (start_ip == "0.0.0.0" and end_ip == "0.0.0.0") or (
                            start_ip == "0.0.0.0" and end_ip == "255.255.255.255"
                        ):
                            violations.append(
                                {
                                    "message": f"SQL firewall rule {resource_name} is too permissive",
                                    "resource": f"{resource_type}.{resource_name}",
                                    "line": resource_config.get("__line__", 1),
                                }
                            )

        return violations

    def _check_vm_disk_encryption(
        self, content: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Check for VMs without disk encryption"""
        violations = []

        if "resource" in content:
            for resource_type, resources in content["resource"].items():
                if (
                    resource_type == "azurerm_linux_virtual_machine"
                    or resource_type == "azurerm_windows_virtual_machine"
                ):
                    for resource_name, resource_config in resources.items():
                        # Check if disk encryption is configured
                        os_disk = resource_config.get("os_disk", {})
                        encryption_settings = os_disk.get("encryption_settings", {})

                        if not encryption_settings or not encryption_settings.get(
                            "enabled", False
                        ):
                            violations.append(
                                {
                                    "message": f"VM {resource_name} does not have disk encryption enabled",
                                    "resource": f"{resource_type}.{resource_name}",
                                    "line": resource_config.get("__line__", 1),
                                }
                            )

        return violations
