"""
GCP Security Rules
"""

from typing import Any, Dict, List


class GCPRules:
    def __init__(self):
        self.rules = [
            {
                "id": "gcp_compute_public_ip",
                "name": "Compute Instance Public IP",
                "category": "compute",
                "severity": "medium",
                "description": "Compute instance has a public IP address",
                "fix_suggestion": "Remove public IP and use Cloud NAT or bastion host for internet access",
                "references": [
                    "https://cloud.google.com/compute/docs/ip-addresses/external-ip-addresses"
                ],
                "evaluate": self._check_compute_public_ip,
            },
            {
                "id": "gcp_firewall_open",
                "name": "Firewall Rule Open to Internet",
                "category": "network",
                "severity": "critical",
                "description": "Firewall rule allows traffic from 0.0.0.0/0",
                "fix_suggestion": "Restrict source ranges to specific IP addresses or ranges",
                "references": ["https://cloud.google.com/vpc/docs/firewalls"],
                "evaluate": self._check_firewall_open,
            },
            {
                "id": "gcp_storage_public",
                "name": "Cloud Storage Public Access",
                "category": "storage",
                "severity": "high",
                "description": "Cloud Storage bucket allows public access",
                "fix_suggestion": "Remove allUsers and allAuthenticatedUsers from bucket IAM",
                "references": [
                    "https://cloud.google.com/storage/docs/access-control/making-data-public"
                ],
                "evaluate": self._check_storage_public_access,
            },
            {
                "id": "gcp_sql_public_ip",
                "name": "Cloud SQL Public IP",
                "category": "database",
                "severity": "high",
                "description": "Cloud SQL instance has a public IP address",
                "fix_suggestion": "Use private IP and remove public IP configuration",
                "references": ["https://cloud.google.com/sql/docs/mysql/private-ip"],
                "evaluate": self._check_sql_public_ip,
            },
        ]

    def get_rules(self, content: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Get rules applicable to the content"""
        return self.rules

    def _check_compute_public_ip(self, content: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for compute instances with public IPs"""
        violations = []

        if "resource" in content:
            for resource_type, resources in content["resource"].items():
                if resource_type == "google_compute_instance":
                    for resource_name, resource_config in resources.items():
                        network_interfaces = resource_config.get(
                            "network_interface", []
                        )
                        if not isinstance(network_interfaces, list):
                            network_interfaces = [network_interfaces]

                        for interface in network_interfaces:
                            access_configs = interface.get("access_config", [])
                            if access_configs:  # Any access_config means public IP
                                violations.append(
                                    {
                                        "message": f"Compute instance {resource_name} has a public IP",
                                        "resource": f"{resource_type}.{resource_name}",
                                        "line": resource_config.get("__line__", 1),
                                    }
                                )
                                break

        return violations

    def _check_firewall_open(self, content: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for firewall rules open to the internet"""
        violations = []

        if "resource" in content:
            for resource_type, resources in content["resource"].items():
                if resource_type == "google_compute_firewall":
                    for resource_name, resource_config in resources.items():
                        source_ranges = resource_config.get("source_ranges", [])
                        direction = resource_config.get("direction", "INGRESS")

                        if direction == "INGRESS" and "0.0.0.0/0" in source_ranges:
                            allow_rules = resource_config.get("allow", [])
                            if allow_rules:  # Only flag if there are allow rules
                                violations.append(
                                    {
                                        "message": f"Firewall rule {resource_name} allows ingress from anywhere",
                                        "resource": f"{resource_type}.{resource_name}",
                                        "line": resource_config.get("__line__", 1),
                                    }
                                )

        return violations

    def _check_storage_public_access(
        self, content: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Check for Cloud Storage buckets with public access"""
        violations = []

        if "resource" in content:
            for resource_type, resources in content["resource"].items():
                if resource_type == "google_storage_bucket_iam_member":
                    for resource_name, resource_config in resources.items():
                        member = resource_config.get("member", "")
                        if member in ["allUsers", "allAuthenticatedUsers"]:
                            violations.append(
                                {
                                    "message": f"Storage bucket IAM {resource_name} grants public access",
                                    "resource": f"{resource_type}.{resource_name}",
                                    "line": resource_config.get("__line__", 1),
                                }
                            )

        return violations

    def _check_sql_public_ip(self, content: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for Cloud SQL instances with public IPs"""
        violations = []

        if "resource" in content:
            for resource_type, resources in content["resource"].items():
                if resource_type == "google_sql_database_instance":
                    for resource_name, resource_config in resources.items():
                        settings = resource_config.get("settings", {})
                        ip_configuration = settings.get("ip_configuration", {})

                        # Check if public IP is explicitly enabled or not disabled
                        ipv4_enabled = ip_configuration.get("ipv4_enabled", True)
                        if ipv4_enabled:
                            violations.append(
                                {
                                    "message": f"Cloud SQL instance {resource_name} has public IP enabled",
                                    "resource": f"{resource_type}.{resource_name}",
                                    "line": resource_config.get("__line__", 1),
                                }
                            )

        return violations
