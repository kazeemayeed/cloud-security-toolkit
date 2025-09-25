"""
Tests for security rules
"""

import pytest
from src.rules.aws_rules import AWSRules
from src.rules.azure_rules import AzureRules
from src.rules.gcp_rules import GCPRules


class TestAWSRules:
    @pytest.fixture
    def aws_rules(self):
        return AWSRules()
    
    def test_s3_public_bucket_detection(self, aws_rules):
        """Test S3 public bucket rule"""
        # Test content with public bucket
        content = {
            'resource': {
                'aws_s3_bucket': {
                    'public_bucket': {
                        'acl': 'public-read',
                        '__line__': 5
                    }
                }
            }
        }
        
        rule = next(r for r in aws_rules.rules if r['id'] == 'aws_s3_public_bucket')
        violations = rule['evaluate'](content)
        
        assert len(violations) == 1
        assert 'public_bucket' in violations[0]['message']
    
    def test_security_group_open_detection(self, aws_rules):
        """Test security group open rule"""
        content = {
            'resource': {
                'aws_security_group': {
                    'open_sg': {
                        'ingress': [{
                            'cidr_blocks': ['0.0.0.0/0'],
                            'from_port': 22
                        }],
                        '__line__': 10
                    }
                }
            }
        }
        
        rule = next(r for r in aws_rules.rules if r['id'] == 'aws_security_group_open')
        violations = rule['evaluate'](content)
        
        assert len(violations) == 1
        assert 'open_sg' in violations[0]['message']


class TestAzureRules:
    @pytest.fixture
    def azure_rules(self):
        return AzureRules()
    
    def test_storage_public_access_detection(self, azure_rules):
        """Test Azure storage public access rule"""
        content = {
            'resource': {
                'azurerm_storage_account': {
                    'public_storage': {
                        'allow_blob_public_access': True,
                        '__line__': 3
                    }
                }
            }
        }
        
        rule = next(r for r in azure_rules.rules if r['id'] == 'azure_storage_public')
        violations = rule['evaluate'](content)
        
        assert len(violations) == 1
        assert 'public_storage' in violations[0]['message']


class TestGCPRules:
    @pytest.fixture
    def gcp_rules(self):
        return GCPRules()
    
    def test_compute_public_ip_detection(self, gcp_rules):
        """Test GCP compute public IP rule"""
        content = {
            'resource': {
                'google_compute_instance': {
                    'public_vm': {
                        'network_interface': [{
                            'access_config': [{}]  # Any access_config means public IP
                        }],
                        '__line__': 8
                    }
                }
            }
        }
        
        rule = next(r for r in gcp_rules.rules if r['id'] == 'gcp_compute_public_ip')
        violations = rule['evaluate'](content)
        
        assert len(violations) == 1
        assert 'public_vm' in violations[0]['message']
