"""
Tests for configuration parsers
"""

import pytest
import tempfile
import json
from pathlib import Path

from src.parsers.terraform import TerraformParser
from src.parsers.cloudformation import CloudFormationParser
from src.parsers.arm import ARMParser


class TestTerraformParser:
    @pytest.fixture
    def parser(self):
        return TerraformParser()

    def test_parse_hcl_format(self, parser):
        """Test parsing HCL format Terraform"""
        hcl_content = """
        resource "aws_s3_bucket" "example" {
          bucket = "my-test-bucket"
          acl    = "private"
        }
        """

        with tempfile.NamedTemporaryFile(mode="w", suffix=".tf", delete=False) as f:
            f.write(hcl_content)
            temp_path = Path(f.name)

        try:
            result = parser.parse(temp_path)
            # The HCL parser returns a dict with 'resource' key containing a list
            assert isinstance(result, dict), f"Expected dict, got {type(result)}"
            assert "resource" in result, f"Expected 'resource' key in {result.keys()}"
            
            # The resource value is a list containing dictionaries
            resource_list = result["resource"]
            assert isinstance(resource_list, list), f"Expected list for resource, got {type(resource_list)}"
            assert len(resource_list) > 0, "Expected non-empty resource list"
            
            # Get the first dictionary from the resource list
            resource_dict = resource_list[0]
            assert isinstance(
                resource_dict, dict
            ), f"Expected dict in resource list, got {type(resource_dict)}"
            assert (
                "aws_s3_bucket" in resource_dict
            ), f"Expected 'aws_s3_bucket' in {resource_dict.keys()}"

        finally:
            temp_path.unlink()

    def test_parse_json_format(self, parser):
        """Test parsing JSON format Terraform"""
        json_content = {
            "resource": {
                "aws_s3_bucket": {
                    "example": {"bucket": "my-test-bucket", "acl": "private"}
                }
            }
        }

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".tf.json", delete=False
        ) as f:
            json.dump(json_content, f)
            temp_path = Path(f.name)

        try:
            result = parser.parse(temp_path)
            assert result == json_content
        finally:
            temp_path.unlink()

    def test_get_resources(self, parser):
        """Test extracting resources from parsed content"""
        content = {
            "resource": {"aws_s3_bucket": {"test": {"bucket": "test-bucket"}}},
            "variable": {"name": {"type": "string"}},
        }

        resources = parser.get_resources(content)
        assert "aws_s3_bucket" in resources
        assert "test" in resources["aws_s3_bucket"]


class TestCloudFormationParser:
    @pytest.fixture
    def parser(self):
        return CloudFormationParser()

    def test_parse_json_cloudformation(self, parser):
        """Test parsing JSON CloudFormation template"""
        template = {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "MyBucket": {
                    "Type": "AWS::S3::Bucket",
                    "Properties": {"BucketName": "my-test-bucket"},
                }
            },
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(template, f)
            temp_path = Path(f.name)

        try:
            result = parser.parse(temp_path)
            assert result == template
        finally:
            temp_path.unlink()

    def test_parse_yaml_cloudformation(self, parser):
        """Test parsing YAML CloudFormation template"""
        yaml_content = """
        AWSTemplateFormatVersion: '2010-09-09'
        Resources:
          MyBucket:
            Type: AWS::S3::Bucket
            Properties:
              BucketName: my-test-bucket
        """

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            temp_path = Path(f.name)

        try:
            result = parser.parse(temp_path)
            assert "Resources" in result
            assert "MyBucket" in result["Resources"]
        finally:
            temp_path.unlink()


class TestARMParser:
    @pytest.fixture
    def parser(self):
        return ARMParser()

    def test_parse_arm_template(self, parser):
        """Test parsing ARM template"""
        template = {
            "$schema": (
                "https://schema.management.azure.com/schemas/2019-04-01/"
                "deploymentTemplate.json#"
            ),
            "contentVersion": "1.0.0.0",
            "resources": [
                {
                    "type": "Microsoft.Storage/storageAccounts",
                    "apiVersion": "2021-04-01",
                    "name": "mystorageaccount",
                    "properties": {"allowBlobPublicAccess": True},
                }
            ],
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(template, f)
            temp_path = Path(f.name)

        try:
            result = parser.parse(temp_path)
            assert result == template
        finally:
            temp_path.unlink()
