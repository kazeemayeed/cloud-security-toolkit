"""
Tests for the security analyzer
"""

import pytest
from pathlib import Path
from unittest.mock import Mock, patch
import tempfile
import json

from src.core.analyzer import SecurityAnalyzer


class TestSecurityAnalyzer:
    @pytest.fixture
    def config(self):
        return {
            'analysis': {
                'severity_threshold': 'medium',
                'output_format': 'json'
            },
            'rules': {
                'aws': ['encryption_at_rest', 'public_access'],
                'azure': ['network_security'],
                'gcp': ['compute_security']
            }
        }
    
    @pytest.fixture
    def analyzer(self, config):
        return SecurityAnalyzer(config)
    
    def test_analyzer_initialization(self, analyzer):
        """Test analyzer initializes correctly"""
        assert analyzer.config is not None
        assert analyzer.rule_engine is not None
        assert analyzer.remediation_engine is not None
        assert 'terraform' in analyzer.parsers
        assert 'cloudformation' in analyzer.parsers
        assert 'arm' in analyzer.parsers
    
    def test_get_files_terraform(self, analyzer):
        """Test getting Terraform files from directory"""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            # Create test files
            (temp_path / "main.tf").write_text("resource \"aws_s3_bucket\" \"test\" {}")
            (temp_path / "variables.tf").write_text("variable \"name\" {}")
            (temp_path / "readme.md").write_text("# README")
            
            files = analyzer._get_files(temp_path, 'terraform')
            
            assert len(files) == 2
            assert any(f.name == 'main.tf' for f in files)
            assert any(f.name == 'variables.tf' for f in files)
    
    def test_get_files_single_file(self, analyzer):
        """Test getting single file"""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            test_file = temp_path / "test.tf"
            test_file.write_text("resource \"aws_s3_bucket\" \"test\" {}")
            
            files = analyzer._get_files(test_file, 'terraform')
            
            assert len(files) == 1
            assert files[0] == test_file
    
    def test_severity_meets_threshold(self, analyzer):
        """Test severity threshold checking"""
        assert analyzer._severity_meets_threshold('critical', 'medium') == True
        assert analyzer._severity_meets_threshold('high', 'medium') == True
        assert analyzer._severity_meets_threshold('medium', 'medium') == True
        assert analyzer._severity_meets_threshold('low', 'medium') == False
        assert analyzer._severity_meets_threshold('high', 'critical') == False
    
    @patch('src.core.analyzer.TerraformParser')
    def test_analyze_file_success(self, mock_parser_class, analyzer):
        """Test successful file analysis"""
        # Setup mock parser
        mock_parser = Mock()
        mock_parser.parse.return_value = {
            'resource': {
                'aws_s3_bucket': {
                    'test': {'acl': 'public-read'}
                }
            }
        }
        analyzer.parsers['terraform'] = mock_parser
        
        # Mock rule engine
        analyzer.rule_engine.evaluate_rule = Mock(return_value=[{
            'severity': 'high',
            'message': 'Test finding',
            'line': 1
        }])
        
        with tempfile.NamedTemporaryFile(suffix='.tf') as temp_file:
            temp_path = Path(temp_file.name)
            
            findings = analyzer._analyze_file(temp_path, mock_parser, 'aws', 'medium')
            
            assert len(findings) > 0
            mock_parser.parse.assert_called_once_with(temp_path)
    
    def test_analyze_path_with_no_files(self, analyzer):
        """Test analysis with no matching files"""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            (temp_path / "readme.txt").write_text("No terraform files here")
            
            results = analyzer.analyze_path(temp_path, 'terraform')
            
            assert results['summary']['files_analyzed'] == 0
            assert results['summary']['total_issues'] == 0
