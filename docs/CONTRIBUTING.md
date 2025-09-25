# Contributing to Cloud Security Toolkit

Thank you for your interest in contributing to the Cloud Security Toolkit! This document provides guidelines and information for contributors.

## Development Setup

### Prerequisites
- Python 3.8 or higher
- Git

### Setting up the development environment

1. Fork the repository on GitHub
2. Clone your fork locally:
```bash
   git clone https://github.com/yourusername/cloud-security-toolkit.git
   cd cloud-security-toolkit
3. Create a virtual environment:
python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
4. Install development dependencies:
make install-dev
5. Run tests to verify setup:
make test

##Development Workflow
Creating a new feature or fix
1. Create a new branch from main:
git checkout -b feature/your-feature-name
2. Make your changes
3. Add tests for your changes
4. Run the test suite:
make test
make lint
5. Commit your changes:
git commit -m "Add: your descriptive commit message"
6. Push to your fork:
git push origin feature/your-feature-name
7. Create a Pull Request
Code Style
We use the following tools for code quality:

Black for code formatting
Flake8 for linting
isort for import sorting

Run formatting before committing:
make format
Commit Messages
Use clear, descriptive commit messages:

Add: new feature description
Fix: bug description
Update: what was updated
Remove: what was removed

Adding New Rules
Rule Structure
Security rules should follow this structure:
{
    'id': 'unique_rule_id',
    'name': 'Human Readable Rule Name',
    'category': 'security_category',  # e.g., 'network', 'storage', 'identity'
    'severity': 'critical|high|medium|low',
    'description': 'Detailed description of the security issue',
    'fix_suggestion': 'How to fix this issue',
    'references': ['https://docs.example.com/security-best-practices'],
    'evaluate': function_that_evaluates_the_rule
}
Adding AWS Rules

Add your rule to src/rules/aws_rules.py
Implement the evaluation function
Add tests in tests/test_rules.py

Example:
def _check_my_new_rule(self, content: Dict[str, Any]) -> List[Dict[str, Any]]:
    violations = []
    
    if 'resource' in content:
        for resource_type, resources in content['resource'].items():
            if resource_type == 'aws_target_resource':
                for resource_name, resource_config in resources.items():
                    if self._has_security_issue(resource_config):
                        violations.append({
                            'message': f'Security issue in {resource_name}',
                            'resource': f'{resource_type}.{resource_name}',
                            'line': resource_config.get('__line__', 1)
                        })
    
    return violations
Testing Rules
All rules must have corresponding tests:
def test_my_new_rule(self, aws_rules):
    content = {
        'resource': {
            'aws_target_resource': {
                'test_resource': {
                    'vulnerable_setting': True,
                    '__line__': 5
                }
            }
        }
    }
    
    rule = next(r for r in aws_rules.rules if r['id'] == 'my_new_rule_id')
    violations = rule['evaluate'](content)
    
    assert len(violations) == 1
    assert 'test_resource' in violations[0]['message']
Adding Support for New Cloud Providers

Create a new rule file: src/rules/newcloud_rules.py
Follow the existing pattern from AWS/Azure/GCP rules
Add parser support if needed
Update the analyzer to include the new provider
Add comprehensive tests
Update documentation

Adding Auto-Remediation
To add auto-fix capability for a rule:

Add the rule ID to auto_fixable_rules in src/core/remediation.py
Implement the fix function:
def _fix_my_rule(self, finding: Dict[str, Any], file_path: Path) -> str:
    content = file_path.read_text()
    
    # Implement the fix logic
    fixed_content = content.replace('bad_config', 'good_config')
    
    if content != fixed_content:
        file_path.write_text(fixed_content)
        return "Applied security fix"
    
    return "No changes needed"
Add tests for the remediation function
