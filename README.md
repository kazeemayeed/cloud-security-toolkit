# Cloud Infrastructure Security "Hardening as Code" Toolkit

A comprehensive security analysis tool for cloud infrastructure configurations that supports AWS, Azure, and GCP across multiple Infrastructure as Code (IaC) formats.

## Features

- ✅ **Multi-Cloud Support**: AWS, Azure, GCP
- ✅ **Multiple IaC Formats**: Terraform, CloudFormation, ARM Templates
- ✅ **Security Rule Engine**: 100+ built-in security rules
- ✅ **Auto-Remediation**: Suggests and applies fixes
- ✅ **CI/CD Integration**: GitHub Actions, Jenkins, GitLab CI
- ✅ **Detailed Reporting**: JSON, HTML, SARIF formats
- ✅ **Custom Rules**: Extensible rule system

## Quick Start

### Installation
```bash
pip install cloud-security-toolkit

## Publishing to PyPI

### Setup

1. Create accounts on:
   - [Test PyPI](https://test.pypi.org/account/register/)
   - [PyPI](https://pypi.org/account/register/)

2. Generate API tokens:
   - Test PyPI: https://test.pypi.org/manage/account/token/
   - PyPI: https://pypi.org/manage/account/token/

3. Add secrets to your GitHub repository:
   - Go to Settings → Secrets and variables → Actions
   - Add `TEST_PYPI_API_TOKEN` with your Test PyPI token
   - Add `PYPI_API_TOKEN` with your PyPI token (for production)

### Manual Publishing
```bash
# Build the package
python -m build

# Check the package
twine check dist/*

# Upload to Test PyPI
twine upload --repository testpypi dist/*

# Upload to PyPI (production)
twine upload dist/*

# Installation from Test PyPI
pip install --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ cloud-security-toolkit
