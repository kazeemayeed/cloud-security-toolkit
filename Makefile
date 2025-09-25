.PHONY: help install test lint format clean build docker-build docker-run

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $1, $2}' $(MAKEFILE_LIST)

install: ## Install dependencies
	pip install -r requirements.txt
	pip install -e .

install-dev: ## Install development dependencies
	pip install -r requirements.txt
	pip install -e ".[dev]"

test: ## Run tests
	pytest tests/ -v --cov=src --cov-report=html --cov-report=term

test-integration: ## Run integration tests
	pytest tests/ -v -m integration

lint: ## Run linting
	flake8 src/ tests/
	black --check src/ tests/

format: ## Format code
	black src/ tests/
	isort src/ tests/

clean: ## Clean build artifacts
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf .pytest_cache/
	rm -rf htmlcov/
	find . -type d -name __pycache__ -delete
	find . -type f -name "*.pyc" -delete

build: clean ## Build package
	python setup.py sdist bdist_wheel

docker-build: ## Build Docker image
	docker build -t cloud-security-toolkit:latest .

docker-run: ## Run Docker container
	docker run --rm -v $(PWD)/infrastructure:/workspace cloud-security-toolkit:latest analyze --path /workspace --format terraform

docker-dev: ## Run development container
	docker-compose run --rm dev

publish-test: build ## Publish to test PyPI
	twine upload --repository testpypi dist/*

publish: build ## Publish to PyPI
	twine upload dist/*

example-terraform: ## Run example on Terraform files
	cloud-security-toolkit analyze --path examples/terraform --format terraform --output reports/terraform-report.json

example-cloudformation: ## Run example on CloudFormation files
	cloud-security-toolkit analyze --path examples/cloudformation --format cloudformation --output reports/cf-report.html

example-arm: ## Run example on ARM templates
	cloud-security-toolkit analyze --path examples/arm --format arm --output reports/arm-report.json

ci: install-dev lint test ## Run CI pipeline locally
