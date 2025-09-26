.PHONY: help install test lint format clean build docker-build docker-run publish-test-check release

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

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
	python -m build

check-package: build ## Check package for issues
	twine check dist/*

publish-test-check: check-package ## Check if we can publish to test PyPI
	@echo "Checking Test PyPI upload (dry run)..."
	@if [ -z "$$TEST_PYPI_API_TOKEN" ]; then \
		echo "❌ TEST_PYPI_API_TOKEN not set. Skipping upload check."; \
		echo "Set TEST_PYPI_API_TOKEN environment variable to test upload."; \
	else \
		echo "✅ TEST_PYPI_API_TOKEN is set. Ready for upload."; \
		TWINE_USERNAME=__token__ TWINE_PASSWORD=$$TEST_PYPI_API_TOKEN twine upload --repository testpypi dist/* --verbose; \
	fi

publish: check-package ## Publish to PyPI (production)
	@if [ -z "$$PYPI_API_TOKEN" ]; then \
		echo "❌ PYPI_API_TOKEN not set. Cannot publish to PyPI."; \
		exit 1; \
	else \
		echo "✅ Publishing to PyPI..."; \
		TWINE_USERNAME=__token__ TWINE_PASSWORD=$$PYPI_API_TOKEN twine upload dist/* --verbose; \
	fi

release: ## Create a new release (requires VERSION environment variable)
	@if [ -z "$$VERSION" ]; then \
		echo "❌ VERSION not set. Usage: make release VERSION=1.0.1"; \
		exit 1; \
	fi
	@echo "Creating release $$VERSION..."
	git tag -a v$$VERSION -m "Release v$$VERSION"
	git push origin v$$VERSION

docker-build: ## Build Docker image
	docker build -t cloud-security-toolkit:latest .

docker-run: ## Run Docker container
	docker run --rm -v $(PWD)/infrastructure:/workspace cloud-security-toolkit:latest analyze --path /workspace --format terraform

docker-dev: ## Run development container
	docker-compose run --rm dev

example-terraform: ## Run example on Terraform files
	cloud-security-toolkit analyze --path examples/terraform --format terraform --output reports/terraform-report.json

example-cloudformation: ## Run example on CloudFormation files
	cloud-security-toolkit analyze --path examples/cloudformation --format cloudformation --output reports/cf-report.html

example-arm: ## Run example on ARM templates
	cloud-security-toolkit analyze --path examples/arm --format arm --output reports/arm-report.json

ci: install-dev lint test check-package ## Run CI pipeline locally
