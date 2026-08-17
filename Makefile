.PHONY: help setup install dev lint test build inventory

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "  %-10s %s\n", $$1, $$2}'

setup: ## Install the pre-commit hook
	pre-commit install

install: ## Install the package
	pip install .

dev: ## Editable install with dev dependencies
	pip install -e ".[dev]"

lint: ## Run ruff
	ruff check .

test: ## Run tests
	pytest -q

build: ## Build sdist and wheel
	python -m build

inventory: ## Regenerate INVENTORY.md from the rule table
	python3 tests/render_inventory.py > INVENTORY.md
