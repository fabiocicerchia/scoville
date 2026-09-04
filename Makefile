# scoville — score the risk of a shell command before it runs.
#
# Every verb this repo exposes lives here; `make` on its own prints them,
# grouped, straight out of the `##` comments below.

.DEFAULT_GOAL := help
# help is pure output; the recipe echo would only be noise.
.SILENT: help

##@ General

.PHONY: help
help: ## Show this help
	awk 'BEGIN {FS = ":.*## "} \
		/^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } \
		/^[a-zA-Z_0-9-]+:.*## / { printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2 }' \
		$(MAKEFILE_LIST)

.PHONY: setup
setup: ## Install the pre-commit hook
	pre-commit install

##@ Development

.PHONY: dev
dev: ## Editable install with dev dependencies
	pip install -e ".[dev]"

.PHONY: install
install: ## Install the package
	pip install .

##@ Quality

.PHONY: lint
lint: ## Run ruff
	ruff check .

.PHONY: test
test: ## Run tests
	pytest -q

##@ Release

.PHONY: build
build: ## Build sdist and wheel
	python -m build

# INVENTORY.md is generated from tests/corpus.tsv — the corpus is the
# calibration, so the inventory has to be regenerated, never edited.
.PHONY: inventory
inventory: ## Regenerate INVENTORY.md from the rule table
	python3 tests/render_inventory.py > INVENTORY.md
