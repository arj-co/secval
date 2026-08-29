.PHONY: all install test test-unit test-policies smoke benchmark-local api dashboard dev build \
        lint typecheck deploy destroy synth diff setup teardown-agentcore bootstrap ui demo-setup

SHELL := /bin/bash
PYTHON := $(shell which python3.11 || which python3)
CEDAR := $(shell which cedar || echo "$$HOME/.cargo/bin/cedar")

# ─── Top-Level Verification & Local Development Targets ──────────────────────

all: test test-policies smoke build

install:
	@echo "📦 Setting up Python virtual environment and dependencies..."
	@if [ ! -d ".venv" ]; then $(PYTHON) -m venv .venv; fi
	@source .venv/bin/activate && pip install --upgrade pip
	@source .venv/bin/activate && pip install -r requirements.txt
	@source .venv/bin/activate && pip install fastapi uvicorn pydantic requests httpx python-dotenv pyyaml pandas scipy jinja2 tabulate pytest pytest-asyncio strands-agents bedrock-agentcore boto3
	@echo "📦 Installing dashboard dependencies..."
	@cd dashboard && npm install
	@echo "✅ Installation complete."

test: test-unit test-policies
	@echo "🧪 Running full test suite..."
	@source .venv/bin/activate && PYTHONPATH=. pytest tests/ -v

test-unit:
	@echo "🧪 Running unit tests..."
	@source .venv/bin/activate && PYTHONPATH=. pytest tests/unit/ -v

test-policies:
	@echo "🛡️ Validating Cedar policies against schema..."
	@if [ -x "$(CEDAR)" ]; then \
		$(CEDAR) validate --policies security/policies/procurement_policies.cedar --schema security/schemas/procurement.cedarschema.json --schema-format json; \
	else \
		echo "⚠️ Cedar CLI binary not found. Skipping CLI validation."; \
	fi
	@source .venv/bin/activate && PYTHONPATH=. pytest tests/unit/test_vertical_slice.py tests/unit/test_policy_repair.py tests/unit/test_attack_variations.py -v

smoke:
	@echo "🚀 Running 5-scenario offline smoke benchmark..."
	@source .venv/bin/activate && PYTHONPATH=. python -m benchmark.runner --smoke

benchmark-local:
	@echo "📊 Running full scenario benchmark matrix..."
	@source .venv/bin/activate && PYTHONPATH=. python -m benchmark.runner --all --reps 2

api:
	@echo "🌐 Starting FastAPI backend server on http://localhost:8000..."
	@source .venv/bin/activate && PYTHONPATH=. uvicorn backend.api.server:app --host 0.0.0.0 --port 8000 --reload

dashboard:
	@echo "💻 Starting Next.js UI Dashboard on http://localhost:3000..."
	@cd dashboard && npm run dev

dev:
	@echo "🚀 Starting both FastAPI API and Next.js Dashboard..."
	@trap 'kill %1; kill %2' SIGINT; \
	(source .venv/bin/activate && PYTHONPATH=. uvicorn backend.api.server:app --host 0.0.0.0 --port 8000) & \
	(cd dashboard && npm run dev) & \
	wait

build:
	@echo "🏗️ Building Next.js production dashboard..."
	@cd dashboard && npm run build

lint:
	@echo "🔍 Linting codebase..."
	@source .venv/bin/activate && python -m py_compile services/*.py security/*.py benchmark/*.py backend/api/*.py agents/*.py agents/adapters/*.py

typecheck:
	@echo "🔍 Type checking dashboard..."
	@cd dashboard && npx tsc --noEmit

# ─── Upstream AWS Deployment Targets (Require AWS_PROFILE) ───────────────────

check-aws-profile:
ifndef AWS_PROFILE
	$(error AWS_PROFILE is not set. Run: export AWS_PROFILE=<your-profile>)
endif

deploy: check-aws-profile
	cdk deploy --all --require-approval never

synth: check-aws-profile
	cdk synth

diff: check-aws-profile
	cdk diff --all

teardown-agentcore: check-aws-profile
	python scripts/teardown_agentcore.py

destroy: check-aws-profile teardown-agentcore
	cdk destroy --all

bootstrap: check-aws-profile
	cdk bootstrap aws://$$(aws sts get-caller-identity --query Account --output text)/us-east-1

setup: check-aws-profile
	python scripts/setup_demo.py

demo-setup: check-aws-profile
	cdk deploy --all --require-approval never
	python scripts/setup_demo.py
	python scripts/configure_agents.py
	python scripts/setup_procurement_gateway.py
	python scripts/setup_phase5_gateway.py
	python scripts/configure_agents.py --inject-only
	python scripts/setup_workload_identity.py
	python scripts/setup_vendor_resource_policy.py
	python scripts/setup_approval_resource_policy.py
	python scripts/toggle_policy_mode.py ENFORCE

ui:
	streamlit run streamlit_app.py
