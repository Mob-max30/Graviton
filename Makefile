.PHONY: setup test validate demo eval bench brief verify-clean

PYTHON ?= python3

setup:
	$(PYTHON) -m venv .venv
	.venv/bin/pip install -r requirements.txt

test:
	$(PYTHON) -m unittest discover -s tests -v

validate:
	$(PYTHON) ../Track-4-Toolkit/validate.py --entry track4_service.py

demo:
	$(PYTHON) -m graviton.demo

eval:
	$(PYTHON) -m graviton detect-eval --out build/detect-metrics.json

bench:
	$(PYTHON) bench/benchmark.py

brief:
	$(PYTHON) docs/brief/generate_brief.py

verify-clean:
	$(PYTHON) tasks.py verify-clean
