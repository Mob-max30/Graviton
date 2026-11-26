.PHONY: setup test-fast test eval bench demo lint audit brief evidence verify-clean

setup:
	python tasks.py setup

test-fast:
	python tasks.py test-fast

test:
	python tasks.py test

eval:
	python tasks.py eval

bench:
	python tasks.py bench

demo:
	python tasks.py demo

ui:
	python tasks.py ui

lint:
	python tasks.py lint

audit:
	python tasks.py audit

brief:
	python tasks.py brief

evidence:
	python tasks.py evidence

verify-clean:
	python tasks.py verify-clean
