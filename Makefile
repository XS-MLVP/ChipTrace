.PHONY: test self-test benchmark

test:
	PYTHONPATH=src python3 -m unittest discover -s tests -v
	node --test tests-js/*.test.js

self-test:
	PYTHONPATH=src ./scripts/self-test.sh

benchmark:
	PYTHONPATH=src python3 scripts/benchmark.py
