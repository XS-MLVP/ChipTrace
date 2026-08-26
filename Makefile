.PHONY: test self-test benchmark benchmark-pack benchmark-export

test:
	PYTHONPATH=src python3 -m unittest discover -s tests -v
	node --test tests/js/*.test.js

self-test:
	PYTHONPATH=src ./scripts/self-test.sh

benchmark:
	PYTHONPATH=src python3 scripts/benchmark.py

benchmark-pack:
	PYTHONPATH=src python3 scripts/benchmark_compression.py

benchmark-export:
	test -n "$(INPUT_SQLITE)"
	PYTHONPATH=src python3 scripts/benchmark_export.py --input-sqlite "$(INPUT_SQLITE)"
