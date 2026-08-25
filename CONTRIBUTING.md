# Contributing

## Development setup

Python 3.10 or newer and Node.js 20 or newer are required.

```bash
python3 -m pip install -e '.[performance]'
make test
python3 -m trace_pipeline self-test
```

## Change rules

- Preserve raw evidence; quality filtering belongs in a versioned projection.
- Do not weaken durable acknowledgement, identity, hash, or atomic-publication
  checks.
- Add a migration and compatibility test for every persistent schema change.
- Add fixtures for every supported request or response shape.
- Do not commit captured prompts, responses, credentials, private endpoints, or
  production identifiers.
- Label performance results with storage, cache, duration, and validation scope.

Changes should include focused tests and update the data contract when they
alter a public field, score, state, or command.
