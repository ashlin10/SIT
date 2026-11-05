# SIT — agent notes

## Run locally
- `cd web_app && ./run.sh` (builds the React SPA, serves HTTPS on :8000). `--no-build` skips the frontend build.
- A self-signed cert is generated into `web_app/certs/` if missing.
- Login users come from `web_app/data/users.json` (`{"user": "password"}`, gitignored); restart the server after editing it.

## Tests
- Policy configuration: `cd web_app && ../venv/bin/python -m pytest policy_configuration/tests -q`
- Use `venv/bin/python` (plain `python` is not on PATH via pyenv).

## FMC REST API constraints (checked against schemas/oas_schemas)
- `object/variablesets`: GET only → VariableSet is reuse-by-name only.
- `policy/identitypolicies`: POST only from FMC 10.0.
- `object/tunneltags`: GET/POST (TunnelTags can appear in rule `sourceZones`).
