# External campaign evidence

`fat experiment external` records bounded work performed by an external
execution engine. It does not add a FAT fuzzing engine or claim that the
external runtime matches a deployed device.

Use this path when a campaign already has its own tested AFL++, Fuzzware, or
similar runner and the repeated need is to pin setup files, select one exact
input, replay it, retain output, and prove cleanup.

## Manifest contract

An `external-campaign/v1` manifest contains:

- the external engine name, version, revision, and execution substrate;
- a short `proof_scope` that states the evidence boundary;
- SHA-256 pins for setup artifacts and retained evidence;
- one or more cases with an exact input, argv vector, timeout, and accepted
  exit codes; and
- an idempotent cleanup argv vector with its own timeout.

Artifact paths are relative to `--root` and cannot contain parent traversal.
The replay argv must contain `{input}` exactly once as a complete argument.
FAT substitutes the verified input path and launches the argv vector directly,
without a shell.

Validate a prepared evidence tree before execution:

```console
fat experiment external validate \
  --file external-campaign.json \
  --root /path/to/campaign \
  --json
```

Run one case inside an existing FAT project:

```console
fat experiment external run \
  --project /path/to/fat-project \
  --file external-campaign.json \
  --root /path/to/campaign \
  --case minimized-crash \
  --json
```

The run creates a FAT session and replay run. It records the exact input,
manifest, declared evidence, stdout, stderr, and a result document containing
the materialized argv, exit code, timeout state, and cleanup result.

The runner always attempts cleanup after the replay command returns, fails,
cannot start, or reaches its timeout. A replay is successful only when its exit
code is declared by the selected case and cleanup passes. Engine-specific
wrappers remain responsible for interpreting their own crash markers and
returning a stable exit code; pin those wrappers as setup artifacts.

This contract deliberately stops at external process execution and evidence
accounting. It does not provide corpus mutation, coverage collection,
peripheral modeling, process debugging, or network delivery.
