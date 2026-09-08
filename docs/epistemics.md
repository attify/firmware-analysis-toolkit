# How to read FAT output

FAT reports hits, evidence, categories, counts, offsets, confidence, validation state, provenance, and next probes. These terms describe what FAT observed.

Some graph-schema names sound more conclusive than they are. `UpdateCandidate`, `AuthorityVerdict`, and `update-authority` are compatibility names for evidence groups and bounded static assessments. They do not represent a final analytical judgment.

- Startup intent does not prove runtime reachability or exploitability.
- Edge AI findings identify artifacts and likely inference stacks; they do not prove that a model executes.
- A structurally valid key length says something about the bytes, not whether the firmware uses those bytes at runtime.
- An emulation validator proves only what that validator checked during that run on that backend.

`fat inspect update --json` is the aggregate surface for envelope, trust, and crypto evidence. It embeds the underlying submodels so downstream tools do not need to reconstruct their relationships from prose.

## Taint analysis

### Binary taint: `taint-cross` and `source-map`

Which function writes a device's shared state and which reads it is a claim about that platform's config API, so FAT ships no such catalog. Without `--state-profile`, `taint-cross` assigns no function a read or write role and produces no cross-binary findings. JSON output is an empty array; the command does not emit a raw symbol inventory.

The two profiles serve different purposes: `--source-profile` supplies binary source/sink models to the analyzer, merged with the core models; `--state-profile` maps read, write, and flush names into shared-state families. A state profile alone does not teach the binary analyzer how an unfamiliar function carries data. Both flags take file paths; an invalid selected file is an error. See `fat taint-cross --help` for the state-profile schema.

Both `--json` and `--as-taint-json` preserve the binary models' identity in `model_provenance` and the state mappings' identity in `state_model_provenance`. External identities include the declared name, selected path, and SHA-256 of the loaded file. Output remains an array of findings, or `[]` when none exist.

`fat source-map --source-profile` likewise adds operator-supplied hints to the ISO C core hints. Its JSON report records `model_provenance` even when no backend candidates match. Source hints describe observed names, not proven flows.

### Shell taint: `taint --lang shell`

Shell is the firmware layer where source-to-sink reachability is cheapest to show. `--lang shell` parses scripts with `tree-sitter-bash` and walks assignments forward, so `$(cat /configs/...)` → `$var` → `sed -i "s/.../$var/g"` comes back as one chain instead of an isolated grep hit. Findings serialize to the same `TaintFinding` JSON as `fat taint --json`, so anything that already reads taint findings deserializes them unchanged.

```bash
fat taint --lang shell --file ./app/init/wifi.sh --summary
fat taint --lang shell --rootfs ./extracted-rootfs --json
fat taint --lang shell --rootfs ./extracted-rootfs --source-profile ./my-target-shell.yaml --severity high
```

The always-loaded shell profile only carries constructs that hold for any POSIX script: positional parameters, `read`, `cat`/`head`/`tail`, the RFC 3875 CGI meta-variables, and the documented `uci get`, `fw_printenv` and `getprop` reads. It asserts nothing about any device's filesystem, so a read of `/configs/...` is `Secondary` on the strength of the read alone — the path's name is not evidence that an attacker can write the file. `--source-profile` takes a YAML overlay you write; a `path-prefix` source in it declares a mount attacker-writable, which promotes reads under that mount to `Primary` and makes the finding cite the mount by name.

Shell taint is deliberately unsound — shell is too dynamic to prove reachability — so every finding lands as a `Candidate` at `WEAK` strength and only flows with a named source are reported. For sink hits without provenance, use `fat sink-discovery --rootfs`.

## Edge AI artifacts

Library filename hints require the four-byte ELF magic and use `artifact_kind: filename-match`, `matched_pattern`, and `evidence`. They do not establish a runtime identity or model format; their metadata omits `runtime` and `format`. The repository contains deterministic synthetic fixtures; it does not redistribute private model corpora.

## Startup intent

Use `fat startup-map` to choose the next target to inspect, not as runtime proof.
