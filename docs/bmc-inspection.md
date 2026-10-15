# Inspecting BMC firmware

`fat inspect bmc` inspects a raw flash image without executing firmware or contacting a controller. It combines FAT's native layout analysis with FIT authentication metadata, located platform strings, and CRC-validated U-Boot environments.

```sh
fat inspect bmc --file flash.mtd
fat inspect bmc --file flash.mtd --details
fat inspect bmc --file flash.mtd --json > inspection.json
fat inspect bmc --file flash.mtd --sarif > findings.sarif
fat inspect bmc --file flash.mtd --sarif --fail-on-warning > findings.sarif
```

JSON uses `bmc-inspection/v1`. Shared FIT evidence and parser diagnostics also appear in `fat inspect headers --file flash.mtd --json`. Every report records the actual input size and SHA256. `--details` only expands text presentation; it does not change analysis, JSON, or SARIF. Inputs are limited to 512 MiB.

## FIT metadata

The report shows FIT offsets, default configuration, component hashes, image and configuration signature nodes, configuration image references, and any `/signature` key metadata in embedded device trees. The declared default configuration is not an observation of the device's selected boot path.

- `BOOT-FIT-HASH-ONLY`: a completely interpreted FIT contains hashes for all image nodes and has no image or configuration signature nodes. This describes the FIT metadata; it does not describe an outer signed package or a controller's boot policy.
- `BOOT-FIT-SIGNATURE-METADATA`: signature nodes exist. Their presence does not establish cryptographic validity or enforcement.
- Control-FDT `required` properties are displayed as stored key policy. The report does not prove that the running bootloader uses that device tree.

Configuration signatures are considered alongside image signatures: an image with hashes can be authenticated through a signed configuration. The parser handles both `hash@1`/`signature@1` and `hash-1`/`signature-1` names. Malformed metadata and analysis budgets are recorded as diagnostics; incomplete blobs cannot generate hash-only findings.

The existing `fat signature-fit` command tests an RSA-PSS/SHA256 byte relationship with a supplied key. It is a separate operation from FIT metadata inspection.

## Stored environments

Automatic discovery checks 4 KiB-aligned offsets within the first 64 MiB for total region sizes of 4, 8, 16, 32, 64, 128 and 256 KiB. Both ordinary and redundant headers and both CRC byte orders are checked. The CRC covers the full data area, excluding the CRC and optional redundant-copy flag. The JSON records search bounds and any truncation.

For a known region, provide its offset and **total stored size**, including the header. Decimal and hexadecimal values are accepted; explicit regions may be unaligned and up to 1 MiB.

```sh
fat inspect bmc --file flash.mtd --env-offset 0x60000 --env-size 0x20000 --details
```

Recovered variables retain byte offsets, region size, CRC validity and redundant-copy flags. Flags are not used to select the active copy. A supplied region that has no valid environment is reported in JSON diagnostics. Invalid or out-of-bounds arguments fail the command.

## Platform and trust markers

OpenBMC/MegaRAC strings and ASPEED compatible strings are independently located evidence. Generic `fwmap`, `sig_table`, and `AdaptiveModules` markers do not establish a vulnerable parser, a reachable update path, or a specific CVE. Raw-string matches are labeled as markers, including their offsets.

PEM headers are also markers: a private-key header generates a qualified warning; public-key and certificate headers are informational. The scanner does not validate a complete key from a header alone or scan inside compressed data. Use FAT extraction and rootfs analysis for embedded files.

## CI output

SARIF 2.1.0 includes stable rule IDs, rule descriptions, the input SHA256, and binary byte locations. Default inspection exits successfully when analysis completes. `--fail-on-warning` emits the full report and then exits nonzero when any warning/error finding exists. Invalid arguments, input I/O failures, and fatal analysis errors also exit nonzero. Malformed FDT candidates remain diagnostics in a successfully completed inspection. CI policy is explicit: metadata observations are not automatically vulnerability verdicts.

## Validation fixtures

Hermetic tests synthesize FITs with hash metadata, image/configuration signatures, malformed structures, and valid/corrupt environment CRCs. Real-image validation should record the source URL, SHA256, command and tool version separately. Firmware binaries are not committed to the repository. OpenBMC TiogaPass and Romulus examples validate those image families; MegaRAC-specific support needs representative MegaRAC artifacts.

The format and trust semantics follow [U-Boot's FIT signature documentation](https://docs.u-boot.org/en/v2024.01/usage/fit/signature.html).
