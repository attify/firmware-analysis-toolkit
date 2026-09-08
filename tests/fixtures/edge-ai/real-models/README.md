# Edge AI Model Fixture Policy

Opaque model binaries are intentionally excluded from the public source tree.
Tests construct deterministic synthetic MAGIK and ONNX inputs at runtime.

Real-corpus validation may be performed locally against lawfully obtained
material, but those artifacts are outside the public repository and its tests.
