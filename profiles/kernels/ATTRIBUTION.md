# Maintained-kernel attribution and provenance

FAT’s build recipes, Kconfig fragments, fixture programs, orchestration scripts,
measurement records, and promotion rules in this directory are authored for FAT.
They describe requirements and do not contain a copied third-party kernel config.

| Project | Source | License | FAT use and disposition |
| --- | --- | --- | --- |
| Linux | [kernel.org](https://www.kernel.org/) | GPL-2.0-only; UAPI material may carry Linux-syscall-note | The pinned source archive is downloaded and built as a separately identified artifact. FAT does not vendor it in this repository. |
| Debian | [Debian](https://www.debian.org/) | Aggregate distribution; individual package licenses apply | Digest-pinned builder base and version-recorded cross-build packages. The produced builder must retain `/usr/share/doc/*/copyright`. |
| QEMU | [QEMU](https://www.qemu.org/) | GPL-2.0-or-later and component licenses | External runtime used to execute fixtures and firmware. QEMU is not redistributed by these records. |
| FirmAE | [FirmAE](https://github.com/pr0v3rbs/FirmAE) | GPL-3.0 | Prior art and retained external fallback. No FirmAE code or kernel configuration is imported into FAT’s maintained profiles. |
| Firmadyne | [Firmadyne](https://github.com/firmadyne/firmadyne) | BSD-3-Clause for repository code; bundled components vary | Prior art for generic firmware rehosting. No FirmAE or Firmadyne kernel configuration is copied. |

Every redistributed third-party input in a kernel artifact bundle must have its
own structured attribution entry naming the project, source URL, license, role,
and redistribution status. A build log is evidence, not a substitute for credit.
