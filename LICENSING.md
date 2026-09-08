# FAT licensing

FAT 2.0's first-party code, profiles, backend adapter documentation, and runtime data use [FSL-1.1-ALv2](LICENSE), except for the components listed below.
This page explains the arrangement; the actual license text controls.

## Use and contributions

Internal commercial use, permitted modifications and forks, and contributions are welcome.
FSL restricts one thing: a Competing Use, which the license defines as *making FAT available to others* in a commercial product or service that substitutes for FAT, substitutes for something Attify already offers using FAT, or provides substantially similar functionality.
Everything else is a Permitted Purpose.
Because the restriction turns on making FAT available to others, using FAT to do your own work — including work you are paid for — is not a Competing Use.
FSL does not require you to publish your modifications.

### What you can do without asking us

| Scenario | Permitted |
|---|---|
| Running FAT on your own firmware, internally | Yes — explicitly a Permitted Purpose |
| A consultant running FAT during a paid client assessment and delivering the findings | Yes — you are using FAT to perform a service, not making FAT available to your client |
| Publishing research, tutorials, or analysis output produced with FAT | Yes — the output is not the Software |
| Modifying FAT and running your fork internally | Yes |
| Scripts, pipelines, and internal automation that call the `fat` CLI | Yes |
| Redistributing FAT, modified or not, for a Permitted Purpose | Yes — keep the license text and the copyright notices |
| Selling a product or hosted service that includes FAT or reproduces substantially similar functionality | Needs permission |
| Using the FAT or Attify names on a fork, or presenting it as an official release | Needs permission — a trademark matter, separate from the license |

A free download attached to a commercial service is not automatically outside the restriction; what matters is whether the overall offering competes.
Note that the restriction reaches only *commercial* products and services, so a genuinely non-commercial fork with similar functionality is a Permitted Purpose.

Attify may negotiate commercial terms, including fees or revenue share, or choose not to grant an exception.
No royalty or revenue share arises automatically from FSL.
These arrangements cannot override third-party rights.
Contact Attify through https://www.attify.com/ for commercial licensing.

Each version becomes additionally available under Apache-2.0 two years after Attify first makes it available.
Public commits can start this period before a package or release is published.
Release notes should record the first-available date and the corresponding Apache-2.0 date, without postponing an earlier date.
See the [FSL FAQ](https://fsl.software/) for examples.
Before conversion, describe FAT as source available, not OSI-approved open source.

## Component exceptions

- `scripts/fat-hook-plugin.c` is a separate optional component under GPL-2.0-or-later.
  See [LICENSES/GPL-2.0-or-later.txt](LICENSES/GPL-2.0-or-later.txt).
  Its QEMU API headers and linked dependencies keep their own terms.
  FSL and commercial permissions from Attify do not replace those obligations.
  FAT releases must not include a compiled hook or QEMU binary without a separate distribution/compliance review.
  Repository separation or loading a plugin dynamically does not itself decide compatibility.
- Third-party dependencies, adapted files, and assets keep their existing terms and notices.
  Consult [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) and each file's attribution.
  The generated Rust license report is an inventory, not proof that all native code and external artifacts have been cleared.
- `CODE_OF_CONDUCT.md` adapts Contributor Covenant 2.1 under CC BY 4.0.
- License documents retain their respective authors' terms.

## FAT 1.x transition

FAT 2.0 is a rewrite published under new terms.
The previously published FAT 1.x history remains MIT.
The publication procedure preserves the last v1 commit on `v1.x` and `v1.0-final`, then adds the reviewed v2 snapshot as a new commit on a branch descended from v1.
These references must be created before publication; this document does not assert that the migration has already happened.

The first public v2 release notes must link to that transition commit and the preserved v1 tag.
Previously granted MIT permissions are not revoked.
Preserve any other pre-existing grants to recipients as well.

## Contribution and trademark policy

Profiles under `profiles/`, adapter documentation under `backends/`, and plugin interfaces remain public contribution surfaces.
Start with a focused PR and include a small example or validation result.
Never submit vendor firmware, extracted filesystems, or third-party material without the necessary rights.
See [CONTRIBUTING.md](CONTRIBUTING.md) for how to get started.

The software license does not grant general rights to Attify branding.
Do not imply that a fork is an official Attify release or endorsed by Attify.
Accurate attribution remains appropriate.
This policy does not claim registered marks or prohibit otherwise lawful descriptive use.
