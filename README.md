<div align="center">

# Wild Kernels for Android devices running GKI 2.0 (5.10+)

[![License: GPL-3.0](https://img.shields.io/badge/license-GPL--3.0-blue.svg)](LICENSE)
[![Third-Party Notices](https://img.shields.io/badge/notices-THIRD__PARTY_NOTICES-lightgrey.svg)](THIRD_PARTY_NOTICES.md)

</div>

> [!CAUTION]
> Wild Kernels is not responsible for bricked devices or damage. By flashing, you assume all risk. Back up your data and understand the risks before flashing.

---

## About

Generic kernels built on [Google's GKI sources](https://android.googlesource.com/kernel/common/) with KernelSU and SUSFS for root hiding and detection evasion — broad compatibility, not guaranteed for every device.

---

## Features

- **KernelSU / KernelSU-Next / ReSukiSU** — root implementations
- **susfs4ksu** — root hiding (incl. Ptrace Leak Fix, Unicode Fix)
- **NoMount / Mountify** — mount metamodules
- **Baseband Guard** — partition protection
- **Networking** — WireGuard, BBR, IPSet, CIFS
- **TMPFS** — xattr / POSIX ACLs
- **BPF** — BTF / eBPF / FUSE-BPF
- **Performance** — incl. NTSync
- **DroidSpaces** — container runtime

> [!TIP]
> Full documentation: [Wiki](https://github.com/WildKernels/GKI_KernelSU_SUSFS/wiki)

---

## Build Your Own Kernel

Fork the repository and follow **[Build Your Own Kernel](docs/build-from-fork.md)** to select one kernel family, patch level, root implementation, and feature set in GitHub Actions.

---

## Local Builds (`trustgki`)

`src/main.rs` is a standalone Rust program that reproduces the whole GitHub Actions
build path — `build.yml` plus every composite action it calls — for one fixed
feature set: **GKI + LXC (Droidspaces-OSS) + KernelSU-Next + SUSFS**.

It needs `git`, `patch`, `curl`, `timeout` and `clang` on `PATH`; the Android
kernel sources (~10 GB) are fetched with `repo` exactly like CI does.

```sh
# Show the build matrix a family expands to (mirrors prepare.yml)
cargo run --release -- list --version android16-6.12

# Build one target: 6.12.x-android16, 2026-06 patch level, sublevel 81
cargo run --release -- build \
    --version android16-6.12 --os-patch-level 2026-06 --sublevel 81 \
    --output-dir ./out

# Build every target in a config (including the lts tip)
cargo run --release -- build --config .github/config/android15-6.6.json
```

The result is `AnyKernel3/Image` (packaged as `<name>-AnyKernel3.zip`) plus a
build summary and `-metadata.json` in the output directory.

### What the program reproduces

| Stage | Source action | Notes |
|-------|---------------|-------|
| Environment, `kernel_patches`, `AnyKernel3` | `setup-build-environment` | `repo` launcher downloaded per run |
| `repo init`/`sync`, deprecated-branch rewrite | `download-kernel` | 3 attempts, 15-minute sync timeout |
| Deterministic clock | inline in `build.yml` | `SOURCE_DATE_EPOCH` = patch-level day 5, 04:20 UTC |
| Sublevel + file name | `extract-sublevel-file-name` | `lts`/`X` reads `SUBLEVEL` from the Makefile |
| Kernel fixes | `kernel-fixes` | glibc ≥ 2.38 Makefile/parse-options, 6.6 namespace include, `VM_PAD_MASK` |
| Root implementation | `root-setup` | KernelSU-Next at a pinned SHA, `drivers/kernelsu` symlink, `CONFIG_KSU=y` |
| SUSFS | `susfs`, `susfs-setup`, `susfs-config`, `susfs-patches`, `susfs-revert-patches` | branch `gki-<family>`, integration patch, per-sublevel fake patches + reverts, `show_pad` |
| `selinux_hide.c` | inline in `build.yml` | pointer-bool-conversion and `static` stripping |
| LXC container runtime | `droidspaces` | SysV IPC/POSIX-mqueue kABI patches, 6.12 IPC symbol exports, namespace configs |
| Root hiding extras | `ptrace`, `unicode-fix` | ptrace leak fix (<5.16), unicode bypass fix |
| Misc options | `misc` | OverlayFS, TMPFS xattr/POSIX ACL, KALLSYMS |
| Device patches | `apply-device-patches` | Samsung `min_kdp` (+`.stg` fallback) and Xiaomi symbol list on 6.6 |
| Branding, ABI, dirty flags | `apply-kernel-branding`, `remove-protected-exports`, `clean-kernel-flags` | |
| Build + artifact | `build-kernel` | `build/build.sh` or Kleaf/Bazel, `Image` copied into `AnyKernel3` |

Version-conditional work is driven entirely by the family (`android12-5.10`
… `android16-6.12`) and the resolved sublevel/patch level, so no per-version
patch, kernel option or fix from the actions is skipped. `--strict-patches`
turns missing optional upstream patches into hard failures.

Features outside the requested scope — NoMount, Baseband Guard, networking
(WireGuard/BBRv3/CIFS/IPSet), NTSync, the BPF/BTF stack and the performance
patch set — are deliberately not applied, and the program prints that list on
every run.

> [!NOTE]
> Two shell quirks are implemented by intent rather than literally: the
> `kernel-fixes` `mm/mmap.c` replacement (the original `sed` expands a bare `&`
> into the whole match and corrupts the line) and the 6.12 SUSFS revert that
> restores one `dma-buf.h` include instead of one copy per `#include` line.
> GitHub-only steps (disk cleanup, swap, cache buckets, artifact/release
> publication) are replaced with local equivalents or omitted.

---

## Installation

See **[Installation Guide](https://github.com/WildKernels/GKI_KernelSU_SUSFS/wiki/Installation)**.

---

## Supported Devices

> [!NOTE]
> These lists are maintained by the community — please update as needed!

See **[Supported Devices](https://github.com/WildKernels/GKI_KernelSU_SUSFS/wiki/Supported-Devices)**.

---

## Our Projects

| Device | Repository | Description |
|--------|------------|-------------|
| **Multi** | [GKI_KernelSU_SUSFS](https://github.com/WildKernels/GKI_KernelSU_SUSFS) | Google GKI sources — built to be generic and work across many devices |
| **Pixel** | [Sultan_KernelSU_SUSFS](https://github.com/WildKernels/Sultan_KernelSU_SUSFS) | Custom kernels for specific Pixel devices — built from Sultan sources |
| **Samsung** | [Samsung_KernelSU_SUSFS](https://github.com/WildKernels/Samsung_KernelSU_SUSFS) | Built from Samsung sources and manifest |
| **OnePlus** | [OnePlus_KernelSU_SUSFS](https://github.com/WildKernels/OnePlus_KernelSU_SUSFS) | Built from OnePlus sources and manifest |

---

## Special Thanks

**These amazing people and projects make this possible:**

- **KernelSU** — [tiann](https://github.com/tiann/KernelSU)
- **KernelSU-Next** — [rifsxd](https://github.com/KernelSU-Next/KernelSU-Next)
- **KernelSU-Next SUSFS Fork** — [pershoot](https://github.com/pershoot/KernelSU-Next)
- **ReSukiSU** — [ReSukiSU](https://github.com/ReSukiSU/ReSukiSU)
- **Magic-KSU** — [5ec1cff](https://github.com/5ec1cff/KernelSU)
- **SUSFS** — [simonpunk](https://gitlab.com/simonpunk/susfs4ksu)
- **SUSFS Module** — [sidex15](https://github.com/sidex15)
- **NoMount** — [maxsteeel](https://github.com/maxsteeel/nomount)
- **DroidSpaces-OSS** — [ravindu644](https://github.com/ravindu644/Droidspaces-OSS)
- **Baseband-guard (BBG)** — [vc-teahouse](https://github.com/vc-teahouse/Baseband-guard)
- **Kernel Patches** — [WildKernels/kernel_patches](https://github.com/WildKernels/kernel_patches)
- **AnyKernel3** — [osm0sis](https://github.com/osm0sis/AnyKernel3)
- **Sultan Kernels (Pixel)** — [kerneltoast](https://github.com/kerneltoast)
- **Device Boot Fix** — [Boot fix commit](https://github.com/Anything-at-25-00/android_kernel_common_android12-5.10/commit/2476d262b597fe8af82cfb7aaf96676f51c6b4ed)

**Contributors to this repository:**

[![Contributors](https://contrib.rocks/image?repo=WildKernels/GKI_KernelSU_SUSFS)](https://github.com/WildKernels/GKI_KernelSU_SUSFS/graphs/contributors)

Have an idea or improvement in mind? Contributions are always welcome — feel free to open a pull request or share your thoughts!

---

## Community

<div align="center">

[![Telegram Group](https://img.shields.io/badge/Telegram-%40WildKernelsTG-2CA5E0?style=for-the-badge&logo=telegram&logoColor=white)](https://t.me/WildKernelsTG)
[![Telegram DM](https://img.shields.io/badge/Telegram-%40TheWildJames-26A5E4?style=for-the-badge&logo=telegram&logoColor=white)](https://t.me/TheWildJames)

</div>

Need help? Open an issue in this repository or reach out on Telegram. Please ask in the [WildKernelsTG group](https://t.me/WildKernelsTG) first for general issues. DMs to [@TheWildJames](https://t.me/TheWildJames) are always open — use for priority / very important, or if you just want to talk and learn.

---

## Donations

> [!IMPORTANT]
> **Kind note:** A donation is truly just a gift — not a payment for support, features, or priority. It doesn't unlock anything extra on our side and doesn't change how we help you; everyone gets the same community support whether you donate or not. Think of it as a kind “thank you” to help keep development going — not a transaction. If you do choose to give, we're genuinely grateful, but please never feel obligated.

- PayPal: [bauhd@outlook.com](mailto:bauhd@outlook.com)
- Card: <https://buy.stripe.com/5kQ28sdi08Nr0Xc2fU5os00>
- LTC: `MVaN1ToSuks2cdK9mB3M8EHCfzQSyEMf6h`
- BTC: `3BBXAMS4ZuCZwfbTXxWGczxHF4isymeyxG`
- ETH: `0x2b9C846c84d58717e784458406235C09a834274e`
- Patreon: <https://patreon.com/WildKernels>
