// SPDX-License-Identifier: GPL-3.0
//! `trustgki` — a self-contained re-implementation of the Wild Kernels GitHub
//! Actions pipeline for **GKI + LXC (DroidSpaces) + KernelSU-Next + SUSFS**.
//!
//! The upstream repository drives its builds through a stack of workflows and
//! composite actions under `.github/`:
//!
//! ```text
//! main.yml  (resolve pins, feature set, release bookkeeping, matrix fan-out)
//!   └── prepare.yml            (config JSON -> matrix of {sublevel, date, variant})
//!         └── build.yml        (one kernel build; the authoritative step order)
//!               ├── setup-build-environment      ├── apply-kernel-branding
//!               ├── download-kernel              ├── remove-protected-exports
//!               ├── extract-sublevel-file-name   ├── clean-kernel-flags
//!               ├── kernel-fixes                 ├── build-kernel
//!               ├── root-setup                   ├── scan-patch-rejects
//!               ├── susfs{,-setup,-config,-patches,-revert-patches}
//!               ├── set-kernel-config            ├── droidspaces
//!               ├── ptrace / unicode-fix         ├── misc
//!               └── apply-device-patches
//! ```
//!
//! This program reproduces `build.yml` end-to-end for a single, narrowly scoped
//! feature set — GKI sources, the LXC-style container runtime patches from
//! Droidspaces-OSS, the KernelSU-Next root implementation and SUSFS root hiding
//! — including every version- and sublevel-specific patch, kernel option and
//! fix that the actions apply. Features that are deliberately *not* part of the
//! scope (NoMount, Baseband Guard, networking/WireGuard/BBRv3, NTSync, the BPF
//! stack and the performance patch set) are documented in [`OUT_OF_SCOPE`].
//!
//! Everything that the actions do with `sed`, `perl` and `python3` one-liners is
//! performed natively in Rust so the transformations are reviewable; `git`,
//! `repo`, `patch`, `make` and `bazel` are still invoked as external tools.

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use regex::Regex;
use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;
use time::macros::format_description;
use time::{Date, Month, OffsetDateTime, Time as ClockTime};

// ---------------------------------------------------------------------------
// Upstream sources (kept byte-identical to the composite actions)
// ---------------------------------------------------------------------------

const REPO_KERNEL_PATCHES: &str = "https://github.com/WildKernels/kernel_patches.git";
const REPO_ANY_KERNEL3: &str = "https://github.com/WildKernels/AnyKernel3.git";
const REPO_DROIDSPACES: &str = "https://github.com/ravindu644/Droidspaces-OSS.git";
const REPO_KSU_NEXT: &str = "https://github.com/KernelSU-Next/KernelSU-Next.git";
const REPO_KSU_NEXT_SUSFS: &str = "https://github.com/pershoot/KernelSU-Next.git";
const REPO_SUSFS: &str = "https://gitlab.com/simonpunk/susfs4ksu.git";
const REPO_KERNEL_MANIFEST: &str = "https://android.googlesource.com/kernel/manifest";
const REPO_KERNEL_COMMON: &str = "https://android.googlesource.com/kernel/common";
const URL_REPO_TOOL: &str = "https://storage.googleapis.com/git-repo-downloads/repo";
const URL_CCACHE: &str =
    "https://github.com/WildKernels/kernel_patches/raw/refs/heads/main/ccache/ccache-x86-64";

const BRANCH_ANY_KERNEL3: &str = "gki-2.0";
const BRANCH_KSU_NEXT: &str = "dev";
const BRANCH_KSU_NEXT_SUSFS: &str = "dev-susfs";

/// Kernel sublevel sentinel used by the config files for "current LTS tip".
const SUBLEVEL_LTS: &str = "X";
/// Patch-level sentinel that disables the date filter.
const PATCH_LEVEL_ALL: &str = "all";

/// Feature flags that exist upstream but are intentionally not reproduced here.
const OUT_OF_SCOPE: &[(&str, &str)] = &[
    (
        "NoMount",
        "nomount/action.yml + nomount-metamodule/action.yml",
    ),
    ("Baseband Guard", "bbg/action.yml"),
    (
        "Networking",
        "networking/action.yml, networking-config, cifs, bbrv3",
    ),
    ("NTSync", "ntsync/action.yml"),
    ("BPF stack", "btf/action.yml, fuse-bpf/action.yml"),
    ("Performance", "performance/action.yml"),
];

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Debug, Parser)]
#[command(
    name = "trustgki",
    about = "Build GKI + LXC (DroidSpaces) + KernelSU-Next + SUSFS kernel images",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Command_,
}

#[derive(Debug, Subcommand)]
enum Command_ {
    /// Run the full kernel build pipeline.
    Build(Box<BuildArgs>),
    /// Print the build targets a config file expands to (mirrors prepare.yml).
    List(ListArgs),
    /// Print the kernel families this binary can build (mirrors `Family::ALL`).
    Families(FamiliesArgs),
}

#[derive(Debug, Args)]
struct ListArgs {
    /// Path to a `.github/config/<family>.json` matrix file.
    #[arg(long)]
    config: Option<PathBuf>,
    /// Kernel family whose config JSON should be read instead of `--config`.
    #[arg(long)]
    version: Option<String>,
    /// Filter: patch date (`YYYY-MM`), sublevel, `lts`, or `All`.
    #[arg(long, default_value = "All")]
    os_patch_level: String,
}

#[derive(Debug, Args)]
struct FamiliesArgs {
    /// Emit a JSON array, ready to be used as a GitHub Actions matrix.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct BuildArgs {
    /// Kernel family, e.g. `android16-6.12` (see `--help` for the full list).
    #[arg(long)]
    version: Option<String>,
    /// Expand every target from a config JSON instead of a single family.
    #[arg(long, conflicts_with = "version")]
    config: Option<PathBuf>,
    /// Patch date (`YYYY-MM`), kernel sublevel, or `lts`.
    #[arg(long, default_value = "")]
    os_patch_level: String,
    /// Kernel sublevel; required unless `--os-patch-level lts` is used.
    #[arg(long)]
    sublevel: Option<String>,
    /// Artifact variant label (appended to the file name when not `Normal`).
    #[arg(long, default_value = "Normal")]
    variant: String,
    /// Branding appended to the kernel release string.
    #[arg(long, default_value = "Wild")]
    brand_name: String,
    /// Working directory that holds `kernel/`, `kernel_patches/`, `AnyKernel3/`.
    #[arg(long)]
    workspace: Option<PathBuf>,
    /// Directory that receives the built `Image` and build metadata.
    #[arg(long)]
    output_dir: Option<PathBuf>,
    /// Bazel disk cache (bazel-based kernels only).
    #[arg(long)]
    bazel_cache: Option<PathBuf>,
    /// Parallel jobs for the legacy `build/build.sh` path (0 = all cores).
    #[arg(long, default_value_t = 0)]
    jobs: usize,
    /// Apply the module version-check bypass hack (off by default).
    #[arg(long, default_value_t = false)]
    bypass: bool,
    /// Enable ccache for the legacy build path.
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    use_cache: bool,
    /// Fail when an optional upstream patch file is missing.
    #[arg(long, default_value_t = false)]
    strict_patches: bool,
    /// Pin the root implementation commit instead of resolving the branch tip.
    #[arg(long)]
    root_commit: Option<String>,
    /// Pin the SUSFS commit instead of resolving the branch tip.
    #[arg(long)]
    susfs_commit: Option<String>,
    /// Pin the Droidspaces-OSS commit instead of the default branch tip.
    #[arg(long)]
    droidspaces_commit: Option<String>,
    /// Pin the WildKernels/kernel_patches commit.
    #[arg(long)]
    kernel_patches_commit: Option<String>,
    /// Pin the WildKernels/AnyKernel3 commit.
    #[arg(long)]
    anykernel3_commit: Option<String>,
}

// ---------------------------------------------------------------------------
// Kernel families
// ---------------------------------------------------------------------------

/// One GKI family: an Android release paired with a kernel LTS series.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Family {
    Android12_5_10,
    Android13_5_10,
    Android13_5_15,
    Android14_5_15,
    Android14_6_1,
    Android15_6_6,
    Android16_6_12,
}

impl Family {
    const ALL: [Family; 7] = [
        Family::Android12_5_10,
        Family::Android13_5_10,
        Family::Android13_5_15,
        Family::Android14_5_15,
        Family::Android14_6_1,
        Family::Android15_6_6,
        Family::Android16_6_12,
    ];

    /// The `version` identifier used by the workflows, e.g. `android16-6.12`.
    fn id(self) -> &'static str {
        match self {
            Family::Android12_5_10 => "android12-5.10",
            Family::Android13_5_10 => "android13-5.10",
            Family::Android13_5_15 => "android13-5.15",
            Family::Android14_5_15 => "android14-5.15",
            Family::Android14_6_1 => "android14-6.1",
            Family::Android15_6_6 => "android15-6.6",
            Family::Android16_6_12 => "android16-6.12",
        }
    }

    fn android(self) -> &'static str {
        match self {
            Family::Android12_5_10 => "android12",
            Family::Android13_5_10 | Family::Android13_5_15 => "android13",
            Family::Android14_5_15 | Family::Android14_6_1 => "android14",
            Family::Android15_6_6 => "android15",
            Family::Android16_6_12 => "android16",
        }
    }

    fn kernel(self) -> &'static str {
        match self {
            Family::Android12_5_10 | Family::Android13_5_10 => "5.10",
            Family::Android13_5_15 | Family::Android14_5_15 => "5.15",
            Family::Android14_6_1 => "6.1",
            Family::Android15_6_6 => "6.6",
            Family::Android16_6_12 => "6.12",
        }
    }

    /// `(major, minor)` of the kernel series.
    fn kernel_ver(self) -> (u32, u32) {
        let mut it = self.kernel().split('.');
        let major = it.next().unwrap_or("0").parse().unwrap_or(0);
        let minor = it.next().unwrap_or("0").parse().unwrap_or(0);
        (major, minor)
    }

    fn parse(value: &str) -> Result<Family> {
        Family::ALL
            .into_iter()
            .find(|f| f.id() == value)
            .ok_or_else(|| {
                let known = Family::ALL
                    .iter()
                    .map(|f| f.id())
                    .collect::<Vec<_>>()
                    .join(", ");
                anyhow::anyhow!("unknown kernel family '{value}' (expected one of: {known})")
            })
    }

    /// The matching config JSON under `.github/config`.
    fn config_file(self) -> PathBuf {
        PathBuf::from(".github/config").join(format!("{}.json", self.id()))
    }

    /// SUSFS branch on `simonpunk/susfs4ksu` — mirrors `gki-{version}`.
    fn susfs_branch(self) -> String {
        format!("gki-{}", self.id())
    }

    fn is_older_than(self, version: (u32, u32)) -> bool {
        self.kernel_ver() < version
    }
}

// ---------------------------------------------------------------------------
// Static kernel configuration sets (from the composite actions)
// ---------------------------------------------------------------------------

/// `root-setup/action.yml` — enable the KernelSU root implementation.
const CFG_ROOT: &[&str] = &["CONFIG_KSU=y"];

/// `susfs-config/action.yml` — the fixed SUSFS option block.
const CFG_SUSFS: &[&str] = &[
    "CONFIG_KSU_SUSFS=y",
    "CONFIG_KSU_SUSFS_SUS_PATH=y",
    "CONFIG_KSU_SUSFS_SUS_MOUNT=y",
    "CONFIG_KSU_SUSFS_SUS_KSTAT=y",
    "CONFIG_KSU_SUSFS_SPOOF_UNAME=y",
    "CONFIG_KSU_SUSFS_ENABLE_LOG=y",
    "CONFIG_KSU_SUSFS_HIDE_KSU_SUSFS_SYMBOLS=y",
    "CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG=y",
    "CONFIG_KSU_SUSFS_SUS_MAP=y",
];

/// `susfs-config/action.yml` — `OPEN_REDIRECT` follows NoMount, which is out of
/// scope, so the "no NoMount" branch is always taken here.
const CFG_SUSFS_OPEN_REDIRECT: &[&str] = &["CONFIG_KSU_SUSFS_OPEN_REDIRECT=y"];

/// `droidspaces/action.yml` — the LXC-style container runtime options.
const CFG_DROIDSPACES: &[&str] = &[
    "CONFIG_PID_NS=y",
    "CONFIG_SYSVIPC=y",
    "CONFIG_POSIX_MQUEUE=y",
    "CONFIG_IPC_NS=y",
    "CONFIG_DEVTMPFS=y",
    "CONFIG_BINFMT_MISC=y",
    "CONFIG_BINFMT_SCRIPT=y",
    "CONFIG_BINFMT_ELF=y",
    "CONFIG_USER_NS=y",
];

/// `misc/action.yml` — applied unconditionally by `build.yml`.
const CFG_MISC: &[&str] = &[
    "CONFIG_OVERLAY_FS=y",
    "CONFIG_TMPFS_XATTR=y",
    "CONFIG_TMPFS_POSIX_ACL=y",
    "CONFIG_KALLSYMS=y",
    "CONFIG_KALLSYMS_ALL=y",
];

// ---------------------------------------------------------------------------
// Options and per-target context
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Options {
    workspace: PathBuf,
    output_dir: PathBuf,
    bazel_cache: PathBuf,
    brand_name: String,
    variant: String,
    jobs: usize,
    bypass: bool,
    use_cache: bool,
    strict_patches: bool,
    root_commit: Option<String>,
    susfs_commit: Option<String>,
    droidspaces_commit: Option<String>,
    kernel_patches_commit: Option<String>,
    anykernel3_commit: Option<String>,
}

impl Options {
    fn jobs(&self) -> usize {
        if self.jobs > 0 {
            self.jobs
        } else {
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4)
        }
    }
}

/// Mutable state for one `build.yml` invocation (one family + sublevel + date).
struct Ctx {
    opts: Options,
    family: Family,
    sublevel_input: String,
    os_patch_level: String,
    /// Numeric sublevel after LTS resolution.
    sublevel: String,
    /// `{kernel}.{sublevel}-{android}-{os_patch_level}[-{variant}]`.
    file_name: String,
    source_date_epoch: i64,
    kbuild_timestamp: String,
    git_date: String,
    /// Resolved SHAs, filled in as the pipeline progresses.
    kernel_sha: String,
    root_sha: String,
    susfs_sha: String,
    root_repo: String,
    droidspaces_sha: String,
    /// Kernel fixes / SUSFS log lines folded into the build summary.
    notes: Vec<String>,
}

impl Ctx {
    fn kernel_dir(&self) -> PathBuf {
        self.opts.workspace.join("kernel")
    }

    fn common_dir(&self) -> PathBuf {
        self.kernel_dir().join("common")
    }

    fn defconfig(&self) -> PathBuf {
        self.common_dir().join("arch/arm64/configs/gki_defconfig")
    }

    fn kernel_patches(&self) -> PathBuf {
        self.opts.workspace.join("kernel_patches")
    }

    fn any_kernel3(&self) -> PathBuf {
        self.opts.workspace.join("AnyKernel3")
    }

    fn susfs_dir(&self) -> PathBuf {
        self.opts.workspace.join("susfs4ksu")
    }

    fn droidspaces_dir(&self) -> PathBuf {
        self.opts.workspace.join("Droidspaces-OSS")
    }

    fn rejects_dir(&self) -> PathBuf {
        self.opts.workspace.join("patch-rejects")
    }

    fn uses_bazel(&self) -> bool {
        !self.kernel_dir().join("build/build.sh").exists()
    }

    fn log(&self, message: impl AsRef<str>) {
        say(&format!(
            "[trustgki {}] {}",
            self.file_name,
            message.as_ref()
        ));
    }

    fn note(&mut self, message: impl Into<String>) {
        let message = message.into();
        self.log(&message);
        self.notes.push(message);
    }
}

// ---------------------------------------------------------------------------
// Process helpers
// ---------------------------------------------------------------------------

fn pstr(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// Print a line and flush immediately so piped logs stream instead of buffering.
fn say(message: &str) {
    println!("{message}");
    let _ = std::io::stdout().flush();
}

/// Run a command, echoing it the way `set -x` would.
fn run(cwd: &Path, program: &str, args: &[&str]) -> Result<()> {
    run_with_env(cwd, program, args, &[])
}

fn run_with_env(cwd: &Path, program: &str, args: &[&str], env: &[(&str, String)]) -> Result<()> {
    let mut shown = String::from(program);
    for arg in args {
        shown.push(' ');
        shown.push_str(arg);
    }
    say(&format!("+ {shown}"));

    let mut cmd = Command::new(program);
    cmd.args(args).current_dir(cwd);
    for (key, value) in env {
        cmd.env(key, value);
    }
    let status = cmd
        .status()
        .with_context(|| format!("failed to spawn `{program}`"))?;
    if !status.success() {
        bail!("command failed ({}): {}", status, shown);
    }
    Ok(())
}

/// Run a command and capture stdout (trailing newlines trimmed).
fn capture(cwd: &Path, program: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(program)
        .args(args)
        .current_dir(cwd)
        .output()
        .with_context(|| format!("failed to spawn `{program}`"))?;
    if !output.status.success() {
        bail!(
            "command failed ({}): {} {}\n{}",
            output.status,
            program,
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .trim_end()
        .to_string())
}

/// `patch -p1` (plus extra flags) with the patch file on stdin, run in `cwd`.
fn patch_file(cwd: &Path, patch: &Path, extra: &[&str]) -> Result<()> {
    if !patch.exists() {
        bail!("patch file not found: {}", pstr(patch));
    }
    let file =
        fs::File::open(patch).with_context(|| format!("cannot open patch {}", pstr(patch)))?;
    say(&format!(
        "+ patch -p1 {} < {}",
        extra.join(" "),
        pstr(patch)
    ));
    let status = Command::new("patch")
        .arg("-p1")
        .args(extra)
        .current_dir(cwd)
        .stdin(Stdio::from(file))
        .status()
        .context("failed to spawn `patch`")?;
    if !status.success() {
        bail!("patch {} failed ({})", pstr(patch), status);
    }
    Ok(())
}

/// `patch -p1 --dry-run` probe.
fn patch_can_apply(cwd: &Path, patch: &Path) -> bool {
    let Ok(file) = fs::File::open(patch) else {
        return false;
    };
    Command::new("patch")
        .args(["-p1", "--dry-run", "--silent"])
        .current_dir(cwd)
        .stdin(Stdio::from(file))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Retry a fallible operation with a fixed delay, mirroring the `retry()`
/// shell helper embedded in the actions.
fn retry<T>(attempts: usize, delay: Duration, mut op: impl FnMut(usize) -> Result<T>) -> Result<T> {
    let mut last: Option<anyhow::Error> = None;
    for attempt in 1..=attempts {
        match op(attempt) {
            Ok(value) => return Ok(value),
            Err(err) => {
                eprintln!("retry {attempt}/{attempts} failed: {err:#}");
                last = Some(err);
                if attempt < attempts {
                    std::thread::sleep(delay);
                }
            }
        }
    }
    Err(last.unwrap_or_else(|| anyhow::anyhow!("retry failed")))
}

/// Resolve a ref to a commit SHA with `git ls-remote`, retrying on failure.
fn ls_remote(repo: &str, reference: &str) -> Result<String> {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    retry(5, Duration::from_secs(5), |_| {
        let out = capture(&cwd, "git", &["ls-remote", repo, reference])?;
        let sha = out
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().next())
            .unwrap_or("")
            .to_string();
        if sha.len() != 40 || !sha.chars().all(|c| c.is_ascii_hexdigit()) {
            bail!("git ls-remote {repo} {reference} returned `{sha}`");
        }
        Ok(sha)
    })
}

/// `git clone --no-checkout` + `fetch --depth=1 <sha>` + detached checkout.
fn clone_pinned(repo: &str, dir: &Path, reference: &str) -> Result<()> {
    let parent = dir
        .parent()
        .ok_or_else(|| anyhow::anyhow!("no parent for {}", pstr(dir)))?;
    run(parent, "git", &["clone", "--no-checkout", repo, &pstr(dir)])?;
    run(dir, "git", &["fetch", "--depth=1", "origin", reference])?;
    run(dir, "git", &["checkout", "--detach", reference])?;
    let head = capture(dir, "git", &["rev-parse", "HEAD"])?;
    if head != reference {
        bail!("{repo} pin mismatch: expected {reference}, got {head}");
    }
    Ok(())
}

fn require_tools(tools: &[&str]) -> Result<()> {
    let mut missing = Vec::new();
    for tool in tools {
        if which::which(tool).is_err() {
            missing.push(*tool);
        }
    }
    if !missing.is_empty() {
        bail!("missing required tool(s): {}", missing.join(", "));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Text-editing helpers (Rust replacements for the actions' sed/perl/python)
// ---------------------------------------------------------------------------

fn read(path: &Path) -> Result<String> {
    fs::read_to_string(path).with_context(|| format!("cannot read {}", pstr(path)))
}

fn write(path: &Path, contents: &str) -> Result<()> {
    fs::write(path, contents).with_context(|| format!("cannot write {}", pstr(path)))
}

/// Address a file relative to the kernel `common/` tree and write it back.
fn edit_common(ctx: &Ctx, rel: &str, f: impl FnOnce(&str) -> String) -> Result<()> {
    let path = ctx.common_dir().join(rel);
    let before = read(&path)?;
    let after = f(&before);
    if after != before {
        write(&path, &after)?;
    }
    Ok(())
}

/// `sed '/needle/a line'` — insert after *every* line containing `needle`.
fn sed_insert_after(content: &str, needle: &str, inserted: &str) -> String {
    let mut out = String::with_capacity(content.len() + inserted.len());
    for line in content.split_inclusive('\n') {
        out.push_str(line);
        if line.contains(needle) {
            out.push_str(inserted);
            if !inserted.ends_with('\n') {
                out.push('\n');
            }
        }
    }
    out
}

/// `sed '/needle/i line'` — insert before *every* line containing `needle`.
fn sed_insert_before(content: &str, needle: &str, inserted: &str) -> String {
    let mut out = String::with_capacity(content.len() + inserted.len());
    for line in content.split_inclusive('\n') {
        if line.contains(needle) {
            out.push_str(inserted);
            if !inserted.ends_with('\n') {
                out.push('\n');
            }
        }
        out.push_str(line);
    }
    out
}

/// `sed '/^needle$/d'` — drop lines whose trimmed content equals `needle`.
fn sed_delete_exact(content: &str, needle: &str) -> String {
    content
        .split_inclusive('\n')
        .filter(|line| line.trim_end_matches(['\n', '\r']) != needle)
        .collect()
}

/// Append a line, adding the missing trailing newline first (`echo >> file`).
fn append_line(content: &str, line: &str) -> String {
    let mut out = content.to_string();
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(line);
    out.push('\n');
    out
}

/// `sed -i '$d'` followed by `echo line >> file` (used by the branding step).
fn replace_last_line(content: &str, line: &str) -> String {
    let mut lines: Vec<&str> = content.split_inclusive('\n').collect();
    lines.pop();
    let mut out = lines.concat();
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(line);
    out.push('\n');
    out
}

/// Regex `replace_all` that keeps the original text unless the closure opts in.
fn regex_replace(
    content: &str,
    pattern: &str,
    replacement: impl Fn(&regex::Captures<'_>) -> Option<String>,
) -> Result<String> {
    let re = Regex::new(pattern).with_context(|| format!("bad regex: {pattern}"))?;
    let mut out = String::with_capacity(content.len());
    let mut last = 0usize;
    for caps in re.captures_iter(content) {
        let whole = caps.get(0).expect("group 0");
        let Some(rep) = replacement(&caps) else {
            continue;
        };
        out.push_str(&content[last..whole.start()]);
        out.push_str(&rep);
        last = whole.end();
    }
    out.push_str(&content[last..]);
    Ok(out)
}

/// Insert `insert` before the first line matching `pattern` (python `count=1`).
fn insert_before_regex_once(content: &str, pattern: &str, insert: &str) -> Result<String> {
    let re = Regex::new(pattern).with_context(|| format!("bad regex: {pattern}"))?;
    let Some(m) = re.find(content) else {
        return Ok(content.to_string());
    };
    let mut out = String::with_capacity(content.len() + insert.len());
    out.push_str(&content[..m.start()]);
    out.push_str(insert);
    out.push_str(&content[m.start()..]);
    Ok(out)
}

/// Apply a py-style `re.sub(pattern, repl, count=1)` on a file.
fn regex_sub_once(
    content: &str,
    pattern: &str,
    replacement: impl Fn(&regex::Captures<'_>) -> String,
) -> Result<String> {
    let re = Regex::new(pattern).with_context(|| format!("bad regex: {pattern}"))?;
    let Some(caps) = re.captures(content) else {
        return Ok(content.to_string());
    };
    let whole = caps.get(0).expect("group 0");
    let mut out = String::with_capacity(content.len());
    out.push_str(&content[..whole.start()]);
    out.push_str(&replacement(&caps));
    out.push_str(&content[whole.end()..]);
    Ok(out)
}

/// `sort -V`-style comparison of dotted numeric versions.
fn version_key(value: &str) -> Vec<u64> {
    value
        .split(|c: char| !c.is_ascii_digit())
        .filter(|part| !part.is_empty())
        .map(|part| part.parse().unwrap_or(0))
        .collect()
}

fn version_ge(a: &str, b: &str) -> bool {
    let (ka, kb) = (version_key(a), version_key(b));
    for i in 0..ka.len().max(kb.len()) {
        let x = ka.get(i).copied().unwrap_or(0);
        let y = kb.get(i).copied().unwrap_or(0);
        if x != y {
            return x > y;
        }
    }
    true
}

/// Numeric sublevel comparison; a non-numeric sublevel never matches a bound.
fn sublevel_le(sublevel: &str, bound: u64) -> bool {
    sublevel
        .trim()
        .parse::<u64>()
        .map(|value| value <= bound)
        .unwrap_or(false)
}

fn sublevel_ge(sublevel: &str, bound: u64) -> bool {
    sublevel
        .trim()
        .parse::<u64>()
        .map(|value| value >= bound)
        .unwrap_or(false)
}

fn chmod_exec(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(perms.mode() | 0o755);
    fs::set_permissions(path, perms)?;
    Ok(())
}

/// Remove every entry inside `dir`, keeping the directory itself
/// (`clean_workspace()` from `download-kernel/action.yml`).
fn empty_dir(dir: &Path) -> Result<()> {
    if !dir.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            fs::remove_dir_all(&path)?;
        } else {
            fs::remove_file(&path)?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// setup-build-environment/action.yml
// ---------------------------------------------------------------------------

/// Clone `kernel_patches` and `AnyKernel3`, and fetch the `repo` launcher.
fn setup_build_environment(ctx: &Ctx) -> Result<()> {
    ctx.log("── setup build environment");
    let ws = &ctx.opts.workspace;
    fs::create_dir_all(ws.join("kernel"))?;
    fs::create_dir_all(ws.join("git-repo"))?;

    // `repo` launcher, retried exactly like the action's `retry` helper.
    let repo_tool = ws.join("git-repo/repo");
    retry(5, Duration::from_secs(5), |attempt| {
        if attempt > 1 {
            eprintln!("retry {attempt}/5: fetching repo launcher");
        }
        run(
            ws,
            "curl",
            &[
                "-LfsS",
                "--retry",
                "5",
                "--retry-delay",
                "5",
                "--retry-all-errors",
                "-o",
                &pstr(&repo_tool),
                URL_REPO_TOOL,
            ],
        )
    })?;
    chmod_exec(&repo_tool)?;

    // WildKernels/kernel_patches — source of every version-specific patch.
    let patches_dir = ctx.kernel_patches();
    if patches_dir.exists() {
        fs::remove_dir_all(&patches_dir)?;
    }
    run(
        ws,
        "git",
        &["clone", REPO_KERNEL_PATCHES, &pstr(&patches_dir)],
    )?;
    if let Some(pin) = &ctx.opts.kernel_patches_commit {
        run(&patches_dir, "git", &["fetch", "--depth=1", "origin", pin])?;
        run(&patches_dir, "git", &["checkout", pin])?;
        let head = capture(&patches_dir, "git", &["rev-parse", "HEAD"])?;
        if &head != pin {
            bail!("kernel_patches pin mismatch: expected {pin}, got {head}");
        }
    }

    // WildKernels/AnyKernel3 (gki-2.0) — receives `Image` and becomes the artifact.
    let ak3_dir = ctx.any_kernel3();
    if ak3_dir.exists() {
        fs::remove_dir_all(&ak3_dir)?;
    }
    run(
        ws,
        "git",
        &[
            "clone",
            "-b",
            BRANCH_ANY_KERNEL3,
            REPO_ANY_KERNEL3,
            &pstr(&ak3_dir),
        ],
    )?;
    if let Some(pin) = &ctx.opts.anykernel3_commit {
        run(&ak3_dir, "git", &["fetch", "--depth=1", "origin", pin])?;
        run(&ak3_dir, "git", &["checkout", pin])?;
        let head = capture(&ak3_dir, "git", &["rev-parse", "HEAD"])?;
        if &head != pin {
            bail!("AnyKernel3 pin mismatch: expected {pin}, got {head}");
        }
    }

    // `Install build deps for BTF generation (android12-5.10)`.
    if ctx.family == Family::Android12_5_10 {
        ctx.log("installing dwarves/libelf-dev (android12-5.10 BTF tooling)");
        let update = run(ws, "sudo", &["apt-get", "update", "-qq"]);
        let install = update.and_then(|_| {
            run(
                ws,
                "sudo",
                &["apt-get", "install", "-y", "-qq", "dwarves", "libelf-dev"],
            )
        });
        if let Err(err) = install {
            ctx.log(format!(
                "warning: could not install BTF tooling automatically ({err:#})"
            ));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// download-kernel/action.yml
// ---------------------------------------------------------------------------

/// `repo init` + `repo sync` for `common-{android}-{kernel}-{patch_level}`.
fn download_kernel(ctx: &mut Ctx) -> Result<()> {
    ctx.log("── download kernel repository (repo init/sync)");
    let kernel = ctx.kernel_dir();
    let repo_tool = ctx.opts.workspace.join("git-repo/repo");
    let branch = format!(
        "common-{}-{}-{}",
        ctx.family.android(),
        ctx.family.kernel(),
        ctx.os_patch_level
    );

    let mut attempt = 1usize;
    loop {
        if attempt > 1 {
            ctx.log(format!(
                "cleaning kernel workspace before retry {attempt}/3"
            ));
            empty_dir(&kernel)?;
            std::thread::sleep(Duration::from_secs(15));
        }
        // The workflow always inits shallow (DEPTHS=(1 1 1)).
        let result = init_kernel_repo(ctx, &kernel, &repo_tool, &branch);
        match result {
            Ok(()) => break,
            Err(err) if attempt < 3 => {
                eprintln!("repo init/sync attempt {attempt}/3 failed: {err:#}");
                attempt += 1;
            }
            Err(err) => return Err(err),
        }
    }

    // `Capture Kernel Common Commit Metadata`.
    let common = ctx.common_dir();
    if common.join(".git").exists() {
        ctx.kernel_sha = capture(&common, "git", &["rev-parse", "HEAD"])?;
        let subject = capture(&common, "git", &["log", "-1", "--format=%s"])?;
        ctx.log(format!(
            "kernel/common commit: {} ({subject})",
            ctx.kernel_sha
        ));
    } else {
        ctx.log("warning: kernel/common is not a git checkout; no commit metadata");
    }
    Ok(())
}

fn init_kernel_repo(ctx: &Ctx, kernel: &Path, repo_tool: &Path, branch: &str) -> Result<()> {
    run(
        kernel,
        &pstr(repo_tool),
        &[
            "init",
            "-u",
            REPO_KERNEL_MANIFEST,
            "-b",
            branch,
            "--depth=1",
        ],
    )?;

    // Deprecated branches live under `deprecated/<branch>` in the manifest.
    let remote = capture(kernel, "git", &["ls-remote", REPO_KERNEL_COMMON, branch])?;
    if remote.contains("deprecated") {
        ctx.log(format!(
            "note: branch {branch} is deprecated; rewriting manifest"
        ));
        let manifest = kernel.join(".repo/manifests/default.xml");
        let content = read(&manifest)?;
        let rewritten = content.replace(
            &format!("\"{branch}\""),
            &format!("\"deprecated/{branch}\""),
        );
        write(&manifest, &rewritten)?;
    }

    run(
        kernel,
        "timeout",
        &[
            "15m",
            &pstr(repo_tool),
            "sync",
            "-c",
            "--current-branch",
            "--no-clone-bundle",
            "--no-tags",
            "--jobs-checkout=4",
            "-j4",
        ],
    )
}

// ---------------------------------------------------------------------------
// Set Build Timestamp + extract-sublevel-file-name/action.yml
// ---------------------------------------------------------------------------

/// `Set Build Timestamp from Kernel Commit` — deterministic build clock.
fn set_build_timestamp(ctx: &mut Ctx) -> Result<()> {
    ctx.log("── set deterministic build timestamp");
    let input = &ctx.os_patch_level;
    let year_month = if input.starts_with("lts") {
        let re = Regex::new(r"^lts-([0-9]{2})$").expect("static regex");
        let now = OffsetDateTime::now_utc();
        match re.captures(input) {
            // `lts-<MM>` pins the month; the year is "now".
            Some(caps) => format!("{}-{}", now.year(), &caps[1]),
            None => format!("{}-{:02}", now.year(), u8::from(now.month())),
        }
    } else {
        input.clone()
    };

    // `FIXED_BUILD_DATE="${OS_PATCH_LEVEL_YM}-05 04:20:00 UTC"`.
    let mut parts = year_month.split('-');
    let year: i32 = parts
        .next()
        .unwrap_or("")
        .parse()
        .with_context(|| format!("cannot parse year from '{year_month}'"))?;
    let month: u8 = parts
        .next()
        .unwrap_or("")
        .parse()
        .with_context(|| format!("cannot parse month from '{year_month}'"))?;
    let month = Month::try_from(month).context("month out of range")?;
    let date = Date::from_calendar_date(year, month, 5)?;
    let clock = ClockTime::from_hms(4, 20, 0)?;
    let stamp = OffsetDateTime::new_utc(date, clock);

    ctx.source_date_epoch = stamp.unix_timestamp();
    ctx.kbuild_timestamp = stamp
        .format(&format_description!(
            "[weekday repr:short] [month repr:short] [day] [hour]:[minute]:[second] UTC [year]"
        ))
        .context("cannot format KBUILD_BUILD_TIMESTAMP")?;
    ctx.git_date = stamp
        .format(&format_description!(
            "[year]-[month]-[day]T[hour]:[minute]:[second]Z"
        ))
        .context("cannot format GIT date")?;
    ctx.log(format!(
        "SOURCE_DATE_EPOCH={} (KBUILD_BUILD_TIMESTAMP=\"{}\")",
        ctx.source_date_epoch, ctx.kbuild_timestamp
    ));
    Ok(())
}

/// `extract-sublevel-file-name/action.yml` — resolve `SUBLEVEL` and `FILE_NAME`.
fn extract_sublevel_and_file_name(ctx: &mut Ctx) -> Result<()> {
    // `X` (the config-file sentinel) and `lts` both mean "read the tip Makefile".
    let resolve_from_makefile = ctx.os_patch_level.eq_ignore_ascii_case("lts")
        || ctx.sublevel_input.eq_ignore_ascii_case(SUBLEVEL_LTS);
    let sublevel = if resolve_from_makefile {
        let makefile = ctx.common_dir().join("Makefile");
        if !makefile.exists() {
            bail!("LTS build requires {}", pstr(&makefile));
        }
        let content = read(&makefile)?;
        let re = Regex::new(r"^[[:space:]]*SUBLEVEL[[:space:]]*=").expect("static regex");
        let matches: Vec<&str> = content.lines().filter(|line| re.is_match(line)).collect();
        if matches.len() != 1 {
            bail!(
                "expected exactly one SUBLEVEL assignment in {}, found {}",
                pstr(&makefile),
                matches.len()
            );
        }
        let value = matches[0]
            .split_once('=')
            .map(|(_, v)| v.trim().to_string())
            .unwrap_or_default();
        if value.is_empty() || !value.chars().all(|c| c.is_ascii_digit()) {
            bail!("invalid numeric SUBLEVEL '{value}' in {}", pstr(&makefile));
        }
        value
    } else {
        ctx.sublevel_input.clone()
    };
    ctx.sublevel = sublevel;

    let mut file_name = format!(
        "{}.{}-{}-{}",
        ctx.family.kernel(),
        ctx.sublevel,
        ctx.family.android(),
        ctx.os_patch_level
    );
    if !ctx.opts.variant.is_empty() && ctx.opts.variant != "Normal" {
        file_name.push_str(&format!("-{}", ctx.opts.variant));
    }
    ctx.file_name = file_name.clone();
    ctx.log(format!("FILE_NAME={file_name} (sublevel={})", ctx.sublevel));
    Ok(())
}

// ---------------------------------------------------------------------------
// kernel-fixes/action.yml
// ---------------------------------------------------------------------------

/// `ldd --version | head -1 | awk '{print $NF}'`.
fn detect_glibc() -> Option<String> {
    let output = Command::new("ldd").arg("--version").output().ok()?;
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    if text.trim().is_empty() {
        text = String::from_utf8_lossy(&output.stderr).into_owned();
    }
    text.lines()
        .next()
        .and_then(|line| line.split_whitespace().last())
        .map(|value| value.to_string())
}

/// Compatibility fixes keyed on glibc, family and sublevel.
fn apply_kernel_fixes(ctx: &mut Ctx) -> Result<()> {
    ctx.log("── kernel fixes");
    let glibc = detect_glibc();
    let glibc_ge_238 = glibc
        .as_deref()
        .map(|value| version_ge(value, "2.38"))
        .unwrap_or(false);
    ctx.log(format!(
        "glibc {} (>= 2.38: {})",
        glibc.as_deref().unwrap_or("unknown"),
        glibc_ge_238
    ));

    if glibc_ge_238 {
        // `tools/bpf/resolve_btfids/Makefile`: forward CFLAGS into the sub-make.
        let finder = "$(Q)$(MAKE) -C $(SUBCMD_SRC) OUTPUT=$(abspath $(dir $@))/ $(abspath $@)";
        let replacer = "$(Q)$(MAKE) -C $(SUBCMD_SRC) EXTRA_CFLAGS=\"$(CFLAGS)\" OUTPUT=$(abspath $(dir $@))/ $(abspath $@)";
        let mut fixed = "false";
        edit_common(ctx, "tools/bpf/resolve_btfids/Makefile", |content| {
            if content.contains(finder) {
                fixed = "true";
                content.replace(finder, replacer)
            } else if content.contains("EXTRA_CFLAGS") {
                fixed = "already_fixed";
                content.to_string()
            } else {
                content.to_string()
            }
        })?;
        ctx.note(format!("Makefile EXTRA_CFLAGS fix: {fixed}"));

        // `tools/lib/subcmd/parse-options.c`: C99 declarations break old trees.
        let needs_parse_fix = (ctx.family == Family::Android13_5_10
            && sublevel_le(&ctx.sublevel, 186))
            || (ctx.family == Family::Android13_5_15 && sublevel_le(&ctx.sublevel, 119))
            || (ctx.family == Family::Android14_5_15 && sublevel_le(&ctx.sublevel, 110));
        if needs_parse_fix {
            edit_common(ctx, "tools/lib/subcmd/parse-options.c", |content| {
                let mut out = sed_insert_after(content, "char *buf = NULL;", "int i;");
                out = out.replace(
                    "for (int i = 0; subcommands[i]; i++) {",
                    "for (i = 0; subcommands[i]; i++) {",
                );
                out = sed_insert_after(&out, "if (subcommands) {", "int i;");
                out.replace(
                    "for (int i = 0; subcommands[i]; i++)",
                    "for (i = 0; subcommands[i]; i++)",
                )
            })?;
            ctx.note("parse-options.c fix: applied");
        } else {
            ctx.note("parse-options.c fix: not applicable");
        }
    } else {
        ctx.note("glibc < 2.38: skipping Makefile/parse-options fixes");
    }

    // android15-6.6 (sublevel <= 58): fs/namespace.c lacks the fs trace hook.
    if ctx.family == Family::Android15_6_6 && sublevel_le(&ctx.sublevel, 58) {
        edit_common(ctx, "fs/namespace.c", |content| {
            if content.contains("#include <trace/hooks/fs.h>") {
                return content.to_string();
            }
            sed_insert_after(
                content,
                "#include <trace/hooks/blk.h>",
                "#include <trace/hooks/fs.h>",
            )
        })?;
        ctx.note("fs/namespace.c include fix (android15-6.6): applied");
    }

    // mm/mmap.c VM_PAD_MASK fix for four pinned sublevels.
    let mmap_fix = (ctx.family == Family::Android12_5_10 && ctx.sublevel == "226")
        || (ctx.family == Family::Android13_5_10 && ctx.sublevel == "223")
        || (ctx.family == Family::Android13_5_15 && ctx.sublevel == "167")
        || (ctx.family == Family::Android14_5_15 && ctx.sublevel == "167");
    if mmap_fix {
        // NOTE: the shell action's `sed` replacement contains a literal `&`,
        // which sed expands to the whole match and corrupts the line. The
        // intended transformation is reproduced here instead.
        let fixed = regex_replace(
            &read(&ctx.common_dir().join("mm/mmap.c"))?,
            r"[ \t]*vm_flags_clear\(new_vma, VM_PAD_MASK\);",
            |_| Some("                new_vma->vm_flags &= ~VM_PAD_MASK;".to_string()),
        )?;
        write(&ctx.common_dir().join("mm/mmap.c"), &fixed)?;
        ctx.note("mm/mmap.c VM_PAD_MASK fix: applied");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// root-setup/action.yml
// ---------------------------------------------------------------------------

/// Clone the KernelSU-Next kernel integration and wire it into `drivers/`.
fn setup_root(ctx: &mut Ctx) -> Result<()> {
    ctx.log("── root implementation (KernelSU-Next)");
    let kernel = ctx.kernel_dir();

    // `next` flavour: the SUSFS-integrated tree lives on the pershoot fork's
    // `dev-susfs` branch (upstream `KernelSU-Next/KernelSU-Next` has no
    // `dev-susfs` branch), so the resolved commit decides which remote to use.
    let reference = match &ctx.opts.root_commit {
        Some(sha) => sha.clone(),
        None => match ls_remote(
            REPO_KSU_NEXT_SUSFS,
            &format!("refs/heads/{BRANCH_KSU_NEXT_SUSFS}"),
        ) {
            Ok(sha) => sha,
            Err(err) => {
                ctx.log(format!(
                    "warning: cannot resolve {BRANCH_KSU_NEXT_SUSFS} ({err:#}); \
                     falling back to upstream {BRANCH_KSU_NEXT}"
                ));
                ls_remote(REPO_KSU_NEXT, &format!("refs/heads/{BRANCH_KSU_NEXT}"))?
            }
        },
    };
    let expected_commit = reference.clone();
    if expected_commit.len() != 40 || !expected_commit.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("root commit must be a full 40-character SHA (got '{expected_commit}')");
    }

    let directory = "KernelSU-Next";
    for candidate in ["KernelSU", "KernelSU-Next", "ReSukiSU"] {
        if candidate != directory && kernel.join(candidate).exists() {
            bail!("refusing mixed root implementations: found {candidate}");
        }
    }

    let drivers_dir = if kernel.join("common/drivers").is_dir() {
        kernel.join("common/drivers")
    } else if kernel.join("drivers").is_dir() {
        kernel.join("drivers")
    } else {
        bail!("kernel drivers directory not found");
    };
    if drivers_dir.join("kernelsu").exists() {
        bail!("refusing to replace an existing kernelsu integration");
    }
    if kernel.join(directory).exists() {
        bail!("refusing to reuse an existing root checkout: {directory}");
    }

    // Prefer the fork that carries the requested commit; fall back to the other.
    let mut last_error = None;
    let mut repo_used = REPO_KSU_NEXT_SUSFS;
    for repo in [REPO_KSU_NEXT_SUSFS, REPO_KSU_NEXT] {
        let target = kernel.join(directory);
        match clone_pinned(repo, &target, &expected_commit) {
            Ok(()) => {
                repo_used = repo;
                last_error = None;
                break;
            }
            Err(err) => {
                eprintln!("root clone from {repo} failed: {err:#}");
                if target.exists() {
                    fs::remove_dir_all(&target).ok();
                }
                last_error = Some(err);
            }
        }
    }
    if let Some(err) = last_error {
        return Err(err.context("could not resolve the KernelSU-Next commit on any remote"));
    }
    ctx.root_repo = repo_used.to_string();

    let checkout = kernel.join(directory);
    if !checkout.join("kernel/Kconfig").is_file() || !checkout.join("kernel/Makefile").is_file() {
        bail!("selected root checkout does not contain a kernel integration");
    }
    ctx.root_sha = capture(&checkout, "git", &["rev-parse", "HEAD"])?;
    let root_version = capture(
        &checkout,
        "git",
        &["describe", "--tags", "--always", "--dirty"],
    )?;
    ctx.note(format!(
        "root={} commit={} version={root_version}",
        repo_used, ctx.root_sha
    ));

    // Symlink `drivers/kernelsu -> <checkout>/kernel`, then register it.
    let relative = path_relative(&checkout.join("kernel"), &drivers_dir)?;
    std::os::unix::fs::symlink(&relative, drivers_dir.join("kernelsu"))
        .context("cannot create drivers/kernelsu symlink")?;

    let makefile = drivers_dir.join("Makefile");
    let makefile_content = read(&makefile)?;
    if !makefile_content.contains("obj-$(CONFIG_KSU) += kernelsu/") {
        write(
            &makefile,
            &append_line(&makefile_content, "obj-$(CONFIG_KSU) += kernelsu/"),
        )?;
    }
    let kconfig = drivers_dir.join("Kconfig");
    let kconfig_content = read(&kconfig)?;
    if !kconfig_content.contains("source \"drivers/kernelsu/Kconfig\"") {
        // `sed -i '/endmenu/i ...'` inserts before each matching line.
        write(
            &kconfig,
            &sed_insert_before(
                &kconfig_content,
                "endmenu",
                "source \"drivers/kernelsu/Kconfig\"",
            ),
        )?;
    }

    set_kernel_config(ctx, CFG_ROOT)
}

/// `realpath --relative-to=<base> <target>`.
fn path_relative(target: &Path, base: &Path) -> Result<PathBuf> {
    let target = fs::canonicalize(target)
        .with_context(|| format!("cannot canonicalize {}", pstr(target)))?;
    let base =
        fs::canonicalize(base).with_context(|| format!("cannot canonicalize {}", pstr(base)))?;
    let target_parts: Vec<_> = target.components().collect();
    let base_parts: Vec<_> = base.components().collect();
    let common = target_parts
        .iter()
        .zip(base_parts.iter())
        .take_while(|(a, b)| a == b)
        .count();
    let mut result = PathBuf::new();
    for _ in common..base_parts.len() {
        result.push("..");
    }
    for part in &target_parts[common..] {
        result.push(part.as_os_str());
    }
    Ok(result)
}

// ---------------------------------------------------------------------------
// set-kernel-config/action.yml
// ---------------------------------------------------------------------------

/// Patch `arch/arm64/configs/gki_defconfig` exactly like the composite action:
/// replace an existing assignment, un-set a `# ... is not set` line, or append.
fn set_kernel_config(ctx: &Ctx, entries: &[&str]) -> Result<()> {
    let defconfig = ctx.defconfig();
    if !defconfig.exists() {
        bail!("ERROR: gki_defconfig not found at {}", pstr(&defconfig));
    }
    let mut content = read(&defconfig)?;
    for raw in entries {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = match line.split_once('=') {
            Some((key, value)) => (key.trim(), value.trim()),
            None => (line, "y"),
        };
        ctx.log(format!("config: {key}={value}"));

        let assignment = Regex::new(&format!(r"(?m)^{}=.*$", regex::escape(key)))?;
        let not_set = format!("# {key} is not set");
        if assignment.is_match(&content) {
            content = assignment
                .replace_all(&content, format!("{key}={value}").as_str())
                .into_owned();
        } else if content.lines().any(|l| l.trim() == not_set) {
            let mut out = String::with_capacity(content.len());
            for line in content.split_inclusive('\n') {
                let bare = line.trim_end_matches(['\n', '\r']);
                if bare.trim() == not_set {
                    out.push_str(&format!("{key}={value}"));
                    if line.ends_with('\n') {
                        out.push('\n');
                    }
                } else {
                    out.push_str(line);
                }
            }
            content = out;
        } else {
            content = append_line(&content, &format!("{key}={value}"));
        }
    }
    write(&defconfig, &content)
}

fn regex_replace_all(content: &str, pattern: &str, replacement: &str) -> Result<String> {
    let re = Regex::new(pattern).with_context(|| format!("bad regex: {pattern}"))?;
    Ok(re.replace_all(content, replacement).into_owned())
}

fn copy_files(src_dir: &Path, dst_dir: &Path) -> Result<()> {
    fs::create_dir_all(dst_dir)?;
    for entry in fs::read_dir(src_dir).with_context(|| format!("cannot read {}", pstr(src_dir)))? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            fs::copy(entry.path(), dst_dir.join(entry.file_name()))?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// susfs{,-setup,-config,-patches,-revert-patches}/action.yml
// ---------------------------------------------------------------------------

/// Clone the SUSFS branch, apply the kernel patch series and revert the
/// per-version "fake" include shims.
fn setup_susfs(ctx: &mut Ctx) -> Result<()> {
    ctx.log("── SUSFS setup + patches");
    let ws = ctx.opts.workspace.clone();
    let dir = ctx.susfs_dir();
    let branch = ctx.family.susfs_branch();

    if dir.exists() {
        fs::remove_dir_all(&dir)?;
    }
    retry(5, Duration::from_secs(5), |_| {
        run(
            &ws,
            "git",
            &["clone", "-b", &branch, REPO_SUSFS, &pstr(&dir)],
        )
    })?;

    let commit = match &ctx.opts.susfs_commit {
        Some(sha) => sha.clone(),
        None => ls_remote(REPO_SUSFS, &format!("refs/heads/{branch}"))?,
    };
    run(&dir, "git", &["checkout", &commit])?;
    ctx.susfs_sha = capture(&dir, "git", &["rev-parse", "HEAD"])?;
    if ctx.susfs_sha != commit {
        bail!(
            "SUSFS commit mismatch: expected {commit}, got {}",
            ctx.susfs_sha
        );
    }
    ctx.log(format!("SUSFS commit {commit} on {branch}"));

    // pershoot's SUSFS↔KernelSU coexistence patches, applied to the SUSFS tree.
    for name in [
        "0001-pershoot-Allow-core-to-be-built-with-no-features.patch",
        "0002-pershoot-Implement-SuSFS-and-Toolkit-coexistence.patch",
    ] {
        let patch = ctx.kernel_patches().join("pershoot/susfs4ksu").join(name);
        if patch.exists() {
            patch_file(&dir, &patch, &[])?;
        } else if ctx.opts.strict_patches {
            bail!("missing required SUSFS patch {}", pstr(&patch));
        } else {
            ctx.note(format!(
                "warning: {} not present in kernel_patches; skipping",
                pstr(&patch)
            ));
        }
    }

    set_kernel_config(ctx, CFG_SUSFS)?;
    set_kernel_config(ctx, CFG_SUSFS_OPEN_REDIRECT)?;

    // susfs-patches: copy the source files and the per-family integration patch.
    let common = ctx.common_dir();
    copy_files(&dir.join("kernel_patches/fs"), &common.join("fs"))?;
    copy_files(
        &dir.join("kernel_patches/include/linux"),
        &common.join("include/linux"),
    )?;
    let integration_name = format!("50_add_susfs_in_gki-{}.patch", ctx.family.id());
    fs::copy(
        dir.join("kernel_patches").join(&integration_name),
        common.join(&integration_name),
    )
    .with_context(|| format!("cannot stage {integration_name}"))?;

    apply_susfs_fake_patches(ctx)?;
    patch_file(&common, &common.join(&integration_name), &[])?;
    revert_susfs_fake_patches(ctx)?;
    Ok(())
}

/// The `fs/notify/fdinfo.c` shim shared by 5.10/5.15 families.
fn fdinfo_shim(content: &str) -> Result<String> {
    // Drop the comment block that follows `if (inode) {`.
    let mut out = regex_replace(
        content,
        r"(?s)(if \(inode\) \{\n)\t\t/\*\n(?:\t\t \*[^\n]*\n)+\t\t \*/\n",
        |caps| Some(caps[1].to_string()),
    )?;
    // Drop the now-unused `mask` local.
    out = regex_replace_all(
        &out,
        r"(?m)^[ \t]*u32 mask = mark->mask & IN_ALL_EVENTS;\n",
        "",
    )?;
    out = regex_replace_all(
        &out,
        r"\bmask,\s*mark->ignored_mask",
        "inotify_mark_user_mask(mark)",
    )?;
    out = regex_replace_all(&out, "ignored_mask:%x", "ignored_mask:0")?;
    // Provide the replacement helper.
    let helper = "static inline u32 inotify_mark_user_mask(struct fsnotify_mark *mark)\n{\n\treturn mark->mask & IN_ALL_EVENTS;\n}\n\n";
    insert_before_regex_once(
        &out,
        r"(?m)^static void inotify_fdinfo\(struct seq_file \*m, struct fsnotify_mark \*mark\)$",
        helper,
    )
}

/// Pre-patch mutations that let the SUSFS series apply to older trees.
fn apply_susfs_fake_patches(ctx: &Ctx) -> Result<()> {
    let family = ctx.family;
    let sublevel = ctx.sublevel.as_str();

    if family == Family::Android12_5_10 && sublevel_le(sublevel, 43) {
        // `int this_len = min_t(int, ...)` -> `size_t this_len = min_t(size_t, ...)`.
        let path = ctx.common_dir().join("fs/proc/base.c");
        let content = read(&path)?;
        let out = regex_replace(
            &content,
            r"(int|size_t)\s+this_len\s*=\s*min_t\s*\(\s*(int|size_t)\s*,",
            |caps| {
                if caps[1] == caps[2] {
                    Some("size_t this_len = min_t(size_t,".to_string())
                } else {
                    None
                }
            },
        )?;
        write(&path, &out)?;
        ctx.log("susfs fake patch: a12-5.10 base.c");
    }

    if (family == Family::Android12_5_10 && sublevel_le(sublevel, 117))
        || (family == Family::Android13_5_10 && sublevel_le(sublevel, 107))
    {
        let path = ctx.common_dir().join("fs/notify/fdinfo.c");
        write(&path, &fdinfo_shim(&read(&path)?)?)?;
        ctx.log("susfs fake patch: 5.10 fdinfo.c");
    }

    if family == Family::Android13_5_15 {
        if sublevel_le(sublevel, 41) {
            edit_common(ctx, "fs/namespace.c", |content| {
                sed_insert_after(
                    content,
                    "#include <linux/shmem_fs.h>",
                    "#include <linux/mnt_idmapping.h>",
                )
            })?;
            edit_common(ctx, "fs/open.c", |content| {
                sed_insert_after(
                    content,
                    "#include <linux/compat.h>",
                    "#include <linux/mnt_idmapping.h>",
                )
            })?;
            let path = ctx.common_dir().join("fs/notify/fdinfo.c");
            write(&path, &fdinfo_shim(&read(&path)?)?)?;
            ctx.log("susfs fake patch: a13-5.15 namespace/open/fdinfo");
        }
        if sublevel_ge(sublevel, 197) {
            edit_common(ctx, "fs/namespace.c", |content| {
                sed_delete_exact(content, "#include <trace/hooks/blk.h>")
            })?;
            edit_common(ctx, "fs/proc/task_mmu.c", |content| {
                sed_delete_exact(content, "#include <trace/hooks/mm.h>")
            })?;
            ctx.log("susfs fake patch: a13-5.15 trace hook includes");
        }
    }

    if family == Family::Android14_6_1 {
        if sublevel_le(sublevel, 25) {
            edit_common(ctx, "fs/proc/base.c", |content| {
                sed_insert_after(
                    content,
                    "#include <trace/events/oom.h>",
                    "#include <trace/hooks/sched.h>",
                )
            })?;
        }
        if sublevel_le(sublevel, 141) {
            edit_common(ctx, "fs/proc/base.c", |content| {
                sed_insert_after(
                    content,
                    "#include <linux/cpufreq_times.h>",
                    "#include <linux/dma-buf.h>",
                )
            })?;
        }
        if sublevel_ge(sublevel, 157) {
            edit_common(ctx, "fs/namespace.c", |content| {
                sed_delete_exact(content, "#include <trace/hooks/blk.h>")
            })?;
        }
        ctx.log("susfs fake patch: a14-6.1 includes");
    }

    if family == Family::Android15_6_6 {
        if sublevel_le(sublevel, 30) {
            let path = ctx.common_dir().join("fs/proc/task_mmu.c");
            let content = read(&path)?;
            let out = regex_sub_once(
                &content,
                r"(\t+\t\tif\s*\(\s*vma->vm_end\s*>\s*last_vma_end\s*\))\n(\t+\t\t\tsmap_gather_stats\(vma,\s*&mss,\s*last_vma_end\);)\n(\t+)\}",
                |caps| {
                    let mut s = String::new();
                    s.push_str(&caps[1]);
                    s.push_str(" {\n");
                    s.push_str(&caps[2]);
                    s.push('\n');
                    s.push_str(&caps[3]);
                    s.push_str("\t\tlast_vma_end = vma->vm_end;\n");
                    s.push_str(&caps[3]);
                    s.push_str("\t}\n");
                    s.push_str(&caps[3]);
                    s.push('}');
                    s
                },
            )?;
            write(&path, &out)?;
        }
        if sublevel_le(sublevel, 30) && ctx.os_patch_level == "2024-07" {
            edit_common(ctx, "fs/proc/task_mmu.c", |content| {
                if content.contains("__fold_filemap_fixup_entry") {
                    return content.to_string();
                }
                sed_insert_before(
                    content,
                    "#include <asm/elf.h>",
                    "#ifndef __fold_filemap_fixup_entry\nstatic inline void __fold_filemap_fixup_entry(struct vma_iterator *iter, unsigned long *end) { }\n#endif /* __fold_filemap_fixup_entry */",
                )
            })?;
        }
        if sublevel_le(sublevel, 92) {
            edit_common(ctx, "fs/proc/base.c", |content| {
                sed_insert_after(
                    content,
                    "#include <linux/cpufreq_times.h>",
                    "#include <linux/dma-buf.h>",
                )
            })?;
        }
        if sublevel_le(sublevel, 57) {
            edit_common(ctx, "mm/memory.c", |content| {
                sed_insert_after(
                    content,
                    "#include <linux/sched/sysctl.h>",
                    "#include <linux/zswap.h>",
                )
            })?;
        }
        ctx.log("susfs fake patch: a15-6.6 includes");
    }

    if family == Family::Android16_6_12 {
        if sublevel_ge(sublevel, 58) {
            edit_common(ctx, "fs/exec.c", |content| {
                sed_delete_exact(content, "#include <linux/dma-buf.h>")
            })?;
        }
        if sublevel_ge(sublevel, 69) {
            edit_common(ctx, "fs/proc/task_mmu.c", |content| {
                content.replace("vma_data_pages", "vma_pages")
            })?;
        }
        ctx.log("susfs fake patch: a16-6.12 dma-buf / vma_pages");
    }
    Ok(())
}

/// Restore the tree after the integration patch has been applied.
fn revert_susfs_fake_patches(ctx: &Ctx) -> Result<()> {
    let family = ctx.family;
    let sublevel = ctx.sublevel.as_str();

    if family == Family::Android12_5_10 && sublevel_le(sublevel, 43) {
        edit_common(ctx, "fs/proc/base.c", |content| {
            content.replace(
                "size_t this_len = min_t(size_t, count, PAGE_SIZE);",
                "int this_len = min_t(int, count, PAGE_SIZE);",
            )
        })?;
    }

    if family == Family::Android13_5_15 {
        if sublevel_le(sublevel, 41) {
            edit_common(ctx, "fs/namespace.c", |content| {
                sed_delete_exact(content, "#include <linux/mnt_idmapping.h>")
            })?;
            edit_common(ctx, "fs/open.c", |content| {
                sed_delete_exact(content, "#include <linux/mnt_idmapping.h>")
            })?;
            edit_common(ctx, "fs/susfs.c", |content| {
                let out = content.replace(
                    "i_uid_into_mnt(i_user_ns(&fi->inode), &fi->inode).val",
                    "i_uid_into_mnt(&init_user_ns, &fi->inode).val",
                );
                out.replace(
                    "i_uid_into_mnt(i_user_ns(inode), inode).val",
                    "i_uid_into_mnt(&init_user_ns, inode).val",
                )
            })?;
        }
        if sublevel_ge(sublevel, 197) {
            edit_common(ctx, "fs/namespace.c", |content| {
                sed_insert_after(
                    content,
                    "#include \"internal.h\"",
                    "#include <trace/hooks/blk.h>",
                )
            })?;
        }
        if sublevel_ge(sublevel, 206) {
            edit_common(ctx, "fs/proc/task_mmu.c", |content| {
                sed_insert_after(
                    content,
                    "#include <linux/pkeys.h>",
                    "#include <trace/hooks/mm.h>",
                )
            })?;
        }
    }

    if family == Family::Android14_6_1 {
        if sublevel_le(sublevel, 25) {
            edit_common(ctx, "fs/proc/base.c", |content| {
                sed_delete_exact(content, "#include <trace/hooks/sched.h>")
            })?;
        }
        if sublevel_le(sublevel, 141) {
            edit_common(ctx, "fs/proc/base.c", |content| {
                sed_delete_exact(content, "#include <linux/dma-buf.h>")
            })?;
        }
        if sublevel_ge(sublevel, 157) {
            edit_common(ctx, "fs/namespace.c", |content| {
                sed_insert_after(
                    content,
                    "#include \"internal.h\"",
                    "#include <trace/hooks/blk.h>",
                )
            })?;
        }
    }

    if family == Family::Android15_6_6 {
        if sublevel_le(sublevel, 92) {
            edit_common(ctx, "fs/proc/base.c", |content| {
                sed_delete_exact(content, "#include <linux/dma-buf.h>")
            })?;
        }
        if sublevel_le(sublevel, 57) {
            edit_common(ctx, "mm/memory.c", |content| {
                sed_delete_exact(content, "#include <linux/zswap.h>")
            })?;
        }
    }

    if family == Family::Android16_6_12 {
        if sublevel_ge(sublevel, 58) {
            // NOTE: the shell action's `sed '/^#include /a ...'` appends the
            // include after *every* `#include` line. The intent — restore the
            // single include dropped above — is implemented here.
            edit_common(ctx, "fs/exec.c", |content| {
                if content.contains("#include <linux/dma-buf.h>") {
                    return content.to_string();
                }
                match content.find("#include ") {
                    Some(idx) => {
                        let end = content[idx..]
                            .find('\n')
                            .map(|offset| idx + offset + 1)
                            .unwrap_or(content.len());
                        let mut out = content[..end].to_string();
                        out.push_str("#include <linux/dma-buf.h>\n");
                        out.push_str(&content[end..]);
                        out
                    }
                    None => content.to_string(),
                }
            })?;
        }
        if sublevel_ge(sublevel, 69) {
            edit_common(ctx, "fs/proc/task_mmu.c", |content| {
                content.replace("vma_pages", "vma_data_pages")
            })?;
        }
    }

    // `Apply show_pad Fix` — return early instead of jumping to the padded path
    // on trees that predate the page-size-migration feature.
    let show_pad_fix = (family == Family::Android12_5_10 && sublevel_le(sublevel, 209))
        || (family == Family::Android13_5_10
            && sublevel_le(sublevel, 209)
            && ctx.os_patch_level != "2024-05")
        || (family == Family::Android13_5_15
            && sublevel_le(sublevel, 148)
            && ctx.os_patch_level != "2024-05")
        || (family == Family::Android14_5_15
            && sublevel_le(sublevel, 148)
            && ctx.os_patch_level != "2024-05")
        || (family == Family::Android14_6_1
            && sublevel_le(sublevel, 75)
            && ctx.os_patch_level != "2024-05");
    if show_pad_fix {
        edit_common(ctx, "fs/proc/task_mmu.c", |content| {
            content.replace("goto show_pad;", "return 0;")
        })?;
        ctx.log("susfs show_pad fix: applied");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// selinux_hide.c pointer-bool-conversion fix (inline in build.yml)
// ---------------------------------------------------------------------------

/// Normalises `selinux_hide.c` for the 6.6+ toolchain, matching the inline
/// `Fix selinux_hide pointer-bool-conversion` step in `build.yml`.
fn fix_selinux_hide(ctx: &mut Ctx) -> Result<()> {
    if !version_ge(ctx.family.kernel(), "6.6") {
        ctx.log("selinux_hide fix: skipped (< 6.6)");
        return Ok(());
    }
    let mut patched = Vec::new();
    for path in find_files_named(&ctx.opts.workspace, "selinux_hide.c")? {
        let mut content = read(&path)?;
        if content.contains("extern void security_dump_masked_av_fn") {
            // Function form: `&fn != NULL` silences both warnings.
            for (from, to) in [
                (
                    "if (security_dump_masked_av_fn)",
                    "if (&security_dump_masked_av_fn)",
                ),
                (
                    "if (security_dump_masked_av_fn != NULL)",
                    "if (&security_dump_masked_av_fn != NULL)",
                ),
                (
                    "if (context_struct_compute_av_fn)",
                    "if (&context_struct_compute_av_fn)",
                ),
                (
                    "if (context_struct_compute_av_fn != NULL)",
                    "if (&context_struct_compute_av_fn != NULL)",
                ),
            ] {
                content = content.replace(from, to);
            }
        } else if content.contains("if (security_dump_masked_av_fn") {
            for (from, to) in [
                (
                    "if (security_dump_masked_av_fn)",
                    "if (security_dump_masked_av_fn != NULL)",
                ),
                (
                    "if (context_struct_compute_av_fn)",
                    "if (context_struct_compute_av_fn != NULL)",
                ),
            ] {
                content = content.replace(from, to);
            }
        }
        // 6.6 declares the helpers `static`, but they are referenced externally
        // after the SUSFS hooks land — drop `static` so the link resolves.
        for name in [
            "int security_context_to_sid_with_policy",
            "int security_sid_to_context_with_policy",
            "void security_compute_av_user_with_policy",
        ] {
            content = content.replace(&format!("\nstatic {name}"), &format!("\n{name}"));
            if content.starts_with(&format!("static {name}")) {
                content = content.replacen(&format!("static {name}"), name, 1);
            }
        }
        write(&path, &content)?;
        patched.push(pstr(&path));
    }
    ctx.note(format!(
        "selinux_hide fix: patched {} file(s)",
        patched.len()
    ));
    Ok(())
}

/// Recursively collect files with the given name (small `find` replacement).
fn find_files_named(root: &Path, name: &str) -> Result<Vec<PathBuf>> {
    let mut found = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_dir() {
                stack.push(path);
            } else if path.file_name() == Some(OsStr::new(name)) {
                found.push(path);
            }
        }
    }
    Ok(found)
}

// ---------------------------------------------------------------------------
// droidspaces/action.yml  (the "LXC" feature)
// ---------------------------------------------------------------------------

/// Clone Droidspaces-OSS, apply its kABI patches and enable the container
/// options (PID/IPC/USER namespaces, SysV IPC, POSIX mqueue, misc binfmts).
fn setup_droidspaces(ctx: &mut Ctx) -> Result<()> {
    ctx.log("── LXC (Droidspaces-OSS)");
    let ws = ctx.opts.workspace.clone();
    let dir = ctx.droidspaces_dir();
    if dir.exists() {
        fs::remove_dir_all(&dir)?;
    }
    retry(5, Duration::from_secs(5), |_| {
        run(
            &ws,
            "git",
            &["clone", "--depth=1", REPO_DROIDSPACES, &pstr(&dir)],
        )
    })?;
    if let Some(pin) = &ctx.opts.droidspaces_commit {
        run(&dir, "git", &["fetch", "--depth=1", "origin", pin])?;
        run(&dir, "git", &["checkout", pin])?;
        let head = capture(&dir, "git", &["rev-parse", "HEAD"])?;
        if &head != pin {
            bail!("Droidspaces pin mismatch: expected {pin}, got {head}");
        }
    }
    ctx.droidspaces_sha = capture(&dir, "git", &["rev-parse", "HEAD"])?;

    let gki = dir.join("Documentation/resources/kernel-patches/GKI");
    let below = gki.join("below-kernel-6.12");
    let above_612 = gki.join("kernel-6.12/001.GKI-6.12-or-above-fix_sysvipc_kabi.patch");
    let below_678 = below.join("001.GKI-below-6.12-fix_sysvipc_kabi_6_7_8.patch");
    let below_mqueue =
        below.join("002.5.10_or_lower_use_android_abi_padding_for_posix_mqueue.patch");

    let common = ctx.common_dir();
    match ctx.family {
        Family::Android16_6_12 => patch_file(&common, &above_612, &[])?,
        Family::Android15_6_6
        | Family::Android14_6_1
        | Family::Android14_5_15
        | Family::Android13_5_15 => patch_file(&common, &below_678, &[])?,
        Family::Android12_5_10 | Family::Android13_5_10 => {
            patch_file(&common, &below_678, &[])?;
            patch_file(&common, &below_mqueue, &[])?;
        }
    }

    // 6.12 only: export the IPC symbols the runtime module links against.
    if ctx.family == Family::Android16_6_12 {
        edit_common(ctx, "ipc/namespace.c", |content| {
            append_line(&append_line(content, ""), "EXPORT_SYMBOL_GPL(put_ipc_ns);")
        })?;
        edit_common(ctx, "ipc/msgutil.c", |content| {
            append_line(&append_line(content, ""), "EXPORT_SYMBOL_GPL(init_ipc_ns);")
        })?;
    }

    set_kernel_config(ctx, CFG_DROIDSPACES)
}

// ---------------------------------------------------------------------------
// ptrace/action.yml + unicode-fix/action.yml + misc/action.yml
// ---------------------------------------------------------------------------

/// `gki_ptrace.patch` for kernels older than 5.16.
fn apply_ptrace_patch(ctx: &mut Ctx) -> Result<()> {
    if ctx.family.is_older_than((5, 16)) {
        let patch = ctx.kernel_patches().join("gki_ptrace.patch");
        patch_file(&ctx.common_dir(), &patch, &["-F", "3"])?;
        ctx.note("ptrace leak fix: applied");
    }
    Ok(())
}

/// Unicode path-traversal fix (split at 6.1, like the action).
fn apply_unicode_fix(ctx: &mut Ctx) -> Result<()> {
    let name = if ctx.family.is_older_than((5, 16)) {
        "common/unicode_bypass_fix_6.1-.patch"
    } else {
        "common/unicode_bypass_fix_6.1+.patch"
    };
    let patch = ctx.kernel_patches().join(name);
    patch_file(&ctx.common_dir(), &patch, &["--forward"])?;
    ctx.note(format!("unicode fix: applied ({name})"));
    Ok(())
}

/// `misc/action.yml` — unconditional misc options.
fn apply_misc_configs(ctx: &Ctx) -> Result<()> {
    set_kernel_config(ctx, CFG_MISC)
}

// ---------------------------------------------------------------------------
// apply-device-patches/action.yml
// ---------------------------------------------------------------------------

/// Samsung/Xiaomi WiFi+Bluetooth fixes, applied to android15-6.6 only.
fn apply_device_patches(ctx: &mut Ctx) -> Result<()> {
    if ctx.family != Family::Android15_6_6 {
        return Ok(());
    }
    ctx.log("── device-specific patches (Samsung/Xiaomi, android15-6.6)");
    apply_samsung_min_kdp(ctx)?;

    // Xiaomi: one extra symbol in the device symbol list.
    let symbol_list = ctx.common_dir().join("android/abi_gki_aarch64_xiaomi");
    let content = read(&symbol_list)?;
    write(
        &symbol_list,
        &append_line(&content, "device_find_any_child"),
    )?;
    ctx.note("xiaomi symbol list: device_find_any_child");
    Ok(())
}

fn apply_samsung_min_kdp(ctx: &mut Ctx) -> Result<()> {
    let common = ctx.common_dir();
    let patch = ctx
        .kernel_patches()
        .join("samsung/min_kdp/add-min_kdp-symbols.patch");
    let min_kdp = ctx.kernel_patches().join("samsung/min_kdp/min_kdp.c");
    if !patch.is_file() {
        bail!("missing Samsung min_kdp patch: {}", pstr(&patch));
    }
    if !min_kdp.is_file() {
        bail!("missing Samsung min_kdp source: {}", pstr(&min_kdp));
    }

    let symbol_list = "android/abi_gki_aarch64_galaxy";
    let mut paths: BTreeSet<String> = patch_target_paths(&patch)?;
    for extra in [symbol_list, "drivers/min_kdp.c", "drivers/Makefile"] {
        paths.insert(extra.to_string());
    }
    for path in &paths {
        if path == "/dev/null"
            || path.starts_with('/')
            || path == ".."
            || path.starts_with("../")
            || path.contains("/../")
        {
            bail!("unsafe Samsung patch path: {path}");
        }
    }

    // Transactional apply: snapshot every touched path first so a failed
    // `patch` run cannot leave the tree half-modified.
    let tx = ctx.opts.workspace.join(".samsung-tx");
    if tx.exists() {
        fs::remove_dir_all(&tx)?;
    }
    fs::create_dir_all(&tx)?;
    let mut snapshot: Vec<(String, bool)> = Vec::new();
    for path in &paths {
        let target = common.join(path);
        let exists = target.exists();
        snapshot.push((path.clone(), exists));
        if exists {
            let dst = tx.join(path);
            fs::create_dir_all(dst.parent().expect("parent"))?;
            fs::copy(&target, &dst)?;
        }
    }

    let apply = (|| -> Result<()> {
        if patch_can_apply(&common, &patch) {
            patch_file(&common, &patch, &["--no-backup-if-mismatch"])
        } else {
            ctx.log("min_kdp patch drifted; using idempotent .stg insert fallback");
            let stg = common.join("android/abi_gki_aarch64.stg");
            write(&stg, &stg_insert(&read(&stg)?))
        }
    })();

    if let Err(err) = apply {
        for (path, existed) in &snapshot {
            let target = common.join(path);
            if *existed {
                fs::copy(tx.join(path), &target).ok();
            } else if target.exists() {
                fs::remove_file(&target).ok();
            }
        }
        fs::remove_dir_all(&tx).ok();
        return Err(err.context("Samsung min_kdp patch failed; tree restored"));
    }
    fs::remove_dir_all(&tx).ok();

    let list_path = common.join(symbol_list);
    let mut content = read(&list_path)?;
    for symbol in [
        "kdp_set_cred_non_rcu",
        "kdp_usecount_dec_and_test",
        "kdp_usecount_inc",
    ] {
        content = append_line(&content, symbol);
    }
    write(&list_path, &content)?;

    fs::copy(&min_kdp, common.join("drivers/min_kdp.c"))?;
    let drivers_makefile = common.join("drivers/Makefile");
    let makefile = read(&drivers_makefile)?;
    if !makefile.lines().any(|line| line == "obj-y += min_kdp.o") {
        write(
            &drivers_makefile,
            &append_line(&makefile, "obj-y += min_kdp.o"),
        )?;
    }
    ctx.note("samsung min_kdp integration: applied");
    Ok(())
}

/// Extract the target paths from a unified diff's `---`/`+++` headers.
fn patch_target_paths(patch: &Path) -> Result<BTreeSet<String>> {
    let content = read(patch)?;
    let mut paths = BTreeSet::new();
    for line in content.lines() {
        let rest = if let Some(rest) = line.strip_prefix("--- ") {
            rest
        } else if let Some(rest) = line.strip_prefix("+++ ") {
            rest
        } else {
            continue;
        };
        let path = rest.split_whitespace().next().unwrap_or("");
        let path = path
            .strip_prefix("a/")
            .or_else(|| path.strip_prefix("b/"))
            .unwrap_or(path);
        if !path.is_empty() {
            paths.insert(path.to_string());
        }
    }
    Ok(paths)
}

/// Port of the `.stg` fallback embedded in `apply-device-patches/action.yml`.
fn stg_insert(src: &str) -> String {
    let mut out = src.to_string();
    let ensure_before = |anchor: &str, block: &str, label: &str, out: &mut String| {
        if out.contains(label) {
            println!("already present: {label}");
            return;
        }
        if let Some(idx) = out.find(anchor) {
            out.insert_str(idx, block);
            println!("inserted {label} at anchor");
        } else {
            if !out.ends_with('\n') {
                out.push('\n');
            }
            out.push_str(block);
            println!("inserted {label} at EOF (anchor missing)");
        }
    };

    let func1 = "function {\n  id: 0x1e5195df\n  return_type_id: 0x48b5725f\n  parameter_id: 0x3d551c03\n  parameter_id: 0x6720d32f\n}\n";
    let func2 = "function {\n  id: 0xc18e39fb\n  return_type_id: 0x4585663f\n  parameter_id: 0x3d551c03\n}\n";
    let elf1 = "elf_symbol {\n  id: 0xb0801f6e\n  name: \"kdp_set_cred_non_rcu\"\n  is_defined: true\n  symbol_type: FUNCTION\n  crc: 0x738bae5e\n  type_id: 0x1e5195df\n  full_name: \"kdp_set_cred_non_rcu\"\n}\n";
    let elf2 = "elf_symbol {\n  id: 0x3037c5bc\n  name: \"kdp_usecount_dec_and_test\"\n  is_defined: true\n  symbol_type: FUNCTION\n  crc: 0xda582aa5\n  type_id: 0xc18e39fb\n  full_name: \"kdp_usecount_dec_and_test\"\n}\n";
    let elf3 = "elf_symbol {\n  id: 0x8334a496\n  name: \"kdp_usecount_inc\"\n  is_defined: true\n  symbol_type: FUNCTION\n  crc: 0xfb342499\n  type_id: 0x1fcd1693\n  full_name: \"kdp_usecount_inc\"\n}\n";

    ensure_before(
        "function {\n  id: 0x1e571002",
        func1,
        "id: 0x1e5195df",
        &mut out,
    );
    ensure_before(
        "function {\n  id: 0xc18f1240",
        func2,
        "id: 0xc18e39fb",
        &mut out,
    );
    let elf_anchor = "elf_symbol {\n  id: 0x493ce9fc\n  name: \"loops_per_jiffy\"";
    for (block, label) in [
        (elf1, "\"kdp_set_cred_non_rcu\""),
        (elf2, "\"kdp_usecount_dec_and_test\""),
        (elf3, "\"kdp_usecount_inc\""),
    ] {
        ensure_before(elf_anchor, block, label, &mut out);
    }

    let iface_ids = ["0xb0801f6e", "0x3037c5bc", "0x8334a496"];
    let missing: Vec<&str> = iface_ids
        .iter()
        .copied()
        .filter(|id| !out.contains(&format!("symbol_id: {id}")))
        .collect();
    if missing.is_empty() {
        println!("interface ids already present");
    } else {
        let anchor = "  symbol_id: 0xc750a072\n";
        if let Some(idx) = out.find(anchor) {
            let insert_at = idx + anchor.len();
            let block: String = missing
                .iter()
                .map(|id| format!("  symbol_id: {id}\n"))
                .collect();
            out.insert_str(insert_at, &block);
        } else if let Some(idx) = out.find("interface {") {
            let end = out[idx..]
                .find("\n}\n")
                .map(|off| idx + off)
                .unwrap_or(out.len());
            let block: String = missing
                .iter()
                .map(|id| format!("  symbol_id: {id}\n"))
                .collect();
            out.insert_str(end, block.trim_end_matches('\n'));
        }
    }
    out
}

// ---------------------------------------------------------------------------
// apply-kernel-branding/action.yml
// ---------------------------------------------------------------------------

/// Rewrite the tail of `scripts/setlocalversion` with the branded suffix.
fn apply_kernel_branding(ctx: &Ctx) -> Result<()> {
    let path = ctx.common_dir().join("scripts/setlocalversion");
    let content = read(&path)?;
    let line = if matches!(ctx.family, Family::Android15_6_6 | Family::Android16_6_12) {
        format!(
            "echo \"{}.{}-{}-{}\"",
            ctx.family.kernel(),
            ctx.sublevel,
            ctx.family.android(),
            ctx.opts.brand_name
        )
    } else {
        format!("echo \"-{}-{}\"", ctx.family.android(), ctx.opts.brand_name)
    };
    write(&path, &replace_last_line(&content, &line))?;
    chmod_exec(&path)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// remove-protected-exports/action.yml + clean-kernel-flags/action.yml
// ---------------------------------------------------------------------------

/// Bazel-only: drop the GKI ABI protected export/module lists.
fn remove_protected_exports(ctx: &mut Ctx) -> Result<()> {
    if !ctx.uses_bazel() {
        ctx.log("remove protected exports: legacy build system, nothing to do");
        return Ok(());
    }
    let common = ctx.common_dir();
    let android_dir = common.join("android");
    if android_dir.is_dir() {
        for entry in fs::read_dir(&android_dir)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with("abi_gki_protected_exports_") {
                if entry.file_type()?.is_dir() {
                    fs::remove_dir_all(entry.path())?;
                } else {
                    fs::remove_file(entry.path())?;
                }
            }
        }
    }
    if let Ok(entries) = fs::read_dir(&android_dir) {
        for entry in entries.flatten() {
            if entry
                .file_name()
                .to_string_lossy()
                .starts_with("abi_gki_protected_exports_")
            {
                bail!("abi_gki_protected_exports_* still exists after removal");
            }
        }
    }

    let build_bazel = common.join("BUILD.bazel");
    let bazel = read(&build_bazel)?;
    let (bazel_out, notes) = strip_protected_lists(&bazel)?;
    write(&build_bazel, &bazel_out)?;
    for note in notes {
        ctx.note(note);
    }

    let modules_bzl = common.join("modules.bzl");
    if modules_bzl.is_file() {
        let content = read(&modules_bzl)?;
        let re = Regex::new(r"(?m)^protected_modules = \[.*\]")?;
        if re.is_match(&content) {
            let out = re
                .replace_all(&content, "protected_modules = []")
                .into_owned();
            if out == content {
                bail!("common/modules.bzl was not modified");
            }
            if !out.contains("protected_modules = []") {
                bail!("protected_modules was not set to [] in common/modules.bzl");
            }
            write(&modules_bzl, &out)?;
        }
    }
    ctx.note("protected exports/modules removed (bazel)");
    Ok(())
}

/// Drop the ABI protected-export and protected-module references from
/// `common/BUILD.bazel`.
///
/// Mirrors `remove-protected-exports/action.yml`, with one deliberate
/// extension: `android14-5.15` and `android14-6.1` declare
/// `"protected_exports_list"` for **both** aarch64 and x86_64 while the action's
/// `rm -rf common/android/abi_gki_protected_exports_*` deletes both files, so
/// every reference to a deleted list is removed here instead of leaving a
/// dangling bazel label behind.
fn strip_protected_lists(bazel: &str) -> Result<(String, Vec<String>)> {
    let mut notes = Vec::new();
    let mut out = bazel.to_string();

    let any_exports = Regex::new(
        r#"(?m)^[ \t]*"protected_exports_list"[ \t]*:[ \t]*"android/abi_gki_protected_exports_[A-Za-z0-9_]+",[ \t]*\n?"#,
    )?;
    let aarch64_exports = Regex::new(
        r#""protected_exports_list"[ \t]*:[ \t]*"android/abi_gki_protected_exports_aarch64""#,
    )?;

    if aarch64_exports.is_match(&out) {
        let before = out.clone();
        out = any_exports.replace_all(&out, "").into_owned();
        if out == before {
            bail!("common/BUILD.bazel was not modified for protected_exports_list");
        }
        if aarch64_exports.is_match(&out) {
            bail!("protected_exports_list reference still present in common/BUILD.bazel");
        }
        notes.push("protected_exports_list entries removed (bazel)".to_string());
    } else {
        // No aarch64 entry: still clean up references to lists we deleted.
        out = any_exports.replace_all(&out, "").into_owned();
    }
    if out.contains("\"protected_exports_list\"") {
        notes.push(
            "warning: common/BUILD.bazel still references a protected exports list".to_string(),
        );
    }

    // 6.12+ spells the protected module list differently from `modules.bzl`.
    if out.contains("protected_module_names_list") {
        let specific = Regex::new(
            r#"(?m)^[ \t]*protected_module_names_list[ \t]*=[ \t]*":gki_(?:aarch64|x86_64)_protected_module_names",[ \t]*\n?"#,
        )?;
        let before = out.clone();
        out = specific.replace_all(&out, "").into_owned();
        if out == before {
            notes.push(
                "warning: protected_module_names_list not matched in common/BUILD.bazel"
                    .to_string(),
            );
        } else {
            notes.push("protected_module_names_list entries removed (bazel)".to_string());
        }
        // Best effort: take out any other assignment of the same name so no
        // reference to a removed target survives.
        if out.contains("protected_module_names_list") {
            let any = Regex::new(r#"(?m)^[ \t]*protected_module_names_list[ \t]*=[^\n]*\n?"#)?;
            out = any.replace_all(&out, "").into_owned();
        }
        if out.contains("protected_module_names_list") {
            notes.push(
                "warning: common/BUILD.bazel still references protected_module_names_list"
                    .to_string(),
            );
        }
    }
    Ok((out, notes))
}

/// Strip `-dirty` from the version stamp and commit the patched tree.
fn clean_kernel_flags(ctx: &Ctx) -> Result<()> {
    let kernel = ctx.kernel_dir();
    if !ctx.uses_bazel() {
        let setlocalversion = kernel.join("common/scripts/setlocalversion");
        let content = read(&setlocalversion)?;
        write(&setlocalversion, &content.replace("-dirty", ""))?;
    } else {
        // `sed -i "/stable_scmversion_cmd/s/-maybe-dirty//g"`.
        let stamp = kernel.join("build/kernel/kleaf/impl/stamp.bzl");
        if stamp.is_file() {
            let content = read(&stamp)?;
            let out: String = content
                .split_inclusive('\n')
                .map(|line| {
                    if line.contains("stable_scmversion_cmd") {
                        line.replace("-maybe-dirty", "")
                    } else {
                        line.to_string()
                    }
                })
                .collect();
            write(&stamp, &out)?;
        }
        let setlocalversion = kernel.join("common/scripts/setlocalversion");
        if setlocalversion.is_file() {
            let content = read(&setlocalversion)?;
            write(&setlocalversion, &content.replace("-dirty", ""))?;
        }
    }

    let common = ctx.common_dir();
    if !common.join(".git").exists() {
        ctx.log("warning: kernel/common is not a git checkout; skipping the dirty-flag commit");
        return Ok(());
    }
    run(common.as_path(), "git", &["add", "."])?;
    let staged = capture(
        common.as_path(),
        "git",
        &["diff", "--cached", "--name-only"],
    )?;
    if staged.trim().is_empty() {
        ctx.log("clean kernel flags: nothing to commit");
        return Ok(());
    }
    run_with_env(
        common.as_path(),
        "git",
        &["commit", "-m", "Wild: Clean Dirty Flag"],
        &[
            ("GIT_AUTHOR_NAME", "github-actions[bot]".to_string()),
            (
                "GIT_AUTHOR_EMAIL",
                "github-actions[bot]@users.noreply.github.com".to_string(),
            ),
            ("GIT_COMMITTER_NAME", "github-actions[bot]".to_string()),
            (
                "GIT_COMMITTER_EMAIL",
                "github-actions[bot]@users.noreply.github.com".to_string(),
            ),
        ],
    )
}

// ---------------------------------------------------------------------------
// bypass-kernel/action.yml
// ---------------------------------------------------------------------------

/// Flip `bad_version:`'s `return 0;` to `return 1;` (opt-in only).
fn apply_bypass_hack(ctx: &Ctx) -> Result<()> {
    let target = if matches!(
        ctx.family,
        Family::Android14_6_1 | Family::Android15_6_6 | Family::Android16_6_12
    ) {
        ctx.common_dir().join("kernel/module/version.c")
    } else {
        ctx.common_dir().join("kernel/module.c")
    };
    let content = read(&target)?;
    let lines: Vec<&str> = content.split_inclusive('\n').collect();
    let start = lines
        .iter()
        .position(|line| line.contains("bad_version:"))
        .ok_or_else(|| anyhow::anyhow!("`bad_version:` not found in {}", pstr(&target)))?;
    let mut out = lines[..=start].concat();
    let mut patched = false;
    for (index, line) in lines.iter().enumerate().skip(start + 1) {
        if !patched && line.contains("return 0;") {
            out.push_str(&line.replacen("return 0;", "return 1;", 1));
            patched = true;
        } else {
            out.push_str(line);
        }
        let _ = index;
    }
    if !patched {
        bail!("bypass hack: no `return 0;` found after `bad_version:`");
    }
    write(&target, &out)?;
    ctx.log("bypass hack applied");
    Ok(())
}

// ---------------------------------------------------------------------------
// build-kernel/action.yml (+ cache-setup for ccache/bazel)
// ---------------------------------------------------------------------------

impl Ctx {
    fn out_dir(&self) -> PathBuf {
        self.opts.workspace.join("out")
    }
}

/// Install/verify ccache for the legacy build path, mirroring `cache-ccache-setup`.
fn setup_ccache(ctx: &Ctx) -> Result<bool> {
    if which::which("ccache").is_ok() {
        return Ok(true);
    }
    ctx.log("installing ccache from kernel_patches");
    let ws = &ctx.opts.workspace;
    let staged = ws.join("ccache");
    if run(
        ws,
        "curl",
        &[
            "-LfsS",
            "--retry",
            "5",
            "--retry-delay",
            "5",
            "--retry-all-errors",
            "--connect-timeout",
            "30",
            "-H",
            "User-Agent: Mozilla/5.0",
            URL_CCACHE,
            "-o",
            &pstr(&staged),
        ],
    )
    .is_err()
    {
        return Ok(false);
    }
    chmod_exec(&staged)?;
    let target = Path::new("/usr/bin/ccache");
    let copied = run(ws, "sudo", &["cp", "-f", &pstr(&staged), "/usr/bin/ccache"])
        .and_then(|_| run(ws, "sudo", &["chmod", "+x", "/usr/bin/ccache"]));
    fs::remove_file(&staged).ok();
    if copied.is_err() {
        ctx.log("warning: could not install ccache; building without it");
        return Ok(false);
    }
    Ok(which::which("ccache").is_ok() || target.exists())
}

/// Environment from `cache-ccache-setup/action.yml`, with the cache directory
/// rooted in the workspace instead of `/home/runner/.ccache`.
fn ccache_env(ctx: &Ctx) -> Vec<(&'static str, String)> {
    let cache_dir = ctx.opts.workspace.join(".ccache");
    fs::create_dir_all(&cache_dir).ok();
    vec![
        ("CCACHE_DIR", pstr(&cache_dir)),
        ("CCACHE_MAXSIZE", "12G".to_string()),
        ("CCACHE_BASEDIR", pstr(&ctx.opts.workspace)),
        ("CCACHE_COMPILERCHECK", "content".to_string()),
        ("CCACHE_NOHASHDIR", "true".to_string()),
        ("CCACHE_IGNOREOPTIONS", "--sysroot*".to_string()),
        ("CCACHE_COMPRESS", "true".to_string()),
        ("CCACHE_COMPRESSLEVEL", "3".to_string()),
        ("CCACHE_DIRECT", "true".to_string()),
        ("CCACHE_FILE_CLONE", "true".to_string()),
        ("CCACHE_INODE_CACHE", "true".to_string()),
        ("CCACHE_IS_KERNEL_COMPILING", "true".to_string()),
        ("CCACHE_UMASK", "002".to_string()),
        ("CCACHE_DEPEND", "true".to_string()),
        ("CCACHE_SLOPPINESS", "file_macro,time_macros,include_file_mtime,include_file_ctime,pch_defines,system_headers,locale".to_string()),
    ]
}

/// Build `//common:kernel_aarch64/Image` with either `build/build.sh` or Kleaf.
fn build_kernel(ctx: &Ctx) -> Result<()> {
    let kernel = ctx.kernel_dir();
    let common = ctx.common_dir();
    ctx.log(format!(
        "── build kernel ({})",
        if ctx.uses_bazel() {
            "bazel/kleaf"
        } else {
            "build.sh"
        }
    ));

    // `Build Kernel` drops `check_defconfig` from the legacy config chain.
    for name in ["build.config.gki", "build.config.gki.aarch64"] {
        let path = common.join(name);
        if path.is_file() {
            let content = read(&path)?;
            if content.contains("check_defconfig") {
                write(&path, &content.replace("check_defconfig", ""))?;
            }
        }
    }

    let out_dir = ctx.out_dir();
    fs::create_dir_all(&out_dir)?;
    let mut env = vec![
        ("SOURCE_DATE_EPOCH", ctx.source_date_epoch.to_string()),
        ("KBUILD_BUILD_TIMESTAMP", ctx.kbuild_timestamp.clone()),
        ("GIT_AUTHOR_DATE", ctx.git_date.clone()),
        ("GIT_COMMITTER_DATE", ctx.git_date.clone()),
    ];

    if !ctx.uses_bazel() {
        let use_ccache = ctx.opts.use_cache && setup_ccache(ctx)?;
        env.extend([
            ("BUILD_GKI_ARTIFACTS", String::new()),
            ("BUILD_GKI_CERTIFICATION_TOOLS", "0".to_string()),
            ("BUILD_SYSTEM_DLKM", "0".to_string()),
            ("SKIP_VENDOR_BOOT", "1".to_string()),
            ("SKIP_EXT_MODULES", "1".to_string()),
            ("SKIP_CP_KERNEL_HDR", "1".to_string()),
            ("OUT_DIR", pstr(&out_dir)),
            ("LTO", "thin".to_string()),
            (
                "BUILD_CONFIG",
                "common/build.config.gki.aarch64".to_string(),
            ),
        ]);
        if use_ccache {
            env.extend(ccache_env(ctx));
            for key in ["CC", "CXX", "HOSTCC", "HOSTCXX"] {
                let value = if key.ends_with("CXX") {
                    "/usr/bin/ccache clang++"
                } else {
                    "/usr/bin/ccache clang"
                };
                env.push((key, value.to_string()));
            }
        }
        let jobs = ctx.opts.jobs().to_string();
        run_with_env(kernel.as_path(), "build/build.sh", &["-j", &jobs], &env)?;
    } else {
        fs::create_dir_all(&ctx.opts.bazel_cache)?;
        let build_bazel = common.join("BUILD.bazel");
        let content = read(&build_bazel)?;
        if !content.contains("check_defconfig = \"disabled\"") {
            let out = sed_insert_after(
                &content,
                "name = \"kernel_aarch64\",",
                "    check_defconfig = \"disabled\",",
            );
            write(&build_bazel, &out)?;
        }
        let disk_cache = format!("--disk_cache={}", pstr(&ctx.opts.bazel_cache));
        run_with_env(
            kernel.as_path(),
            "tools/bazel",
            &[
                "build",
                "--config=fast",
                &disk_cache,
                "//common:kernel_aarch64/Image",
            ],
            &env,
        )?;
    }
    Ok(())
}

/// `Gather Build Artifacts` — copy `Image` into the AnyKernel3 checkout.
fn gather_artifacts(ctx: &Ctx) -> Result<PathBuf> {
    let candidates = [
        ctx.kernel_dir()
            .join("bazel-bin/common/kernel_aarch64/Image"),
        ctx.out_dir().join("dist/Image"),
        ctx.out_dir().join("Image"),
    ];
    for candidate in candidates {
        if candidate.is_file() {
            let destination = ctx.any_kernel3().join("Image");
            fs::copy(&candidate, &destination)
                .with_context(|| format!("cannot copy {}", pstr(&candidate)))?;
            ctx.log(format!(
                "artifact: {} -> {}",
                pstr(&candidate),
                pstr(&destination)
            ));
            return Ok(destination);
        }
    }
    bail!(
        "no kernel Image produced (looked in {} and {})",
        pstr(
            &ctx.kernel_dir()
                .join("bazel-bin/common/kernel_aarch64/Image")
        ),
        pstr(&ctx.out_dir().join("dist/Image"))
    )
}

// ---------------------------------------------------------------------------
// scan-patch-rejects/action.yml
// ---------------------------------------------------------------------------

/// Collect `.rej` files into `patch-rejects/` (the CI equivalent uploads them).
fn scan_patch_rejects(ctx: &Ctx) -> Result<usize> {
    let kernel = ctx.kernel_dir();
    let rejects = ctx.rejects_dir();
    fs::create_dir_all(&rejects)?;
    let mut count = 0usize;
    for path in find_files_with_extension(&kernel, "rej")? {
        if path.file_name() == Some(OsStr::new("i2c-nomadik.c.rej")) {
            continue;
        }
        let relative = path.strip_prefix(&kernel).unwrap_or(&path);
        let destination = rejects.join(relative);
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::copy(&path, &destination)?;
        let original = path.with_extension("");
        if original.is_file() {
            fs::copy(&original, destination.with_extension(""))?;
        }
        let mut index = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(rejects.join("index.txt"))?;
        writeln!(index, "{}", relative.display())?;
        count += 1;
    }
    if count > 0 {
        ctx.log(format!("patch rejects collected: {count}"));
    }
    Ok(count)
}

fn find_files_with_extension(root: &Path, extension: &str) -> Result<Vec<PathBuf>> {
    let mut found = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_dir() {
                stack.push(path);
            } else if path.extension() == Some(OsStr::new(extension)) {
                found.push(path);
            }
        }
    }
    Ok(found)
}

// ---------------------------------------------------------------------------
// Consolidated Build Summary + metadata (from build.yml)
// ---------------------------------------------------------------------------

fn susfs_version(ctx: &Ctx) -> String {
    let header = ctx.common_dir().join("include/linux/susfs.h");
    let Ok(content) = fs::read_to_string(&header) else {
        return "N/A".to_string();
    };
    for line in content.lines() {
        if line.contains("#define SUSFS_VERSION")
            && let Some(start) = line.find('"')
            && let Some(end) = line[start + 1..].find('"')
        {
            return line[start + 1..start + 1 + end].to_string();
        }
    }
    "N/A".to_string()
}

/// Write the human-readable summary, the machine-readable metadata and a zip of
/// the AnyKernel3 payload into the output directory.
fn write_summary(ctx: &Ctx, image: &Path, rejects: usize) -> Result<()> {
    let output = &ctx.opts.output_dir;
    fs::create_dir_all(output)?;
    let version_string = capture(
        output,
        "sh",
        &[
            "-c",
            &format!(
                "strings {} | grep -m1 '^Linux version ' | sed 's/Linux version //' || true",
                pstr(image)
            ),
        ],
    )
    .unwrap_or_default();
    let susfs_ver = susfs_version(ctx);

    let mut summary = String::new();
    summary.push_str(&format!(
        "## {} {} ({}) - {} release\n\n",
        ctx.family.android(),
        ctx.family.kernel(),
        ctx.sublevel,
        ctx.opts.variant
    ));
    summary.push_str("| Metric | Value |\n|--------|-------|\n");
    summary.push_str("| **Status** | [+] Success |\n");
    summary.push_str(&format!(
        "| **Kernel** | {}.{}-{}-{} |\n",
        ctx.family.kernel(),
        ctx.sublevel,
        ctx.family.android(),
        ctx.os_patch_level
    ));
    if !version_string.is_empty() {
        summary.push_str(&format!("| **Version String** | `{version_string}` |\n"));
    }
    summary.push_str("| **Root Implementation** | KernelSU-Next |\n");
    summary.push_str(&format!("| **Root Commit** | {} |\n", ctx.root_sha));
    summary.push_str(&format!("| **Root Remote** | {} |\n", ctx.root_repo));
    summary.push_str(&format!("| **SUSFS Version** | {susfs_ver} |\n"));
    summary.push_str(&format!("| **SUSFS Commit** | {} |\n", ctx.susfs_sha));
    summary.push_str(&format!(
        "| **DroidSpaces (LXC) Commit** | {} |\n",
        ctx.droidspaces_sha
    ));
    summary.push_str(&format!(
        "| **Kernel Source Commit** | {} |\n",
        ctx.kernel_sha
    ));
    summary.push_str("| **Feature Set** | SUSFS+DS+KernelSU-Next |\n");
    summary.push_str(&format!("| **Patch Rejects** | {rejects} |\n"));
    summary.push_str(&format!(
        "| **SOURCE_DATE_EPOCH** | {} |\n",
        ctx.source_date_epoch
    ));
    summary.push_str(&format!("| **Image** | {} |\n", pstr(image)));
    if !ctx.notes.is_empty() {
        summary.push_str("\n### Applied Fixes\n\n");
        for note in &ctx.notes {
            summary.push_str(&format!("- {note}\n"));
        }
    }
    let summary_path = output.join(format!("build-summary-{}.md", ctx.file_name));
    write(&summary_path, &summary)?;

    let metadata = serde_json::json!({
        "method": "GKI source build with SHA-pinned KernelSU-Next, SUSFS and DroidSpaces (LXC)",
        "root": {
            "implementation": "KernelSU-Next",
            "manager": "KernelSU Next Manager",
            "commit": ctx.root_sha,
            "remote": ctx.root_repo,
        },
        "susfs": {
            "branch": ctx.family.susfs_branch(),
            "commit": ctx.susfs_sha,
            "version": susfs_ver,
        },
        "lxc": {
            "project": "Droidspaces-OSS",
            "commit": ctx.droidspaces_sha,
        },
        "kernel": {
            "family": ctx.family.id(),
            "android": ctx.family.android(),
            "kernel_version": ctx.family.kernel(),
            "sublevel": ctx.sublevel,
            "os_patch_level": ctx.os_patch_level,
            "variant": ctx.opts.variant,
            "source_commit": ctx.kernel_sha,
            "version_string": version_string,
        },
        "image": pstr(image),
        "patch_rejects": rejects,
        "source_date_epoch": ctx.source_date_epoch,
    });
    write(
        &output.join(format!("{}-metadata.json", ctx.file_name)),
        &serde_json::to_string_pretty(&metadata)?,
    )?;

    // Best-effort flashable package, mirroring the release packaging step.
    let zip_path = output.join(format!("{}-AnyKernel3.zip", ctx.file_name));
    let zip_result = run(&ctx.any_kernel3(), "zip", &["-qr", &pstr(&zip_path), "."]);
    if let Err(err) = zip_result {
        ctx.log(format!(
            "warning: could not create AnyKernel3 zip ({err:#})"
        ));
    }
    ctx.log(format!("summary: {}", pstr(&summary_path)));
    Ok(())
}

// ---------------------------------------------------------------------------
// Pipeline
// ---------------------------------------------------------------------------

impl Ctx {
    fn new(opts: Options, family: Family, sublevel_input: String, os_patch_level: String) -> Ctx {
        let provisional = format!("{}-{}", family.id(), os_patch_level);
        Ctx {
            opts,
            family,
            sublevel_input,
            os_patch_level,
            sublevel: SUBLEVEL_LTS.to_string(),
            file_name: provisional,
            source_date_epoch: 0,
            kbuild_timestamp: String::new(),
            git_date: String::new(),
            kernel_sha: "N/A".to_string(),
            root_sha: "N/A".to_string(),
            susfs_sha: "N/A".to_string(),
            root_repo: REPO_KSU_NEXT_SUSFS.to_string(),
            droidspaces_sha: "N/A".to_string(),
            notes: Vec::new(),
        }
    }
}

/// `build.yml`, in order, restricted to GKI + LXC + KernelSU-Next + SUSFS.
fn build_target(
    opts: &Options,
    family: Family,
    sublevel_input: String,
    os_patch_level: String,
) -> Result<()> {
    let mut ctx = Ctx::new(opts.clone(), family, sublevel_input, os_patch_level);
    say(&format!(
        "\n=== {} | patch level {} | variant {} ===",
        ctx.family.id(),
        ctx.os_patch_level,
        ctx.opts.variant
    ));

    setup_build_environment(&ctx)?;
    empty_dir(&ctx.kernel_dir())?;
    download_kernel(&mut ctx)?;
    set_build_timestamp(&mut ctx)?;
    extract_sublevel_and_file_name(&mut ctx)?;

    apply_kernel_fixes(&mut ctx)?;
    setup_root(&mut ctx)?;
    setup_susfs(&mut ctx)?;
    fix_selinux_hide(&mut ctx)?;
    setup_droidspaces(&mut ctx)?;
    apply_ptrace_patch(&mut ctx)?;
    apply_unicode_fix(&mut ctx)?;
    apply_misc_configs(&ctx)?;
    apply_device_patches(&mut ctx)?;
    if ctx.opts.bypass {
        apply_bypass_hack(&ctx)?;
    }
    apply_kernel_branding(&ctx)?;
    remove_protected_exports(&mut ctx)?;
    clean_kernel_flags(&ctx)?;

    let rejects = scan_patch_rejects(&ctx)?;
    build_kernel(&ctx)?;
    let image = gather_artifacts(&ctx)?;
    write_summary(&ctx, &image, rejects)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Config-driven targets (prepare.yml)
// ---------------------------------------------------------------------------

#[derive(Debug, serde::Deserialize)]
struct ConfigFile {
    version: String,
    include: Vec<ConfigEntry>,
}

#[derive(Debug, serde::Deserialize, Clone)]
struct ConfigEntry {
    sublevel: String,
    date: String,
    #[serde(default)]
    variant: Option<String>,
}

#[derive(Debug, Clone)]
struct Target {
    family: Family,
    sublevel: String,
    os_patch_level: String,
    variant: String,
}

/// Read a `.github/config/*.json` file and expand it the way `prepare.yml` does:
/// every entry yields a `Normal` target, plus one target per extra entry
/// variant — unless a specific variant was requested, in which case every entry
/// is labelled with it. The `os_patch_level` filter then narrows the result.
fn targets_from_config(
    config: &Path,
    filter: &str,
    requested_variant: &str,
) -> Result<Vec<Target>> {
    let content = fs::read_to_string(config)
        .with_context(|| format!("config file not found: {}", pstr(config)))?;
    let parsed: ConfigFile = serde_json::from_str(&content)
        .with_context(|| format!("invalid config {}", pstr(config)))?;
    let family = Family::parse(&parsed.version)?;
    let filter = filter.trim().to_lowercase();
    let filter = if filter == PATCH_LEVEL_ALL {
        ""
    } else {
        &filter
    };
    let requested = if requested_variant == "Normal" {
        ""
    } else {
        requested_variant
    };

    let mut targets = Vec::new();
    let mut seen: BTreeSet<(String, String, String)> = BTreeSet::new();
    let mut push = |sublevel: &str, date: &str, variant: &str, targets: &mut Vec<Target>| {
        let key = (sublevel.to_string(), date.to_string(), variant.to_string());
        if seen.insert(key) {
            targets.push(Target {
                family,
                sublevel: sublevel.to_string(),
                os_patch_level: date.to_string(),
                variant: variant.to_string(),
            });
        }
    };
    for entry in &parsed.include {
        if requested.is_empty() {
            push(&entry.sublevel, &entry.date, "Normal", &mut targets);
            if let Some(variant) = &entry.variant {
                push(&entry.sublevel, &entry.date, variant, &mut targets);
            }
        } else {
            push(&entry.sublevel, &entry.date, requested, &mut targets);
        }
    }

    if !filter.is_empty() {
        let by_date: Vec<Target> = targets
            .iter()
            .filter(|t| t.os_patch_level.to_lowercase() == filter)
            .cloned()
            .collect();
        targets = if by_date.is_empty() {
            targets
                .into_iter()
                .filter(|t| t.sublevel == filter)
                .collect()
        } else {
            by_date
        };
    }
    if targets.is_empty() {
        bail!("no build targets match patch level '{filter}'");
    }
    Ok(targets)
}

fn resolve_options(args: &BuildArgs) -> Options {
    let workspace = args
        .workspace
        .clone()
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    let output_dir = args
        .output_dir
        .clone()
        .unwrap_or_else(|| workspace.join("out"));
    let bazel_cache = args.bazel_cache.clone().unwrap_or_else(|| {
        std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| workspace.clone())
            .join(".cache/bazel")
    });
    Options {
        workspace,
        output_dir,
        bazel_cache,
        brand_name: args.brand_name.clone(),
        variant: args.variant.clone(),
        jobs: args.jobs,
        bypass: args.bypass,
        use_cache: args.use_cache,
        strict_patches: args.strict_patches,
        root_commit: args.root_commit.clone(),
        susfs_commit: args.susfs_commit.clone(),
        droidspaces_commit: args.droidspaces_commit.clone(),
        kernel_patches_commit: args.kernel_patches_commit.clone(),
        anykernel3_commit: args.anykernel3_commit.clone(),
    }
}

fn run_build(args: BuildArgs) -> Result<()> {
    let opts = resolve_options(&args);
    require_tools(&["git", "patch", "curl", "timeout", "clang"])?;
    fs::create_dir_all(&opts.workspace)?;

    say("trustgki — GKI + LXC + KernelSU-Next + SUSFS");
    say(&format!("workspace : {}", pstr(&opts.workspace)));
    say(&format!("output    : {}", pstr(&opts.output_dir)));
    say("not built : (features outside scope)");
    for (feature, source) in OUT_OF_SCOPE {
        say(&format!("            - {feature:14} ({source})"));
    }

    let no_patch_filter = args.os_patch_level.trim().is_empty();
    let targets = if let Some(config) = &args.config {
        // Like `main.yml`: an unset patch level means "everything".
        let filter = if no_patch_filter {
            PATCH_LEVEL_ALL
        } else {
            args.os_patch_level.as_str()
        };
        targets_from_config(config, filter, &args.variant)?
    } else {
        let version = args
            .version
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("--version is required when --config is not used"))?;
        let family = Family::parse(version)?;
        vec![Target {
            family,
            sublevel: args
                .sublevel
                .clone()
                .unwrap_or_else(|| SUBLEVEL_LTS.to_string()),
            // An unset patch level builds the current LTS tip of the family.
            os_patch_level: if no_patch_filter {
                "lts".to_string()
            } else {
                args.os_patch_level.clone()
            },
            variant: args.variant.clone(),
        }]
    };

    say(&format!("targets   : {}", targets.len()));
    for target in targets {
        build_target(&opts, target.family, target.sublevel, target.os_patch_level)
            .with_context(|| format!("build failed for {}", target.family.id()))?;
    }
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command_::Build(args) => run_build(*args),
        Command_::List(args) => {
            let config = match (&args.config, &args.version) {
                (Some(path), _) => path.clone(),
                (None, Some(version)) => Family::parse(version)?.config_file(),
                (None, None) => bail!("either --config or --version is required"),
            };
            for target in targets_from_config(&config, &args.os_patch_level, "Normal")? {
                println!(
                    "{}\tsublevel={}\tpatch-level={}\tvariant={}",
                    target.family.id(),
                    target.sublevel,
                    target.os_patch_level,
                    target.variant
                );
            }
            Ok(())
        }
        Command_::Families(args) => {
            let ids: Vec<&str> = Family::ALL.iter().map(|family| family.id()).collect();
            if args.json {
                say(&serde_json::to_string(&ids)?);
            } else {
                for id in ids {
                    say(id);
                }
            }
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// Tests — these pin the Rust re-implementations to the shell actions' semantics
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sed_helpers_match_sed_semantics() {
        let content = "a\n// needle\nb\n// needle\nc\n";
        assert_eq!(
            sed_insert_after(content, "needle", "ins"),
            "a\n// needle\nins\nb\n// needle\nins\nc\n"
        );
        assert_eq!(
            sed_insert_before(content, "needle", "ins"),
            "a\nins\n// needle\nb\nins\n// needle\nc\n"
        );
        assert_eq!(
            sed_delete_exact(
                "#include <linux/pkeys.h>\n#include <linux/pkeys.h.x>\n",
                "#include <linux/pkeys.h>"
            ),
            "#include <linux/pkeys.h.x>\n"
        );
    }

    #[test]
    fn line_helpers_match_echo_and_sed_dollar_d() {
        assert_eq!(append_line("x", "y"), "x\ny\n");
        assert_eq!(append_line("x\n", "y"), "x\ny\n");
        assert_eq!(replace_last_line("a\nb\n", "echo \"x\""), "a\necho \"x\"\n");
        assert_eq!(replace_last_line("a", "c"), "c\n");
        assert_eq!(replace_last_line("", "c"), "c\n");
    }

    #[test]
    fn sort_v_style_comparisons() {
        assert!(version_ge("2.39", "2.38"));
        assert!(version_ge("2.38", "2.38"));
        assert!(!version_ge("2.37", "2.38"));
        assert!(version_ge("6.6", "6.6"));
        assert!(!version_ge("6.1", "6.6"));
        assert!(version_ge("6.12", "6.6"));
        assert!(sublevel_le("58", 58));
        assert!(!sublevel_le("59", 58));
        assert!(!sublevel_le("X", 58));
        assert!(sublevel_ge("197", 197));
    }

    #[test]
    fn fdinfo_shim_rewrites_like_the_perl_python_pipeline() {
        let input = "static void inotify_fdinfo(struct seq_file *m, struct fsnotify_mark *mark)\n\
{\n\
\tstruct inode *inode = NULL;\n\
\n\
\tif (inode) {\n\
\t\t/*\n\
\t\t * old kernels print the raw mask\n\
\t\t */\n\
\t\tseq_printf(m, \"ino:%lx mask:%x ignored_mask:%x\", 1, 2, 3);\n\
\t}\n\
\t{\n\
\t\tu32 mask = mark->mask & IN_ALL_EVENTS;\n\
\t\tseq_printf(m, \"mask, mark->ignored_mask\");\n\
\t}\n\
}\n";
        let out = fdinfo_shim(input).expect("shim");
        assert!(!out.contains("old kernels print the raw mask"));
        assert!(!out.contains("u32 mask = mark->mask & IN_ALL_EVENTS;"));
        assert!(out.contains("ignored_mask:0"));
        assert!(out.contains("\"inotify_mark_user_mask(mark)\""));
        assert!(out.starts_with(
            "static inline u32 inotify_mark_user_mask(struct fsnotify_mark *mark)\n\
{\n\treturn mark->mask & IN_ALL_EVENTS;\n}\n\n\
static void inotify_fdinfo"
        ));
    }

    #[test]
    fn this_len_upgrade_only_when_types_match() {
        let pattern = r"(int|size_t)\s+this_len\s*=\s*min_t\s*\(\s*(int|size_t)\s*,";
        let upgrade = |caps: &regex::Captures<'_>| {
            if caps[1] == caps[2] {
                Some("size_t this_len = min_t(size_t,".to_string())
            } else {
                None
            }
        };
        assert_eq!(
            regex_replace(
                "int this_len = min_t(int, count, PAGE_SIZE);",
                pattern,
                upgrade
            )
            .unwrap(),
            "size_t this_len = min_t(size_t, count, PAGE_SIZE);"
        );
        assert_eq!(
            regex_replace(
                "size_t this_len = min_t(int, count, PAGE_SIZE);",
                pattern,
                upgrade
            )
            .unwrap(),
            "size_t this_len = min_t(int, count, PAGE_SIZE);"
        );
    }

    #[test]
    fn android15_6_6_task_mmu_rewrite_matches_the_python_count_one_sub() {
        // python: (\t+\t\tif (...))\n(\t+\t\t\tsmap_gather_stats(...);)\n(\t+)\}
        let input = "\t\t\tif (vma->vm_end > last_vma_end)\n\
\t\t\t\tsmap_gather_stats(vma, &mss, last_vma_end);\n\
\t}\n";
        let out = regex_sub_once(
            input,
            r"(\t+\t\tif\s*\(\s*vma->vm_end\s*>\s*last_vma_end\s*\))\n(\t+\t\t\tsmap_gather_stats\(vma,\s*&mss,\s*last_vma_end\);)\n(\t+)\}",
            |caps| {
                let mut s = String::new();
                s.push_str(&caps[1]);
                s.push_str(" {\n");
                s.push_str(&caps[2]);
                s.push('\n');
                s.push_str(&caps[3]);
                s.push_str("\t\tlast_vma_end = vma->vm_end;\n");
                s.push_str(&caps[3]);
                s.push_str("\t}\n");
                s.push_str(&caps[3]);
                s.push('}');
                s
            },
        )
        .unwrap();
        assert_eq!(
            out,
            "\t\t\tif (vma->vm_end > last_vma_end) {\n\
\t\t\t\tsmap_gather_stats(vma, &mss, last_vma_end);\n\
\t\t\tlast_vma_end = vma->vm_end;\n\
\t\t}\n\
\t}\n"
        );
    }

    #[test]
    fn stg_fallback_inserts_symbols_and_is_idempotent() {
        let src = "function {\n  id: 0x1e571002\n}\n\
function {\n  id: 0xc18f1240\n}\n\
elf_symbol {\n  id: 0x493ce9fc\n  name: \"loops_per_jiffy\"\n}\n\
interface {\n  symbol_id: 0xc750a072\n}\n";
        let once = stg_insert(src);
        assert!(once.contains("kdp_set_cred_non_rcu"));
        assert!(once.contains("symbol_id: 0xb0801f6e"));
        assert!(once.contains("symbol_id: 0x3037c5bc"));
        assert!(once.contains("symbol_id: 0x8334a496"));
        assert_eq!(once, stg_insert(&once), "stg fallback must be idempotent");
    }

    #[test]
    fn patch_target_paths_reads_unified_diff_headers() {
        let patch = std::env::temp_dir().join("trustgki-test.patch");
        fs::write(
            &patch,
            "diff --git a/android/abi_gki_aarch64.stg b/android/abi_gki_aarch64.stg\n\
--- a/android/abi_gki_aarch64.stg\n\
+++ b/android/abi_gki_aarch64.stg\n\
@@ -1 +1 @@\n\
-old\n\
+new\n\
--- a/drivers/Makefile\n\
+++ b/drivers/Makefile\n",
        )
        .unwrap();
        let paths = patch_target_paths(&patch).unwrap();
        assert!(paths.contains("android/abi_gki_aarch64.stg"));
        assert!(paths.contains("drivers/Makefile"));
        assert!(
            !paths
                .iter()
                .any(|p| p.starts_with("a/") || p.starts_with("b/"))
        );
        fs::remove_file(&patch).ok();
    }

    #[test]
    fn config_targets_expand_like_prepare_yml() {
        let config = Path::new(".github/config/android14-6.1.json");
        if !config.exists() {
            return; // repository layout not available in this test run
        }
        let all = targets_from_config(config, "All", "Normal").unwrap();
        assert!(all.iter().any(|t| t.variant == "TheWildJames"));
        assert!(all.iter().any(|t| t.os_patch_level == "lts"));
        let filtered = targets_from_config(config, "2025-12", "Normal").unwrap();
        assert!(filtered.iter().all(|t| t.os_patch_level == "2025-12"));
        let by_sublevel = targets_from_config(config, "157", "Normal").unwrap();
        assert!(by_sublevel.iter().all(|t| t.sublevel == "157"));
        // A requested variant labels every entry instead of the entry variants.
        let labeled = targets_from_config(config, "All", "Custom").unwrap();
        assert!(labeled.iter().all(|t| t.variant == "Custom"));
        assert_eq!(labeled.len(), 32);
    }

    #[test]
    fn supported_families_match_the_workflow_matrix() {
        let ids: Vec<&str> = Family::ALL.iter().map(|family| family.id()).collect();
        assert_eq!(ids.len(), 7);
        assert_eq!(
            ids,
            vec![
                "android12-5.10",
                "android13-5.10",
                "android13-5.15",
                "android14-5.15",
                "android14-6.1",
                "android15-6.6",
                "android16-6.12",
            ]
        );
        // Every supported family must have a config JSON to expand.
        for family in Family::ALL {
            assert!(
                family.config_file().is_file(),
                "missing {}",
                family.config_file().display()
            );
        }
    }

    /// Shape taken from `android14-6.1-lts:common/BUILD.bazel`, which declares
    /// the protected exports list for aarch64 *and* x86_64.
    #[test]
    fn protected_exports_list_removes_every_deleted_reference() {
        let src = r#"kernel_build(
    name = "kernel_aarch64",
    **{
        "protected_exports_list": "android/abi_gki_protected_exports_aarch64",
        "protected_modules_list": "android/gki_aarch64_protected_modules",
    },
    **{
        "protected_exports_list": "android/abi_gki_protected_exports_x86_64",
        "protected_modules_list": "android/gki_x86_64_protected_modules",
    },
)
"#;
        let (out, notes) = strip_protected_lists(src).unwrap();
        assert!(!out.contains("protected_exports_list"));
        assert!(!out.contains("abi_gki_protected_exports_"));
        // protected_modules_list is untouched (modules.bzl own that check).
        assert_eq!(out.matches("protected_modules_list").count(), 2);
        assert!(
            notes
                .iter()
                .any(|n| n.contains("protected_exports_list entries removed")),
            "notes: {notes:?}"
        );
        // Running again is a no-op and must not fail.
        let (again, _) = strip_protected_lists(&out).unwrap();
        assert_eq!(again, out);
    }

    /// Shape taken from `android16-6.12-lts:common/BUILD.bazel`.
    #[test]
    fn protected_module_names_list_is_stripped_for_6_12() {
        let src = r#"kernel_build(
    name = "kernel_aarch64",
    protected_module_names_list = ":gki_aarch64_protected_module_names",
)

kernel_build(
    name = "kernel_aarch64_16k",
    protected_module_names_list = ":gki_aarch64_protected_module_names",
)
"#;
        let (out, notes) = strip_protected_lists(src).unwrap();
        assert!(!out.contains("protected_module_names_list"));
        assert!(
            notes
                .iter()
                .any(|n| n.contains("protected_module_names_list entries removed")),
            "notes: {notes:?}"
        );
        let (again, _) = strip_protected_lists(&out).unwrap();
        assert_eq!(again, out);
    }

    #[test]
    fn protected_lists_are_left_alone_when_absent() {
        let src = "kernel_build(\n    name = \"kernel_aarch64\",\n)\n";
        let (out, notes) = strip_protected_lists(src).unwrap();
        assert_eq!(out, src);
        assert!(notes.is_empty(), "notes: {notes:?}");
    }

    /// Build a throwaway workspace that looks enough like `kernel/common`.
    fn scratch_ctx(family: Family, sublevel: &str, os_patch_level: &str) -> (Ctx, PathBuf) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static SEQ: AtomicUsize = AtomicUsize::new(0);
        let root = std::env::temp_dir().join(format!(
            "trustgki-test-{}-{}-{}",
            std::process::id(),
            sublevel,
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        if root.exists() {
            fs::remove_dir_all(&root).unwrap();
        }
        fs::create_dir_all(root.join("kernel/common/fs/proc")).unwrap();
        let opts = Options {
            workspace: root.clone(),
            output_dir: root.join("out"),
            bazel_cache: root.join("bazel"),
            brand_name: "Wild".to_string(),
            variant: "Normal".to_string(),
            jobs: 1,
            bypass: false,
            use_cache: false,
            strict_patches: false,
            root_commit: None,
            susfs_commit: None,
            droidspaces_commit: None,
            kernel_patches_commit: None,
            anykernel3_commit: None,
        };
        let ctx = Ctx::new(
            opts,
            family,
            sublevel.to_string(),
            os_patch_level.to_string(),
        );
        (ctx, root)
    }

    #[test]
    fn android16_6_12_fake_patches_round_trip() {
        let (mut ctx, root) = scratch_ctx(Family::Android16_6_12, "69", "2026-03");
        ctx.sublevel = "69".to_string();
        let exec = ctx.common_dir().join("fs/exec.c");
        let task_mmu = ctx.common_dir().join("fs/proc/task_mmu.c");
        let exec_before =
            "#include <linux/fs.h>\n#include <linux/dma-buf.h>\n#include <linux/mm.h>\n";
        let mmu_before =
            "static void show_smap(struct seq_file *m, void *v)\n{\n\tvma_data_pages(vma);\n}\n";
        fs::write(&exec, exec_before).unwrap();
        fs::write(&task_mmu, mmu_before).unwrap();

        apply_susfs_fake_patches(&ctx).unwrap();
        assert_eq!(
            read(&exec).unwrap(),
            "#include <linux/fs.h>\n#include <linux/mm.h>\n"
        );
        assert_eq!(
            read(&task_mmu).unwrap(),
            "static void show_smap(struct seq_file *m, void *v)\n{\n\tvma_pages(vma);\n}\n"
        );

        revert_susfs_fake_patches(&ctx).unwrap();
        let exec_after = read(&exec).unwrap();
        assert_eq!(exec_after.matches("#include <linux/dma-buf.h>").count(), 1);
        assert_eq!(read(&task_mmu).unwrap(), mmu_before);
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn set_kernel_config_matches_the_patch_action() {
        let (ctx, root) = scratch_ctx(Family::Android16_6_12, "69", "2026-03");
        let defconfig = ctx.defconfig();
        fs::create_dir_all(defconfig.parent().unwrap()).unwrap();
        fs::write(
            &defconfig,
            "# CONFIG_KALLSYMS_ALL is not set\nCONFIG_OVERLAY_FS=n\nCONFIG_UNRELATED=y\n",
        )
        .unwrap();
        set_kernel_config(&ctx, CFG_MISC).unwrap();
        let out = read(&defconfig).unwrap();
        assert!(out.contains("CONFIG_KALLSYMS_ALL=y\n"));
        assert!(out.contains("CONFIG_OVERLAY_FS=y\n"));
        assert!(out.contains("CONFIG_TMPFS_XATTR=y\n")); // appended
        assert!(out.contains("CONFIG_UNRELATED=y\n")); // untouched
        assert!(!out.contains("CONFIG_OVERLAY_FS=n"));
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn branding_rewrites_the_last_setlocalversion_line() {
        let (mut ctx, root) = scratch_ctx(Family::Android16_6_12, "69", "2026-03");
        ctx.sublevel = "69".to_string();
        let path = ctx.common_dir().join("scripts/setlocalversion");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, "#!/bin/sh\necho old\n").unwrap();
        apply_kernel_branding(&ctx).unwrap();
        assert_eq!(
            read(&path).unwrap(),
            "#!/bin/sh\necho \"6.12.69-android16-Wild\"\n"
        );

        let (legacy, root2) = scratch_ctx(Family::Android14_6_1, "157", "2025-12");
        let path2 = legacy.common_dir().join("scripts/setlocalversion");
        fs::create_dir_all(path2.parent().unwrap()).unwrap();
        fs::write(&path2, "#!/bin/sh\necho old\n").unwrap();
        apply_kernel_branding(&legacy).unwrap();
        assert_eq!(
            read(&path2).unwrap(),
            "#!/bin/sh\necho \"-android14-Wild\"\n"
        );
        fs::remove_dir_all(root).ok();
        fs::remove_dir_all(root2).ok();
    }
}
