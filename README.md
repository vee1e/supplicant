<div align="center">

# supplicant

**A CLI that checks a dependency version bump against that package's own release history. Run it before you take a bump.**

</div>

## What it is

For developers and security engineers who review dependency bumps. supplicant downloads both versions of an npm or PyPI package, shows what changed, and flags anything that does not match the package's own habits.

Most scanners compare a package against the rest of the world. supplicant compares a bump against the package itself. Release cadence, authors, repository, install hooks, payload size. A package that never shipped an install hook and suddenly ships one in a patch bump stands out.

## Why

The 2026 ChainDrop attacks published signed, routine-looking malicious patch versions. `keyv@6.0.0` passed behavioral and provenance checks. What it could not pass was its own history. supplicant catches that pattern, and it can still see versions npm has already deleted.

## What makes it different

| Capability | supplicant | npm diff | Socket.dev | OSV-Scanner |
|---|---|---|---|---|
| Shows a security-scored version diff | yes | raw diff only | no | no |
| Compares against the package's own history | yes | no | no | no |
| Reconstructs unpublished (yanked) versions | yes | no | no | no |
| Known-vulnerability matching (OSV) | yes | no | partial | yes |

## Try it

```bash
git clone <your-fork-or-path>
cd supplicant
pip install -e .
```

Python 3.11 or newer. No third-party dependencies, nothing else to install.

```bash
# scan a package.json and its dependencies
supplicant scan package.json

# what changed between two versions?
supplicant diff lodash@4.17.20 lodash@4.17.21
```

## Commands

| Command | What it does |
|---|---|
| `supplicant scan <target>` | Resolves a dependency tree and scans every package. Target can be a package, `package.json`, or a lockfile. |
| `supplicant diff <pkg@a> <pkg@b>` | The main command. Diffs two versions and decides whether you should take the bump. |
| `supplicant graph <target>` | Renders the dependency tree as a security graph. |
| `supplicant forensics <pkg@ver>` | Reconstructs a version that was unpublished, from CDN archives. |
| `supplicant fence <name>` | Shows who owns the same name on npm and PyPI. |

## Output and exit codes

| Format | Works with |
|---|---|
| `text` | scan, diff (default) |
| `json` | scan, diff, graph |
| `sarif` | scan, diff (SARIF 2.1.0, for GitHub code scanning) |
| `dot` | scan, graph (default for graph) |
| `graph` | scan |

| Exit code | Meaning |
|---|---|
| 0 | clean, no findings at or above `--min-severity` |
| 1 | findings at or above `--min-severity` |
| 2 | scan error |
| 3 | usage error |

The default `--min-severity` is medium. Low signals are hidden unless you pass `--min-severity low` or `--min-severity info`.

## Detectors

| Signal | What it catches | Weight |
|---|---|---|
| `baseline_deviation` | A bump that breaks the package's own habits: release cadence, author, repository, a first-ever install hook, a large new payload | primary |
| `known_vulnerability` | Matching advisories from the OSV.dev feed, including its malicious-package feed | primary |
| `install_script_network` | Install hooks that curl-pipe to sh, download then execute, spawn processes, or write outside the package | primary |
| `obfuscation` | eval, base64, and high-entropy code in newly added files | supporting |
| `native_binary` | Newly introduced ELF, PE, or Mach-O binaries, and large binary-looking files | supporting |
| `unexpected_permissions` | Setuid or world-writable files, and shipped credentials (content-verified) | supporting |
| `typosquatting` | Names an edit-distance of 2 or fewer from popular packages, weighted by first-publish date | supporting |
| `identity_fence` | The same name owned by different parties on npm and PyPI | informational |
| `fingerprint_match` | Identical deltas across several packages, the signature of a coordinated worm | beta, needs a batch run |

## Catching an attack

`keyv@6.0.0` was the ChainDrop payload. npm unpublished it, so the registry cannot serve it anymore. supplicant reconstructs it from a CDN archive and diffs it against the last good release.

```
$ supplicant diff keyv@5.2.0 keyv@6.0.0
 keyv 5.2.0 → 6.0.0
├─ files added:   3   (Math_Symbol.js, dist/index.d.mts, setup.mjs)
├─ files modified:   3   (README.md, dist/index.d.cts, package.json)
├─ files removed:   4   (LICENSE, dist/index.cjs, dist/index.d.ts, dist/index.js)
│
├─ fingerprint: hooks:+1/-0|bins:+0|obf:0|author:+0|repo:+0|deps:+1|deltabytes:+847973|binratio:0.00
│
├─ CRITICAL  baseline_deviation  - new install hooks: setup.mjs; first-ever install hook with 817826 bytes of new payload
│
├─ HIGH  install_script_network  - install hook newly introduced in this version
│            evidence: file=setup.mjs
│
└─ verdict: DO NOT TAKE THIS BUMP (block)
```

The diff tells it. A package that never had an install hook gets one, plus a payload bigger than anything it ever shipped. Exit code 1, so a CI gate on this bump fails.

## Non-goals

Not a runtime host monitor. Not a package blocking proxy. Not a full static analysis tool. v0.1 scans npm and PyPI only.

## License

MIT
