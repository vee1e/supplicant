# supplicant deployment guide

How to install supplicant, wire it into CI, and run it on a schedule. supplicant is a stateless CLI. Every command fetches what it needs, caches it on disk, and exits. Everything it remembers lives in one folder, the `--cache-dir`.

## Requirements

| Need | Notes |
|---|---|
| Python | 3.11 or newer |
| Outbound HTTPS | npm registry, PyPI, OSV.dev. The CDN hosts are optional, see egress below |
| Privileges | none, no root, no agents |

## Install

```bash
git clone <your-fork-or-path>
cd supplicant
pip install -e .
supplicant --version
```

To check the install: `supplicant --help` exits 0. A bad flag exits 3.

## Configuration

Flags only, no config file in v0.1.

| Behavior | Flag to change it | Default |
|---|---|---|
| Cache and archive location | `--cache-dir PATH` | `~/.cache/supplicant` |
| OSV advisory checks | `--no-osv` | on |
| Gate threshold | `--min-severity LEVEL` | `medium` |
| Tree recursion depth | `--max-depth N` | `10` |
| Output format | `--format FMT` | `text` for scan and diff, `dot` for graph |
| Color output | `--no-color` | on |

There are no secrets and no telemetry. Package names leave your machine only in the registry and OSV requests the scan makes.

### Cache layout

```
~/.cache/supplicant/
├── blobs/      cached HTTP responses, keyed by content hash
├── tmp/        transient download staging, cleaned on success
└── archive/    immutable per-version archive
    ├── tarballs/    every artifact ever fetched
    ├── extracted/   extracted trees for offline analysis
    └── index/       per-version metadata records
```

The archive is the forensics store. It is how `forensics` and `diff` keep working after a malicious version is unpublished. Back it up.

## CI and CD

Exit codes drive the gate.

| Exit | Meaning |
|---|---|
| 0 | clean, no findings at or above the severity floor |
| 1 | findings at or above the severity floor, block the merge |
| 2 | scan error |
| 3 | usage error |

GitHub Actions example. Scan the lockfile on every PR, and run a nightly scan so a compromise shipped as a routine update is caught within a day.

```yaml
name: supply-chain
on:
  pull_request:
    paths:
      - '**/package.json'
      - '**/package-lock.json'
      - '**/requirements.txt'
  schedule:
    - cron: '0 3 * * *'

jobs:
  supplicant:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: '3.12' }
      - run: pip install -e .
      - name: Scan the lockfile
        run: supplicant scan package-lock.json --min-severity high
      - name: Save the archive for the next run
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: supplicant-archive
          path: ~/.cache/supplicant/archive
```

Two patterns that work well:

- Diff the old and new resolved versions in a bump PR, and block on critical or high.
- Scan the full locked tree every night and alert on new findings. Dependabot bumps do not trigger that, so it is the backstop.

## Scheduled runs

No daemon, use cron or a job runner.

```cron
3 0 * * * cd /srv/app && \
  supplicant scan /srv/app/package-lock.json \
    --min-severity medium --format json \
    --cache-dir /var/cache/supplicant \
    > /var/log/supplicant/scan-$(date +\%F).json 2>&1
```

Use one fixed `--cache-dir`. Repeat scans stay fast, and you only fetch each version once. Distinguish exit 1 (findings) from exit 2 (error) in your alerting. Put a timeout on the whole job; large cold trees take minutes.

## Performance

The numbers below are estimates, not measurements.

| Scan | Cache | Time |
|---|---|---|
| one small package, cached | about 1 MB | seconds |
| 50-dep lockfile | about 30 MB | under a minute |
| 1000-dep tree, cold | 1-2 GB | several minutes |
| 1000-dep tree, warm | same | seconds |

Fresh scans are network-bound and serial in v0.1. The disk cache makes repeat scans near-instant. For very large trees, `--no-osv` skips advisory lookups and runs only the behavioral detectors.

## Firewalls and egress

Allowlist the primary registries and OSV:

```
registry.npmjs.org
pypi.org
files.pythonhosted.org
api.osv.dev
```

The CDN hosts are optional fallbacks for reconstructing unpublished versions:

```
unpkg.com
cdn.jsdelivr.net
data.jsdelivr.com
```

If you block the CDNs, every normal package still resolves from the primary registries. Only diffs and forensics on unpublished versions fail. For fully offline deployments, pre-warm the archive on a networked host and point `--cache-dir` at read-only media.

## Operations

### Back up the archive

The archive cannot be recreated after a version disappears from the CDNs.

```bash
tar czf supplicant-archive-$(date +%F).tgz ~/.cache/supplicant/archive
```

In CI, cache it between runs so diffs keep working when a malicious version is unpublished mid-incident.

### Clean the cache

Only `tmp/` is transient. You may delete `blobs/` to reclaim space; it refetches. Keep `archive/`.

```bash
rm -rf ~/.cache/supplicant/blobs ~/.cache/supplicant/tmp
```

### Upgrade

The CLI is stateless. Reinstall the package to upgrade. The cache is content-addressed, so no migration is needed.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `error: <pkg>@<ver> not found in the registry, unpkg, or jsDelivr archives` | The version was unpublished and no CDN copy remains. If you scanned it before, the archived copy still works offline. |
| Diff of a malicious version exits 2 | CDN fallback blocked by a firewall, or the version predates CDN caches. Unblock the CDNs or use the archive. |
| `integrity check failed` | The fetched npm tarball did not match the published checksum. Retry. If it persists, the registry served tampered bytes. Treat that as a scan error (exit 2). |
| First scan is slow | Expected, cold cache plus serial downloads. Re-run for near-instant results. |
| Lockfile scan shows no tree | Lockfile scans are flat by design. Use `scan <pkg>` for a resolved tree. |
| `fence requests` shows different owners on npm and PyPI | That is the identity fence working. The two names are unrelated projects. |
| Scan of a clean package exits 1 | Run with `--min-severity high`, or look for low and informational signals with `--min-severity low` or `--min-severity info`. |

## Known limitations

- `server` mode is not implemented and exits 2.
- No sandboxed install execution. supplicant scans install scripts as text. It never runs them.
- Docker images and GitHub repositories are not supported yet.
- The fingerprint worm detector needs a batch run and cannot fire from a single diff.
- Typosquatting and the identity fence are low-severity signals, excluded from lockfile scans.

## Quick reference

```bash
supplicant scan <pkg> | <pkg>@<ver> | npm:pkg@ver | pypi:pkg==ver | <lockfile> | <package.json>
supplicant diff <pkg>@<a> <pkg>@<b>
supplicant graph <target> --format dot
supplicant forensics <pkg>@<ver>
supplicant fence <name>
```
