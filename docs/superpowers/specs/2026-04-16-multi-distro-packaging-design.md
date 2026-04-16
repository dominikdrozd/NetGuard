# Multi-Distro Packaging — Design Spec

- **Date:** 2026-04-16
- **Status:** Draft — pending user review
- **Scope:** Produce `.deb`, `.rpm`, and Arch `.pkg.tar.zst` packages in CI as GitHub Release assets.
- **Out of scope:** Hosted APT/DNF/pacman repositories, AUR submission, Flatpak/Snap/AppImage.

## 1. Goals

1. On a supported Debian/Ubuntu, Fedora/RHEL, or Arch box, a user can run a single `apt install ./pkg` / `dnf install ./pkg` / `pacman -U pkg` and end up with a working, running `netguard.service`.
2. Package install does **not** enable HTTPS decryption (mitmproxy stays `enabled = false` in config). User opts in later.
3. Every release (tag push `v*`) ships the three packages alongside the existing tarballs.
4. CI smoke-tests each package on a matching distro container before shipping.

## 2. Non-goals

- Upstream Debian / Fedora / official-repo compliance. Packages are acceptable for direct download + install, not for submission to distro archives.
- Cross-distro `apt-get upgrade` style auto-updates. Users re-download new releases manually.
- Running NFQUEUE or real packet interception inside CI smoke tests — the kernel-facing paths are not exercisable in containerized CI.

## 3. Architecture overview

New top-level `packaging/` directory:

```
packaging/
├── nfpm.yaml              # shared config, templated per arch/version
├── scripts/
│   ├── postinstall.sh
│   ├── preremove.sh
│   └── postremove.sh
└── README.md              # maintainer notes (how to regenerate locally)
```

Tool: **nfpm** (goreleaser/nfpm) — a single Go binary that consumes one YAML and emits `.deb`, `.rpm`, and `.pkg.tar.zst`. Runs on the existing `ubuntu-22.04` / `ubuntu-22.04-arm` runners; no per-distro containers required for *building* (containers are only used for smoke testing).

`deploy.sh` stays as the canonical installer for the tarball path. The three packages duplicate its **provisioning** steps (deploy.sh steps 6–7) into `postinstall.sh`, but skip **dependency install / build** (deploy.sh steps 0–5) because the package declares runtime deps via its manifest.

## 4. Package contents

Package metadata declares `License: MIT` across all three formats. If the repo doesn't yet have a `LICENSE` file at the root, one is added as part of this work (MIT boilerplate, `Dominik Drozd` copyright). The `LICENSE` file is shipped in the package at `/usr/share/doc/netguard/LICENSE` (Debian/RPM convention) and `/usr/share/licenses/netguard/LICENSE` (Arch convention) via the `nfpm` `contents:` block.

Every format installs the same binary files:

| Source | Destination | Mode |
|---|---|---|
| `target/<triple>/release/netguard` | `/usr/local/bin/netguard` | 0755 |
| `config/netguard.toml` | `/usr/share/netguard/netguard.toml` | 0644 |
| `systemd/netguard.service` | `/lib/systemd/system/netguard.service` | 0644 |

`config/netguard.toml` is shipped to `/usr/share/netguard/` (a template), **not** directly to `/etc/netguard/netguard.toml`. The postinstall copies it into `/etc` only on first install, which lets package upgrades leave user-edited configs alone.

### 4.1 Runtime dependencies

| Capability | Debian | RPM | Arch |
|---|---|---|---|
| iptables | `iptables` | `iptables` | `iptables` |
| libnetfilter_queue | `libnetfilter-queue1` | `libnetfilter_queue` | `libnetfilter_queue` |
| libnfnetlink | `libnfnetlink0` | `libnfnetlink` | `libnfnetlink` |
| libmnl | `libmnl0` | `libmnl` | `libmnl` |
| mitmproxy | `mitmproxy` | `mitmproxy` | `mitmproxy` |
| CA trust helper | `ca-certificates` | `ca-certificates` | `ca-certificates-utils` |

Build-time `*-dev` / `*-devel` packages are **not** runtime deps — only the shared libs ship.

## 5. Install/remove lifecycle

### 5.1 `postinstall.sh` — idempotent, root, runs on install + upgrade

1. Create `netguard-mitm` system user (`useradd -r -s /usr/sbin/nologin`) if missing.
2. Install dirs:
   - `/etc/netguard` 0755 root:root
   - `/var/log/netguard` 0750 root:root
   - `/var/lib/netguard/mitm` 0750 netguard-mitm:netguard-mitm
   - `/run/netguard` 0755 (created by systemd `RuntimeDirectory`, but bootstrapped here for CA gen below)
3. If `/etc/netguard/netguard.toml` missing → copy from `/usr/share/netguard/netguard.toml`. **Never overwrite** an existing config.
4. If `/etc/netguard/rules.json` missing → seed `{"version":1,"rules":[]}` at 0644.
5. If `/var/lib/netguard/mitm/mitmproxy-ca-cert.pem` missing → bootstrap via `timeout -s KILL 4 sudo -u netguard-mitm env HOME=/var/lib/netguard/mitm mitmdump --set confdir=/var/lib/netguard/mitm --listen-host 127.0.0.1 --listen-port <random 40000-49999> --mode regular` (mirrors `deploy.sh`). **Does NOT install the CA into the system trust store** — this is the opt-in step the user triggers later via web UI / CLI.
6. `systemctl daemon-reload`, `systemctl enable --now netguard.service`.

### 5.2 `preremove.sh` — runs on uninstall **and** upgrade

- `systemctl stop netguard.service` (best-effort; never fail the removal).
- `systemctl disable netguard.service` **only on full removal**, not on upgrade. Detection:
  - Debian: `$1` is `remove` or `purge` on removal, `upgrade` on upgrade.
  - RPM: `$1 -eq 0` on removal, `$1 -eq 1` on upgrade.
  - Arch: distinct `pre_remove` / `pre_upgrade` functions — use an arg-parsing shim at the top of the shared script to normalize into a single `$ACTION` var (`install`, `upgrade`, `remove`).

### 5.3 `postremove.sh` — runs after file deletion on full removal

- `systemctl daemon-reload`.
- **Leaves** `/etc/netguard`, `/var/log/netguard`, `/var/lib/netguard` in place. These are user data (config, CA, logs). Debian `purge` removes them; RPM/Arch users remove manually.
- **No iptables flushing here.** The systemd unit's `ExecStopPost=/usr/local/bin/netguard --cleanup` already ran during `preremove.sh`'s `systemctl stop`, which removes NetGuard-owned rules only. Blanket `iptables -F` (as in `deploy.sh` step 7) is appropriate on first install of a freshly-provisioned box but would wipe unrelated user-added rules on uninstall — so we don't do it.

### 5.4 Shared arg-parsing shim

All three scripts start with:

```sh
#!/bin/sh
set -e
# nfpm invokes all three packagers through the same script path, but each
# format passes different arguments. Normalize to $ACTION = install|upgrade|remove.
case "${1:-}" in
    configure)           ACTION=install ;;        # deb postinst
    2)                   ACTION=upgrade ;;        # rpm postin, $1=2 on upgrade
    1)                   ACTION=install ;;        # rpm postin, $1=1 on fresh install
    remove|purge)        ACTION=remove ;;         # deb preremove/postremove
    0)                   ACTION=remove ;;         # rpm, $1=0 on uninstall
    upgrade|failed-upgrade) ACTION=upgrade ;;     # deb preremove during upgrade
    *)                   ACTION=install ;;        # arch / fallback
esac
```

## 6. Port allocation — runtime fallback

Config values in `netguard.toml` are **starting hints**, not hard-bound ports.

### 6.1 Web UI (`crates/netguard-web`)

When binding the axum listener:

```rust
let mut port = cfg.web.listen_port;
let max_attempts = 20;
let listener = loop {
    match TcpListener::bind((cfg.web.listen_addr, port)).await {
        Ok(l) => break l,
        Err(e) if e.kind() == AddrInUse && port < cfg.web.listen_port + max_attempts => {
            port += 1;
        }
        Err(e) => return Err(e.into()),
    }
};
tracing::info!("web UI bound to {}:{}", cfg.web.listen_addr, port);
```

The actually-bound port is exposed via `/api/status` (new field `bound_web_port: u16`). The web UI already loads `/api/status` on startup — no additional UI surgery needed beyond reading that field.

### 6.2 mitmproxy subprocess (`crates/netguard-mitm`)

Same pattern in the process launcher: probe ports starting at `cfg.mitmproxy.listen_port`, increment up to `+20`, pass the chosen port to `mitmdump --listen-port`. Store the chosen port in the shared state the web handler reads, so `/api/status.bound_mitm_port` reports it when mitmproxy is running.

### 6.3 Why runtime and not install-time

- Install-time probing would hard-write a config value that can become stale (another app claims the port weeks later → daemon fails on next restart).
- Runtime probing always finds a free port on each start, at the cost of the UI port possibly shifting across restarts. In practice the starting hint (3031) is rarely taken, so the port is stable on most boxes.

## 7. Versioning

- Tag build (`git push v1.2.3`): `version = 1.2.3`.
- Dev build (master branch push): `version = 0.0.0-dev.<unix-timestamp>.<short-sha>`.
- Uses dashes only (no tildes) — all three formats accept this; RPM has quirks with `~` in some contexts that make it not worth the trouble.
- `nfpm.yaml` consumes `$NFPM_VERSION` from the environment, set by the CI `version` step.

## 8. CI workflow changes (`.github/workflows/build.yml`)

### 8.1 Extend matrix in existing `build` job

Add `nfpm_arch` column:

| arch | runner | cargo target | nfpm_arch |
|---|---|---|---|
| x86_64 | `ubuntu-22.04` | `x86_64-unknown-linux-gnu` | `amd64` |
| aarch64 | `ubuntu-22.04-arm` | `aarch64-unknown-linux-gnu` | `arm64` |

### 8.2 New steps in `build` job (after existing "Build daemon (release)")

```yaml
- name: Install nfpm
  run: |
    curl -fsSL -o /tmp/nfpm.tar.gz \
      "https://github.com/goreleaser/nfpm/releases/download/v2.41.0/nfpm_2.41.0_Linux_${{ matrix.nfpm_arch }}.tar.gz"
    sudo tar -xzf /tmp/nfpm.tar.gz -C /usr/local/bin nfpm
    nfpm --version

- name: Build packages
  env:
    NFPM_ARCH: ${{ matrix.nfpm_arch }}
    NFPM_VERSION: ${{ steps.version.outputs.nfpm_version }}
    CARGO_TARGET: ${{ matrix.target }}
  run: |
    mkdir -p dist
    for fmt in deb rpm archlinux; do
      nfpm pkg --packager "$fmt" --config packaging/nfpm.yaml --target dist/
    done
    (cd dist && sha256sum netguard* > packages.sha256)
    ls -la dist/
```

### 8.3 Artifact upload

Extend the existing `upload-artifact` `path:` glob to include `dist/*.deb`, `dist/*.rpm`, `dist/*.pkg.tar.zst`, `dist/packages.sha256`.

### 8.4 New jobs — smoke tests

Three new jobs (`smoke-deb`, `smoke-rpm`, `smoke-arch`), all on `ubuntu-22.04`, run after `build`, in parallel.

Common structure (Debian example):

```yaml
smoke-deb:
  name: Smoke test (deb)
  needs: build
  runs-on: ubuntu-22.04
  container:
    image: debian:12
    options: --privileged --cap-add=NET_ADMIN --cap-add=NET_RAW --cgroupns=host --tmpfs /tmp --tmpfs /run
  steps:
    - uses: actions/download-artifact@v4
      with: { name: netguard-x86_64, path: dist }
    - name: Install systemd + prereqs
      run: |
        apt-get update
        apt-get install -y systemd ca-certificates
    - name: Start systemd as PID 1 alternative
      run: |
        # bootstrap systemd within the container
        exec /lib/systemd/systemd --system --unit=multi-user.target &
        sleep 3
    - name: Install package
      run: apt-get install -y ./dist/netguard_*_amd64.deb
    - name: Wait for service
      run: |
        for i in $(seq 1 10); do
          systemctl is-active netguard && break || sleep 1
        done
        systemctl is-active netguard
    - name: Uninstall
      run: |
        apt-get remove -y netguard
        test ! -f /lib/systemd/system/netguard.service
```

Variants:
- `smoke-rpm`: `fedora:40` container, `dnf install`, `dnf remove`.
- `smoke-arch`: `archlinux:base` container, `pacman -U --noconfirm`, `pacman -R --noconfirm`.

Smoke tests run **x86_64 only**. aarch64 install-script parity is validated by the shared postinstall script; re-running on an ARM container adds ~15 CI-minutes for negligible new information.

### 8.5 Release job

Existing `release` job needs one change — extend `files:` glob:

```yaml
files: |
  release-artifacts/*.tar.gz
  release-artifacts/*.sha256
  release-artifacts/*.deb
  release-artifacts/*.rpm
  release-artifacts/*.pkg.tar.zst
```

Update the release-notes body (`body:` block) with install instructions for each format:

```
apt install ./netguard_<VER>_amd64.deb
dnf install ./netguard-<VER>.x86_64.rpm
pacman -U netguard-<VER>-x86_64.pkg.tar.zst
```

## 9. Testing strategy

| Layer | What it tests | Where |
|---|---|---|
| nfpm config validity | `nfpm.yaml` parses; file sources exist | Implicit — `nfpm pkg` fails fast if misconfigured |
| Install scripts | `postinstall.sh` idempotency, user/dir creation, service enable | Smoke jobs (`debian:12`, `fedora:40`, `archlinux:base`) |
| Service startup | Config parse, port bind, systemd unit correctness | Smoke jobs assert `systemctl is-active netguard` |
| Uninstall cleanup | preremove + postremove work | Smoke jobs assert service file removed |
| Port fallback logic | Web/mitmproxy retry on `EADDRINUSE` | New unit test in `netguard-web` + `netguard-mitm` (seed the retry with a listener already holding the starting port) |

**Explicit non-coverage:** NFQUEUE packet interception, iptables rule insertion, actual mitmproxy MITM of HTTPS traffic. None of these are feasible inside GitHub-hosted CI without a kernel-traffic fixture outside the current scope.

## 10. Rollout plan

1. Add `packaging/` directory + scripts (no CI changes yet). Validate locally with `nfpm pkg` on a dev box.
2. Add port-fallback logic to `netguard-web` + `netguard-mitm`, with unit tests. Separate commit — this is a daemon change, not a packaging change.
3. Wire packages into existing `build` job.
4. Add the three smoke jobs.
5. Update `release` job to attach packages + refresh release-notes body.
6. Tag a pre-release (`v0.3.0-rc1`) to dry-run the full pipeline.
7. Tag the real release once rc1 smoke tests pass.

## 11. Open risks

- **systemd-in-Docker smoke tests** can be flaky on GitHub runners if cgroup config drifts. Mitigation: if the `--cgroupns=host` + `/tmp /run` tmpfs formula stops working, fall back to verifying package install only (skip service-start assertion) and document it as a CI limitation.
- **mitmproxy system trust install** is deliberately NOT done on package install. If a user misreads this as "installing the package enables HTTPS decryption," that's a docs problem — README needs a clear "packages install in safe mode; HTTPS decryption is separately opt-in" sentence. Add this alongside the release-notes update.
- **nfpm version pinning** — pinned to `v2.41.0` in this spec. Periodic bumps needed; track via a single `NFPM_VERSION` env in the workflow.
