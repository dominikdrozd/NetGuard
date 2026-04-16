# Packaging

This directory produces `.deb`, `.rpm`, and Arch `.pkg.tar.zst` packages via
[nfpm](https://nfpm.goreleaser.com/). CI builds them automatically on every
tag push; these are the instructions for building them locally.

## One-time setup

```sh
curl -fsSL -o /tmp/nfpm.tar.gz \
  https://github.com/goreleaser/nfpm/releases/download/v2.41.0/nfpm_2.41.0_Linux_x86_64.tar.gz
sudo tar -xzf /tmp/nfpm.tar.gz -C /usr/local/bin nfpm
```

## Build

From the repo root:

```sh
# 1. Build the binary first
cargo build --release --target x86_64-unknown-linux-gnu

# 2. Produce all three packages
cd packaging
export NFPM_ARCH=amd64
export NFPM_VERSION=0.3.0  # or dev string
export CARGO_TARGET=x86_64-unknown-linux-gnu
for fmt in deb rpm archlinux; do
    nfpm pkg --packager "$fmt" --config nfpm.yaml --target ../dist/
done
```

## Install behavior

All three packages share `scripts/postinstall.sh`. On install:

1. Creates `netguard-mitm` system user.
2. Provisions `/etc/netguard/`, `/var/log/netguard/`, `/var/lib/netguard/mitm/`.
3. Copies default config to `/etc/netguard/netguard.toml` (first install only).
4. Bootstraps the mitmproxy CA under `/var/lib/netguard/mitm/` without installing it into the system trust store.
5. Enables + starts `netguard.service`.

HTTPS decryption is **off by default**. To enable, use the web UI toggle
(requires `allow_runtime_toggle = true` in config) or edit the config file
directly.

## What each script expects

| Script | Runs on | Exit non-zero? |
|---|---|---|
| `postinstall.sh` | install + upgrade | Fails install on error |
| `preremove.sh` | remove + upgrade | Best-effort; never fails |
| `postremove.sh` | remove (after file deletion) | Best-effort; never fails |

All three source `_action.sh` first to normalize `deb`/`rpm`/`arch` arg
conventions into a single `$ACTION` variable (`install` / `upgrade` / `remove`).
