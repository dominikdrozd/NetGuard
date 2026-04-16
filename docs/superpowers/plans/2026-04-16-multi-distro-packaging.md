# Multi-Distro Packaging Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `.deb`, `.rpm`, and Arch `.pkg.tar.zst` packages as GitHub Release assets, with smoke tests, safe mitmproxy default, and runtime port fallback for the web UI + mitmproxy.

**Architecture:** Single `nfpm.yaml` produces all three formats on existing Ubuntu runners. Three shared install scripts (with a format-normalizing arg shim) distill `deploy.sh`'s provisioning. Daemon gets a `+N` port-fallback helper in `netguard-core`, used by both the axum listener and the mitmdump launcher; the chosen ports are exposed via a new `/api/status` endpoint.

**Tech Stack:** Rust (Tokio, axum), Go (nfpm — invoked as a CLI), Bash (install scripts), GitHub Actions (matrix + container jobs).

**Spec deviation note:** Spec §6.1 says "the web UI already loads `/api/status`". It does not — there's `/api/stats`, `/api/mitmproxy`, etc., but no `/api/status`. Task A4 adds the endpoint. No UI wiring beyond that; the frontend can read it on demand later.

---

## File structure

**Create:**
- `LICENSE` — MIT boilerplate.
- `crates/netguard-core/src/port_probe.rs` — async `try_bind_from(addr, start_port, max_attempts)` helper + unit tests.
- `packaging/nfpm.yaml` — shared nfpm config.
- `packaging/scripts/postinstall.sh` — user/dir/CA bootstrap + enable service.
- `packaging/scripts/preremove.sh` — stop + disable-on-full-removal.
- `packaging/scripts/postremove.sh` — daemon-reload only.
- `packaging/scripts/_action.sh` — sourced shim; normalizes format-specific args into `$ACTION`.
- `packaging/README.md` — maintainer notes for local package builds.

**Modify:**
- `Cargo.toml` — add workspace-level `[workspace.package] license = "MIT"` + repo metadata; set per-crate `license.workspace = true`.
- `crates/netguard-core/src/lib.rs` — expose `port_probe` module.
- `crates/netguard-web/src/server.rs` — call `port_probe::try_bind_from`; `start_server` now returns the bound port.
- `crates/netguard-web/src/state.rs` — `listen_port` becomes the *bound* port (kept as existing field, value updated in `start_server`).
- `crates/netguard-web/src/api.rs` — add `get_status` handler + `StatusResponse` struct.
- `crates/netguard-web/src/server.rs` — route `GET /api/status`.
- `crates/netguard-mitm/src/bridge.rs` — probe ports before launching `mitmdump`; return chosen port from `start_bridge`.
- `crates/netguard-mitm/src/controller.rs` — track and expose `bound_listen_port()`.
- `crates/netguard-daemon/src/main.rs` — thread the bound web port back into state (no functional logic change beyond receiving the return value).
- `.github/workflows/build.yml` — add `nfpm_arch` matrix column, nfpm install + package-build steps, artifact upload globs, three smoke jobs, release-job file globs.
- `README.md` — add install instructions for `.deb` / `.rpm` / Arch packages.

---

## Phase A — Daemon runtime port fallback

Goal: a single well-tested helper in core, consumed by both the web server and the mitm bridge. This phase leaves packaging untouched; it's a standalone daemon improvement that CAN ship without the packaging work.

### Task A1: Port-probe helper in `netguard-core`

**Files:**
- Create: `crates/netguard-core/src/port_probe.rs`
- Modify: `crates/netguard-core/src/lib.rs`
- Test: `crates/netguard-core/src/port_probe.rs` (inline `#[cfg(test)]`)

- [ ] **Step 1: Create the test file with failing tests**

In a new file `crates/netguard-core/src/port_probe.rs`:

```rust
//! Bind a TCP listener starting at `start_port` and incrementing up to
//! `start_port + max_attempts - 1` if the starting port is busy.

use std::io;
use std::net::SocketAddr;
use tokio::net::TcpListener;

/// Try to bind a TCP listener, starting at `start_port`. If `AddrInUse`,
/// increment the port and retry up to `max_attempts - 1` additional times.
/// Returns `(listener, bound_port)`. Any error other than `AddrInUse`
/// aborts immediately.
pub async fn try_bind_from(
    addr: &str,
    start_port: u16,
    max_attempts: u16,
) -> io::Result<(TcpListener, u16)> {
    let mut last_err: Option<io::Error> = None;
    for offset in 0..max_attempts {
        let port = start_port.saturating_add(offset);
        let bind_addr: SocketAddr = format!("{addr}:{port}").parse().map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidInput, format!("bad bind addr: {e}"))
        })?;
        match TcpListener::bind(bind_addr).await {
            Ok(l) => return Ok((l, port)),
            Err(e) if e.kind() == io::ErrorKind::AddrInUse => {
                last_err = Some(e);
                continue;
            }
            Err(e) => return Err(e),
        }
    }
    Err(last_err.unwrap_or_else(|| {
        io::Error::new(io::ErrorKind::AddrInUse, "no free port in range")
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn returns_start_port_when_free() {
        // Bind to port 0 to get an OS-assigned port — guaranteed free,
        // then release and ask try_bind_from to claim it.
        let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);

        let (_listener, bound) = try_bind_from("127.0.0.1", port, 5).await.unwrap();
        assert_eq!(bound, port);
    }

    #[tokio::test]
    async fn falls_back_when_start_port_taken() {
        // Hold port N, ask helper to start at N with 5 attempts — expect N+1.
        let hold = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = hold.local_addr().unwrap().port();

        let (_listener, bound) = try_bind_from("127.0.0.1", port, 5).await.unwrap();
        assert!(bound >= port + 1 && bound <= port + 4,
            "expected fallback in range, got {bound}");
    }

    #[tokio::test]
    async fn errors_when_no_free_port_in_range() {
        // Occupy 3 consecutive ports, ask helper with max_attempts=3 → error.
        let a = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let start = a.local_addr().unwrap().port();
        // Attempt to grab start+1 and start+2. If either is taken by another
        // process on the test host, skip — this is a best-effort test.
        let Ok(_b) = tokio::net::TcpListener::bind(format!("127.0.0.1:{}", start + 1)).await else {
            return;
        };
        let Ok(_c) = tokio::net::TcpListener::bind(format!("127.0.0.1:{}", start + 2)).await else {
            return;
        };

        let result = try_bind_from("127.0.0.1", start, 3).await;
        assert!(result.is_err());
    }
}
```

- [ ] **Step 2: Add module to `lib.rs`**

In `crates/netguard-core/src/lib.rs`, add near the other `pub mod …` lines:

```rust
pub mod port_probe;
```

- [ ] **Step 3: Run tests — expect pass**

```bash
cargo test -p netguard-core port_probe
```

Expected: 3 passed.

- [ ] **Step 4: Commit**

```bash
git add crates/netguard-core/src/port_probe.rs crates/netguard-core/src/lib.rs
git commit -m "feat(core): add port_probe helper with +N fallback"
```

---

### Task A2: Wire port probe into the web server

**Files:**
- Modify: `crates/netguard-web/src/server.rs` (function `start_server` around line 191)
- Modify: `crates/netguard-web/src/state.rs` (update comment on `listen_port`)
- Modify: `crates/netguard-daemon/src/main.rs` (receive + thread bound port)

- [ ] **Step 1: Update `start_server` signature to use probe**

Replace `start_server` in `crates/netguard-web/src/server.rs` (lines ~191-206):

```rust
pub async fn start_server(
    state: AppState,
    addr: &str,
    start_port: u16,
) -> Result<u16, std::io::Error> {
    let (listener, bound_port) =
        netguard_core::port_probe::try_bind_from(addr, start_port, 20).await?;
    if bound_port != start_port {
        tracing::warn!(
            "configured web port {start_port} was busy; bound to {bound_port} instead"
        );
    } else {
        tracing::info!("Web UI bound to http://{addr}:{bound_port}");
    }

    // Update state so `/api/status` and ws handlers report the real port.
    // AppState is Clone (Arc inside), so `state.clone()` here points at the
    // same underlying fields — but `listen_port` is a plain u16 copy. We set
    // it on the clone that goes into the router below. Callers that need the
    // bound port get it from the return value.
    let mut state = state;
    state.listen_port = bound_port;

    let app = build_router(state);
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;
    Ok(bound_port)
}
```

- [ ] **Step 2: Update `AppState` doc comment in `state.rs`**

In `crates/netguard-web/src/state.rs`, replace the `pub listen_port: u16,` line with:

```rust
/// The port the web server is *actually* bound to. May differ from the
/// configured `web.listen_port` if that port was busy — the server uses
/// `port_probe::try_bind_from` with a +20 fallback window at startup.
pub listen_port: u16,
```

- [ ] **Step 3: Update caller in `netguard-daemon/src/main.rs`**

Find the call to `start_server` around line 318 (search for `start_server`). Current code passes a `web_port` and discards any return value. Update to capture the returned port (plan A2 does not need to *use* the port yet — task A4 surfaces it).

Replace the relevant block (single call site — search `start_server(` to locate it):

```rust
let bound_web_port = netguard_web::server::start_server(
    app_state.clone(),
    &config.web.listen_addr,
    config.web.listen_port,
).await?;
tracing::info!("web server bound to {bound_web_port}");
```

If the existing code uses `?` inline / spawns in a task, preserve that pattern — just thread the return value through.

- [ ] **Step 4: Build + run existing test suite**

```bash
cargo build --release -p netguard-web -p netguard-daemon
cargo test --workspace --no-fail-fast
```

Expected: build succeeds; existing tests still pass; the three new `port_probe` tests pass.

- [ ] **Step 5: Manual smoke — kill the normal port, confirm fallback**

Only run if you have a local dev environment with iptables access. Otherwise skip (CI + A4 covers this).

```bash
# In terminal 1 — hold port 3031
python3 -c "import socket; s=socket.socket(); s.bind(('127.0.0.1',3031)); s.listen(); input()"
# In terminal 2 — run daemon, observe "bound to 3032 instead" warning
sudo ./target/release/netguard --config config/netguard.toml
# Confirm the UI answers on 3032
curl -s http://127.0.0.1:3032/ | head -c 100
```

- [ ] **Step 6: Commit**

```bash
git add crates/netguard-web/src/server.rs crates/netguard-web/src/state.rs crates/netguard-daemon/src/main.rs
git commit -m "feat(web): runtime port fallback with +20 window"
```

---

### Task A3: Wire port probe into the mitmproxy bridge

**Files:**
- Modify: `crates/netguard-mitm/src/bridge.rs` (function that builds the `mitmdump` command around line 117-135)
- Modify: `crates/netguard-mitm/src/controller.rs` (store chosen port)

- [ ] **Step 1: Probe port before spawning mitmdump**

In `crates/netguard-mitm/src/bridge.rs`, inside the function that launches mitmdump (search for `.arg("mitmdump")` around line 117), add a port-probe step immediately before the `Command::new(...)` call:

```rust
// Find a free port starting at cfg.listen_port. Unlike the web UI we drop
// the probe listener immediately — mitmdump will bind it moments later,
// which is racy but the +20 window makes collisions vanishingly rare.
let bound_port = {
    let (probe, p) = netguard_core::port_probe::try_bind_from(
        "127.0.0.1",
        cfg.listen_port,
        20,
    )
    .await?;
    drop(probe);
    p
};
if bound_port != cfg.listen_port {
    tracing::warn!(
        "configured mitm port {} was busy; using {} instead",
        cfg.listen_port,
        bound_port,
    );
}
```

Then change the `.arg(cfg.listen_port.to_string())` line (~line 123) to use `bound_port.to_string()`. Also update the log line on ~line 158 (`runuser -u {} -- mitmdump --mode transparent --listen {}:{}`) to log `bound_port` instead of `cfg.listen_port`.

Finally, change the function's return type to include the port. Current likely signature returns a `BridgeHandle` (or similar). Change it to `Result<(BridgeHandle, u16), Error>` — the `u16` is `bound_port`. Update the single caller in `controller.rs` (next step).

- [ ] **Step 2: Store bound port in controller**

In `crates/netguard-mitm/src/controller.rs`, find the struct that holds the bridge handle (search for `bridge_cfg` ~line 50). Add a sibling field:

```rust
/// Port mitmdump is actually listening on. `None` while the bridge is
/// disabled. Written once when `enable()` successfully starts the bridge.
bound_listen_port: std::sync::Mutex<Option<u16>>,
```

In the constructor, initialize it to `Mutex::new(None)`.

In `enable()` (around line 140-170), capture the returned `(handle, port)` and store it:

```rust
let (handle, port) = start_bridge(&self.bridge_cfg).await?;
*self.bound_listen_port.lock().unwrap() = Some(port);
// ... existing handle-storage code ...
```

In `disable()` (around line 181 onwards), clear it:

```rust
*self.bound_listen_port.lock().unwrap() = None;
```

Add a public accessor:

```rust
pub fn bound_listen_port(&self) -> Option<u16> {
    *self.bound_listen_port.lock().unwrap()
}
```

Also, critically, the `install_redirect(uid, port)` call on line ~166 must now receive `port` (the returned value), not `self.bridge_cfg.listen_port`. Update that argument.

- [ ] **Step 3: Build**

```bash
cargo build --release -p netguard-mitm -p netguard-daemon
```

Expected: clean build.

- [ ] **Step 4: Run mitm unit tests**

```bash
cargo test -p netguard-mitm --no-fail-fast
```

Expected: existing tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/netguard-mitm/src/bridge.rs crates/netguard-mitm/src/controller.rs
git commit -m "feat(mitm): runtime port fallback for mitmdump launch"
```

---

### Task A4: Add `/api/status` endpoint

**Files:**
- Modify: `crates/netguard-web/src/api.rs` (add handler + response struct)
- Modify: `crates/netguard-web/src/server.rs` (add route)
- Test: integration-style test in `crates/netguard-web/src/api.rs` (`#[cfg(test)]`, optional — see step 3)

- [ ] **Step 1: Add `StatusResponse` + handler in `api.rs`**

Append to `crates/netguard-web/src/api.rs`:

```rust
#[derive(serde::Serialize)]
pub struct StatusResponse {
    /// Port the web UI is currently bound to.
    pub bound_web_port: u16,
    /// Port mitmdump is currently listening on, or null if mitmproxy is
    /// disabled.
    pub bound_mitm_port: Option<u16>,
    /// True iff mitmproxy is currently running (matches bound_mitm_port
    /// being Some, but explicit for UI legibility).
    pub mitm_enabled: bool,
}

pub async fn get_status(
    axum::extract::State(state): axum::extract::State<crate::state::AppState>,
) -> axum::Json<StatusResponse> {
    let bound_mitm_port = state.mitm_controller.bound_listen_port();
    axum::Json(StatusResponse {
        bound_web_port: state.listen_port,
        bound_mitm_port,
        mitm_enabled: bound_mitm_port.is_some(),
    })
}
```

- [ ] **Step 2: Register the route in `server.rs`**

In `crates/netguard-web/src/server.rs`, find the `api_routes` `Router::new()` chain (around line 62). Add:

```rust
        .route("/status", get(api::get_status))
```

Insert it right after `.route("/stats", get(api::get_stats))`.

- [ ] **Step 3: Build and smoke-test the endpoint**

```bash
cargo build --release -p netguard-web
cargo test -p netguard-web --no-fail-fast
```

Manual smoke (only if you have a running daemon):

```bash
TOKEN=$(sudo cat /etc/netguard/api_token)
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:3031/api/status | jq
```

Expected response:

```json
{
  "bound_web_port": 3031,
  "bound_mitm_port": null,
  "mitm_enabled": false
}
```

After enabling mitmproxy via the UI, `bound_mitm_port` should become a number (typically `8080`) and `mitm_enabled: true`.

- [ ] **Step 4: Commit**

```bash
git add crates/netguard-web/src/api.rs crates/netguard-web/src/server.rs
git commit -m "feat(web): add /api/status with bound port info"
```

---

## Phase B — Packaging assets

Can run in parallel with Phase A since it doesn't touch daemon code. The phase-A work is referenced in Phase C smoke tests but not in the packaging manifest itself.

### Task B1: Add LICENSE + update Cargo.toml

**Files:**
- Create: `LICENSE`
- Modify: `Cargo.toml`

- [ ] **Step 1: Create `LICENSE` with MIT text**

Write to `LICENSE`:

```
MIT License

Copyright (c) 2026 Dominik Drozd

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

- [ ] **Step 2: Add license metadata to `Cargo.toml`**

Open `Cargo.toml` (workspace root). Add a `[workspace.package]` block below `resolver = "2"`:

```toml
[workspace.package]
version = "0.3.0"
edition = "2021"
license = "MIT"
repository = "https://github.com/dominikjchs/NetworkLocalizerApp"
authors = ["Dominik Drozd <dominik@jchs.software>"]
```

(Adjust the `repository` URL if the actual repo path differs — grep git's remote if unsure: `git remote -v`.)

Then in each crate's `Cargo.toml` (`crates/netguard-core/Cargo.toml`, `crates/netguard-nfq/Cargo.toml`, `crates/netguard-web/Cargo.toml`, `crates/netguard-daemon/Cargo.toml`, `crates/netguard-mitm/Cargo.toml`), under `[package]`, add:

```toml
license.workspace = true
repository.workspace = true
authors.workspace = true
version.workspace = true
edition.workspace = true
```

Remove any duplicated `edition`, `version`, `authors` lines they had before (to avoid "overridden" warnings).

- [ ] **Step 3: Verify build still works**

```bash
cargo build --workspace
```

Expected: clean build, no "license not set" warnings.

- [ ] **Step 4: Commit**

```bash
git add LICENSE Cargo.toml crates/*/Cargo.toml
git commit -m "chore: add MIT LICENSE + workspace.package metadata"
```

---

### Task B2: Shared action shim + `postinstall.sh`

**Files:**
- Create: `packaging/scripts/_action.sh`
- Create: `packaging/scripts/postinstall.sh`

- [ ] **Step 1: Write `_action.sh` — action-normalizing shim**

Create `packaging/scripts/_action.sh`:

```sh
#!/bin/sh
# Normalize packaging-format args into a single $ACTION var.
#
# Debian: configure | remove | purge | upgrade | failed-upgrade   (in $1)
# RPM:    1 on first install, 2 on upgrade, 0 on uninstall         (in $1)
# Arch:   no args — separate pre_install/pre_upgrade/pre_remove fns;
#         nfpm collapses these into one script, so fallback is ok.
#
# Sets $ACTION to one of: install | upgrade | remove
# Not executed directly — sourced by the three lifecycle scripts.

case "${1:-install}" in
    configure|1)                   ACTION=install ;;
    2|upgrade|failed-upgrade)      ACTION=upgrade ;;
    0|remove|purge)                ACTION=remove ;;
    *)                             ACTION=install ;;
esac

export ACTION
```

- [ ] **Step 2: Write `postinstall.sh`**

Create `packaging/scripts/postinstall.sh`:

```sh
#!/bin/sh
# NetGuard package postinstall — idempotent, runs as root on install + upgrade.
# Distilled from deploy.sh steps 6 (provisioning) + 7 (enable service).
# Does NOT install the mitmproxy CA into the system trust store — that is
# an explicit opt-in via the web UI / CLI (see README §"Decrypting HTTPS").

set -e

. /usr/share/netguard/_action.sh "$@"

echo "netguard postinstall: action=$ACTION"

# ---- 1. System user for mitmproxy -----------------------------------------
if ! id -u netguard-mitm >/dev/null 2>&1; then
    echo "  creating netguard-mitm system user"
    useradd -r -s /usr/sbin/nologin netguard-mitm
fi

# ---- 2. Directories -------------------------------------------------------
install -d -o root -g root -m 0755 /etc/netguard
install -d -o root -g root -m 0750 /var/log/netguard
install -d -o netguard-mitm -g netguard-mitm -m 0750 /var/lib/netguard/mitm

# ---- 3. Default config — first install only ------------------------------
if [ ! -f /etc/netguard/netguard.toml ]; then
    echo "  installing default config"
    install -m 0644 /usr/share/netguard/netguard.toml /etc/netguard/netguard.toml
fi

if [ ! -f /etc/netguard/rules.json ]; then
    echo "  seeding empty rule set"
    printf '{"version":1,"rules":[]}\n' > /etc/netguard/rules.json
    chmod 0644 /etc/netguard/rules.json
fi

# ---- 4. Bootstrap mitmproxy CA (safe: doesn't touch system trust) --------
if [ ! -f /var/lib/netguard/mitm/mitmproxy-ca-cert.pem ]; then
    echo "  bootstrapping mitmproxy CA"
    BOOTSTRAP_PORT=$(awk 'BEGIN{srand(); print int(40000 + rand()*9999)}')
    sudo -u netguard-mitm env HOME=/var/lib/netguard/mitm \
        timeout -s KILL 4 \
        mitmdump \
            --set confdir=/var/lib/netguard/mitm \
            --listen-host 127.0.0.1 \
            --listen-port "$BOOTSTRAP_PORT" \
            --mode regular \
            --set termlog_verbosity=error \
            >/dev/null 2>&1 || true
    if [ -f /var/lib/netguard/mitm/mitmproxy-ca-cert.pem ]; then
        echo "  CA generated"
    else
        echo "  ! CA bootstrap failed — enable mitm from the UI to retry" >&2
    fi
fi

# ---- 5. Enable + start the service ---------------------------------------
systemctl daemon-reload
if [ "$ACTION" = "install" ]; then
    systemctl enable --now netguard.service
else
    # upgrade — restart if already enabled, but don't force-enable
    systemctl try-restart netguard.service || true
fi

echo "netguard postinstall: done"
echo "Web UI at http://127.0.0.1:$(awk -F'=' '/^listen_port/{gsub(/ /,"",$2); print $2; exit}' /etc/netguard/netguard.toml) (port may differ if in use; check journalctl -u netguard)"
```

- [ ] **Step 3: Make scripts executable + lint**

```bash
chmod +x packaging/scripts/postinstall.sh packaging/scripts/_action.sh
sh -n packaging/scripts/postinstall.sh
sh -n packaging/scripts/_action.sh
```

Expected: no output (syntax clean).

- [ ] **Step 4: Commit**

```bash
git add packaging/scripts/postinstall.sh packaging/scripts/_action.sh
git commit -m "feat(packaging): postinstall script + action-normalizing shim"
```

---

### Task B3: `preremove.sh`

**Files:**
- Create: `packaging/scripts/preremove.sh`

- [ ] **Step 1: Write `preremove.sh`**

Create `packaging/scripts/preremove.sh`:

```sh
#!/bin/sh
# NetGuard package preremove — stops the service cleanly. Disables it only
# on full removal, not on upgrade.

set -e

. /usr/share/netguard/_action.sh "$@"

echo "netguard preremove: action=$ACTION"

# Stop is best-effort — never fail a removal because the service was
# already dead.
systemctl stop netguard.service 2>/dev/null || true

# Disable only on full removal; on upgrade systemctl re-enables after the
# new unit is dropped in.
if [ "$ACTION" = "remove" ]; then
    systemctl disable netguard.service 2>/dev/null || true
fi

exit 0
```

- [ ] **Step 2: Make executable + syntax-check**

```bash
chmod +x packaging/scripts/preremove.sh
sh -n packaging/scripts/preremove.sh
```

- [ ] **Step 3: Commit**

```bash
git add packaging/scripts/preremove.sh
git commit -m "feat(packaging): preremove script (stop + conditional disable)"
```

---

### Task B4: `postremove.sh`

**Files:**
- Create: `packaging/scripts/postremove.sh`

- [ ] **Step 1: Write `postremove.sh`**

Create `packaging/scripts/postremove.sh`:

```sh
#!/bin/sh
# NetGuard package postremove — daemon-reload after unit file deletion.
#
# Intentional non-actions:
#   - Does NOT flush iptables. The daemon's ExecStopPost=netguard --cleanup
#     already ran during preremove's systemctl stop and removed NetGuard-
#     owned rules. Blanket iptables -F would wipe unrelated user rules.
#   - Does NOT remove /etc/netguard, /var/log/netguard, /var/lib/netguard.
#     These are user data. Debian `purge` removes /etc; RPM/Arch users
#     remove manually.
#   - Does NOT remove the netguard-mitm system user. Harmless to leave,
#     and removing it would orphan file ownership under /var/lib/netguard.

set -e

. /usr/share/netguard/_action.sh "$@"

echo "netguard postremove: action=$ACTION"

systemctl daemon-reload 2>/dev/null || true

exit 0
```

- [ ] **Step 2: Make executable + syntax-check**

```bash
chmod +x packaging/scripts/postremove.sh
sh -n packaging/scripts/postremove.sh
```

- [ ] **Step 3: Commit**

```bash
git add packaging/scripts/postremove.sh
git commit -m "feat(packaging): postremove script (daemon-reload only)"
```

---

### Task B5: `nfpm.yaml`

**Files:**
- Create: `packaging/nfpm.yaml`

- [ ] **Step 1: Write `nfpm.yaml`**

Create `packaging/nfpm.yaml`:

```yaml
# nfpm config for NetGuard — consumed by `nfpm pkg --packager {deb|rpm|archlinux}`.
#
# Environment variables required at pkg time:
#   NFPM_ARCH      — amd64 | arm64   (Debian naming; nfpm auto-translates)
#   NFPM_VERSION   — e.g. 1.2.3 or 0.0.0-dev.1713296312.abc1234
#   CARGO_TARGET   — e.g. x86_64-unknown-linux-gnu (to locate the built binary)

name: netguard
arch: ${NFPM_ARCH}
platform: linux
version: ${NFPM_VERSION}
section: net
priority: optional
maintainer: "Dominik Drozd <dominik@jchs.software>"
description: |
  NetGuard — Linux application firewall.
  Per-application outbound connection control via NFQUEUE, with optional
  transparent HTTPS decryption through a privilege-separated mitmproxy.
vendor: "Dominik Drozd"
homepage: "https://github.com/dominikjchs/NetworkLocalizerApp"
license: MIT

depends:
  - iptables
  - libnetfilter-queue1
  - libnfnetlink0
  - libmnl0
  - mitmproxy
  - ca-certificates

contents:
  - src: ../target/${CARGO_TARGET}/release/netguard
    dst: /usr/local/bin/netguard
    file_info:
      mode: 0755

  - src: ../config/netguard.toml
    dst: /usr/share/netguard/netguard.toml
    file_info:
      mode: 0644

  - src: ../systemd/netguard.service
    dst: /lib/systemd/system/netguard.service
    file_info:
      mode: 0644

  - src: ./scripts/_action.sh
    dst: /usr/share/netguard/_action.sh
    file_info:
      mode: 0755

  - src: ../LICENSE
    dst: /usr/share/doc/netguard/LICENSE
    file_info:
      mode: 0644
    packager: deb

  - src: ../LICENSE
    dst: /usr/share/doc/netguard/LICENSE
    file_info:
      mode: 0644
    packager: rpm

  - src: ../LICENSE
    dst: /usr/share/licenses/netguard/LICENSE
    file_info:
      mode: 0644
    packager: archlinux

scripts:
  postinstall: ./scripts/postinstall.sh
  preremove: ./scripts/preremove.sh
  postremove: ./scripts/postremove.sh

overrides:
  rpm:
    depends:
      - iptables
      - libnetfilter_queue
      - libnfnetlink
      - libmnl
      - mitmproxy
      - ca-certificates
  archlinux:
    depends:
      - iptables
      - libnetfilter_queue
      - libnfnetlink
      - libmnl
      - mitmproxy
      - ca-certificates-utils
```

- [ ] **Step 2: Install nfpm locally + validate config**

```bash
# Install nfpm locally (one-time — or skip and validate in CI only).
# On Linux:
curl -fsSL -o /tmp/nfpm.tar.gz \
  "https://github.com/goreleaser/nfpm/releases/download/v2.41.0/nfpm_2.41.0_Linux_x86_64.tar.gz"
sudo tar -xzf /tmp/nfpm.tar.gz -C /usr/local/bin nfpm
# On Windows dev box — skip; CI will validate.

# Validate (dry-run — fails if schema is bad)
cd packaging
NFPM_ARCH=amd64 NFPM_VERSION=0.0.0-test CARGO_TARGET=x86_64-unknown-linux-gnu \
  nfpm pkg --packager deb --config nfpm.yaml --target /tmp/test-deb/
```

Expected: success, produces `/tmp/test-deb/netguard_0.0.0-test_amd64.deb` (requires the binary to exist at `target/x86_64-unknown-linux-gnu/release/netguard` — build it first with `cargo build --release --target x86_64-unknown-linux-gnu`).

If you can't build locally (e.g. on Windows dev box), skip this step — CI catches it in task C2.

- [ ] **Step 3: Commit**

```bash
git add packaging/nfpm.yaml
git commit -m "feat(packaging): nfpm config for deb/rpm/archlinux"
```

---

### Task B6: Packaging README

**Files:**
- Create: `packaging/README.md`

- [ ] **Step 1: Write `packaging/README.md`**

Create `packaging/README.md`:

```markdown
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
```

- [ ] **Step 2: Commit**

```bash
git add packaging/README.md
git commit -m "docs(packaging): maintainer readme"
```

---

## Phase C — CI wiring

Depends on Phase B (nfpm.yaml + scripts must exist). Independent of Phase A at the packaging level (smoke tests verify service start, which does not *require* the port-fallback code, but Phase A is strongly recommended to ship alongside so the port field in `/api/status` is meaningful).

### Task C1: Extend `build` job matrix + version output

**Files:**
- Modify: `.github/workflows/build.yml`

- [ ] **Step 1: Add `nfpm_arch` to the matrix**

In `.github/workflows/build.yml`, find the `build` job's `strategy.matrix.include` block (line ~137). Update both matrix rows to add `nfpm_arch`:

```yaml
        include:
          - arch: x86_64
            runner: ubuntu-22.04
            target: x86_64-unknown-linux-gnu
            nfpm_arch: amd64
          - arch: aarch64
            runner: ubuntu-22.04-arm
            target: aarch64-unknown-linux-gnu
            nfpm_arch: arm64
```

- [ ] **Step 2: Split the version step to also emit a packaging-safe version**

Replace the existing `Determine version` step (line ~187) with:

```yaml
      - name: Determine version
        id: version
        run: |
          if [[ "${GITHUB_REF}" == refs/tags/* ]]; then
            VERSION="${GITHUB_REF#refs/tags/}"
            # Strip leading 'v' for nfpm — versions must start with a digit.
            NFPM_VERSION="${VERSION#v}"
          else
            # Dev build: lexically sortable, all three formats accept dashes.
            TS="$(date -u +%s)"
            SHA="$(git rev-parse --short HEAD)"
            VERSION="dev-$SHA"
            NFPM_VERSION="0.0.0-dev.${TS}.${SHA}"
          fi
          echo "version=$VERSION" >> "$GITHUB_OUTPUT"
          echo "nfpm_version=$NFPM_VERSION" >> "$GITHUB_OUTPUT"
          echo "Building version: $VERSION (nfpm: $NFPM_VERSION)"
```

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/build.yml
git commit -m "ci: add nfpm_arch to matrix + packaging-safe version string"
```

---

### Task C2: Install nfpm + build packages in `build` job

**Files:**
- Modify: `.github/workflows/build.yml`

- [ ] **Step 1: Add nfpm install step after `Build daemon (release)`**

Locate the `Build daemon (release)` step (line ~183) in the `build` job. Immediately **after** it, insert:

```yaml
      - name: Install nfpm
        run: |
          NFPM_VERSION=2.41.0
          curl -fsSL -o /tmp/nfpm.tar.gz \
            "https://github.com/goreleaser/nfpm/releases/download/v${NFPM_VERSION}/nfpm_${NFPM_VERSION}_Linux_${{ matrix.nfpm_arch }}.tar.gz"
          sudo tar -xzf /tmp/nfpm.tar.gz -C /usr/local/bin nfpm
          nfpm --version

      - name: Build packages (deb, rpm, archlinux)
        env:
          NFPM_ARCH: ${{ matrix.nfpm_arch }}
          NFPM_VERSION: ${{ steps.version.outputs.nfpm_version }}
          CARGO_TARGET: ${{ matrix.target }}
        working-directory: packaging
        run: |
          mkdir -p ../dist
          for fmt in deb rpm archlinux; do
            nfpm pkg --packager "$fmt" --config nfpm.yaml --target ../dist/
          done
          ( cd ../dist && sha256sum netguard* > packages.sha256 )
          ls -la ../dist/
```

- [ ] **Step 2: Extend the tarball-packaging step to leave packages in `dist/` alongside**

The existing `Package tarball` step (line ~199) puts its tarball in `dist/$PKG.tar.gz`. The new packages also land in `dist/`. No collision — tarball is named `netguard-VER-ARCH-linux.tar.gz`, packages are `netguard_VER_ARCH.deb` / `netguard-VER-ARCH.rpm` / `netguard-VER-ARCH.pkg.tar.zst`. No change needed.

- [ ] **Step 3: Update the artifact upload step**

The existing `upload-artifact` step (line ~218) uploads `dist/*.tar.gz` + `dist/*.sha256`. Replace its `path:` block with:

```yaml
          path: |
            dist/*.tar.gz
            dist/*.sha256
            dist/*.deb
            dist/*.rpm
            dist/*.pkg.tar.zst
            dist/packages.sha256
```

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/build.yml
git commit -m "ci: build deb/rpm/archlinux packages via nfpm"
```

---

### Task C3: Smoke test job — `.deb` on Debian 12

**Files:**
- Modify: `.github/workflows/build.yml`

- [ ] **Step 1: Append `smoke-deb` job after `build`**

After the `build` job (line ~224), before the `release` job, insert:

```yaml
  # ------------------------------------------------------------------
  # Smoke tests — install the just-built packages on a matching distro
  # container + assert the service starts + uninstall cleanly.
  # x86_64 only; aarch64 install-script parity is enforced by the
  # shared postinstall.sh.
  # ------------------------------------------------------------------
  smoke-deb:
    name: Smoke (deb / debian:12)
    needs: build
    runs-on: ubuntu-22.04
    timeout-minutes: 10
    container:
      image: debian:12
      options: --privileged --cap-add=NET_ADMIN --cap-add=NET_RAW --cgroupns=host --tmpfs /tmp --tmpfs /run --tmpfs /run/lock
    steps:
      - uses: actions/download-artifact@v4
        with:
          name: netguard-x86_64
          path: dist

      - name: Install base tools
        run: |
          apt-get update
          apt-get install -y systemd systemd-sysv ca-certificates curl procps

      - name: Bootstrap systemd
        run: |
          # Start systemd in the background; wait for it to come up.
          exec /lib/systemd/systemd --system --unit=multi-user.target &
          for i in $(seq 1 10); do
            systemctl is-system-running 2>/dev/null && break || sleep 1
          done
          systemctl --version

      - name: Install package
        run: |
          apt-get install -y ./dist/netguard_*_amd64.deb
          systemctl status netguard --no-pager || true

      - name: Assert service active
        run: |
          for i in $(seq 1 15); do
            if systemctl is-active --quiet netguard; then
              echo "netguard active after ${i}s"
              exit 0
            fi
            sleep 1
          done
          echo "netguard did not become active within 15s" >&2
          journalctl -u netguard --no-pager | tail -n 50 >&2
          exit 1

      - name: Uninstall
        run: |
          apt-get remove -y netguard
          test ! -f /lib/systemd/system/netguard.service || { echo "unit file leaked"; exit 1; }
          systemctl is-active --quiet netguard && { echo "service still active"; exit 1; } || true
          echo "clean removal"
```

- [ ] **Step 2: Commit**

```bash
git add .github/workflows/build.yml
git commit -m "ci: smoke test deb package on debian:12"
```

---

### Task C4: Smoke test job — `.rpm` on Fedora 40

**Files:**
- Modify: `.github/workflows/build.yml`

- [ ] **Step 1: Append `smoke-rpm` job after `smoke-deb`**

```yaml
  smoke-rpm:
    name: Smoke (rpm / fedora:40)
    needs: build
    runs-on: ubuntu-22.04
    timeout-minutes: 10
    container:
      image: fedora:40
      options: --privileged --cap-add=NET_ADMIN --cap-add=NET_RAW --cgroupns=host --tmpfs /tmp --tmpfs /run --tmpfs /run/lock
    steps:
      - uses: actions/download-artifact@v4
        with:
          name: netguard-x86_64
          path: dist

      - name: Install base tools
        run: |
          dnf install -y systemd ca-certificates curl procps-ng

      - name: Bootstrap systemd
        run: |
          exec /lib/systemd/systemd --system --unit=multi-user.target &
          for i in $(seq 1 10); do
            systemctl is-system-running 2>/dev/null && break || sleep 1
          done

      - name: Install package
        run: |
          dnf install -y ./dist/netguard-*.x86_64.rpm
          systemctl status netguard --no-pager || true

      - name: Assert service active
        run: |
          for i in $(seq 1 15); do
            if systemctl is-active --quiet netguard; then
              echo "netguard active after ${i}s"
              exit 0
            fi
            sleep 1
          done
          journalctl -u netguard --no-pager | tail -n 50 >&2
          exit 1

      - name: Uninstall
        run: |
          dnf remove -y netguard
          test ! -f /lib/systemd/system/netguard.service || { echo "unit file leaked"; exit 1; }
          echo "clean removal"
```

- [ ] **Step 2: Commit**

```bash
git add .github/workflows/build.yml
git commit -m "ci: smoke test rpm package on fedora:40"
```

---

### Task C5: Smoke test job — Arch `.pkg.tar.zst`

**Files:**
- Modify: `.github/workflows/build.yml`

- [ ] **Step 1: Append `smoke-arch` job after `smoke-rpm`**

```yaml
  smoke-arch:
    name: Smoke (archlinux)
    needs: build
    runs-on: ubuntu-22.04
    timeout-minutes: 10
    container:
      image: archlinux:base
      options: --privileged --cap-add=NET_ADMIN --cap-add=NET_RAW --cgroupns=host --tmpfs /tmp --tmpfs /run --tmpfs /run/lock
    steps:
      - uses: actions/download-artifact@v4
        with:
          name: netguard-x86_64
          path: dist

      - name: Install base tools
        run: |
          pacman -Sy --noconfirm
          pacman -S --noconfirm systemd ca-certificates curl procps-ng

      - name: Bootstrap systemd
        run: |
          exec /usr/lib/systemd/systemd --system --unit=multi-user.target &
          for i in $(seq 1 10); do
            systemctl is-system-running 2>/dev/null && break || sleep 1
          done

      - name: Install package
        run: |
          pacman -U --noconfirm ./dist/netguard-*.pkg.tar.zst
          systemctl status netguard --no-pager || true

      - name: Assert service active
        run: |
          for i in $(seq 1 15); do
            if systemctl is-active --quiet netguard; then
              echo "netguard active after ${i}s"
              exit 0
            fi
            sleep 1
          done
          journalctl -u netguard --no-pager | tail -n 50 >&2
          exit 1

      - name: Uninstall
        run: |
          pacman -R --noconfirm netguard
          test ! -f /lib/systemd/system/netguard.service || { echo "unit file leaked"; exit 1; }
          echo "clean removal"
```

- [ ] **Step 2: Commit**

```bash
git add .github/workflows/build.yml
git commit -m "ci: smoke test archlinux package"
```

---

### Task C6: Update release job

**Files:**
- Modify: `.github/workflows/build.yml`

- [ ] **Step 1: Add smoke jobs to release's `needs:`**

Locate `release:` job (line ~231). Update its `needs:` to include the three smoke jobs:

```yaml
    needs: [lint, test, build, smoke-deb, smoke-rpm, smoke-arch]
```

- [ ] **Step 2: Extend `files:` glob**

In the `softprops/action-gh-release@v2` step, replace the `files:` block with:

```yaml
          files: |
            release-artifacts/*.tar.gz
            release-artifacts/*.sha256
            release-artifacts/*.deb
            release-artifacts/*.rpm
            release-artifacts/*.pkg.tar.zst
            release-artifacts/packages.sha256
```

- [ ] **Step 3: Update release-notes body**

Replace the `body:` block with install instructions for all formats:

```yaml
          body: |
            ## NetGuard ${{ github.ref_name }}

            Linux application firewall — Rust + React. See README for install.

            ### Install

            **Debian / Ubuntu:**
            ```bash
            curl -fsSL -O https://github.com/${{ github.repository }}/releases/download/${{ github.ref_name }}/netguard_${{ github.ref_name }}_amd64.deb
            sudo apt install ./netguard_${{ github.ref_name }}_amd64.deb
            ```

            **Fedora / RHEL:**
            ```bash
            sudo dnf install https://github.com/${{ github.repository }}/releases/download/${{ github.ref_name }}/netguard-${{ github.ref_name }}.x86_64.rpm
            ```

            **Arch Linux:**
            ```bash
            curl -fsSL -O https://github.com/${{ github.repository }}/releases/download/${{ github.ref_name }}/netguard-${{ github.ref_name }}-x86_64.pkg.tar.zst
            sudo pacman -U netguard-${{ github.ref_name }}-x86_64.pkg.tar.zst
            ```

            **Tarball (any distro):**
            ```bash
            curl -fsSL -o netguard.tar.gz \
              https://github.com/${{ github.repository }}/releases/download/${{ github.ref_name }}/netguard-${{ github.ref_name }}-x86_64-linux.tar.gz
            tar -xzf netguard.tar.gz
            cd netguard-${{ github.ref_name }}-x86_64-linux
            ./deploy.sh
            ```

            **All install paths are "safe mode" by default:** mitmproxy stays disabled until you opt in via the web UI toggle. HTTPS decryption never happens on install.

            Verify with `sha256sum -c packages.sha256` (packages) or the matching `.sha256` file (tarball).
```

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/build.yml
git commit -m "ci(release): attach deb/rpm/arch packages + update notes"
```

---

## Phase D — Docs + release rehearsal

### Task D1: README install section update

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Locate the install section**

Grep for the existing install instructions:

```bash
grep -n -E "^##|install|deploy.sh" README.md | head -40
```

You're looking for the section that documents installing from the tarball.

- [ ] **Step 2: Add a native-package install block above the tarball instructions**

Insert (adjust heading level to match):

```markdown
### Install from a native package (recommended)

Grab the right file for your distro from [Releases](https://github.com/dominikjchs/NetworkLocalizerApp/releases):

| Distro | Command |
|---|---|
| Debian / Ubuntu | `sudo apt install ./netguard_<VER>_amd64.deb` |
| Fedora / RHEL | `sudo dnf install ./netguard-<VER>.x86_64.rpm` |
| Arch Linux | `sudo pacman -U netguard-<VER>-x86_64.pkg.tar.zst` |

The package pulls in runtime deps (`iptables`, `libnetfilter_queue`, `mitmproxy`, etc.), creates the `netguard-mitm` system user, seeds config under `/etc/netguard/`, bootstraps the mitmproxy CA, and starts the systemd service. HTTPS decryption is **off by default** — enable it from the web UI.

### Install from the tarball (any distro)

<existing-content-preserved>
```

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: native-package install instructions for deb/rpm/arch"
```

---

### Task D2: Release rehearsal (pre-release tag)

**Files:** none (CI-driven)

- [ ] **Step 1: Push a pre-release tag**

```bash
git tag v0.3.0-rc1
git push origin v0.3.0-rc1
```

- [ ] **Step 2: Watch CI**

Open the workflow run in the GitHub UI. Verify the following jobs pass:
- `lint`
- `test`
- `frontend`
- `build` (both x86_64 and aarch64)
- `smoke-deb`
- `smoke-rpm`
- `smoke-arch`
- `release`

- [ ] **Step 3: Inspect the draft release**

Visit `Releases → v0.3.0-rc1`. Confirm the following assets are attached:
- `netguard-v0.3.0-rc1-x86_64-linux.tar.gz` (+ `.sha256`)
- `netguard-v0.3.0-rc1-aarch64-linux.tar.gz` (+ `.sha256`)
- `netguard_0.3.0-rc1_amd64.deb`
- `netguard_0.3.0-rc1_arm64.deb`
- `netguard-0.3.0-rc1.x86_64.rpm`
- `netguard-0.3.0-rc1.aarch64.rpm`
- `netguard-0.3.0-rc1-x86_64.pkg.tar.zst`
- `netguard-0.3.0-rc1-aarch64.pkg.tar.zst`
- `packages.sha256`

- [ ] **Step 4: Install rehearsal (optional, on a real box)**

On a Debian/Ubuntu box:

```bash
wget https://github.com/dominikjchs/NetworkLocalizerApp/releases/download/v0.3.0-rc1/netguard_0.3.0-rc1_amd64.deb
sudo apt install ./netguard_0.3.0-rc1_amd64.deb
systemctl status netguard
curl -s http://127.0.0.1:3031/api/status -H "Authorization: Bearer $(sudo cat /etc/netguard/api_token)"
sudo apt remove netguard
```

- [ ] **Step 5: Promote to real release**

If rc1 passes all of the above, cut `v0.3.0`:

```bash
git tag v0.3.0
git push origin v0.3.0
```

- [ ] **Step 6: Delete the rc1 tag (optional cleanup)**

```bash
git tag -d v0.3.0-rc1
git push origin :refs/tags/v0.3.0-rc1
# And delete the rc1 release from the GitHub UI.
```

---

## Self-review checklist (already completed inline during plan-writing)

- ✅ Every spec section has a task (§3 → B1-B6, §4 → B5, §5 → B2-B4, §6 → A1-A4, §7 → C1, §8 → C2-C6, §9 → covered in A1/A2/A3 tests + smoke jobs, §10 → D2).
- ✅ Spec deviation called out at top (new `/api/status` endpoint vs. spec's "already loads").
- ✅ Type consistency: `bound_listen_port()` accessor name is used consistently (A3 defines it, A4 calls it).
- ✅ No placeholders.
- ✅ All code blocks are complete, not "similar to above".
