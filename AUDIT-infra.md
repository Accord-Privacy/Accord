# Accord Infrastructure Audit
*2026-02-17*

## Cargo.toml (Workspace)
| Severity | Finding |
|----------|---------|
| MEDIUM | `repository` field points to old `Gfisch27/Accord` — should be `Accord-Privacy/Accord` |
| LOW | Copyright in tauri.conf.json says "© 2025" — should be 2026 |
| LOW | `rust-version = "1.86"` — verify this is intentional minimum |

## Tauri Config (desktop/tauri.conf.json)
| Severity | Finding |
|----------|---------|
| HIGH | CSP `connect-src` allows `http:` and `ws:` (unencrypted). Production should restrict to `https:` and `wss:` only, with dev-only exception for localhost |
| MEDIUM | No `dangerousRemoteDomainIpcAccess` restrictions — default is fine but should be explicitly documented |
| LOW | `$schema` URL points to third-party `nicedayto/tauri-settings-schema` — should use official Tauri schema |

## Dockerfile
| Severity | Finding |
|----------|---------|
| MEDIUM | Healthcheck only checks `test -f /proc/1/cmdline` — not a real health check. Should curl/wget a health endpoint |
| MEDIUM | Dummy source caching trick only includes core + server, but workspace has 6 crates. Docker build will fail if other crates are referenced |
| LOW | No explicit version pinning for base images (`rust:1.86-slim`, `debian:bookworm-slim`) |

## CI (.github/workflows/)
| Severity | Finding |
|----------|---------|
| MEDIUM | `ci.yml` — tests only run `-p accord-core -p accord-core-minimal -p accord-server`. Missing: accord-cli, standalone-demo, desktop (at minimum `cargo check` all) |
| LOW | No clippy lint step |
| LOW | No security audit step (`cargo audit`) |
| LOW | Windows workflow has code signing env vars but no actual signing setup documented |

## Unpushed Changes
- 1 commit (`21eb865`) with 17 files not yet on GitHub
- Desktop UI server URL configurability, startup scripts, community docs
- Should push after audit fixes are applied
