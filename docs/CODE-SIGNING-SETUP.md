# Windows Code Signing Setup

## Why Sign?
Without code signing, Windows shows SmartScreen warnings that scare users. For beta this is acceptable (click "More info" → "Run anyway"), but for public release you need a certificate.

## Options (cheapest to most expensive)

### 1. Self-Signed (Free, beta only)
- Still shows warnings but installer works
- **Current approach** — fine for Gage's testing

### 2. SignPath.io (Free for OSS)
- Free code signing for open-source projects
- Apply at https://signpath.io/open-source
- Integrates with GitHub Actions

### 3. SSL.com EV Certificate (~$300-500/year)
- Instant SmartScreen reputation (no warning period)
- EV = Extended Validation, best for installers
- Store in GitHub Secrets as base64-encoded PFX

### 4. Certum Open Source Certificate (~$25/year)
- Cheapest real certificate
- Takes time to build SmartScreen reputation
- https://shop.certum.eu/open-source-code-signing-certificate.html

## GitHub Actions Integration

Once you have a certificate, add these repo secrets:
- `TAURI_SIGNING_PRIVATE_KEY` — the signing key
- `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` — key password

For Windows Authenticode (PFX-based), update the workflow:
```yaml
env:
  WINDOWS_CERTIFICATE: ${{ secrets.WINDOWS_CERTIFICATE_BASE64 }}
  WINDOWS_CERTIFICATE_PASSWORD: ${{ secrets.WINDOWS_CERTIFICATE_PASSWORD }}
```

And in `tauri.conf.json`, set `certificateThumbprint` to your cert's thumbprint.

## Recommendation
Start with **no signing** (beta), apply to **SignPath** for free OSS signing, upgrade to **SSL.com EV** before public launch.
