# OTP Inbox

Collects verification codes from the `sms-messages` and `mailbox-entries` Rostack resources and presents a normalized, copyable inbox. Rostack credentials remain server-side and message bodies are not returned to the browser.

The backend is a dependency-free Go service. Browser code is TypeScript compiled by the Go-native TypeScript 7 compiler (`tsgo`). Node.js is not used for building or running the application.

## Run

Create `.env` from `.env.example`, set `CONNECT_ROSTACK_TOKEN` and `MAIL_ROSTACK_TOKEN`, then run:

```sh
go install github.com/microsoft/typescript-go/cmd/tsgo@latest
tsgo -p tsconfig.json
go run .
```

For development, run the watcher:

```sh
./scripts/dev.sh
```

It rebuilds the frontend with `tsgo` and restarts the Go server when Go, TypeScript, HTML, CSS, or `tsconfig.json` files change.

The service discovers both Rostack implementations, polls their collection snapshots every 15 seconds, and serves the UI on port 3000. See `.env.example` for optional endpoint and timing configuration.

## Bitwarden TOTP

Set `BITWARDEN_API_URL` to a logged-in [Bitwarden CLI `bw serve`](https://bitwarden.com/help/cli/) endpoint. The browser prompts for the master password when the vault is locked. The backend forwards it once to Bitwarden's `/unlock` endpoint and does not retain it.

```sh
bw sync
bw serve --hostname all --port 8087
```

Logging in with `bw login --apikey` does not decrypt the vault; the user must still unlock it with their master password. The application reads login items containing `login.totp`, calculates RFC 6238 codes in Go, and streams code rollover to the browser once per second. Master passwords and TOTP seeds remain server-side and are not written to browser storage.

The current `bw serve` implementation does not authenticate individual HTTP requests. Never expose it publicly; isolate it on loopback or a private sidecar network. `BITWARDEN_API_TOKEN` is optional and is sent as a bearer token only when an authenticated reverse proxy protects the endpoint. Omit `BITWARDEN_API_URL` to disable Bitwarden support.

### Bitwarden sidecar image

`Dockerfile.bitwarden` creates a dedicated Bitwarden CLI image. On startup it:

1. Configures `BW_SERVER` when supplied.
2. Logs in non-interactively using `BW_CLIENTID` and `BW_CLIENTSECRET`.
3. Downloads the encrypted vault during login.
4. Starts `bw serve` on port 8087 while leaving the vault locked.

Build it directly with:

```sh
docker build -f Dockerfile.bitwarden -t otp-bitwarden-cli .
```

The included `docker-compose.yml` connects the OTP service and sidecar through an internal-only network. The sidecar also joins the default network so it can reach the configured Bitwarden server over HTTPS; port 8087 remains unpublished.

```sh
docker compose up --build
```

For Compose development with automatic image rebuilds and container restarts when files change:

```sh
docker compose up --watch
```

Application source and static asset changes rebuild `otp`. Changes to `Dockerfile.bitwarden` or its entrypoint rebuild only `bitwarden-cli`.

Set `BW_CLIENTID` and `BW_CLIENTSECRET` to the personal API key values from Bitwarden account settings. These authenticate the CLI but cannot replace the master password required by the frontend unlock form. Do not publish sidecar port 8087.

`BW_SERVER` must use HTTPS. For Bitwarden cloud, omit it or use `https://vault.bitwarden.com`. Plain HTTP is rejected by Bitwarden CLI. For a self-hosted server with a private CA, set its PEM certificate in `BITWARDEN_CA_CERT_PEM`; the entrypoint writes it only to memory-backed storage.

### Non-persistence

Both containers use read-only root filesystems. Bitwarden CLI configuration, encrypted vault cache, login state, and optional CA material live only in a `tmpfs` mounted at `/data`. OTP records and parsed TOTP seeds exist only in Go process memory. There are no named volumes, databases, browser storage, or host bind mounts. Restarting the containers erases all runtime state and requires Bitwarden API-key login and master-password unlock again.

Only 4-8 digit values near verification terminology are accepted. Codes older than `OTP_MAX_AGE_MS` are discarded.

After five minutes without pointer, keyboard, touch, or scroll activity, the server locks Bitwarden, erases received OTPs and cached TOTP seeds, and prevents polling from repopulating codes. The user must enter the master password again. Configure the deadline with `INACTIVITY_TIMEOUT_MS`.

When Bitwarden is configured, its master-password unlock protects the entire workspace. Received SMS/mail OTPs are not collected into the visible in-memory store until the vault has been unlocked, and both received OTPs and TOTP codes are cleared together when the workspace locks.

Each browser tab creates a random capability in `sessionStorage`. The backend authorizes only the tab that submitted the successful master-password unlock and requires that capability on snapshots, refreshes, activity reports, and realtime streams. Other tabs and browsers remain locked and receive no OTP or TOTP data even while the shared Bitwarden sidecar process is unlocked. Closing the tab discards its capability.

Run backend tests with `go test ./...`. The Docker build compiles both TypeScript and Go and produces a minimal runtime image containing only the application binary and CA certificates.

## Helm

Released charts are published through GitHub Pages:

```sh
helm repo add otp-inbox https://pmh-only.github.io/otp
helm repo update
helm upgrade --install otp otp-inbox/otp-inbox \
  --namespace otp --create-namespace \
  --set secrets.existingSecret=otp-rostack
```

The referenced Secret must contain `CONNECT_ROSTACK_TOKEN` and `MAIL_ROSTACK_TOKEN`. See [`charts/otp/README.md`](charts/otp/README.md) for chart configuration details.
