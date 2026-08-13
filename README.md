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

Only 4-8 digit values near verification terminology are accepted. Codes older than `OTP_MAX_AGE_MS` are discarded.

Run backend tests with `go test ./...`. The Docker build compiles both TypeScript and Go and produces a minimal runtime image containing only the application binary and CA certificates.
