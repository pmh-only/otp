#!/bin/sh
set -eu

if [ -z "${BW_CLIENTID:-}" ]; then
  printf '%s\n' 'BW_CLIENTID is required' >&2
  exit 1
fi

if [ -z "${BW_CLIENTSECRET:-}" ]; then
  printf '%s\n' 'BW_CLIENTSECRET is required' >&2
  exit 1
fi

if [ -n "${BITWARDEN_CA_CERT_PEM:-}" ]; then
  printf '%s\n' "$BITWARDEN_CA_CERT_PEM" > /data/bitwarden-ca.pem
  export NODE_EXTRA_CA_CERTS=/data/bitwarden-ca.pem
fi

if [ -n "${BW_SERVER:-}" ]; then
  case "$BW_SERVER" in
    https://*) ;;
    *)
      printf 'BW_SERVER must use HTTPS, got: %s\n' "$BW_SERVER" >&2
      printf '%s\n' 'For self-signed HTTPS, mount the CA certificate and set NODE_EXTRA_CA_CERTS.' >&2
      exit 1
      ;;
  esac
  bw config server "$BW_SERVER" >/dev/null
fi

status="$(bw status | node -e '
let input = "";
process.stdin.on("data", chunk => input += chunk);
process.stdin.on("end", () => {
  try { process.stdout.write(JSON.parse(input).status || "unknown"); }
  catch { process.stdout.write("unknown"); }
});
')"

if [ "$status" = "unauthenticated" ]; then
  bw login --apikey >/dev/null
fi

status="$(bw status | node -e '
let input = "";
process.stdin.on("data", chunk => input += chunk);
process.stdin.on("end", () => {
  try { process.stdout.write(JSON.parse(input).status || "unknown"); }
  catch { process.stdout.write("unknown"); }
});
')"

if [ "$status" != "locked" ] && [ "$status" != "unlocked" ]; then
  printf 'Bitwarden login failed; status is %s\n' "$status" >&2
  exit 1
fi

# API-key login authenticates and syncs encrypted vault data, but deliberately
# leaves the vault locked until the user unlocks it through the OTP frontend.
exec bw serve --hostname all --port 8087
