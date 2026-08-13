# OTP Inbox Helm chart

Add the GitHub Pages chart repository:

```sh
helm repo add otp-inbox https://pmh-only.github.io/otp
helm repo update
```

Install with an existing Kubernetes Secret containing `CONNECT_ROSTACK_TOKEN` and `MAIL_ROSTACK_TOKEN`:

```sh
helm upgrade --install otp otp-inbox/otp-inbox \
  --namespace otp --create-namespace \
  --set secrets.existingSecret=otp-rostack
```

Alternatively, set `secrets.connectRostackToken` and `secrets.mailRostackToken` to let Helm create the Secret. Prefer an existing Secret in production so credentials are not stored in Helm release values.

## Bitwarden

Enable the chart-managed Bitwarden CLI sidecar and provide its personal API key through the same Secret:

```yaml
bitwarden:
  enabled: true

secrets:
  existingSecret: otp-secrets
```

The Secret must additionally contain `BW_CLIENTID` and `BW_CLIENTSECRET`. When Helm creates the Secret instead, set `secrets.bitwardenClientId` and `secrets.bitwardenClientSecret`. Sealed Secret users must provide encrypted `BW_CLIENTID` and `BW_CLIENTSECRET` entries. Set `bitwarden.server` for a self-hosted HTTPS server and `bitwarden.caCertPem` when it uses a private CA.

The sidecar defaults to `ghcr.io/pmh-only/otp-bitwarden-cli` with the chart app version. Override `bitwarden.image.repository` or `bitwarden.image.tag` when publishing the image elsewhere. Leave `bitwarden.enabled` false and set `config.bitwardenApiUrl` to continue using an externally managed `bw serve` endpoint.

## Sealed Secrets

To let the chart create a Bitnami `SealedSecret`, provide values encrypted with `kubeseal --raw`. The default strict scope binds ciphertext to both the Helm release's generated Secret name and its namespace:

```sh
kubeseal --raw --name otp-otp-inbox --namespace otp < connect-token.txt
```

```yaml
sealedSecret:
  enabled: true
  encryptedData:
    CONNECT_ROSTACK_TOKEN: Ag...
    MAIL_ROSTACK_TOKEN: Ag...
```

For namespace-wide or cluster-wide ciphertext, add the matching controller annotation under `sealedSecret.annotations`. `sealedSecret.enabled` and `secrets.existingSecret` are mutually exclusive.

## Gateway API

Enable an `HTTPRoute` and attach it to an existing Gateway:

```yaml
gatewayApi:
  enabled: true
  parentRefs:
    - name: public
      namespace: gateway-system
      sectionName: https
  hostnames:
    - otp.example.com
```

The Gateway listener must permit routes from the chart namespace. `gatewayApi.enabled` and `ingress.enabled` are mutually exclusive. Path matches and HTTPRoute filters can be configured through `gatewayApi.matches` and `gatewayApi.filters`.

The application stores session authorization and OTP data in process memory. The chart therefore defaults to one replica and uses the `Recreate` deployment strategy.
