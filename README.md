# ssl-handshake-check

The `ssl-handshake-check` verifies a TLS handshake succeeds for a configured domain and port using the available certificate authorities.

## Configuration

Set these environment variables in the `HealthCheck` spec:

- `DOMAIN_NAME` (required): domain name to check.
- `PORT` (required): TLS port to check (for example, `443`).
- `SELF_SIGNED` (required): set to `true` when using self-signed certificates.

If you use a custom certificate, mount it at `/etc/ssl/selfsign/certificate.crt` as shown in the file-based example.

## Build

- `just build` builds the container image locally.
- `just test` runs unit tests.
- `just binary` builds the binary in `bin/`.

## Example HealthCheck

Apply the example below or the provided `healthcheck.yaml`:

```yaml
apiVersion: kuberhealthy.github.io/v2
kind: HealthCheck
metadata:
  name: ssl-handshake
  namespace: kuberhealthy
spec:
  runInterval: 5m
  timeout: 10m
  podSpec:
    spec:
      containers:
        - name: ssl-handshake
          image: kuberhealthy/ssl-handshake-check:sha-<short-sha>
          imagePullPolicy: IfNotPresent
          env:
            - name: DOMAIN_NAME
              value: "kubernetes.default"
            - name: PORT
              value: "443"
            - name: SELF_SIGNED
              value: "true"
      restartPolicy: Never
```
