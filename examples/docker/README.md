## Docker usage (devguard)

This repo ships a `Dockerfile` with an entrypoint that runs `devguard`.

### Build

```bash
docker build -t devguard:local .
```

### Run (plain)

```bash
docker run --rm devguard:local --help
```

### Run a public GitHub leak scan (redacted output)

This uses the spec-driven sweep (`public_github_secrets`) and writes a redacted JSON report.

```bash
docker run --rm \
  -e GITHUB_TOKEN="$(gh auth token)" \
  -v "$PWD/.state:/app/.state" \
  devguard:local \
  sweep --spec devguard.spec.fast.yaml --only public_github_secrets
```

### Embed in another Dockerfile (base-image pattern)

```dockerfile
FROM devguard:local AS devguard

FROM debian:stable-slim

# Copy the devguard virtualenv and entrypoint.
COPY --from=devguard /app /opt/devguard

ENV PATH="/opt/devguard/.venv/bin:${PATH}" \
    DEVGUARD_SPEC="/opt/devguard/devguard.spec.fast.yaml"

ENTRYPOINT ["devguard"]
CMD ["sweep", "--spec", "/opt/devguard/devguard.spec.fast.yaml", "--only", "public_github_secrets"]
```
