## Docker usage (Guardian)

This repo ships a `Dockerfile` with an entrypoint that runs `guardian`.

### Build

```bash
docker build -t guardian:local .
```

### Run (plain)

```bash
docker run --rm guardian:local --help
```

### Run a public GitHub leak scan (redacted output)

This uses the spec-driven sweep (`public_github_secrets`) and writes a redacted JSON report.

```bash
docker run --rm \
  -e GITHUB_TOKEN="$(gh auth token)" \
  -v "$PWD/.state:/app/.state" \
  guardian:local \
  sweep --spec guardian.spec.fast.yaml --only public_github_secrets
```

### Embed in another Dockerfile (base-image pattern)

```dockerfile
FROM guardian:local AS guardian

FROM debian:stable-slim

# Copy the Guardian virtualenv and entrypoint.
COPY --from=guardian /app /opt/guardian

ENV PATH="/opt/guardian/.venv/bin:${PATH}" \
    GUARDIAN_SPEC="/opt/guardian/guardian.spec.fast.yaml"

ENTRYPOINT ["guardian"]
CMD ["sweep", "--spec", "/opt/guardian/guardian.spec.fast.yaml", "--only", "public_github_secrets"]
```
