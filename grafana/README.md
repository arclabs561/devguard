# Grafana Integration for Guardian

Guardian exports Prometheus metrics that can be visualized in Grafana.

## Setup

### 1. Install Prometheus

```bash
# Using Homebrew (macOS)
brew install prometheus

# Or download from https://prometheus.io/download/
```

### 2. Configure Prometheus

Create `prometheus.yml`:

```yaml
global:
  scrape_interval: 30s

scrape_configs:
  - job_name: 'devguard'
    static_configs:
      - targets: ['localhost:9090']  # Guardian metrics port
```

### 3. Start Prometheus

```bash
prometheus --config.file=prometheus.yml
```

### 4. Import Grafana Dashboard

1. Start Grafana (or use Grafana Cloud)
2. Go to Dashboards → Import
3. Upload `grafana/dashboards/devguard.json`
4. Select Prometheus as the data source
5. Configure the dashboard

## Metrics Available

### Check Metrics
- `devguard_checks_total` - Total checks performed (by type and status)
- `devguard_check_duration_seconds` - Check duration histogram
- `devguard_check_errors_total` - Check errors (by type)

### Security Metrics
- `devguard_vulnerabilities_total` - Vulnerabilities (by severity)
- `devguard_repository_alerts_total` - Repository alerts (by state)

### Deployment Metrics
- `devguard_deployments_total` - Deployments (by status)

### Cost Metrics
- `devguard_service_cost_usd` - Service costs in USD (by service and period)
- `devguard_service_usage` - Service usage (by service and unit)
- `devguard_service_usage_percent` - Usage percentage (0-100)
- `devguard_service_usage_limit` - Usage limits

## Dashboard Features

The Guardian Grafana dashboard includes:

1. **Overview Panels**
   - Total checks
   - Vulnerabilities count
   - Unhealthy deployments
   - Total service costs

2. **Usage Tracking**
   - Service usage over time
   - Usage percentage with thresholds
   - Cost breakdown by service

3. **Security Monitoring**
   - Vulnerabilities by severity
   - Check success rate
   - Error breakdown

4. **Cost Management**
   - Service costs over time
   - Cost breakdown table
   - Usage vs limits

## Accessing Metrics

Guardian exposes metrics at:
- Dashboard: `http://localhost:8080/metrics`
- Standalone: `http://localhost:9090/metrics` (if metrics server enabled)

## Configuration

Set in `.env`:
```bash
METRICS_ENABLED=true
METRICS_PORT=9090
```

## Grafana Cloud

You can also use Grafana Cloud:
1. Sign up at https://grafana.com
2. Create a Prometheus data source
3. Configure remote_write in Prometheus to send to Grafana Cloud
4. Import the dashboard JSON

