"""Web dashboard for devguard monitoring."""

import hashlib
import hmac
import logging
import os
import secrets
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request, Security, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.security import APIKeyHeader
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from devguard.config import get_settings
from devguard.core import Guardian

logger = logging.getLogger(__name__)


def get_real_client_ip(request: Request) -> str:
    """Get real client IP, respecting proxy headers.

    Priority:
    1. Fly-Client-IP (Fly.io)
    2. CF-Connecting-IP (Cloudflare)
    3. X-Real-IP (nginx)
    4. X-Forwarded-For (first IP in chain)
    5. request.client.host (direct connection)
    """
    # Fly.io sets this header
    fly_ip = request.headers.get("Fly-Client-IP")
    if fly_ip:
        return fly_ip

    # Cloudflare sets this header
    cf_ip = request.headers.get("CF-Connecting-IP")
    if cf_ip:
        return cf_ip

    # Common proxy header
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip

    # X-Forwarded-For can contain multiple IPs: client, proxy1, proxy2
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        # First IP is the original client
        return forwarded_for.split(",")[0].strip()

    # Fall back to direct connection
    if request.client:
        return request.client.host

    return "unknown"


# Rate limiting with proxy-aware IP detection
limiter = Limiter(key_func=get_real_client_ip)

# API Key authentication
API_KEY_NAME = "X-API-Key"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

# Session configuration
SESSION_TIMEOUT_SECONDS = 24 * 60 * 60  # 24 hours
SESSION_COOKIE_NAME = "devguard_session"


def _get_session_secret() -> bytes:
    """Get or derive the session signing secret."""
    settings = get_settings()
    # Use dashboard API key as base for session secret
    # If not set, use a per-process random secret (sessions won't survive restarts)
    if settings.dashboard_api_key:
        return hashlib.sha256(settings.dashboard_api_key.encode()).digest()
    else:
        # Generate a random secret for development (not persistent)
        if not hasattr(_get_session_secret, "_dev_secret"):
            _get_session_secret._dev_secret = secrets.token_bytes(32)
            logger.warning("Using ephemeral session secret (development mode)")
        return _get_session_secret._dev_secret


def _sign_session(data: str) -> str:
    """Create a signed session token."""
    secret = _get_session_secret()
    signature = hmac.new(secret, data.encode(), hashlib.sha256).hexdigest()
    return f"{data}.{signature}"


def _verify_signed_session(token: str) -> str | None:
    """Verify a signed session token and return the data if valid."""
    if "." not in token:
        return None

    try:
        data, signature = token.rsplit(".", 1)
        secret = _get_session_secret()
        expected_sig = hmac.new(secret, data.encode(), hashlib.sha256).hexdigest()

        if not hmac.compare_digest(signature, expected_sig):
            return None

        return data
    except Exception:
        return None


def create_session_token() -> str:
    """Create a new signed session token with expiry."""
    expiry = int(time.time()) + SESSION_TIMEOUT_SECONDS
    session_id = secrets.token_urlsafe(16)
    data = f"{session_id}:{expiry}"
    return _sign_session(data)


def verify_session(request: Request) -> str:
    """Verify session cookie (stateless, signed)."""
    session_token = request.cookies.get(SESSION_COOKIE_NAME)
    if not session_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session required",
        )

    data = _verify_signed_session(session_token)
    if not data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid session",
        )

    try:
        session_id, expiry_str = data.split(":", 1)
        expiry = int(expiry_str)

        if time.time() > expiry:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session expired",
            )

        return session_id
    except (ValueError, TypeError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid session format",
        )


def verify_api_key(api_key: str = Security(api_key_header)) -> str:
    """Verify API key from header."""
    settings = get_settings()
    expected_key = settings.dashboard_api_key
    if not expected_key:
        logger.warning("DASHBOARD_API_KEY not set - allowing all access (development mode)")
        return "dev"
    if not api_key or api_key != expected_key:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or missing API key",
        )
    return api_key


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager for startup/shutdown."""
    logger.info("devguard dashboard server starting")
    yield
    logger.info("devguard dashboard server shutting down")


app = FastAPI(
    title="devguard Dashboard",
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
)

# Add rate limiting
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS configuration
settings = get_settings()
allowed_origins = settings.allowed_origins
if not allowed_origins:
    allowed_origins = []

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Security headers middleware
@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    """Add security headers to all responses."""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    if settings.environment == "production":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


@app.get("/", response_class=HTMLResponse)
@limiter.limit("30/minute")
async def dashboard(request: Request):
    """Main dashboard page."""
    csrf_token = secrets.token_urlsafe(32)
    html = get_dashboard_html(csrf_token)
    return HTMLResponse(content=html)


@app.get("/config", response_class=HTMLResponse)
@limiter.limit("30/minute")
async def config_page(request: Request):
    """Configuration browser page."""
    html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>devguard Configuration</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: #0a0a0a;
            color: #e0e0e0;
            padding: 20px;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        h1 { color: #4a9eff; margin-bottom: 20px; }
        .nav { margin-bottom: 20px; }
        .nav a { color: #4a9eff; margin-right: 20px; text-decoration: none; }
        .nav a:hover { text-decoration: underline; }
        .section { background: #1a1a1a; padding: 20px; margin-bottom: 20px; border-radius: 8px; }
        .section h2 { color: #4a9eff; margin-bottom: 15px; }
        .config-item { display: flex; justify-content: space-between; padding: 10px; border-bottom: 1px solid #2a2a2a; }
        .config-item:last-child { border-bottom: none; }
        .config-label { color: #888; }
        .config-value { color: #fff; font-weight: bold; }
        .status-ok { color: #44ff44; }
        .status-error { color: #ff4444; }
        .refresh-btn { 
            background: #4a9eff; 
            color: #000; 
            border: none; 
            padding: 10px 20px; 
            border-radius: 4px; 
            cursor: pointer; 
            margin-top: 20px;
        }
        .refresh-btn:hover { background: #5ab0ff; }
    </style>
</head>
<body>
    <div class="container">
        <h1>devguard Configuration</h1>
        <div class="nav">
            <a href="/">Dashboard</a>
            <a href="/config">Configuration</a>
        </div>
        <div id="config"></div>
        <button class="refresh-btn" onclick="loadConfig()">Refresh</button>
    </div>
    <script>
        async function loadConfig() {
            try {
                const response = await fetch('/api/config');
                const config = await response.json();
                renderConfig(config);
            } catch (error) {
                document.getElementById('config').innerHTML = 
                    '<div class="section"><p style="color: #ff4444;">Error loading config</p></div>';
            }
        }

        function renderConfig(config) {
            let html = '';

            // Services
            html += '<div class="section"><h2>API Keys & Services</h2>';
            for (const [service, data] of Object.entries(config.services)) {
                const status = data.configured ? '<span class="status-ok">✓ Configured</span>' : 
                              '<span class="status-error">✗ Not configured</span>';
                html += `<div class="config-item">
                    <span class="config-label">${service}</span>
                    <span class="config-value">${status}</span>
                </div>`;
            }
            html += '</div>';

            // Monitoring
            html += '<div class="section"><h2>Monitoring Configuration</h2>';
            for (const [key, value] of Object.entries(config.monitoring)) {
                html += `<div class="config-item">
                    <span class="config-label">${key.replace(/_/g, ' ')}</span>
                    <span class="config-value">${value}</span>
                </div>`;
            }
            html += '</div>';

            // Dashboard
            html += '<div class="section"><h2>Dashboard Configuration</h2>';
            for (const [key, value] of Object.entries(config.dashboard)) {
                const displayValue = typeof value === 'boolean' ? (value ? 'Yes' : 'No') : value;
                html += `<div class="config-item">
                    <span class="config-label">${key.replace(/_/g, ' ')}</span>
                    <span class="config-value">${displayValue}</span>
                </div>`;
            }
            html += '</div>';

            // Environment
            html += `<div class="section"><h2>Environment</h2>
                <div class="config-item">
                    <span class="config-label">Mode</span>
                    <span class="config-value">${config.environment}</span>
                </div>
            </div>`;

            document.getElementById('config').innerHTML = html;
        }

        // Load on page load
        loadConfig();
    </script>
</body>
</html>
"""
    return HTMLResponse(content=html)


def get_dashboard_html(csrf_token: str) -> str:
    """Generate dashboard HTML."""
    return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>devguard Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto,
                Oxygen, Ubuntu, Cantarell, sans-serif;
            background: #0a0a0a;
            color: #e0e0e0;
            padding: 20px;
            line-height: 1.6;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        h1 {
            color: #4a9eff;
            margin-bottom: 30px;
        }
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .card {
            background: #1a1a1a;
            border: 1px solid #2a2a2a;
            border-radius: 8px;
            padding: 20px;
        }
        .card h3 {
            color: #888;
            font-size: 14px;
            margin-bottom: 10px;
            text-transform: uppercase;
        }
        .card .value {
            font-size: 32px;
            font-weight: bold;
            color: #4a9eff;
        }
        .card .critical { color: #ff4444; }
        .card .warning { color: #ffaa00; }
        .card .healthy { color: #44ff44; }
        .checks {
            margin-top: 30px;
        }
        .check-item {
            background: #1a1a1a;
            border: 1px solid #2a2a2a;
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 15px;
        }
        .check-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }
        .check-type {
            font-weight: bold;
            color: #4a9eff;
        }
        .check-status {
            padding: 4px 12px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: bold;
        }
        .status-success { background: #44ff44; color: #000; }
        .status-error { background: #ff4444; color: #fff; }
        .refresh-info {
            color: #666;
            font-size: 12px;
            margin-top: 20px;
            text-align: center;
        }
        .error { color: #ff4444; }
    </style>
</head>
<body>
    <div class="container">
        <h1>devguard Dashboard</h1>
        <div style="margin-bottom: 20px;">
            <a href="/" style="color: #4a9eff; margin-right: 20px;">Dashboard</a>
            <a href="/config" style="color: #4a9eff;">Configuration</a>
        </div>
        <div class="summary" id="summary"></div>
        <div class="checks" id="checks"></div>
        <div class="refresh-info">Auto-refreshing every 30 seconds</div>
    </div>
    <script>
        async function fetchData() {
            try {
                const response = await fetch('/api/report');
                if (!response.ok) throw new Error('Failed to fetch');
                const data = await response.json();
                updateDashboard(data);
            } catch (error) {
                console.error('Error fetching data:', error);
                const errorMsg = 'Error loading data. Check console for details.';
                document.getElementById('checks').innerHTML =
                    `<div class="check-item error">${errorMsg}</div>`;
            }
        }

        function updateDashboard(data) {
            const summary = data.summary || {};
            const checks = data.checks || [];

            // Update summary
            const summaryHtml = `
                <div class="card">
                    <h3>Total Checks</h3>
                    <div class="value">${summary.total_checks || 0}</div>
                </div>
                <div class="card">
                    <h3>Vulnerabilities</h3>
                    <div class="value ${summary.total_vulnerabilities > 0 ? 'critical' : 'healthy'}">
                        ${summary.total_vulnerabilities || 0}
                    </div>
                </div>
                <div class="card">
                    <h3>Critical</h3>
                    <div class="value critical">${summary.critical_vulnerabilities || 0}</div>
                </div>
                <div class="card">
                    <h3>Unhealthy Deployments</h3>
                    <div class="value ${summary.unhealthy_deployments > 0 ? 'warning' : 'healthy'}">
                        ${summary.unhealthy_deployments || 0}
                    </div>
                </div>
                <div class="card">
                    <h3>Total Cost (USD)</h3>
                    <div class="value ${summary.total_cost_usd > 0 ? 'warning' : 'healthy'}">
                        $${(summary.total_cost_usd || 0).toFixed(2)}
                    </div>
                </div>
            `;
            document.getElementById('summary').innerHTML = summaryHtml;

            // Update checks
            const checksHtml = checks.map(check => `
                <div class="check-item">
                    <div class="check-header">
                        <span class="check-type">${check.check_type.toUpperCase()}</span>
                        <span class="check-status ${check.success ? 'status-success' : 'status-error'}">
                            ${check.success ? '✓ Success' : '✗ Failed'}
                        </span>
                    </div>
                    ${check.errors.length > 0 ?
                        `<div class="error">Errors: ${check.errors.join(', ')}</div>` : ''}
                    ${check.cost_metrics && check.cost_metrics.length > 0 ?
                        `<div style="margin-top: 10px; padding: 10px; background: #1a1a1a; border-radius: 4px; border-left: 3px solid #4a9eff;">
                            <strong style="color: #4a9eff;">Cost Metrics:</strong>
                            ${check.cost_metrics.map(m => {
                                const amount = m.amount || 0;
                                const usage = m.usage || 0;
                                const limit = m.limit || 0;
                                const usagePct = m.usage_percent || 0;
                                const limitStr = limit > 0 ? limit.toLocaleString() : 'N/A';
                                return `
                                    <div style="margin-top: 8px; padding: 8px; background: #0f0f0f; border-radius: 3px;">
                                        <strong style="color: #fff;">${m.service.toUpperCase()}</strong><br/>
                                        Cost: <span style="color: ${amount > 0 ? '#ffaa44' : '#888'}">$${amount.toFixed(2)}</span> | 
                                        Usage: <span style="color: ${usagePct > 80 ? '#ff4444' : usagePct > 50 ? '#ffaa44' : '#44ff44'}">${usage.toLocaleString()} / ${limitStr}</span> 
                                        <span style="color: #888;">(${usagePct.toFixed(1)}%)</span>
                                    </div>
                                `;
                            }).join('')}
                        </div>` : 
                        check.errors.length === 0 ? 
                            `<div style="margin-top: 10px; padding: 8px; background: #1a1a1a; border-radius: 4px; color: #888; font-size: 12px;">
                                No cost metrics available
                            </div>` : ''}
                    ${check.metadata && Object.keys(check.metadata).length > 0 ?
                        `<div style="margin-top: 10px; font-size: 12px; color: #888;">
                            ${Object.entries(check.metadata).map(([k, v]) => `${k}: ${v}`).join(' | ')}
                        </div>` : ''}
                </div>
            `).join('');
            document.getElementById('checks').innerHTML = checksHtml;
        }

        // Initial load
        fetchData();

        // Auto-refresh every 30 seconds
        setInterval(fetchData, 30000);
    </script>
</body>
</html>
"""


@app.post("/api/login")
@limiter.limit("5/minute")
async def login(request: Request, api_key: str):
    """Login with API key and create session."""
    settings = get_settings()
    expected_key = settings.dashboard_api_key

    if not expected_key:
        logger.warning("DASHBOARD_API_KEY not set - allowing login (development mode)")
    elif api_key != expected_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
        )

    # Create signed session token (stateless - works across replicas)
    session_token = create_session_token()

    response = JSONResponse({"status": "success"})
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=session_token,
        httponly=True,
        secure=settings.environment == "production",
        samesite="lax",
        max_age=SESSION_TIMEOUT_SECONDS,
    )
    return response


@app.get("/api/config")
@limiter.limit("30/minute")
async def get_config(request: Request):
    """Get current configuration (sanitized - no secrets)."""
    settings = get_settings()

    # Return config without exposing secrets
    config_dict = {
        "services": {
            "github": {"configured": bool(settings.github_token)},
            "vercel": {"configured": bool(settings.vercel_token)},
            "fly": {"configured": bool(settings.fly_api_token)},
            "snyk": {"configured": bool(settings.snyk_token)},
            "firecrawl": {"configured": bool(settings.firecrawl_api_key)},
            "tavily": {"configured": bool(settings.tavily_api_key)},
            "anthropic": {"configured": bool(settings.anthropic_api_key)},
            "openrouter": {"configured": bool(settings.openrouter_api_key)},
        },
        "monitoring": {
            "npm_packages_count": len(settings.npm_packages_to_monitor)
            if settings.npm_packages_to_monitor
            else 0,
            "github_repos_count": len(settings.github_repos_to_monitor)
            if settings.github_repos_to_monitor
            else 0,
            "vercel_projects_count": len(settings.vercel_projects_to_monitor)
            if settings.vercel_projects_to_monitor
            else 0,
            "fly_apps_count": len(settings.fly_apps_to_monitor)
            if settings.fly_apps_to_monitor
            else 0,
            "check_interval_seconds": settings.check_interval_seconds,
        },
        "dashboard": {
            "enabled": settings.dashboard_enabled,
            "host": settings.dashboard_host,
            "port": settings.dashboard_port,
            "api_key_set": bool(settings.dashboard_api_key),
            "metrics_enabled": settings.metrics_enabled,
        },
        "environment": settings.environment,
    }

    return JSONResponse(config_dict)


@app.get("/api/report")
@limiter.limit("30/minute")
async def get_report(request: Request):
    """Get current monitoring report."""
    settings = get_settings()
    guardian = Guardian(settings)
    report = await guardian.run_checks()

    # Convert to dict for JSON response
    report_dict = {
        "generated_at": report.generated_at.isoformat(),
        "summary": report.summary,
        "checks": [
            {
                "check_type": check.check_type,
                "timestamp": check.timestamp.isoformat(),
                "success": check.success,
                "vulnerabilities_count": len(check.vulnerabilities),
                "deployments_count": len(check.deployments),
                "repository_alerts_count": len(check.repository_alerts),
                "errors": check.errors,
                "cost_metrics": [
                    {
                        "service": cost.service,
                        "period": cost.period,
                        "amount": cost.amount if cost.amount is not None else 0.0,
                        "usage": cost.usage if cost.usage is not None else 0.0,
                        "limit": cost.limit if cost.limit is not None else 0.0,
                        "usage_percent": cost.usage_percent
                        if cost.usage_percent is not None
                        else 0.0,
                        "metadata": cost.metadata,
                    }
                    for cost in check.cost_metrics
                ],
                "metadata": check.metadata,
            }
            for check in report.checks
        ],
    }

    return JSONResponse(report_dict)


@app.get("/health")
async def health():
    """Health check endpoint."""
    return JSONResponse({"status": "healthy"})


@app.get("/metrics")
async def metrics():
    """Prometheus metrics endpoint."""
    from fastapi.responses import Response

    from devguard.metrics import get_metrics

    return Response(content=get_metrics(), media_type="text/plain")


def run_dashboard(host: str | None = None, port: int | None = None) -> None:
    """Run the dashboard server."""
    import uvicorn

    settings = get_settings()
    dashboard_host = host or settings.dashboard_host
    dashboard_port = port or settings.dashboard_port

    # Use PORT env var if set (for Fly.io, etc.)
    env_port = os.getenv("PORT")
    if env_port:
        dashboard_port = int(env_port)

    # Start Prometheus metrics server if enabled
    if settings.metrics_enabled:
        try:
            from devguard.metrics import start_metrics_server

            start_metrics_server(port=settings.metrics_port)
            logger.info(f"Prometheus metrics server started on port {settings.metrics_port}")
        except Exception as e:
            logger.warning(f"Failed to start metrics server: {e}")

    logger.info(f"Starting devguard dashboard on {dashboard_host}:{dashboard_port}")
    logger.info(f"Metrics endpoint: http://{dashboard_host}:{dashboard_port}/metrics")
    uvicorn.run(app, host=dashboard_host, port=dashboard_port)
