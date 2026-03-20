"""Shared helper functions for CLI commands."""

import asyncio
import logging

import httpx
from rich.console import Console

from devguard.config import Settings

console = Console()
logger = logging.getLogger(__name__)


async def test_github_token(token: str) -> tuple[bool, str]:
    """Test a GitHub token.

    Returns:
        Tuple of (success, message)
    """
    try:
        from github import Auth, Github

        auth = Auth.Token(token)
        github = Github(auth=auth)
        user = github.get_user()
        return True, f"Authenticated as {user.login}"
    except Exception as e:
        return False, f"Token invalid - {str(e)}"


async def test_vercel_token(token: str) -> tuple[bool, str]:
    """Test a Vercel token.

    Returns:
        Tuple of (success, message)
    """
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                "https://api.vercel.com/v2/user",
                headers={"Authorization": f"Bearer {token}"},
                timeout=10.0,
            )
            if response.status_code == 200:
                data = response.json()
                name = data.get("user", {}).get("name", "Unknown")
                return True, f"Authenticated as {name}"
            else:
                return False, f"Token invalid (HTTP {response.status_code})"
    except Exception as e:
        return False, f"Error - {str(e)}"


async def test_fly_token(token: str) -> tuple[bool, str]:
    """Test a Fly.io token.

    Returns:
        Tuple of (success, message)
    """
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                "https://api.machines.dev/v1/apps",
                headers={"Authorization": f"Bearer {token}"},
                timeout=10.0,
            )
            if response.status_code == 200:
                return True, "Token is valid"
            else:
                return False, f"Token invalid (HTTP {response.status_code})"
    except Exception as e:
        return False, f"Error - {str(e)}"


async def test_snyk_token(token: str) -> tuple[bool, str]:
    """Test a Snyk token.

    Returns:
        Tuple of (success, message)
    """
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                "https://api.snyk.io/v1/user/me",
                headers={"Authorization": f"token {token}"},
                timeout=10.0,
            )
            if response.status_code == 200:
                data = response.json()
                email = data.get("email", "Unknown")
                return True, f"Authenticated as {email}"
            else:
                return False, f"Token invalid (HTTP {response.status_code})"
    except Exception as e:
        return False, f"Error - {str(e)}"


async def test_service_token(service: str, token: str) -> tuple[bool, str]:
    """Test a token for a given service.

    Args:
        service: Service name (gh, github, vercel, fly, snyk)
        token: Token to test

    Returns:
        Tuple of (success, message)
    """
    service = service.lower()

    if service in ("gh", "github"):
        return await test_github_token(token)
    elif service == "vercel":
        return await test_vercel_token(token)
    elif service == "fly":
        return await test_fly_token(token)
    elif service == "snyk":
        return await test_snyk_token(token)
    else:
        return False, f"Unknown service: {service}"


def show_auth_status(settings: Settings) -> None:
    """Show authentication status for all configured services.

    Args:
        settings: Guardian settings
    """
    console.print("[bold blue]Guardian Authentication Status[/bold blue]\n")

    # GitHub
    if settings.github_token:
        token_str = (
            settings.github_token.get_secret_value()
            if hasattr(settings.github_token, "get_secret_value")
            else str(settings.github_token)
        )
        success, message = asyncio.run(test_github_token(token_str))
        if success:
            console.print(f"[bold green]✓[/bold green] GitHub: {message}")
        else:
            console.print(f"[bold red]✗[/bold red] GitHub: {message}")
    else:
        console.print("[yellow]○[/yellow] GitHub: Not configured")

    # Vercel
    if settings.vercel_token:
        token_str = (
            settings.vercel_token.get_secret_value()
            if hasattr(settings.vercel_token, "get_secret_value")
            else str(settings.vercel_token)
        )
        success, message = asyncio.run(test_vercel_token(token_str))
        if success:
            console.print(f"[bold green]✓[/bold green] Vercel: {message}")
        else:
            console.print(f"[bold red]✗[/bold red] Vercel: {message}")
    else:
        console.print("[yellow]○[/yellow] Vercel: Not configured")

    # Fly.io
    if settings.fly_api_token:
        token_str = (
            settings.fly_api_token.get_secret_value()
            if hasattr(settings.fly_api_token, "get_secret_value")
            else str(settings.fly_api_token)
        )
        success, message = asyncio.run(test_fly_token(token_str))
        if success:
            console.print(f"[bold green]✓[/bold green] Fly.io: {message}")
        else:
            console.print(f"[bold red]✗[/bold red] Fly.io: {message}")
    else:
        console.print("[yellow]○[/yellow] Fly.io: Not configured")

    # Snyk
    if settings.snyk_token:
        token_str = (
            settings.snyk_token.get_secret_value()
            if hasattr(settings.snyk_token, "get_secret_value")
            else str(settings.snyk_token)
        )
        success, message = asyncio.run(test_snyk_token(token_str))
        if success:
            console.print(f"[bold green]✓[/bold green] Snyk: {message}")
        else:
            console.print(f"[bold red]✗[/bold red] Snyk: {message}")
    else:
        console.print("[yellow]○[/yellow] Snyk: Not configured")
