"""GitHub monitoring must stay within the configured repositories."""

from unittest.mock import AsyncMock, Mock, call

import pytest

pytest.importorskip("github", reason="pygithub not installed (monitoring extra)")

from devguard.checkers.github import GitHubChecker, GithubException
from devguard.config import Settings


@pytest.fixture
def checker(monkeypatch):
    client = Mock()
    client.get_user.return_value.get_repos.return_value = [Mock(full_name="unrelated/private")]
    monkeypatch.setattr("devguard.checkers.github.Github", Mock(return_value=client))
    settings = Settings(github_token="fixture", github_org=None, github_repos_to_monitor=[])
    instance = GitHubChecker(settings)
    monkeypatch.setattr(instance, "_get_dependabot_alerts", AsyncMock(return_value=[]))
    return instance


async def test_missing_explicit_repo_stays_in_scope(checker):
    checker.settings.github_repos_to_monitor = ["sample/missing"]
    checker.github.get_repo.side_effect = GithubException(404, {}, {})

    result = await checker.check()

    assert not result.success
    assert len(result.errors) == 1
    assert "sample/missing" in result.errors[0]
    checker.github.get_user.assert_not_called()
    checker._get_dependabot_alerts.assert_not_awaited()


async def test_empty_organization_stays_empty(checker):
    checker.settings.github_org = "sample"
    checker.github.get_organization.return_value.get_repos.return_value = []

    result = await checker.check()

    assert result.success
    checker.github.get_organization.assert_called_once_with("sample")
    checker.github.get_user.assert_not_called()
    checker._get_dependabot_alerts.assert_not_awaited()


async def test_accessible_repos_checked_once_when_an_explicit_lookup_fails(checker):
    org_repo = Mock(full_name="sample/project")
    extra_repo = Mock(full_name="other/extra")
    checker.settings.github_org = "sample"
    checker.settings.github_repos_to_monitor = ["other/missing", "sample/project", "other/extra"]
    checker.github.get_organization.return_value.get_repos.return_value = [org_repo]
    checker.github.get_repo.side_effect = [GithubException(403, {}, {}), org_repo, extra_repo]

    result = await checker.check()

    assert not result.success
    assert len(result.errors) == 1
    assert "other/missing" in result.errors[0]
    assert checker._get_dependabot_alerts.await_args_list == [call(org_repo), call(extra_repo)]
    checker.github.get_user.assert_not_called()
