"""Checkers for various services.

All checker imports are lazy to avoid requiring optional dependencies
(pygithub, etc.) at import time. Import individual checkers directly::

    from devguard.checkers.github import GitHubChecker
"""
