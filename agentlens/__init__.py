"""AgentLens package."""

from importlib.metadata import PackageNotFoundError, version


def _resolve_version() -> str:
    for distribution_name in ("agentlens-scanner", "agentlens"):
        try:
            return version(distribution_name)
        except PackageNotFoundError:
            continue
    return "0.1.0"


__version__ = _resolve_version()


__all__ = ["__version__"]
