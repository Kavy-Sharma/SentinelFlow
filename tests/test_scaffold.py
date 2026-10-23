"""Basic scaffolding and package sanity tests."""

import sentinelflow


def test_package_import() -> None:
    """Verify package import and metadata attributes."""
    assert sentinelflow.__version__ == "0.1.0"
