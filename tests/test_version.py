"""Test package version."""

from redforge import __version__


def test_version_exists() -> None:
    """Test that version is defined."""
    assert __version__ is not None
    assert isinstance(__version__, str)
