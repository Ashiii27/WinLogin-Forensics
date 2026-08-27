"""Shared pytest fixtures for WinLogin Forensics."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

FIXTURES = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture
def fixtures_dir() -> Path:
    """Return the tests/fixtures directory."""
    return FIXTURES


@pytest.fixture
def sample_security_xml(fixtures_dir: Path) -> Path:
    """Path to the sample Security XML export."""
    return fixtures_dir / "events" / "sample_security.xml"


@pytest.fixture
def sample_security_evtx(fixtures_dir: Path) -> Path:
    """Path to the sample Security EVTX binary."""
    return fixtures_dir / "events" / "sample_security.evtx"
