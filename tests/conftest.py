"""
Shared pytest fixtures providing isolated temporary SQLite databases for every test module.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("FIREBASE_ENABLED", "false")
os.environ.setdefault("RATE_LIMIT_AUTH_PER_MIN", "200")
os.environ.setdefault("RATE_LIMIT_API_PER_MIN", "500")


@pytest.fixture()
def isolated_app(tmp_path: Path, monkeypatch):
    """Configure an isolated temp SQLite DB and return a ready FastAPI TestClient."""
    db_file = tmp_path / "test_securefl.db"
    db_url = f"sqlite+aiosqlite:///{db_file.as_posix()}"

    import backend.database as db_mod
    import backend.main as main_mod
    import backend.routers.threats as threats_mod

    test_engine = create_async_engine(db_url, echo=False)
    test_session_maker = async_sessionmaker(
        bind=test_engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
        autocommit=False,
    )

    monkeypatch.setattr(db_mod, "engine", test_engine)
    monkeypatch.setattr(db_mod, "AsyncSessionLocal", test_session_maker)
    monkeypatch.setattr(main_mod, "AsyncSessionLocal", test_session_maker)
    monkeypatch.setattr(threats_mod, "AsyncSessionLocal", test_session_maker)

    with TestClient(main_mod.app) as client:
        yield client
