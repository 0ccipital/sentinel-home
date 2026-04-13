"""Shared fixtures for SentinelHome tests."""
import os
os.environ["SENTINEL_DEV"] = "1"

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sentinel_home.database import Base


@pytest.fixture
def db_session():
    """In-memory SQLite session for tests."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


@pytest.fixture
def app():
    """FastAPI test app."""
    os.environ["SENTINEL_DEV"] = "1"
    from sentinel_home.main import create_app
    return create_app()


@pytest.fixture
def client(app):
    """Test client with lifespan (DB init, scheduler, etc.)."""
    from fastapi.testclient import TestClient
    with TestClient(app) as c:
        yield c
