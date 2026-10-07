import pytest

import database
from app import create_app
from tests.sample_data import SAMPLE_PACKETS


@pytest.fixture
def db(monkeypatch, tmp_path):
    """Empty temporary database."""
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "test.db")
    database.init_db()
    return database.DB_PATH


@pytest.fixture
def loaded_db(db):
    """Temporary database pre-filled with SAMPLE_PACKETS."""
    for packet in SAMPLE_PACKETS:
        database.insert_packet(packet)
    return db


@pytest.fixture
def client(db):
    return create_app().test_client()
