"""Playwright fixtures: a live Flask server on a temp DB + a headless Chromium."""

import threading

import pytest
from werkzeug.serving import make_server

import database
from app import create_app
from tests.sample_data import SAMPLE_PACKETS

_insert_alert = getattr(database, "insert_alert", lambda alert: None)


@pytest.fixture(scope="session")
def live_server(tmp_path_factory):
    original = database.DB_PATH
    database.DB_PATH = tmp_path_factory.mktemp("ui") / "ui.db"
    database.init_db()
    for _p in SAMPLE_PACKETS:
        database.insert_packet(_p)
    _insert_alert({
        "source_ip": "10.0.0.66",
        "alert_type": "Possible Port Scan",
        "severity": "High",
        "description": "10.0.0.66 contacted 40 distinct ports within 10s (threshold 15). This may be a port scan.",
    })
    server = make_server("127.0.0.1", 0, create_app(), threaded=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()
    database.DB_PATH = original


@pytest.fixture(scope="session")
def browser():
    sync_api = pytest.importorskip("playwright.sync_api")
    with sync_api.sync_playwright() as p:
        try:
            instance = p.chromium.launch()
        except Exception as exc:
            pytest.skip(f"Chromium not installed ({exc}). Run: playwright install chromium")
        yield instance
        instance.close()


@pytest.fixture
def page(browser, live_server):
    page = browser.new_page()
    page.goto(live_server)
    yield page
    page.close()
