"""UI tests (Playwright): load, table, filters, search, alerts, buttons."""

import pytest
from playwright.sync_api import expect


def need(page, selector):
    if page.locator(selector).count() == 0:
        pytest.skip(f"{selector} not on the page yet (depends on a teammate's PR)")


def rows(page):
    return page.locator("#packet-table-body tr")


def test_dashboard_loads(page):
    expect(page).to_have_title("Network Traffic Analyzer")
    expect(page.locator("h1")).to_have_text("Network Traffic Analyzer")


def test_packet_table_and_stat_cards(page):
    expect(rows(page)).to_have_count(4)
    expect(page.locator("#stat-total")).to_have_text("4")
    expect(page.locator("#stat-tcp")).to_have_text("2")
    expect(page.locator("#stat-udp")).to_have_text("1")
    expect(page.locator("#stat-icmp")).to_have_text("1")


def test_protocol_filter_updates_table_and_stats(page):
    page.click('.protocol-filter-btn[data-protocol="UDP"]')
    expect(rows(page)).to_have_count(1)
    expect(page.locator("#stat-total")).to_have_text("1")
    expect(page.locator("#stat-udp")).to_have_text("1")


def test_ip_search(page):
    page.fill("#filter-source-ip", "192.168.1")
    expect(rows(page)).to_have_count(1)
    expect(rows(page).first).to_contain_text("8.8.8.8")


def test_port_filter(page):
    page.fill("#filter-destination-port", "53")
    expect(rows(page)).to_have_count(1)


def test_combined_filters_then_clear(page):
    page.fill("#filter-source-ip", "10.0.0")
    page.click('.protocol-filter-btn[data-protocol="TCP"]')
    expect(rows(page)).to_have_count(1)
    page.click("#clear-filters")
    expect(rows(page)).to_have_count(4)


def test_no_match_message(page):
    page.fill("#filter-source-port", "9")
    expect(page.locator("#packet-table-body .empty-row")).to_contain_text("No packets match")


def test_invalid_ip_shows_error_not_crash(page):
    page.fill("#filter-source-ip", "not-an-ip")
    expect(page.locator("#filter-error")).to_be_visible()
    expect(page.locator("#filter-error")).to_contain_text("Invalid source_ip")


def test_alert_is_displayed(page):
    need(page, "#alerts-table-body")
    expect(page.locator("#alerts-table-body")).to_contain_text("Possible Port Scan")
    expect(page.locator("#alerts-table-body .severity-badge.High")).to_be_visible()


def test_capture_controls_present(page):
    need(page, "#capture-start")
    expect(page.locator("#capture-start")).to_be_visible()
    expect(page.locator("#capture-stop")).to_be_disabled()


def test_pause_button_toggles(page):
    need(page, "#refresh-toggle")
    button = page.locator("#refresh-toggle")
    button.click()
    expect(button).to_have_text("Resume auto-refresh")
    button.click()
    expect(button).to_have_text("Pause auto-refresh")
