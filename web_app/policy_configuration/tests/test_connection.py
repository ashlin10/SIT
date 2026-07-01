"""Tests for source/target connection management + metadata + guards."""
import pytest

from policy_configuration.services import connection as conn
from policy_configuration.services.client import PolicyFmcClient, FmcApiError


def test_read_server_metadata(monkeypatch):
    from .conftest import FakeFmcClient
    client = FakeFmcClient(version="7.6.0 (build 999)", build="", model="FMCv")
    meta = conn.read_server_metadata(client)
    assert meta.status == "connected"
    assert meta.version.startswith("7.6")
    assert meta.build == "999"  # extracted from "(build 999)"
    assert meta.domain_name == "Global"


def test_is_same_fmc_detects_identical_host_domain():
    a = PolicyFmcClient("https://fmc.example.com:443", {"X-auth-access-token": "t"}, "dom-1")
    b = PolicyFmcClient("https://fmc.example.com:443", {"X-auth-access-token": "t"}, "dom-1")
    c = PolicyFmcClient("https://other.example.com", {"X-auth-access-token": "t"}, "dom-1")
    d = PolicyFmcClient("https://fmc.example.com:443", {"X-auth-access-token": "t"}, "dom-2")
    assert conn.is_same_fmc(a, b) is True
    assert conn.is_same_fmc(a, c) is False
    assert conn.is_same_fmc(a, d) is False  # different domain


def test_connect_source_blocks_same_fmc(monkeypatch):
    # Authenticate returns a fixed domain/headers.
    monkeypatch.setattr(conn, "authenticate_isolated",
                        lambda *a, **k: ("dom-1", {"X-auth-access-token": "t"}))
    # Target client points at the same host+domain.
    target = PolicyFmcClient("https://same.example.com", {"X-auth-access-token": "t"}, "dom-1")
    monkeypatch.setattr(conn, "build_target_client", lambda ctx, debug=False: target)
    ctx = {"fmc_auth": {"headers": {"x": 1}, "domain_uuid": "dom-1"}}
    with pytest.raises(ValueError):
        conn.connect_source(ctx, "https://same.example.com", "admin", "pw")


def test_connect_source_without_target_returns_warning(monkeypatch):
    monkeypatch.setattr(conn, "authenticate_isolated",
                        lambda *a, **k: ("dom-1", {"X-auth-access-token": "t"}))
    monkeypatch.setattr(conn, "build_target_client", lambda ctx, debug=False: None)

    from .conftest import FakeFmcClient
    # Patch read_server_metadata to avoid network.
    monkeypatch.setattr(conn, "read_server_metadata",
                        lambda c: conn.FmcMetadata(host=c.fmc_ip, status="connected", version="7.6"))
    ctx = {}
    result = conn.connect_source(ctx, "https://src.example.com", "admin", "pw")
    assert result["success"] is True
    assert result["target"]["status"] == "disconnected"
    assert "warning" in result
    # Source auth persisted in ctx (in-memory only).
    assert ctx["policy_source_auth"]["fmc_ip"].startswith("https://src")


def test_authenticate_isolated_invalid_credentials(monkeypatch):
    class _Resp:
        status_code = 401
        headers = {}
        text = ""

    monkeypatch.setattr(conn.requests, "post", lambda *a, **k: _Resp())
    with pytest.raises(FmcApiError):
        conn.authenticate_isolated("https://fmc.example.com", "admin", "bad")
