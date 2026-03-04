import os
import pytest
from unittest.mock import MagicMock, patch

import network_capture


# =========================
# Helper: Fake Packet Builder
# =========================

def make_http_packet(host="example.com", uri="/index.html",
                     content_type="text/plain", file_data_hex=None):
    pkt = MagicMock()
    pkt.http = MagicMock()

    pkt.http.host = host
    pkt.http.request_uri = uri
    pkt.http.content_type = content_type

    if file_data_hex:
        pkt.http.file_data = file_data_hex
    else:
        del pkt.http.file_data

    return pkt


def make_dns_packet(query="example.com"):
    pkt = MagicMock()
    pkt.dns = MagicMock()
    pkt.dns.qry_name = query
    return pkt


def make_ftp_packet(command="USER", arg="test"):
    pkt = MagicMock()
    pkt.ftp = MagicMock()
    pkt.ftp.request_command = command
    pkt.ftp.request_arg = arg
    return pkt


# =========================
# HTTP Tests
# =========================

def test_extract_urls():
    analyzer = network_capture.HTTPAnalyzer("dummy.pcap", "out")
    pkt = make_http_packet()

    urls = analyzer.extract_urls(pkt)
    assert "http://example.com/index.html" in urls


def test_extract_payload():
    analyzer = network_capture.HTTPAnalyzer("dummy.pcap", "out")
    data = "48656c6c6f"  # "Hello" in hex
    pkt = make_http_packet(file_data_hex=data)

    payload = analyzer.extract_payload(pkt)
    assert payload == b"Hello"


# =========================
# HTTP Analyze (Mock FileCapture)
# =========================

@patch("network_capture.pyshark.FileCapture")
def test_http_analyze(mock_capture, tmp_path):
    pkt = make_http_packet(file_data_hex="48656c6c6f")

    mock_capture.return_value = [pkt]

    analyzer = network_capture.HTTPAnalyzer("dummy.pcap", tmp_path)
    analyzer.analyze()

    urls_file = tmp_path / "http" / "urls.txt"
    assert urls_file.exists()


# =========================
# DNS Tests
# =========================

@patch("network_capture.pyshark.FileCapture")
def test_dns_analyze(mock_capture, tmp_path):
    pkt = make_dns_packet("test.com")
    mock_capture.return_value = [pkt]

    analyzer = network_capture.DNSAnalyzer("dummy.pcap", tmp_path)
    analyzer.analyze()

    dns_file = tmp_path / "dns" / "dns_queries.txt"
    assert dns_file.exists()

    with open(dns_file) as f:
        content = f.read()
        assert "test.com" in content


# =========================
# FTP Tests
# =========================

@patch("network_capture.pyshark.FileCapture")
def test_ftp_analyze(mock_capture, tmp_path):
    pkt = make_ftp_packet("USER", "admin")
    mock_capture.return_value = [pkt]

    analyzer = network_capture.FTPAnalyzer("dummy.pcap", tmp_path)
    analyzer.analyze()

    ftp_file = tmp_path / "ftp" / "ftp_commands.txt"
    assert ftp_file.exists()

    with open(ftp_file) as f:
        content = f.read()
        assert "USER admin" in content


# =========================
# HTTPS Skip Test (No TLS key)
# =========================

def test_https_skip_if_no_key(tmp_path):
    analyzer = network_capture.HTTPSAnalyzer("dummy.pcap", tmp_path, "missing.key")
    analyzer.analyze()  # Should not crash