"""Tests for Vulnerability Assessment category of CyberGuardToolkit."""

import pytest
from unittest.mock import patch, MagicMock

from cyberguard_toolkit import CyberGuardToolkit, InputValidator, RiskScorer


# ═══════════════════════════════════════════════════════════════════════════
# CVE LOOKUP
# ═══════════════════════════════════════════════════════════════════════════

class TestCVELookup:

    def test_no_cve_input(self, toolkit):
        with patch("cyberguard_toolkit.Prompt.ask", return_value=""):
            toolkit._cve_lookup()

    def test_invalid_cve(self, toolkit):
        with patch("cyberguard_toolkit.Prompt.ask", return_value="not-a-cve"):
            toolkit._cve_lookup()

    def test_valid_cve_not_found(self, toolkit):
        with patch("cyberguard_toolkit.Prompt.ask",
                   return_value="CVE-2021-44228"), \
             patch.object(toolkit.threat_intel, "nvd_cve_lookup",
                          return_value={"vulnerabilities": []}):
            toolkit._cve_lookup()

    def test_valid_cve_found(self, toolkit):
        resp = {
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2021-44228",
                    "descriptions": [
                        {"lang": "en", "value": "Log4Shell RCE"},
                    ],
                    "metrics": {
                        "cvssMetricV31": [{
                            "cvssData": {
                                "baseScore": 10.0,
                                "baseSeverity": "CRITICAL",
                            },
                        }],
                    },
                    "published": "2021-12-10T10:15:00",
                    "lastModified": "2022-01-01T00:00:00",
                },
            }],
        }
        with patch("cyberguard_toolkit.Prompt.ask",
                   return_value="CVE-2021-44228"), \
             patch.object(toolkit.threat_intel, "nvd_cve_lookup",
                          return_value=resp):
            toolkit._cve_lookup()

    def test_cve_no_cvss(self, toolkit):
        resp = {
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2020-1234",
                    "descriptions": [
                        {"lang": "en", "value": "Some vuln"},
                    ],
                    "metrics": {},
                    "published": "2020-01-01T00:00:00",
                    "lastModified": "2020-06-01T00:00:00",
                },
            }],
        }
        with patch("cyberguard_toolkit.Prompt.ask",
                   return_value="CVE-2020-1234"), \
             patch.object(toolkit.threat_intel, "nvd_cve_lookup",
                          return_value=resp):
            toolkit._cve_lookup()

    def test_cve_api_error(self, toolkit):
        with patch("cyberguard_toolkit.Prompt.ask",
                   return_value="CVE-2021-44228"), \
             patch.object(toolkit.threat_intel, "nvd_cve_lookup",
                          side_effect=Exception("API error")):
            toolkit._cve_lookup()


# ═══════════════════════════════════════════════════════════════════════════
# SSL/TLS ANALYZER (interactive)
# ═══════════════════════════════════════════════════════════════════════════

class TestSSLTLSAnalyzer:

    def test_no_target(self, toolkit):
        with patch("cyberguard_toolkit.Prompt.ask", return_value=""):
            toolkit._ssl_tls_analyzer()

    def test_connection_fail(self, toolkit):
        with patch("cyberguard_toolkit.Prompt.ask",
                   side_effect=["example.com", "443"]), \
             patch("socket.create_connection",
                   side_effect=ConnectionRefusedError("refused")):
            toolkit._ssl_tls_analyzer()

    def test_ssl_verification_error(self, toolkit):
        import ssl
        mock_ctx = MagicMock()
        mock_sock = MagicMock()
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)
        mock_ctx.wrap_socket.side_effect = ssl.SSLCertVerificationError("cert err")
        with patch("cyberguard_toolkit.Prompt.ask",
                   side_effect=["example.com", "443"]), \
             patch("ssl.create_default_context", return_value=mock_ctx), \
             patch("socket.create_connection", return_value=mock_sock), \
             patch.object(toolkit.exporter, "ask_export"):
            toolkit._ssl_tls_analyzer()

    def test_custom_port(self, toolkit):
        with patch("cyberguard_toolkit.Prompt.ask",
                   side_effect=["example.com", "8443"]), \
             patch("socket.create_connection",
                   side_effect=Exception("timeout")):
            toolkit._ssl_tls_analyzer()

    def test_invalid_port(self, toolkit):
        with patch("cyberguard_toolkit.Prompt.ask",
                   side_effect=["example.com", "abc"]), \
             patch("socket.create_connection",
                   side_effect=Exception("timeout")):
            toolkit._ssl_tls_analyzer()


# ═══════════════════════════════════════════════════════════════════════════
# SSL/TLS ANALYZER AUTO (for full vuln scan)
# ═══════════════════════════════════════════════════════════════════════════

class TestSSLTLSAnalyzerAuto:

    def test_auto_ssl_success(self, toolkit):
        mock_ssock = MagicMock()
        mock_ssock.getpeercert.return_value = {
            "subject": ((("commonName", "example.com"),),),
            "issuer": ((("organizationName", "Let's Encrypt"),),),
            "notBefore": "Jan  1 00:00:00 2025 GMT",
            "notAfter": "Dec 31 23:59:59 2030 GMT",
            "subjectAltName": (("DNS", "example.com"),),
        }
        mock_ssock.version.return_value = "TLSv1.3"
        mock_ssock.cipher.return_value = (
            "TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        mock_ssock.__enter__ = MagicMock(return_value=mock_ssock)
        mock_ssock.__exit__ = MagicMock(return_value=False)

        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.return_value = mock_ssock

        mock_sock = MagicMock()
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)

        with patch("ssl.create_default_context", return_value=mock_ctx), \
             patch("socket.create_connection", return_value=mock_sock):
            vulns = []
            toolkit._ssl_tls_analyzer_auto("example.com", vulns)
            assert len(vulns) == 0

    def test_auto_ssl_deprecated_protocol(self, toolkit):
        mock_ssock = MagicMock()
        mock_ssock.getpeercert.return_value = {
            "subject": ((("commonName", "old.com"),),),
            "issuer": ((("organizationName", "CA"),),),
            "notBefore": "Jan  1 00:00:00 2025 GMT",
            "notAfter": "Dec 31 23:59:59 2030 GMT",
        }
        mock_ssock.version.return_value = "TLSv1"
        mock_ssock.__enter__ = MagicMock(return_value=mock_ssock)
        mock_ssock.__exit__ = MagicMock(return_value=False)

        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.return_value = mock_ssock

        mock_sock = MagicMock()
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)

        with patch("ssl.create_default_context", return_value=mock_ctx), \
             patch("socket.create_connection", return_value=mock_sock):
            vulns = []
            toolkit._ssl_tls_analyzer_auto("old.com", vulns)
            assert any("deprecated" in v.get("description", "").lower()
                       or "TLSv1" in v.get("description", "")
                       for v in vulns)

    def test_auto_ssl_cert_verify_fail(self, toolkit):
        import ssl
        mock_ctx = MagicMock()
        mock_sock = MagicMock()
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)
        mock_ctx.wrap_socket.side_effect = ssl.SSLCertVerificationError(
            "bad cert")
        with patch("ssl.create_default_context", return_value=mock_ctx), \
             patch("socket.create_connection", return_value=mock_sock):
            vulns = []
            toolkit._ssl_tls_analyzer_auto("bad.com", vulns)
            assert any("verification" in v.get("description", "").lower()
                       or "SSL-004" in v.get("id", "")
                       for v in vulns)

    def test_auto_ssl_connection_error(self, toolkit):
        with patch("ssl.create_default_context"), \
             patch("socket.create_connection",
                   side_effect=Exception("timeout")):
            vulns = []
            toolkit._ssl_tls_analyzer_auto("down.com", vulns)
            assert len(vulns) == 0


# ═══════════════════════════════════════════════════════════════════════════
# WEB HEADERS AUTO
# ═══════════════════════════════════════════════════════════════════════════

class TestWebHeadersAuto:

    def test_headers_all_present(self, toolkit):
        mock_resp = MagicMock()
        mock_resp.headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
        }
        with patch("requests.head", return_value=mock_resp):
            vulns = []
            toolkit._web_headers_auto("https://secure.com", vulns)
            assert len(vulns) == 0

    def test_headers_missing(self, toolkit):
        mock_resp = MagicMock()
        mock_resp.headers = {}
        with patch("requests.head", return_value=mock_resp):
            vulns = []
            toolkit._web_headers_auto("https://insecure.com", vulns)
            assert len(vulns) > 0

    def test_headers_request_fails(self, toolkit):
        with patch("requests.head", side_effect=Exception("timeout")):
            vulns = []
            toolkit._web_headers_auto("https://down.com", vulns)
            assert len(vulns) == 0


# ═══════════════════════════════════════════════════════════════════════════
# SOFTWARE VERSION CHECK
# ═══════════════════════════════════════════════════════════════════════════

class TestSoftwareVersionCheck:

    def test_dpkg_and_pip(self, toolkit):
        dpkg_out = (
            "ii  openssl  3.0.2-0ubuntu1  amd64  SSL library\n"
            "ii  curl  7.81.0  amd64  HTTP tool\n"
        )
        pip_out = '[{"name": "requests", "version": "2.31.0"}]'
        with patch.object(toolkit.cmd, "run",
                          side_effect=[
                              (0, dpkg_out, ""),
                              (0, pip_out, ""),
                          ]):
            toolkit._software_version_check()

    def test_dpkg_fails(self, toolkit):
        with patch.object(toolkit.cmd, "run",
                          side_effect=[
                              (1, "", "error"),
                              (0, "[]", ""),
                          ]):
            toolkit._software_version_check()

    def test_pip_invalid_json(self, toolkit):
        with patch.object(toolkit.cmd, "run",
                          side_effect=[
                              (0, "", ""),
                              (0, "not json", ""),
                          ]):
            toolkit._software_version_check()


# ═══════════════════════════════════════════════════════════════════════════
# EXPLOIT SEARCH
# ═══════════════════════════════════════════════════════════════════════════

class TestExploitSearch:

    def test_no_query(self, toolkit):
        with patch("cyberguard_toolkit.Prompt.ask", return_value=""):
            toolkit._exploit_search()

    def test_no_searchsploit(self, toolkit):
        with patch("cyberguard_toolkit.Prompt.ask", return_value="apache"), \
             patch.object(toolkit.cmd, "has_command", return_value=False):
            toolkit._exploit_search()

    def test_searchsploit_found(self, toolkit):
        json_out = (
            '{"RESULTS_EXPLOIT": [{"Title": "Apache RCE",'
            ' "Path": "/path", "Date_Published": "2023-01-01"}]}'
        )
        with patch("cyberguard_toolkit.Prompt.ask", return_value="apache"), \
             patch.object(toolkit.cmd, "has_command", return_value=True), \
             patch.object(toolkit.cmd, "run",
                          return_value=(0, json_out, "")):
            toolkit._exploit_search()

    def test_searchsploit_no_results(self, toolkit):
        with patch("cyberguard_toolkit.Prompt.ask",
                   return_value="nonexistent"), \
             patch.object(toolkit.cmd, "has_command", return_value=True), \
             patch.object(toolkit.cmd, "run",
                          return_value=(0, '{"RESULTS_EXPLOIT": []}', "")):
            toolkit._exploit_search()

    def test_searchsploit_bad_json(self, toolkit):
        with patch("cyberguard_toolkit.Prompt.ask", return_value="test"), \
             patch.object(toolkit.cmd, "has_command", return_value=True), \
             patch.object(toolkit.cmd, "run",
                          return_value=(0, "not json output", "")):
            toolkit._exploit_search()


# ═══════════════════════════════════════════════════════════════════════════
# WEB SECURITY HEADERS (interactive)
# ═══════════════════════════════════════════════════════════════════════════

class TestWebSecurityHeaders:

    def test_no_url(self, toolkit):
        with patch("cyberguard_toolkit.Prompt.ask", return_value=""):
            toolkit._web_security_headers()

    def test_request_fails(self, toolkit):
        with patch("cyberguard_toolkit.Prompt.ask",
                   return_value="https://down.com"), \
             patch("requests.head",
                   side_effect=Exception("timeout")):
            toolkit._web_security_headers()

    def test_all_headers_present(self, toolkit):
        mock_resp = MagicMock()
        mock_resp.headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Referrer-Policy": "strict-origin",
            "Permissions-Policy": "geolocation=()",
            "Cache-Control": "no-store",
            "Pragma": "no-cache",
            "X-Permitted-Cross-Domain-Policies": "none",
            "Set-Cookie": "session=abc; Secure; HttpOnly",
        }
        with patch("cyberguard_toolkit.Prompt.ask",
                   return_value="https://secure.com"), \
             patch("requests.head", return_value=mock_resp), \
             patch.object(toolkit.exporter, "ask_export"):
            toolkit._web_security_headers()

    def test_missing_headers_and_cookies(self, toolkit):
        mock_resp = MagicMock()
        mock_resp.headers = {
            "Set-Cookie": "session=abc",
        }
        with patch("cyberguard_toolkit.Prompt.ask",
                   return_value="https://insecure.com"), \
             patch("requests.head", return_value=mock_resp), \
             patch.object(toolkit.exporter, "ask_export"):
            toolkit._web_security_headers()
            assert len(toolkit.findings) > 0

    def test_url_without_scheme(self, toolkit):
        mock_resp = MagicMock()
        mock_resp.headers = {}
        with patch("cyberguard_toolkit.Prompt.ask",
                   return_value="example.com"), \
             patch("requests.head", return_value=mock_resp), \
             patch.object(toolkit.exporter, "ask_export"):
            toolkit._web_security_headers()


# ═══════════════════════════════════════════════════════════════════════════
# CONFIG COMPLIANCE (CIS)
# ═══════════════════════════════════════════════════════════════════════════

class TestConfigCompliance:

    def test_config_compliance(self, toolkit):
        results = [
            {"id": "1.1.1", "title": "Test", "status": "PASS",
             "category": "FS", "details": ""},
            {"id": "1.1.2", "title": "Test2", "status": "FAIL",
             "category": "FS", "details": "fail"},
        ]
        with patch.object(toolkit.compliance, "run_cis_checks",
                          return_value=results), \
             patch.object(toolkit.exporter, "ask_export"):
            toolkit._config_compliance()
            assert "cis" in toolkit.scores


# ═══════════════════════════════════════════════════════════════════════════
# FULL VULN SCAN
# ═══════════════════════════════════════════════════════════════════════════

class TestFullVulnScan:

    def test_no_target(self, toolkit):
        with patch("cyberguard_toolkit.Prompt.ask", return_value=""):
            toolkit._full_vuln_scan()

    def test_full_scan_with_vulns(self, toolkit):
        def add_vuln(host_or_url, vulns):
            vulns.append({"id": "TEST-1", "severity": "HIGH",
                          "description": "Test vuln"})

        with patch("cyberguard_toolkit.Prompt.ask",
                   return_value="example.com"), \
             patch.object(toolkit, "_full_vuln_port_scan",
                          side_effect=add_vuln), \
             patch.object(toolkit, "_ssl_tls_analyzer_auto"), \
             patch.object(toolkit, "_web_headers_auto"), \
             patch.object(toolkit, "_software_version_check"), \
             patch.object(toolkit, "_full_vuln_config_compliance"), \
             patch.object(toolkit, "_full_vuln_exploit_search"), \
             patch.object(toolkit, "_full_vuln_service_check"), \
             patch.object(toolkit.exporter, "ask_export"):
            toolkit._full_vuln_scan()

    def test_full_scan_no_vulns(self, toolkit):
        with patch("cyberguard_toolkit.Prompt.ask",
                   return_value="secure.com"), \
             patch.object(toolkit, "_full_vuln_port_scan"), \
             patch.object(toolkit, "_ssl_tls_analyzer_auto"), \
             patch.object(toolkit, "_web_headers_auto"), \
             patch.object(toolkit, "_software_version_check"), \
             patch.object(toolkit, "_full_vuln_config_compliance"), \
             patch.object(toolkit, "_full_vuln_exploit_search"), \
             patch.object(toolkit, "_full_vuln_service_check"):
            toolkit._full_vuln_scan()

    def test_full_scan_url_input(self, toolkit):
        with patch("cyberguard_toolkit.Prompt.ask",
                   return_value="https://example.com/path"), \
             patch.object(toolkit, "_full_vuln_port_scan"), \
             patch.object(toolkit, "_ssl_tls_analyzer_auto"), \
             patch.object(toolkit, "_web_headers_auto"), \
             patch.object(toolkit, "_software_version_check"), \
             patch.object(toolkit, "_full_vuln_config_compliance"), \
             patch.object(toolkit, "_full_vuln_exploit_search"), \
             patch.object(toolkit, "_full_vuln_service_check"):
            toolkit._full_vuln_scan()

    def test_full_scan_multiple_severities(self, toolkit):
        """Test summary counts with mixed severity vulns."""
        def add_vulns(host_or_url, vulns):
            vulns.append({"id": "T-1", "severity": "HIGH",
                          "description": "vuln 1"})
            vulns.append({"id": "T-2", "severity": "MEDIUM",
                          "description": "vuln 2"})

        with patch("cyberguard_toolkit.Prompt.ask",
                   return_value="example.com"), \
             patch.object(toolkit, "_full_vuln_port_scan",
                          side_effect=add_vulns), \
             patch.object(toolkit, "_ssl_tls_analyzer_auto"), \
             patch.object(toolkit, "_web_headers_auto"), \
             patch.object(toolkit, "_software_version_check"), \
             patch.object(toolkit, "_full_vuln_config_compliance"), \
             patch.object(toolkit, "_full_vuln_exploit_search"), \
             patch.object(toolkit, "_full_vuln_service_check"), \
             patch.object(toolkit.exporter, "ask_export"):
            toolkit._full_vuln_scan()
            assert len(toolkit.findings) >= 2


# ═══════════════════════════════════════════════════════════════════════════
# FULL VULN PORT SCAN
# ═══════════════════════════════════════════════════════════════════════════

class TestFullVulnPortScan:

    def test_no_open_ports(self, toolkit):
        with patch("socket.create_connection",
                   side_effect=ConnectionRefusedError("refused")):
            vulns = []
            toolkit._full_vuln_port_scan("example.com", vulns)
            assert len(vulns) == 0

    def test_risky_ports_open(self, toolkit):
        mock_sock = MagicMock()
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)

        def connect_side_effect(addr, timeout=None):
            # Allow only port 23 (Telnet) and 445 (SMB)
            if addr[1] in (23, 445):
                return mock_sock
            raise ConnectionRefusedError("refused")

        with patch("socket.create_connection",
                   side_effect=connect_side_effect):
            vulns = []
            toolkit._full_vuln_port_scan("target.com", vulns)
            assert len(vulns) == 2
            assert any("HIGH" in v.get("severity", "") for v in vulns)

    def test_medium_severity_port(self, toolkit):
        mock_sock = MagicMock()
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)

        def connect_side_effect(addr, timeout=None):
            # Port 8080 is MEDIUM severity
            if addr[1] == 8080:
                return mock_sock
            raise ConnectionRefusedError("refused")

        with patch("socket.create_connection",
                   side_effect=connect_side_effect):
            vulns = []
            toolkit._full_vuln_port_scan("target.com", vulns)
            assert len(vulns) == 1
            assert vulns[0]["severity"] == "MEDIUM"

    def test_connection_exception(self, toolkit):
        with patch("socket.create_connection",
                   side_effect=Exception("network error")):
            vulns = []
            toolkit._full_vuln_port_scan("target.com", vulns)
            assert len(vulns) == 0


# ═══════════════════════════════════════════════════════════════════════════
# FULL VULN CONFIG COMPLIANCE
# ═══════════════════════════════════════════════════════════════════════════

class TestFullVulnConfigCompliance:

    def test_with_failures(self, toolkit):
        results = [
            {"id": "1.1.1", "title": "cramfs disabled",
             "status": "PASS", "category": "Filesystem"},
            {"id": "5.2.8", "title": "SSH root login",
             "status": "FAIL", "category": "SSH",
             "details": "PermitRootLogin=yes"},
            {"id": "3.1.1", "title": "IP forwarding",
             "status": "FAIL", "category": "Network",
             "details": "enabled"},
        ]
        with patch.object(toolkit.compliance, "run_cis_checks",
                          return_value=results):
            vulns = []
            toolkit._full_vuln_config_compliance(vulns)
            assert len(vulns) == 2
            assert any("SSH" in v.get("description", "") for v in vulns)

    def test_all_pass(self, toolkit):
        results = [
            {"id": "1.1.1", "title": "test",
             "status": "PASS", "category": "FS"},
        ]
        with patch.object(toolkit.compliance, "run_cis_checks",
                          return_value=results):
            vulns = []
            toolkit._full_vuln_config_compliance(vulns)
            assert len(vulns) == 0

    def test_compliance_error(self, toolkit):
        with patch.object(toolkit.compliance, "run_cis_checks",
                          side_effect=Exception("error")):
            vulns = []
            toolkit._full_vuln_config_compliance(vulns)
            assert len(vulns) == 0


# ═══════════════════════════════════════════════════════════════════════════
# FULL VULN EXPLOIT SEARCH
# ═══════════════════════════════════════════════════════════════════════════

class TestFullVulnExploitSearch:

    def test_no_searchsploit(self, toolkit):
        with patch.object(toolkit.cmd, "has_command", return_value=False):
            toolkit._full_vuln_exploit_search([])

    def test_no_relevant_vulns(self, toolkit):
        vulns = [{"id": "SSL-001", "severity": "HIGH",
                  "description": "Deprecated TLS"}]
        with patch.object(toolkit.cmd, "has_command", return_value=True):
            toolkit._full_vuln_exploit_search(vulns)

    def test_with_service_vulns(self, toolkit):
        vulns = [{"id": "PORT-445", "severity": "HIGH",
                  "description": "Risky service exposed: SMB on port 445"}]
        json_out = (
            '{"RESULTS_EXPLOIT": [{"Title": "SMB Exploit",'
            ' "Path": "/path", "Date_Published": "2023"}]}'
        )
        with patch.object(toolkit.cmd, "has_command", return_value=True), \
             patch.object(toolkit.cmd, "run",
                          return_value=(0, json_out, "")):
            toolkit._full_vuln_exploit_search(vulns)
            assert any("exploit" in v.get("description", "").lower()
                       or "EXPLOIT" in v.get("id", "")
                       for v in vulns)

    def test_searchsploit_no_results(self, toolkit):
        vulns = [{"id": "PORT-23", "severity": "HIGH",
                  "description": "Unencrypted service: Telnet on port 23"}]
        with patch.object(toolkit.cmd, "has_command", return_value=True), \
             patch.object(toolkit.cmd, "run",
                          return_value=(0, '{"RESULTS_EXPLOIT": []}', "")):
            toolkit._full_vuln_exploit_search(vulns)


# ═══════════════════════════════════════════════════════════════════════════
# FULL VULN SERVICE CHECK
# ═══════════════════════════════════════════════════════════════════════════

class TestFullVulnServiceCheck:

    def test_wide_open_services(self, toolkit):
        ss_out = (
            "State Recv-Q Send-Q Local:Port Peer:Port\n"
            "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n"
            "LISTEN 0 128 127.0.0.1:5432 0.0.0.0:*\n"
        )
        with patch.object(toolkit.cmd, "run",
                          return_value=(0, ss_out, "")):
            vulns = []
            toolkit._full_vuln_service_check("target.com", vulns)
            assert any("0.0.0.0" in v.get("description", "")
                       for v in vulns)

    def test_no_wide_open(self, toolkit):
        ss_out = (
            "State Recv-Q Send-Q Local:Port Peer:Port\n"
            "LISTEN 0 128 127.0.0.1:5432 0.0.0.0:*\n"
        )
        with patch.object(toolkit.cmd, "run",
                          return_value=(0, ss_out, "")):
            vulns = []
            toolkit._full_vuln_service_check("target.com", vulns)
            assert len(vulns) == 0

    def test_ss_fails(self, toolkit):
        with patch.object(toolkit.cmd, "run",
                          return_value=(1, "", "error")):
            vulns = []
            toolkit._full_vuln_service_check("target.com", vulns)
            assert len(vulns) == 0

    def test_ss_exception(self, toolkit):
        with patch.object(toolkit.cmd, "run",
                          side_effect=Exception("error")):
            vulns = []
            toolkit._full_vuln_service_check("target.com", vulns)
            assert len(vulns) == 0
