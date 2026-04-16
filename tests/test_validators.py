"""Tests for InputValidator class — 31 tests across 12 test classes."""

from cyberguard_toolkit import InputValidator


class TestValidateIP:

    def test_valid_ipv4(self):
        assert InputValidator.validate_ip("192.168.1.1")
        assert InputValidator.validate_ip("8.8.8.8")
        assert InputValidator.validate_ip("255.255.255.255")
        assert InputValidator.validate_ip("0.0.0.0")

    def test_valid_ipv6(self):
        assert InputValidator.validate_ip("::1")
        assert InputValidator.validate_ip("2001:db8::1")

    def test_invalid_ip(self):
        assert not InputValidator.validate_ip("999.999.999.999")
        assert not InputValidator.validate_ip("abc")
        assert not InputValidator.validate_ip("192.168.1")
        assert not InputValidator.validate_ip("192.168.1.1.1")

    def test_ip_with_whitespace(self):
        assert InputValidator.validate_ip("  8.8.8.8  ")


class TestValidateCIDR:

    def test_valid_cidr(self):
        assert InputValidator.validate_cidr("192.168.1.0/24")
        assert InputValidator.validate_cidr("10.0.0.0/8")
        assert InputValidator.validate_cidr("0.0.0.0/0")

    def test_invalid_cidr(self):
        assert not InputValidator.validate_cidr("abc/24")
        assert not InputValidator.validate_cidr("192.168.1.0/33")


class TestValidateCVE:

    def test_valid_cve(self):
        assert InputValidator.validate_cve("CVE-2024-1234")
        assert InputValidator.validate_cve("CVE-2023-12345")
        assert InputValidator.validate_cve("cve-2024-1234")

    def test_invalid_cve(self):
        assert not InputValidator.validate_cve("CVE-24-1234")
        assert not InputValidator.validate_cve("CVE-2024-12")
        assert not InputValidator.validate_cve("not-a-cve")


class TestValidatePort:

    def test_valid_ports(self):
        assert InputValidator.validate_port("1")
        assert InputValidator.validate_port("80")
        assert InputValidator.validate_port("443")
        assert InputValidator.validate_port("65535")

    def test_invalid_ports(self):
        assert not InputValidator.validate_port("0")
        assert not InputValidator.validate_port("65536")
        assert not InputValidator.validate_port("abc")
        assert not InputValidator.validate_port("-1")


class TestValidateDomain:

    def test_valid_domains(self):
        assert InputValidator.validate_domain("example.com")
        assert InputValidator.validate_domain("sub.example.com")
        assert InputValidator.validate_domain("test.co.uk")

    def test_invalid_domains(self):
        assert not InputValidator.validate_domain("localhost")
        assert not InputValidator.validate_domain("-example.com")


class TestValidateHash:

    def test_md5(self):
        assert InputValidator.validate_hash("d41d8cd98f00b204e9800998ecf8427e") == "md5"

    def test_sha1(self):
        assert InputValidator.validate_hash("da39a3ee5e6b4b0d3255bfef95601890afd80709") == "sha1"

    def test_sha256(self):
        result = InputValidator.validate_hash(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        assert result == "sha256"

    def test_invalid_hash(self):
        assert InputValidator.validate_hash("not_a_hash") is None


class TestValidatePID:

    def test_valid_pid(self):
        assert InputValidator.validate_pid("1")
        assert InputValidator.validate_pid("1234")

    def test_invalid_pid(self):
        assert not InputValidator.validate_pid("0")
        assert not InputValidator.validate_pid("-1")
        assert not InputValidator.validate_pid("abc")


class TestValidateEmail:

    def test_valid(self):
        assert InputValidator.validate_email("user@example.com")
        assert InputValidator.validate_email("user+tag@domain.co.uk")

    def test_invalid(self):
        assert not InputValidator.validate_email("not-an-email")
        assert not InputValidator.validate_email("@domain.com")


class TestValidateURL:

    def test_valid(self):
        assert InputValidator.validate_url("https://example.com")
        assert InputValidator.validate_url("http://test.com/path")

    def test_invalid(self):
        assert not InputValidator.validate_url("ftp://server.com")
        assert not InputValidator.validate_url("not-a-url")


class TestValidatePortRange:

    def test_valid(self):
        assert InputValidator.validate_port_range("1-100") == (1, 100)
        assert InputValidator.validate_port_range("80-443") == (80, 443)
        assert InputValidator.validate_port_range("1-65535") == (1, 65535)

    def test_invalid(self):
        assert InputValidator.validate_port_range("100-1") is None
        assert InputValidator.validate_port_range("abc") is None
        assert InputValidator.validate_port_range("0-100") is None
        assert InputValidator.validate_port_range("1-70000") is None


class TestDetectInputType:

    def test_ip(self):
        assert InputValidator.detect_input_type("8.8.8.8") == "ip"

    def test_domain(self):
        assert InputValidator.detect_input_type("example.com") == "domain"

    def test_url(self):
        assert InputValidator.detect_input_type("https://example.com") == "url"

    def test_unknown(self):
        assert InputValidator.detect_input_type("random") == "unknown"


class TestSanitizeFilename:

    def test_normal(self):
        assert InputValidator.sanitize_filename("report.json") == "report.json"

    def test_special_chars(self):
        result = InputValidator.sanitize_filename("file/with:special<chars>")
        assert "/" not in result
        assert ":" not in result

    def test_long_name(self):
        result = InputValidator.sanitize_filename("a" * 198)
        assert len(result) <= 100
