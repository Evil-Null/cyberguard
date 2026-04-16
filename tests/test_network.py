"""Tests for Network Security category handlers."""

import pytest
from unittest.mock import patch, MagicMock, call

from cyberguard_toolkit import CyberGuardToolkit, InputValidator


class TestPortScanner:
    """Tests for _port_scanner method."""

    def test_invalid_target(self, toolkit):
        with patch("cyberguard_toolkit.Prompt.ask", return_value="not valid!!!"):
            toolkit._port_scanner()
        assert len(toolkit.findings) == 0

    def test_empty_target(self, toolkit):
        with patch("cyberguard_toolkit.Prompt.ask", return_value=""):
            toolkit._port_scanner()

    def test_valid_scan_quick(self, toolkit):
        with patch("cyberguard_toolkit.Prompt.ask", return_value="127.0.0.1"), \
             patch("cyberguard_toolkit.questionary.select") as mock_select, \
             patch("socket.socket") as mock_sock:
            mock_select.return_value.ask.return_value = "Quick (top 65 ports)"
            mock_instance = MagicMock()
            mock_instance.connect_ex.return_value = 1
            mock_sock.return_value = mock_instance
            toolkit._port_scanner()

    def test_scan_finds_open_port(self, toolkit):
        with patch("cyberguard_toolkit.Prompt.ask", return_value="127.0.0.1"), \
             patch("cyberguard_toolkit.questionary.select") as mock_select, \
             patch("socket.socket") as mock_sock:
            mock_select.return_value.ask.return_value = "Quick (top 65 ports)"
            mock_instance = MagicMock()
            mock_instance.connect_ex.return_value = 0
            mock_instance.recv.side_effect = Exception("timeout")
            mock_sock.return_value = mock_instance
            toolkit._port_scanner()

    def test_scan_suspicious_port_finding(self, toolkit):
        with patch("cyberguard_toolkit.Prompt.ask", return_value="127.0.0.1"), \
             patch("cyberguard_toolkit.questionary.select") as mock_select, \
             patch("socket.socket") as mock_sock, \
             patch("cyberguard_toolkit.TOP_100_PORTS", [4444, 80]):
            mock_select.return_value.ask.side_effect = [
                "Quick (top 65 ports)",
                "Skip",
            ]
            mock_instance = MagicMock()

            def connect_ex_side_effect(addr):
                if addr[1] == 4444:
                    return 0
                return 1

            mock_instance.connect_ex.side_effect = connect_ex_side_effect
            mock_instance.recv.side_effect = Exception("timeout")
            mock_sock.return_value = mock_instance
            toolkit._port_scanner()
            assert any("Suspicious" in f["title"] for f in toolkit.findings)

    def test_custom_port_range(self, toolkit):
        with patch("cyberguard_toolkit.Prompt.ask") as mock_prompt, \
             patch("cyberguard_toolkit.questionary.select") as mock_select, \
             patch("socket.socket") as mock_sock:
            mock_prompt.side_effect = ["127.0.0.1", "80-82"]
            mock_select.return_value.ask.side_effect = [
                "Custom range",
                "Skip",
            ]
            mock_instance = MagicMock()
            mock_instance.connect_ex.return_value = 1
            mock_sock.return_value = mock_instance
            toolkit._port_scanner()

    def test_custom_port_range_invalid(self, toolkit):
        with patch("cyberguard_toolkit.Prompt.ask") as mock_prompt, \
             patch("cyberguard_toolkit.questionary.select") as mock_select:
            mock_prompt.side_effect = ["127.0.0.1", "invalid"]
            mock_select.return_value.ask.return_value = "Custom range"
            toolkit._port_scanner()

    def test_scan_type_none(self, toolkit):
        with patch("cyberguard_toolkit.Prompt.ask", return_value="127.0.0.1"), \
             patch("cyberguard_toolkit.questionary.select") as mock_select:
            mock_select.return_value.ask.return_value = None
            toolkit._port_scanner()


class TestServiceDetection:
    """Tests for _service_detection method."""

    def test_local_services(self, toolkit, sample_ss_output):
        with patch("cyberguard_toolkit.questionary.select") as mock_select, \
             patch.object(toolkit.cmd, "run", return_value=(0, sample_ss_output, "")):
            mock_select.return_value.ask.return_value = "Local services (ss)"
            toolkit._service_detection()

    def test_local_services_fail(self, toolkit):
        with patch("cyberguard_toolkit.questionary.select") as mock_select, \
             patch.object(toolkit.cmd, "run", return_value=(1, "", "error")):
            mock_select.return_value.ask.return_value = "Local services (ss)"
            toolkit._service_detection()

    def test_remote_nmap_missing(self, toolkit):
        with patch("cyberguard_toolkit.questionary.select") as mock_select, \
             patch("cyberguard_toolkit.Prompt.ask", return_value="8.8.8.8"), \
             patch.object(toolkit.cmd, "has_command", return_value=False):
            mock_select.return_value.ask.return_value = "Remote scan (nmap -sV)"
            toolkit._service_detection()

    def test_remote_nmap_success(self, toolkit):
        with patch("cyberguard_toolkit.questionary.select") as mock_select, \
             patch("cyberguard_toolkit.Prompt.ask", return_value="8.8.8.8"), \
             patch.object(toolkit.cmd, "has_command", return_value=True), \
             patch.object(
                 toolkit.cmd, "run",
                 return_value=(0, "PORT STATE SERVICE\n22/tcp open ssh", ""),
             ):
            mock_select.return_value.ask.return_value = "Remote scan (nmap -sV)"
            toolkit._service_detection()

    def test_none_choice(self, toolkit):
        with patch("cyberguard_toolkit.questionary.select") as mock_select:
            mock_select.return_value.ask.return_value = None
            toolkit._service_detection()


class TestDNSRecon:
    """Tests for _dns_recon method."""

    def test_no_dnspython(self, toolkit, monkeypatch):
        monkeypatch.setattr("cyberguard_toolkit.HAS_DNSPYTHON", False)
        toolkit._dns_recon()

    def test_invalid_domain(self, toolkit):
        with patch("cyberguard_toolkit.Prompt.ask", return_value="not valid"):
            toolkit._dns_recon()

    def test_empty_domain(self, toolkit):
        with patch("cyberguard_toolkit.Prompt.ask", return_value=""):
            toolkit._dns_recon()

    @patch("cyberguard_toolkit.dns.resolver.resolve")
    def test_valid_domain(self, mock_resolve, toolkit):
        mock_resolve.side_effect = Exception("No answer")
        with patch("cyberguard_toolkit.Prompt.ask", return_value="example.com"), \
             patch("cyberguard_toolkit.Confirm.ask", return_value=False), \
             patch("cyberguard_toolkit.questionary.select") as mock_select:
            mock_select.return_value.ask.return_value = "Skip"
            toolkit._dns_recon()


class TestFirewallAudit:
    """Tests for _firewall_audit method."""

    def test_ufw_active(self, toolkit):
        with patch.object(
            toolkit.cmd, "run",
            return_value=(0, "Status: active\nDefault: deny (incoming)\n", ""),
        ):
            toolkit._firewall_audit()

    def test_ufw_inactive(self, toolkit):
        with patch.object(
            toolkit.cmd, "run",
            return_value=(0, "Status: inactive\n", ""),
        ):
            toolkit._firewall_audit()
            assert any("inactive" in f["title"].lower() for f in toolkit.findings)

    def test_ufw_wide_open(self, toolkit):
        with patch.object(
            toolkit.cmd, "run",
            return_value=(
                0,
                "Status: active\nTo Action From\n80 ALLOW Anywhere\n443 ALLOW Anywhere\n",
                "",
            ),
        ):
            toolkit._firewall_audit()

    def test_no_firewall(self, toolkit):
        with patch.object(
            toolkit.cmd, "run",
            side_effect=[(1, "", ""), (1, "", "")],
        ):
            toolkit._firewall_audit()


class TestARPMonitor:
    """Tests for _arp_monitor method."""

    def test_arp_normal(self, toolkit):
        with patch.object(
            toolkit.cmd, "run",
            return_value=(
                0,
                "192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:01 REACHABLE\n"
                "192.168.1.2 dev eth0 lladdr aa:bb:cc:dd:ee:02 STALE\n",
                "",
            ),
        ):
            toolkit._arp_monitor()
        assert len(toolkit.findings) == 0

    def test_arp_spoofing_detected(self, toolkit, sample_arp_output):
        with patch.object(
            toolkit.cmd, "run",
            return_value=(0, sample_arp_output, ""),
        ):
            toolkit._arp_monitor()
        assert any("Duplicate MAC" in f["title"] for f in toolkit.findings)

    def test_arp_failed(self, toolkit):
        with patch.object(
            toolkit.cmd, "run",
            return_value=(1, "", "error"),
        ):
            toolkit._arp_monitor()


class TestNetworkConnections:
    """Tests for _network_connections method."""

    def test_connections_with_suspicious(self, toolkit, sample_ss_output):
        with patch.object(
            toolkit.cmd, "run",
            return_value=(0, sample_ss_output, ""),
        ):
            toolkit._network_connections()
        assert any("Suspicious" in f["title"] for f in toolkit.findings)

    def test_connections_fail(self, toolkit):
        with patch.object(
            toolkit.cmd, "run",
            return_value=(1, "", "err"),
        ):
            toolkit._network_connections()


class TestVPNDetection:
    """Tests for _vpn_detection method."""

    def test_no_vpn(self, toolkit):
        with patch.object(
            toolkit.cmd, "run",
            side_effect=[
                (0, "1: lo: <LOOPBACK> mtu 65536\n2: eth0: <BROADCAST>\n", ""),
                (1, "", ""),
                (0, "", ""),
            ],
        ), patch.object(toolkit.cmd, "has_command", return_value=False):
            toolkit._vpn_detection()

    def test_wireguard_detected(self, toolkit):
        with patch.object(
            toolkit.cmd, "run",
            side_effect=[
                (0, "1: lo: <LOOPBACK>\n3: wg0: <POINTOPOINT>\n", ""),
                (0, "interface: wg0\npublic key: abc\n", ""),
                (1, "", ""),
                (0, "", ""),
            ],
        ), patch.object(toolkit.cmd, "has_command", return_value=True):
            toolkit._vpn_detection()


class TestBandwidthSummary:
    """Tests for _bandwidth_summary method."""

    def test_bandwidth(self, toolkit, sample_proc_net_dev):
        with patch.object(
            toolkit.cmd, "read_proc_file",
            return_value=sample_proc_net_dev,
        ), patch.object(
            toolkit.cmd, "run",
            return_value=(0, "TCP: 10 (estab 5)", ""),
        ):
            toolkit._bandwidth_summary()

    def test_bandwidth_no_proc(self, toolkit):
        with patch.object(
            toolkit.cmd, "read_proc_file",
            return_value=None,
        ), patch.object(
            toolkit.cmd, "run",
            return_value=(0, "TCP: 0", ""),
        ):
            toolkit._bandwidth_summary()


class TestHumanBytes:
    """Tests for _human_bytes static method."""

    def test_bytes(self):
        assert CyberGuardToolkit._human_bytes(0) == "0.0 B"
        assert CyberGuardToolkit._human_bytes(500) == "500.0 B"

    def test_kilobytes(self):
        assert "KB" in CyberGuardToolkit._human_bytes(2048)

    def test_megabytes(self):
        assert "MB" in CyberGuardToolkit._human_bytes(5 * 1024 * 1024)

    def test_gigabytes(self):
        assert "GB" in CyberGuardToolkit._human_bytes(2 * (1024 ** 3))

    def test_terabytes(self):
        assert "TB" in CyberGuardToolkit._human_bytes(3 * (1024 ** 4))
