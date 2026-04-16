"""CyberGuardToolkit network domain methods."""
import ipaddress
import logging
import re
import socket
import subprocess
import time
from typing import Any, Dict, List


class NetworkMixin:
    """Mixin providing network functionality to CyberGuardToolkit."""

    def _port_scanner(self):
        UI.print_section("Port Scanner")
        target = UI.ask_input("Target IP or hostname")
        if not target:
            return
        target = target.strip()
        if not InputValidator.validate_ip(target) and not InputValidator.validate_domain(target):
            UI.print_error("Invalid target. Enter an IP address or domain.")
            return

        scan_type = UI.ask_menu("Scan type:", [
            "Quick (top 65 ports)",
            "Common (top 1000 ports)",
            "Full (1-65535)",
            "Custom range",
        ])
        if not scan_type:
            return

        if scan_type.startswith("Quick"):
            ports = TOP_100_PORTS
        elif scan_type.startswith("Common"):
            ports = TOP_1000_PORTS
        elif scan_type.startswith("Full"):
            ports = list(range(1, 65536))
        else:
            pr = UI.ask_input("Port range (e.g., 1-1000)")
            if not pr:
                return
            parsed = InputValidator.validate_port_range(pr)
            if not parsed:
                UI.print_error("Invalid port range")
                return
            ports = list(range(parsed[0], parsed[1] + 1))

        timeout_val = 1.0
        if len(ports) > 1000:
            timeout_val = 0.5

        results = []
        common_services = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
            80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc",
            139: "netbios", 143: "imap", 161: "snmp", 389: "ldap",
            443: "https", 445: "smb", 465: "smtps", 514: "syslog",
            587: "submission", 636: "ldaps", 993: "imaps", 995: "pop3s",
            1433: "mssql", 1521: "oracle", 2049: "nfs", 3306: "mysql",
            3389: "rdp", 5432: "postgresql", 5900: "vnc", 6379: "redis",
            8080: "http-proxy", 8443: "https-alt", 9090: "web-mgmt",
            9200: "elasticsearch", 27017: "mongodb",
        }

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        ) as progress:
            task = progress.add_task(f"Scanning {target}", total=len(ports))
            for port in ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(timeout_val)
                    rc = sock.connect_ex((target, port))
                    if rc == 0:
                        service = common_services.get(port, "unknown")
                        banner = ""
                        try:
                            sock.settimeout(2)
                            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                            banner = sock.recv(256).decode("utf-8", errors="replace").strip()
                        except Exception as e:
                            self.config.logger.debug("Banner grab failed for %s:%s: %s", target, port, e)
                            pass
                        results.append({
                            "port": port, "state": "open",
                            "service": service, "banner": banner,
                        })
                    sock.close()
                except Exception as e:
                    self.config.logger.debug("Port scan connect failed for %s:%s: %s", target, port, e)
                    pass
                progress.advance(task)

        UI.print_port_scan_results(target, results)
        self.config.save_session_history("port_scan", f"{target}: {len(results)} open ports")

        if results:
            suspicious = [r for r in results if r["port"] in SUSPICIOUS_PORTS]
            if suspicious:
                for s in suspicious:
                    self._add_finding(
                        f"Suspicious port {s['port']} open on {target}",
                        "HIGH",
                        f"Port {s['port']} ({s['service']}) is commonly used by malware",
                        "Investigate and close if not needed",
                        "Network", "Detect",
                    )
            self.exporter.ask_export(
                results, f"port_scan_{target}",
                rows=results,
                txt="\n".join(f"Port {r['port']}: {r['service']}" for r in results),
            )


    def _service_detection(self):
        UI.print_section("Service Detection")
        choice = UI.ask_menu("Detection method:", [
            "Local services (ss)",
            "Remote scan (nmap -sV)",
        ])
        if not choice:
            return

        if choice.startswith("Local"):
            rc, out, _ = self.cmd.run(["ss", "-tlnp"], timeout=15)
            if rc != 0:
                UI.print_error("Failed to run ss command")
                return
            services = []
            for line in out.splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 5:
                    local = parts[3]
                    process = parts[5] if len(parts) > 5 else ""
                    process_match = re.search(r'"([^"]+)"', process)
                    proc_name = process_match.group(1) if process_match else "unknown"
                    services.append({
                        "state": parts[0], "local_addr": local,
                        "service": proc_name,
                    })
            rows = [[s["local_addr"], s["service"], s["state"]] for s in services]
            UI.print_table("Local Listening Services",
                           [("Address", "cyan"), ("Service", "white"), ("State", "green")],
                           rows)
            if services:
                self.exporter.ask_export(services, "local_services", rows=services)
        else:
            target = UI.ask_input("Target IP or hostname")
            if not target:
                return
            if not self.cmd.has_command("nmap"):
                UI.print_error("nmap is not installed. Install with: sudo apt install nmap")
                return
            UI.print_info(f"Running nmap service detection on {target}...")
            rc, out, err = self.cmd.run(
                ["nmap", "-sV", "--top-ports", "100", "-T4", target],
                timeout=120,
            )
            if rc == 0:
                console.print(f"\n{out}")
            else:
                UI.print_error(f"nmap failed: {err}")


    def _dns_recon(self):
        UI.print_section("DNS Reconnaissance")
        if not HAS_DNSPYTHON:
            UI.print_error("dnspython not installed. Install with: pip install dnspython")
            return

        domain = UI.ask_input("Target domain")
        if not domain or not InputValidator.validate_domain(domain.strip()):
            UI.print_error("Invalid domain")
            return
        domain = domain.strip()

        records = {}
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "SRV"]

        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}")) as progress:
            task = progress.add_task("Querying DNS records...", total=len(record_types))
            for rtype in record_types:
                try:
                    answers = dns.resolver.resolve(domain, rtype)
                    records[rtype] = [str(r) for r in answers]
                except Exception as e:
                    self.config.logger.debug("DNS %s lookup failed: %s", rtype, e)
                    pass
                progress.advance(task)

        UI.print_dns_results(domain, records)

        # Subdomain brute force
        if UI.confirm("Run subdomain enumeration?"):
            common_subs = [
                "www", "mail", "ftp", "admin", "blog", "dev", "staging",
                "api", "app", "cdn", "docs", "git", "jenkins", "jira",
                "login", "m", "media", "ns1", "ns2", "portal", "shop",
                "smtp", "ssh", "test", "vpn", "webmail", "wiki", "mx",
                "db", "backup", "monitoring", "status", "internal",
            ]
            found_subs = []
            with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                          BarColumn(), TextColumn("{task.percentage:>3.0f}%")) as progress:
                task = progress.add_task("Enumerating subdomains", total=len(common_subs))
                for sub in common_subs:
                    full = f"{sub}.{domain}"
                    try:
                        answers = dns.resolver.resolve(full, "A")
                        ips = [str(r) for r in answers]
                        found_subs.append({"subdomain": full, "ips": ips})
                    except Exception as e:
                        self.config.logger.debug("Subdomain %s failed: %s", full, e)
                        pass
                    progress.advance(task)

            if found_subs:
                rows = [[s["subdomain"], ", ".join(s["ips"])] for s in found_subs]
                UI.print_table("Discovered Subdomains",
                               [("Subdomain", "cyan"), ("IP Addresses", "white")], rows)

        all_data = {"domain": domain, "records": records}
        self.config.save_session_history("dns_recon", f"{domain}: {sum(len(v) for v in records.values())} records")
        self.exporter.ask_export(all_data, f"dns_{domain}", rows=[
            {"type": t, "value": v} for t, vals in records.items() for v in vals
        ])


    def _firewall_audit(self):
        UI.print_section("Firewall Rule Audit")
        findings = []

        # Check ufw
        rc, out, _ = self.cmd.run(["ufw", "status", "verbose"], timeout=10)
        if rc == 0:
            UI.print_subsection("UFW Status")
            console.print(f"\n{out}")
            if "inactive" in out.lower():
                findings.append({"title": "UFW firewall is inactive", "severity": Severity.HIGH,
                                 "recommendation": "Enable with: sudo ufw enable"})
                self._add_finding("Firewall is inactive", "HIGH",
                                  "UFW firewall is not enabled",
                                  "Enable with: sudo ufw enable", "Network", "Protect")
            if "allow" in out.lower() and "anywhere" in out.lower():
                wide_rules = [l for l in out.splitlines() if "ALLOW" in l and "Anywhere" in l]
                if wide_rules:
                    findings.append({"title": f"{len(wide_rules)} wide-open ALLOW rules",
                                     "severity": Severity.MEDIUM})
        else:
            # Try iptables
            rc2, out2, _ = self.cmd.run(["iptables", "-L", "-n", "--line-numbers"], timeout=10)
            if rc2 == 0:
                UI.print_subsection("iptables Rules")
                console.print(f"\n{out2}")
            else:
                UI.print_warning("Cannot read firewall status (try with sudo)")

        if findings:
            for f in findings:
                UI.print_finding(f["severity"], f["title"])


    def _arp_monitor(self):
        UI.print_section("ARP Monitor")
        rc, out, _ = self.cmd.run(["ip", "neigh", "show"], timeout=10)
        if rc != 0:
            UI.print_error("Failed to read ARP table")
            return

        entries = []
        mac_to_ips: Dict[str, List[str]] = {}
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 5:
                ip = parts[0]
                mac = parts[4] if parts[4] != "FAILED" else "N/A"
                state = parts[-1]
                entries.append({"ip": ip, "mac": mac, "state": state})
                if mac != "N/A":
                    mac_to_ips.setdefault(mac, []).append(ip)

        rows = [[e["ip"], e["mac"], e["state"]] for e in entries]
        UI.print_table("ARP Table",
                       [("IP Address", "cyan"), ("MAC Address", "yellow"), ("State", "green")],
                       rows)

        # Check for duplicate MACs (potential ARP spoofing)
        dupes = {mac: ips for mac, ips in mac_to_ips.items() if len(ips) > 1}
        if dupes:
            UI.print_warning("Potential ARP spoofing detected!")
            for mac, ips in dupes.items():
                UI.print_finding("HIGH", f"MAC {mac} mapped to multiple IPs: {', '.join(ips)}")
                self._add_finding(
                    f"Duplicate MAC detected: {mac}", "HIGH",
                    f"MAC {mac} is associated with IPs: {', '.join(ips)}",
                    "Investigate for ARP spoofing", "Network", "Detect",
                )


    def _network_connections(self):
        UI.print_section("Network Connection Monitor")
        rc, out, _ = self.cmd.run(["ss", "-tunap"], timeout=15)
        if rc != 0:
            UI.print_error("Failed to run ss command")
            return

        connections = []
        for line in out.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 5:
                proto = parts[0]
                local = parts[3]
                remote = parts[4]
                state = parts[1] if len(parts) > 1 else ""
                process = parts[5] if len(parts) > 5 else ""
                process_match = re.search(r'"([^"]+)"', process)
                proc_name = process_match.group(1) if process_match else ""

                suspicious = False
                # Check for suspicious remote ports
                try:
                    remote_port = int(remote.rsplit(":", 1)[-1])
                    if remote_port in SUSPICIOUS_PORTS:
                        suspicious = True
                except (ValueError, IndexError):
                    pass

                connections.append({
                    "proto": proto, "local": local, "remote": remote,
                    "state": state, "process": proc_name, "suspicious": suspicious,
                })

        UI.print_connections_table(connections)

        suspicious_conns = [c for c in connections if c["suspicious"]]
        if suspicious_conns:
            UI.print_warning(f"Found {len(suspicious_conns)} suspicious connection(s)!")
            for c in suspicious_conns:
                self._add_finding(
                    f"Suspicious connection to {c['remote']}", "HIGH",
                    f"Process '{c['process']}' connected to suspicious port",
                    "Investigate the connection and process", "Network", "Detect",
                )

        self.config.save_session_history("connections", f"{len(connections)} active connections")


    def _vpn_detection(self):
        UI.print_section("VPN/Tunnel Detection")
        vpns_found = []

        # Check interfaces
        rc, out, _ = self.cmd.run(["ip", "link", "show"], timeout=10)
        if rc == 0:
            for line in out.splitlines():
                for vpn_type in ["tun", "tap", "wg", "ppp", "vti", "gre"]:
                    if f"{vpn_type}" in line.lower():
                        iface = line.split(":")[1].strip().split("@")[0] if ":" in line else "unknown"
                        vpns_found.append({"type": vpn_type, "interface": iface})

        # WireGuard
        if self.cmd.has_command("wg"):
            rc, out, _ = self.cmd.run(["wg", "show"], timeout=10)
            if rc == 0 and out.strip():
                vpns_found.append({"type": "WireGuard", "interface": "wg", "details": out[:200]})

        # OpenVPN
        rc, out, _ = self.cmd.run(["pgrep", "-a", "openvpn"], timeout=5)
        if rc == 0 and out.strip():
            vpns_found.append({"type": "OpenVPN", "interface": "tun", "details": out[:200]})

        # SSH tunnels
        rc, out, _ = self.cmd.run(["ss", "-tnp"], timeout=10)
        if rc == 0:
            ssh_tunnels = [l for l in out.splitlines() if "ssh" in l.lower() and "ESTAB" in l]
            if ssh_tunnels:
                vpns_found.append({"type": "SSH Tunnel", "interface": "N/A",
                                   "details": f"{len(ssh_tunnels)} SSH tunnel(s)"})

        if vpns_found:
            rows = [[v["type"], v.get("interface", "N/A"), v.get("details", "")[:60]]
                    for v in vpns_found]
            UI.print_table("VPN/Tunnels Detected",
                           [("Type", "cyan"), ("Interface", "yellow"), ("Details", "white")],
                           rows)
        else:
            UI.print_info("No VPN/tunnel interfaces detected")


    def _bandwidth_summary(self):
        UI.print_section("Bandwidth & Traffic Summary")

        # /proc/net/dev
        content = self.cmd.read_proc_file("/proc/net/dev")
        if content:
            interfaces = []
            for line in content.splitlines()[2:]:
                parts = line.split()
                if len(parts) >= 10:
                    iface = parts[0].rstrip(":")
                    rx_bytes = int(parts[1])
                    tx_bytes = int(parts[9])
                    interfaces.append({
                        "interface": iface,
                        "rx_bytes": rx_bytes,
                        "tx_bytes": tx_bytes,
                        "rx_human": self._human_bytes(rx_bytes),
                        "tx_human": self._human_bytes(tx_bytes),
                    })
            rows = [[i["interface"], i["rx_human"], i["tx_human"]]
                    for i in interfaces if i["rx_bytes"] > 0 or i["tx_bytes"] > 0]
            UI.print_table("Network Interface Traffic",
                           [("Interface", "cyan"), ("RX", "green"), ("TX", "yellow")],
                           rows)

        # ss -s
        rc, out, _ = self.cmd.run(["ss", "-s"], timeout=10)
        if rc == 0:
            UI.print_subsection("Socket Statistics")
            console.print(f"\n{out}")

    @staticmethod


    def _network_security_menu(self):
        while True:
            choice = UI.ask_menu("Network Security", [
                "1) Port Scanner",
                "2) Service Detection",
                "3) DNS Reconnaissance",
                "4) Firewall Rule Audit",
                "5) ARP Monitor",
                "6) Network Connection Monitor",
                "7) VPN/Tunnel Detection",
                "8) Bandwidth & Traffic Summary",
                "0) Back",
            ])
            if not choice or choice.startswith("0"):
                return
            num = choice.split(")")[0].strip()
            actions = {
                "1": self._port_scanner, "2": self._service_detection,
                "3": self._dns_recon, "4": self._firewall_audit,
                "5": self._arp_monitor, "6": self._network_connections,
                "7": self._vpn_detection, "8": self._bandwidth_summary,
            }
            fn = actions.get(num)
            if fn:
                try:
                    fn()
                except Exception as e:
                    UI.print_error(f"Error: {e}")
                    self.config.logger.error(f"Network error: {e}", exc_info=True)

