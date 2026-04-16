"""CyberGuardToolkit vuln domain methods."""
import json
import logging
import re
import ssl
import socket
from datetime import datetime
from typing import Any, Dict, List
import requests
from cyberguard.constants import SECURITY_HEADERS, Severity


class VulnMixin:
    """Mixin providing vuln functionality to CyberGuardToolkit."""

    def _ssl_tls_analyzer(self):
        UI.print_section("SSL/TLS Analyzer")
        target = UI.ask_input("Target hostname (e.g., example.com)")
        if not target:
            return
        target = target.strip()
        port_str = UI.ask_input("Port (default: 443)") or "443"
        try:
            port = int(port_str.strip())
        except ValueError:
            port = 443

        UI.print_info(f"Analyzing SSL/TLS for {target}:{port}...")
        results = {"target": target, "port": port, "issues": []}

        try:
            context = ssl.create_default_context()
            with socket.create_connection((target, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()

                    results["protocol"] = version
                    results["cipher"] = cipher[0] if cipher else "N/A"
                    results["bits"] = cipher[2] if cipher and len(cipher) > 2 else "N/A"

                    # Certificate info
                    subject = dict(x[0] for x in cert.get("subject", []))
                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    results["subject_cn"] = subject.get("commonName", "N/A")
                    results["issuer"] = issuer.get("organizationName", "N/A")
                    results["not_before"] = cert.get("notBefore", "N/A")
                    results["not_after"] = cert.get("notAfter", "N/A")
                    results["san"] = [v for _, v in cert.get("subjectAltName", [])]

                    # Check expiry
                    try:
                        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                        days_left = (not_after - datetime.now(timezone.utc).replace(tzinfo=None)).days
                        results["days_until_expiry"] = days_left
                        if days_left < 0:
                            results["issues"].append({"severity": Severity.CRITICAL,
                                                       "title": "Certificate expired",
                                                       "details": f"Expired {abs(days_left)} days ago"})
                        elif days_left < 30:
                            results["issues"].append({"severity": Severity.HIGH,
                                                       "title": "Certificate expiring soon",
                                                       "details": f"{days_left} days remaining"})
                    except Exception as e:
                        self.config.logger.warning("SSL certificate expiry parse failed for %s:%s: %s", target, port, e)
                        pass

                    # Protocol version check
                    if version in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
                        results["issues"].append({
                            "severity": Severity.HIGH,
                            "title": f"Deprecated protocol: {version}",
                            "details": "Upgrade to TLSv1.2 or TLSv1.3",
                        })

            info = {
                "Subject CN": results.get("subject_cn", "N/A"),
                "Issuer": results.get("issuer", "N/A"),
                "Protocol": results.get("protocol", "N/A"),
                "Cipher": results.get("cipher", "N/A"),
                "Key Bits": results.get("bits", "N/A"),
                "Valid Until": results.get("not_after", "N/A"),
                "Days Until Expiry": results.get("days_until_expiry", "N/A"),
                "SANs": ", ".join(results.get("san", [])[:5]),
            }
            UI.print_key_value(info, f"SSL/TLS: {target}:{port}")

            if results["issues"]:
                for issue in results["issues"]:
                    UI.print_finding(issue["severity"], issue["title"], issue.get("details", ""))
                    self._add_finding(issue["title"], issue["severity"],
                                      issue.get("details", ""), "", "Vulnerability", "Protect")
            else:
                UI.print_success("No SSL/TLS issues found")

        except ssl.SSLCertVerificationError as e:
            UI.print_finding("HIGH", "SSL Certificate Verification Failed", str(e))
            results["issues"].append({"severity": Severity.HIGH, "title": "Cert verification failed"})
        except Exception as e:
            UI.print_error(f"SSL connection failed: {e}")
            return

        self.exporter.ask_export(results, f"ssl_{target}")


    def _ssl_tls_analyzer_auto(self, target: str, vulns: list):
        """Automated SSL check for full vuln scan."""
        try:
            context = ssl.create_default_context()
            host = target.split(":")[0]
            with socket.create_connection((host, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    version = ssock.version()
                    if version in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
                        vulns.append({"id": "SSL-001", "severity": Severity.HIGH,
                                      "description": f"Deprecated TLS: {version}",
                                      "affected": target})
                    try:
                        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                        days = (not_after - datetime.now(timezone.utc).replace(tzinfo=None)).days
                        if days < 0:
                            vulns.append({"id": "SSL-002", "severity": Severity.CRITICAL,
                                          "description": "Expired certificate", "affected": target})
                        elif days < 30:
                            vulns.append({"id": "SSL-003", "severity": Severity.HIGH,
                                          "description": f"Certificate expires in {days} days",
                                          "affected": target})
                    except Exception as e:
                        self.config.logger.warning("SSL auto-analysis certificate parse failed for %s: %s", target, e)
                        pass
        except ssl.SSLCertVerificationError:
            vulns.append({"id": "SSL-004", "severity": Severity.HIGH,
                          "description": "Certificate verification failed", "affected": target})
        except Exception as e:
            self.config.logger.debug("SSL auto-analysis failed for %s: %s", target, e)
            pass


    def _cve_lookup(self):
        UI.print_section("CVE Lookup")
        cve_id = UI.ask_input("Enter CVE ID (e.g., CVE-2024-1234)")
        if not cve_id:
            return
        cve_id = cve_id.strip().upper()
        if not InputValidator.validate_cve(cve_id):
            UI.print_error("Invalid CVE ID format (expected CVE-YYYY-NNNNN)")
            return

        try:
            with console.status("Querying NVD..."):
                data = self.threat_intel.nvd_cve_lookup(cve_id)
        except ValueError as e:
            UI.print_warning(f"API note: {e}")
            UI.print_info("NVD API works without a key but with rate limits")
            try:
                with console.status("Querying NVD (no key)..."):
                    data = self.threat_intel.nvd_cve_lookup(cve_id)
            except Exception as e2:
                UI.print_error(f"NVD lookup failed: {e2}")
                return
        except Exception as e:
            UI.print_error(f"NVD lookup failed: {e}")
            return

        vulns = data.get("vulnerabilities", [])
        if not vulns:
            UI.print_warning(f"No data found for {cve_id}")
            return

        cve_data = vulns[0].get("cve", {})
        descriptions = cve_data.get("descriptions", [])
        desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "N/A")

        metrics = cve_data.get("metrics", {})
        cvss_v31 = metrics.get("cvssMetricV31", [{}])
        cvss_score = "N/A"
        cvss_severity = "N/A"
        if cvss_v31:
            cvss_data = cvss_v31[0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore", "N/A")
            cvss_severity = cvss_data.get("baseSeverity", "N/A")

        info = {
            "CVE ID": cve_id,
            "Description": desc[:200],
            "CVSS Score": cvss_score,
            "Severity": cvss_severity,
            "Published": cve_data.get("published", "N/A")[:10],
            "Modified": cve_data.get("lastModified", "N/A")[:10],
        }
        UI.print_key_value(info, f"CVE Details: {cve_id}")
        self.config.save_session_history("cve_lookup", f"{cve_id}: CVSS {cvss_score}")


    def _web_security_headers(self):
        UI.print_section("Web Security Headers Check")
        url = UI.ask_input("Target URL (e.g., https://example.com)")
        if not url:
            return
        url = url.strip()
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        try:
            with console.status("Checking headers..."):
                resp = requests.head(url, timeout=REQUEST_TIMEOUT, allow_redirects=True,
                                     headers={"User-Agent": USER_AGENT})
        except Exception as e:
            UI.print_error(f"Request failed: {e}")
            return

        headers = dict(resp.headers)
        results = []

        for header in SECURITY_HEADERS:
            present = header in headers or header.lower() in {h.lower() for h in headers}
            value = headers.get(header, "Missing")
            results.append({
                "header": header,
                "value": value[:80] if value != "Missing" else "Missing",
                "status": "PASS" if present else "FAIL",
            })

        # Cookie security
        cookies = resp.headers.get("Set-Cookie", "")
        if cookies:
            if "secure" not in cookies.lower():
                results.append({"header": "Cookie Secure Flag", "value": "Missing", "status": "FAIL"})
            if "httponly" not in cookies.lower():
                results.append({"header": "Cookie HttpOnly Flag", "value": "Missing", "status": "FAIL"})

        for r in results:
            UI.print_check(r["status"], r["header"],
                           r["value"] if r["status"] == "FAIL" else "")
            if r["status"] == "FAIL":
                self._add_finding(f"Missing header: {r['header']}", "MEDIUM",
                                  f"Security header {r['header']} is not set",
                                  f"Add {r['header']} header to responses", "Vulnerability", "Protect")

        passed = sum(1 for r in results if r["status"] == "PASS")
        score = RiskScorer.score_compliance(passed, len(results))
        UI.print_score_panel(score["score"], score["grade"], "Web Headers Score")
        self.exporter.ask_export(results, f"headers_{urlparse(url).netloc}",
                                 rows=results)


    def _web_headers_auto(self, url: str, vulns: list):
        """Automated header check for full vuln scan."""
        try:
            resp = requests.head(url, timeout=REQUEST_TIMEOUT, allow_redirects=True,
                                 headers={"User-Agent": USER_AGENT})
            headers = {h.lower() for h in resp.headers}
            for h in ["strict-transport-security", "content-security-policy",
                       "x-content-type-options", "x-frame-options"]:
                if h not in headers:
                    vulns.append({"id": f"HDR-{h[:6].upper()}", "severity": Severity.MEDIUM,
                                  "description": f"Missing: {h}", "affected": url})
        except Exception as e:
            self.config.logger.debug("Web headers fetch failed for %s: %s", url, e)
            pass

    # ═══════════════════════════════════════════════════════════════════
    # CATEGORY 4: MONITORING & SIEM
    # ═══════════════════════════════════════════════════════════════════


    def _software_version_check(self):
        UI.print_section("Software Version Checker")

        # dpkg packages
        UI.print_subsection("Installed Packages (dpkg)")
        rc, out, _ = self.cmd.run(["dpkg", "-l"], timeout=15)
        packages = []
        if rc == 0:
            for line in out.splitlines():
                if line.startswith("ii"):
                    parts = line.split()
                    if len(parts) >= 3:
                        packages.append({"name": parts[1], "version": parts[2],
                                          "desc": " ".join(parts[3:])[:50]})
            UI.print_info(f"Total installed packages: {len(packages)}")

        # pip packages
        UI.print_subsection("Python Packages (pip)")
        rc, out, _ = self.cmd.run(["pip", "list", "--format=json"], timeout=15)
        pip_packages = []
        if rc == 0:
            try:
                pip_packages = json.loads(out)
                UI.print_info(f"Total pip packages: {len(pip_packages)}")
            except json.JSONDecodeError:
                pass

        # Show top packages with known CVE keywords
        security_pkgs = ["openssl", "openssh", "linux-image", "sudo", "curl",
                         "wget", "python3", "nginx", "apache2", "mysql", "postgresql"]
        sec_installed = [p for p in packages if any(s in p["name"] for s in security_pkgs)]
        if sec_installed:
            rows = [[p["name"], p["version"]] for p in sec_installed[:20]]
            UI.print_table("Security-Relevant Packages",
                           [("Package", "cyan"), ("Version", "yellow")], rows)


    def _exploit_search(self):
        UI.print_section("Exploit DB Search")
        query = UI.ask_input("Search term (e.g., CVE ID or software name)")
        if not query:
            return

        # Try searchsploit
        if self.cmd.has_command("searchsploit"):
            UI.print_info("Searching local Exploit-DB...")
            rc, out, _ = self.cmd.run(["searchsploit", "--json", query.strip()], timeout=30)
            if rc == 0:
                try:
                    data = json.loads(out)
                    exploits = data.get("RESULTS_EXPLOIT", [])
                    if exploits:
                        rows = [[e.get("Title", "")[:60], e.get("Path", "")[:40],
                                 e.get("Date_Published", "")] for e in exploits[:20]]
                        UI.print_table(f"Exploits for: {query}",
                                       [("Title", "white"), ("Path", "cyan"), ("Date", "dim")],
                                       rows)
                    else:
                        UI.print_warning("No exploits found in local database")
                except json.JSONDecodeError:
                    console.print(out[:2000])
        else:
            UI.print_warning("searchsploit not installed. Install with: sudo apt install exploitdb")


    def _config_compliance(self):
        UI.print_section("Configuration Compliance")
        UI.print_info("Running CIS Benchmark checks...")
        results = self.compliance.run_cis_checks()
        passed = sum(1 for r in results if r["status"] == "PASS")
        total = len(results)
        score = RiskScorer.score_compliance(passed, total)

        for r in results:
            UI.print_check(r["status"], f"[{r['id']}] {r['title']}", r.get("details", ""))

        UI.print_score_panel(score["score"], score["grade"], "CIS Compliance Score")
        self.scores["cis"] = score

        html = HTMLReportGenerator.compliance_report(results, "CIS Benchmark", score)
        self.exporter.ask_export(
            {"results": results, "score": score},
            "cis_compliance",
            rows=results, html=html,
        )


    def _full_vuln_scan(self):
        UI.print_section("Full Vulnerability Scan")
        target = UI.ask_input("Target hostname or URL")
        if not target:
            return
        target = target.strip()
        host = target.split("://")[-1].split("/")[0].split(":")[0]

        all_vulns = []
        phase = 0

        # Phase 1: Port Scan
        phase += 1
        UI.print_info(f"Phase {phase}/7: Port Scan...")
        self._full_vuln_port_scan(host, all_vulns)

        # Phase 2: SSL/TLS Analysis
        phase += 1
        UI.print_info(f"Phase {phase}/7: SSL/TLS Analysis...")
        if InputValidator.validate_domain(host) or "." in host:
            self._ssl_tls_analyzer_auto(host, all_vulns)

        # Phase 3: Web Security Headers
        phase += 1
        UI.print_info(f"Phase {phase}/7: Web Security Headers...")
        url = target if target.startswith("http") else f"https://{host}"
        self._web_headers_auto(url, all_vulns)

        # Phase 4: Software Version Check
        phase += 1
        UI.print_info(f"Phase {phase}/7: Software Version Check...")
        self._software_version_check()

        # Phase 5: Configuration Compliance (CIS)
        phase += 1
        UI.print_info(f"Phase {phase}/7: Configuration Compliance...")
        self._full_vuln_config_compliance(all_vulns)

        # Phase 6: Exploit Search (for found CVEs)
        phase += 1
        UI.print_info(f"Phase {phase}/7: Exploit Search...")
        self._full_vuln_exploit_search(all_vulns)

        # Phase 7: Service Vulnerability Check
        phase += 1
        UI.print_info(f"Phase {phase}/7: Service Vulnerability Check...")
        self._full_vuln_service_check(host, all_vulns)

        # Summary
        console.print()
        UI.print_subsection(f"Scan Summary: {target}")
        severity_counts = {}
        for v in all_vulns:
            sev = v.get("severity", Severity.INFO)
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if sev in severity_counts:
                color = {"CRITICAL": "red", "HIGH": "bright_red", "MEDIUM": "yellow",
                         "LOW": "blue", "INFO": "dim"}.get(sev, "white")
                console.print(f"  [{color}]{sev}: {severity_counts[sev]}[/{color}]")
        UI.print_info(f"Total vulnerabilities found: {len(all_vulns)}")

        if all_vulns:
            score = RiskScorer.score_host(all_vulns)
            UI.print_score_panel(score["score"], score["grade"], "Vulnerability Score")
            for v in all_vulns:
                self._add_finding(
                    v.get("description", "Unknown"), v.get("severity", Severity.MEDIUM),
                    f"{v.get('id', 'N/A')}: {v.get('description', '')}",
                    v.get("recommendation", "Review and remediate"),
                    "Vulnerability", "Detect",
                )
            html = HTMLReportGenerator.vulnerability_report(all_vulns, score)
            self.exporter.ask_export(
                {"vulns": all_vulns, "score": score},
                f"vuln_scan_{host}",
                rows=all_vulns, html=html,
            )
            self.config.save_session_history("full_vuln_scan",
                                             f"{host}: {len(all_vulns)} vulns, score {score['score']}")
        else:
            UI.print_success("No vulnerabilities detected")
            self.config.save_session_history("full_vuln_scan", f"{host}: clean")


    def _vuln_assessment_menu(self):
        while True:
            choice = UI.ask_menu("Vulnerability Assessment", [
                "1) CVE Lookup",
                "2) SSL/TLS Analyzer",
                "3) Software Version Checker",
                "4) Exploit DB Search",
                "5) Web Security Headers",
                "6) Config Compliance Check",
                "7) Full Vulnerability Scan",
                "0) Back",
            ])
            if not choice or choice.startswith("0"):
                return
            num = choice.split(")")[0].strip()
            actions = {
                "1": self._cve_lookup, "2": self._ssl_tls_analyzer,
                "3": self._software_version_check, "4": self._exploit_search,
                "5": self._web_security_headers, "6": self._config_compliance,
                "7": self._full_vuln_scan,
            }
            fn = actions.get(num)
            if fn:
                try:
                    fn()
                except Exception as e:
                    UI.print_error(f"Error: {e}")
                    self.config.logger.error(f"Vuln error: {e}", exc_info=True)

