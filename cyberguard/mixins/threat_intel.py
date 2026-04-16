"""CyberGuardToolkit threat_intel domain methods."""
import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, List
from cyberguard.constants import IOCS_FILE, MAX_BULK_IPS, Severity


class ThreatIntelMixin:
    """Mixin providing threat_intel functionality to CyberGuardToolkit."""

    def _ip_reputation(self):
        UI.print_section("IP Reputation — VirusTotal")
        if not self.config.has_api_key("virustotal"):
            UI.print_error("VirusTotal API key not configured. Set in Settings.")
            return
        ip = UI.ask_input("Enter IP address")
        if not ip or not InputValidator.validate_ip(ip.strip()):
            UI.print_error("Invalid IP address")
            return
        ip = ip.strip()

        try:
            with console.status("Querying VirusTotal..."):
                data = self.threat_intel.vt_ip_reputation(ip)
            UI.print_threat_intel(data, "virustotal")
            self.config.save_session_history("ip_reputation", f"VT: {ip}")
            self.exporter.ask_export(data, f"vt_ip_{ip}")
        except Exception as e:
            UI.print_error(f"VirusTotal query failed: {e}")


    def _ip_abuse_check(self):
        UI.print_section("IP Abuse Check — AbuseIPDB")
        if not self.config.has_api_key("abuseipdb"):
            UI.print_error("AbuseIPDB API key not configured. Set in Settings.")
            return
        ip = UI.ask_input("Enter IP address")
        if not ip or not InputValidator.validate_ip(ip.strip()):
            UI.print_error("Invalid IP address")
            return
        ip = ip.strip()

        try:
            with console.status("Querying AbuseIPDB..."):
                data = self.threat_intel.abuseipdb_check(ip)
            UI.print_threat_intel(data, "abuseipdb")

            abuse_score = data.get("data", {}).get("abuseConfidenceScore", 0)
            if abuse_score >= 75:
                self._add_finding(f"High abuse score for {ip}: {abuse_score}%", "HIGH",
                                  f"AbuseIPDB confidence: {abuse_score}%",
                                  f"Consider blocking {ip}", "Threat Intel", "Detect")
            self.exporter.ask_export(data, f"abuse_{ip}")
        except Exception as e:
            UI.print_error(f"AbuseIPDB query failed: {e}")


    def _hash_reputation(self):
        UI.print_section("Hash/File Reputation — VirusTotal")
        if not self.config.has_api_key("virustotal"):
            UI.print_error("VirusTotal API key not configured. Set in Settings.")
            return
        hash_input = UI.ask_input("Enter file hash (MD5/SHA1/SHA256)")
        if not hash_input:
            return
        hash_input = hash_input.strip()
        hash_type = InputValidator.validate_hash(hash_input)
        if not hash_type:
            UI.print_error("Invalid hash format")
            return

        try:
            with console.status("Querying VirusTotal..."):
                data = self.threat_intel.vt_hash_reputation(hash_input)
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            info = {
                "Hash": hash_input,
                "Type": hash_type.upper(),
                "Name": attrs.get("meaningful_name", "N/A"),
                "Type Description": attrs.get("type_description", "N/A"),
                "Size": f"{attrs.get('size', 0)} bytes",
                "Malicious": stats.get("malicious", 0),
                "Suspicious": stats.get("suspicious", 0),
                "Harmless": stats.get("harmless", 0),
                "Undetected": stats.get("undetected", 0),
            }
            UI.print_key_value(info, "File Reputation")

            if stats.get("malicious", 0) > 0:
                self._add_finding(f"Malicious file detected: {hash_input[:16]}...", "CRITICAL",
                                  f"{stats['malicious']} detections",
                                  "Quarantine the file immediately", "Threat Intel", "Detect")
        except requests.exceptions.HTTPError as e:
            if e.response and e.response.status_code == 404:
                UI.print_info("Hash not found in VirusTotal database")
            else:
                UI.print_error(f"Query failed: {e}")
        except Exception as e:
            UI.print_error(f"Query failed: {e}")


    def _whois_intelligence(self):
        UI.print_section("WHOIS Intelligence")
        target = UI.ask_input("Enter domain or IP")
        if not target:
            return
        target = target.strip()

        if self.cmd.has_command("whois"):
            with console.status("Running WHOIS lookup..."):
                rc, out, _ = self.cmd.run(["whois", target], timeout=30)
            if rc == 0:
                console.print(Panel(out[:3000], title=f"WHOIS: {target}",
                                    border_style="bright_blue"))
                self.exporter.ask_export({"target": target, "whois": out},
                                         f"whois_{target}",
                                         txt=out)
            else:
                UI.print_error("WHOIS lookup failed")
        else:
            UI.print_error("whois command not found. Install with: sudo apt install whois")


    def _mitre_attack_mapper(self):
        UI.print_section("MITRE ATT&CK Technique Mapper")

        choice = UI.ask_menu("Action:", [
            "Search by technique ID",
            "Search by keyword",
            "Browse all techniques",
            "Map findings to ATT&CK",
            "Back",
        ])
        if not choice or choice == "Back":
            return

        if choice.startswith("Search by technique"):
            tid = UI.ask_input("Technique ID (e.g., T1059)")
            if tid:
                tid = tid.strip().upper()
                matches = {k: v for k, v in MITRE_TECHNIQUES.items()
                           if k.startswith(tid)}
                if matches:
                    rows = [[k, v["name"], v["tactic"]] for k, v in matches.items()]
                    UI.print_table("MITRE ATT&CK Techniques",
                                   [("ID", "cyan"), ("Name", "white"), ("Tactic", "yellow")],
                                   rows)
                else:
                    UI.print_warning("No matching techniques found")

        elif choice.startswith("Search by keyword"):
            kw = UI.ask_input("Keyword")
            if kw:
                kw_lower = kw.strip().lower()
                matches = {k: v for k, v in MITRE_TECHNIQUES.items()
                           if kw_lower in v["name"].lower() or kw_lower in v["tactic"].lower()}
                if matches:
                    rows = [[k, v["name"], v["tactic"]] for k, v in matches.items()]
                    UI.print_table("Matching Techniques",
                                   [("ID", "cyan"), ("Name", "white"), ("Tactic", "yellow")],
                                   rows)
                else:
                    UI.print_warning("No matches found")

        elif choice.startswith("Browse"):
            rows = [[k, v["name"], v["tactic"]] for k, v in MITRE_TECHNIQUES.items()]
            UI.print_table("MITRE ATT&CK Techniques",
                           [("ID", "cyan"), ("Name", "white"), ("Tactic", "yellow")],
                           rows)

        elif choice.startswith("Map findings"):
            if not self.findings:
                UI.print_warning("No findings to map. Run some assessments first.")
                return
            mapped = []
            for f in self.findings:
                techniques = []
                title_lower = f.get("title", "").lower()
                if "brute" in title_lower or "login" in title_lower:
                    techniques.append("T1110")
                if "ssh" in title_lower:
                    techniques.append("T1021.004")
                if "suid" in title_lower or "permission" in title_lower:
                    techniques.append("T1548")
                if "service" in title_lower:
                    techniques.append("T1543")
                if "cron" in title_lower:
                    techniques.append("T1053.003")
                if techniques:
                    mapped.append({"finding": f["title"], "techniques": techniques})

            if mapped:
                rows = [[m["finding"][:50], ", ".join(m["techniques"])] for m in mapped]
                UI.print_table("Findings → ATT&CK Mapping",
                               [("Finding", "white"), ("Techniques", "cyan")], rows)
            else:
                UI.print_info("No findings could be mapped to ATT&CK techniques")


    def _ioc_manager(self):
        UI.print_section("Indicator of Compromise (IoC) Manager")

        choice = UI.ask_menu("IoC Action:", [
            "Add IoC",
            "Search IoCs",
            "List all IoCs",
            "Import from file",
            "Export IoCs",
            "Back",
        ])
        if not choice or choice == "Back":
            return

        iocs = self._load_iocs()

        if choice.startswith("Add"):
            ioc_type = UI.ask_menu("IoC type:", ["ip", "domain", "hash", "url", "email", "cve"])
            if not ioc_type:
                return
            value = UI.ask_input(f"Enter {ioc_type} value")
            if not value:
                return
            description = UI.ask_input("Description (optional)") or ""
            ioc = {
                "type": ioc_type, "value": value.strip(),
                "description": description,
                "added": datetime.now().isoformat(),
                "source": "manual",
            }
            iocs.append(ioc)
            self._save_iocs(iocs)
            UI.print_success(f"IoC added: {ioc_type} = {value.strip()}")

        elif choice.startswith("Search"):
            query = UI.ask_input("Search term")
            if query:
                matches = [i for i in iocs if query.strip().lower() in
                           f"{i['value']} {i.get('description', '')}".lower()]
                if matches:
                    rows = [[i["type"], i["value"][:40], i.get("description", "")[:30],
                             i.get("added", "")[:10]] for i in matches]
                    UI.print_table("Matching IoCs",
                                   [("Type", "cyan"), ("Value", "white"),
                                    ("Description", "dim"), ("Added", "dim")],
                                   rows)
                else:
                    UI.print_warning("No matching IoCs found")

        elif choice.startswith("List"):
            if iocs:
                rows = [[i["type"], i["value"][:40], i.get("description", "")[:30],
                         i.get("added", "")[:10]] for i in iocs[-50:]]
                UI.print_table(f"IoC Database ({len(iocs)} total)",
                               [("Type", "cyan"), ("Value", "white"),
                                ("Description", "dim"), ("Added", "dim")],
                               rows)
            else:
                UI.print_info("IoC database is empty")

        elif choice.startswith("Import"):
            path = UI.ask_input("JSON file path")
            if path:
                try:
                    new_iocs = json.loads(Path(path.strip()).read_text(encoding="utf-8"))
                    if isinstance(new_iocs, list):
                        iocs.extend(new_iocs)
                        self._save_iocs(iocs)
                        UI.print_success(f"Imported {len(new_iocs)} IoCs")
                except Exception as e:
                    UI.print_error(f"Import failed: {e}")

        elif choice.startswith("Export"):
            self.exporter.export_json(iocs, "iocs_export")
            UI.print_success("IoCs exported")


    def _load_iocs(self) -> list:
        if IOCS_FILE.exists():
            try:
                return json.loads(IOCS_FILE.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                return []
        return []


    def _save_iocs(self, iocs: list):
        IOCS_FILE.write_text(json.dumps(iocs, indent=2), encoding="utf-8")


    def _bulk_ip_reputation(self):
        UI.print_section("Bulk IP Reputation Check")
        if not self.config.has_api_key("virustotal") and not self.config.has_api_key("abuseipdb"):
            UI.print_error("No API keys configured for VT or AbuseIPDB")
            return

        ip_input = UI.ask_input("Enter IPs (comma-separated) or file path")
        if not ip_input:
            return

        ips = []
        if Path(ip_input.strip()).exists():
            try:
                content = Path(ip_input.strip()).read_text(encoding="utf-8")
                ips = [l.strip() for l in content.splitlines() if l.strip()]
            except OSError:
                UI.print_error("Cannot read file")
                return
        else:
            ips = [ip.strip() for ip in ip_input.split(",")]

        ips = [ip for ip in ips if InputValidator.validate_ip(ip)]
        if not ips:
            UI.print_error("No valid IPs provided")
            return
        if len(ips) > MAX_BULK_IPS:
            UI.print_warning(f"Limiting to {MAX_BULK_IPS} IPs")
            ips = ips[:MAX_BULK_IPS]

        results = []
        with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                       BarColumn(), TextColumn("{task.percentage:>3.0f}%")) as progress:
            task = progress.add_task("Checking IPs", total=len(ips))
            for ip in ips:
                result = {"ip": ip, "vt_malicious": "N/A", "abuse_score": "N/A"}
                if self.config.has_api_key("virustotal"):
                    try:
                        data = self.threat_intel.vt_ip_reputation(ip)
                        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                        result["vt_malicious"] = stats.get("malicious", 0)
                    except Exception as e:
                        self.config.logger.debug("VirusTotal enrichment failed for %s: %s", ip, e)
                        pass
                if self.config.has_api_key("abuseipdb"):
                    try:
                        data = self.threat_intel.abuseipdb_check(ip)
                        result["abuse_score"] = data.get("data", {}).get("abuseConfidenceScore", 0)
                    except Exception as e:
                        self.config.logger.debug("AbuseIPDB enrichment failed for %s: %s", ip, e)
                        pass
                results.append(result)
                progress.advance(task)

        rows = [[r["ip"], str(r["vt_malicious"]), f"{r['abuse_score']}%"
                 if r["abuse_score"] != "N/A" else "N/A"] for r in results]
        UI.print_table("Bulk IP Reputation Results",
                       [("IP", "cyan"), ("VT Malicious", "red"), ("Abuse Score", "yellow")],
                       rows)
        self.exporter.ask_export(results, "bulk_ip_reputation", rows=results)

    # ═══════════════════════════════════════════════════════════════════
    # CATEGORY 6: FORENSICS & INCIDENT RESPONSE
    # ═══════════════════════════════════════════════════════════════════


    def _threat_intel_menu(self):
        while True:
            choice = UI.ask_menu("Threat Intelligence", [
                "1) IP Reputation (VirusTotal)",
                "2) IP Abuse Check (AbuseIPDB)",
                "3) Hash/File Reputation (VirusTotal)",
                "4) WHOIS Intelligence",
                "5) MITRE ATT&CK Mapper",
                "6) IoC Manager",
                "7) Bulk IP Reputation",
                "0) Back",
            ])
            if not choice or choice.startswith("0"):
                return
            num = choice.split(")")[0].strip()
            actions = {
                "1": self._ip_reputation, "2": self._ip_abuse_check,
                "3": self._hash_reputation, "4": self._whois_intelligence,
                "5": self._mitre_attack_mapper, "6": self._ioc_manager,
                "7": self._bulk_ip_reputation,
            }
            fn = actions.get(num)
            if fn:
                try:
                    fn()
                except Exception as e:
                    UI.print_error(f"Error: {e}")
                    self.config.logger.error(f"TI error: {e}", exc_info=True)

