# CyberGuard Professional Security Toolkit

Enterprise-grade cybersecurity assessment platform for Linux infrastructure. Unified CLI interface covering the full security lifecycle — from reconnaissance to compliance reporting.

## Architecture

**16 specialized classes | 52+ security functions | 5,400+ lines**

```
┌─────────────────────────────────────────────────────────┐
│                    CyberGuardToolkit                    │
│              Main Orchestrator & Menu System             │
├──────────┬──────────┬───────────┬──────────┬────────────┤
│ Network  │ Harden   │ VulnAssess│ Monitor  │ ThreatIntel│
│ Security │ Audit    │ & CVE     │ & SIEM   │ & MITRE    │
├──────────┴──────────┴───────────┴──────────┴────────────┤
│  Forensics & IR  │  Compliance (NIST/CIS)  │ Reporting  │
├──────────────────┴─────────────────────────┴────────────┤
│  Config │ Validator │ RiskScorer │ AlertManager │ Export │
└─────────────────────────────────────────────────────────┘
```

## Capabilities

| Module | Scope |
|--------|-------|
| **Network Security** | Port scanning, service detection, DNS recon, firewall audit, ARP monitoring, VPN/tunnel detection |
| **System Hardening** | OS audit, SUID/SGID, kernel params (24), SSH config (14), PAM/user security, full hardening score |
| **Vulnerability Assessment** | CVE lookup (NVD API v2), SSL/TLS analysis, web security headers, exploit search, 7-phase full scan |
| **Monitoring & SIEM** | Log analysis, file integrity monitoring, process anomaly detection, brute-force detection, real-time dashboard |
| **Threat Intelligence** | VirusTotal, AbuseIPDB, WHOIS, MITRE ATT&CK mapping (37 techniques), IoC management, bulk IP reputation |
| **Forensics & IR** | Volatile data capture, evidence packaging (tar.gz + SHA-256 chain of custody), timeline analysis, log correlation |
| **Compliance** | NIST CSF (5 functions), CIS Benchmark (55 automated checks), risk scoring 0–100, executive summary (A–F grade) |

## Automated Workflows

| Workflow | Phases | Use Case |
|----------|--------|----------|
| Quick Security Audit | 5 | Rapid posture check |
| Full Security Assessment | 8 | Comprehensive evaluation |
| Incident Response Snapshot | 5 | Active incident triage |
| Pre-Deployment Check | 6 | Production readiness |
| Monthly Security Review | 7 | Recurring compliance |

## Quick Start

```bash
# Setup
chmod +x setup.sh && ./setup.sh

# Run
./cyberguard

# Full access (logs, firewall, kernel parameters)
sudo ./cyberguard
```

## Requirements

- Python 3.8+
- Linux (Ubuntu/Debian recommended)

**Python dependencies** (installed automatically by `setup.sh`):
```
rich  ·  questionary  ·  requests  ·  dnspython  ·  psutil  ·  cryptography
```

**Optional system tools** (extend functionality):
```
nmap  ·  whois  ·  searchsploit  ·  net-tools
```

## API Integration

| Provider | Purpose | Key Required |
|----------|---------|:------------:|
| [VirusTotal](https://virustotal.com) | IP/hash reputation, file analysis | Free |
| [AbuseIPDB](https://abuseipdb.com) | IP abuse scoring, bulk checks | Free |
| [NVD](https://nvd.nist.gov) | CVE database queries | Optional |

> All API-dependent features degrade gracefully — offline modules (network, hardening, monitoring, forensics, compliance) work without any keys.

## Output

- **Formats:** JSON, CSV, TXT, HTML (standalone dark-theme reports)
- **Session directory:** `~/cyberguard-results/session_YYYYMMDD_HHMMSS/`
- **Risk scoring:** Per-category 0–100 score with historical tracking
- **Executive reports:** Non-technical HTML summaries with A–F grading

## License

Proprietary. All rights reserved.

Made in Georgia.
