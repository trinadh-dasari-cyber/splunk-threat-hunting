# 🔎 Splunk Log Analysis & Threat Hunting

**Academic project — SIEM log analysis and threat hunting using Splunk as part of MS Cybersecurity coursework at University of Central Missouri**

---

## Overview

This project was completed as part of my MS Cybersecurity program at the University of Central Missouri. I ingested and analyzed Windows and Linux logs in Splunk, built SPL correlation searches targeting known attack patterns, and produced structured threat hunting reports mapped to MITRE ATT&CK — simulating real-world SOC analyst workflows.

---

## Academic Context

- **Institution:** University of Central Missouri
- **Program:** MS Cybersecurity
- **Focus:** SIEM engineering, threat detection, log analysis

---

## Log Sources Used

- **Windows Security Logs** — Event IDs: 4624, 4625, 4648, 4672, 4688
- **Linux Syslogs** — Auth failures, sudo usage, cron activity

---

## What Was Done

### Log Ingestion & Normalization
- Ingested Windows Security event logs and Linux syslogs into Splunk
- Configured index management and sourcetype parsing for consistent log structure
- Normalized field names for cross-so
