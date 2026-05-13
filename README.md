# 🔎 Splunk Log Analysis & Threat Hunting

**Centralized SIEM monitoring and structured threat hunting using Splunk and MITRE ATT&CK**

---

## Overview

This project focused on building a production-style threat hunting workflow in Splunk — ingesting and normalizing Windows and Linux logs, developing correlation searches for known attack patterns, and producing structured hunting reports aligned to SOC analytical standards.

---

## Log Sources

- **Windows Security Logs** — Event IDs: 4624, 4625, 4648, 4672, 4688
- **Linux Syslogs** — Auth failures, sudo usage, cron activity

---

## What Was Built

### Log Ingestion & Normalization
- Ingested Windows Security event logs and Linux syslogs into Splunk
- Configured index management and sourcetype parsing for consistent log structure
- Normalized field names for cross-source correlation

### SPL Correlation Searches

**Brute-force detection — 10+ failed logins in 5 minutes:**

    index=windows EventCode=4625
    | bin _time span=5m
    | stats count as FailCount by src_ip, user, _time
    | where FailCount > 10

**Privilege escalation — account added to admin group:**

    index=windows EventCode=4728 OR EventCode=4732
    | table _time, src_user, user, Group_Name, host

**Lateral movement — unusual remote login pattern:**

    index=windows EventCode=4624 Logon_Type=3
    | stats dc(host) as UniqueHosts by user
    | where UniqueHosts > 3

### Real-Time Alerting
- Built alerts for brute-force attempts, privilege escalation sequences, and lateral movement indicators
- Configured alert throttling to reduce noise on high-volume sources

### Threat Hunting Reports
- Investigated flagged events and reconstructed attack timelines
- Mapped findings to MITRE ATT&CK tactics and techniques
- Produced structured reports aligned to SOC analytical workflows

---

## MITRE ATT&CK Coverage

- **T1110** — Brute Force (Credential Access) → Failed login correlation
- **T1078** — Valid Accounts (Privilege Escalation) → Admin group membership changes
- **T1021** — Remote Services (Lateral Movement) → Cross-host login analysis

---

## Skills Demonstrated

`Splunk` `SPL` `Log Analysis` `Threat Hunting` `MITRE ATT&CK` `SIEM Engineering` `Windows Event Logs` `Linux Syslog` `Incident Response`
