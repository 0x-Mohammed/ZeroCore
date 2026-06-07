<div align="center">

# ZeroCore
### Kernel-Level EDR Agent · File Integrity Monitor · Automated Threat Response

[

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)

](https://python.org)
[

![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat-square&logo=go&logoColor=white)

](https://golang.org)
[

![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

](LICENSE)
[

![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-blue?style=flat-square)

](https://github.com/0x-Mohammed/ZeroCore)

Open-source EDR agent with eBPF kernel probes, real-time process attribution, and automated IP mitigation.

</div>

---

## What is ZeroCore?

ZeroCore monitors your system at the kernel level. When a file is modified, it tells you exactly who did it:




[WARNING] fim.event  path=/etc/passwd  action=MODIFIED  severity=HIGH
pid=4122   process=python3   parent=bash
user=root  uid=0  command=python3 exploit.py


---

## Features

- File Integrity Monitor — Sub-1-second detection with SHA-256 baseline
- Process Attribution — Exact PID, process, parent, user, and command
- eBPF Kernel Probe — Hooks into kernel syscalls on Linux
- ETW + Sysmon — Windows support via Event Tracing
- Auto IP Block — Automated firewall response with rate limiting
- REST API — Full API with authentication
- Web Dashboard — Single-file dashboard, no server required
- SIEM Ready — JSON logs for Splunk, Elastic, Loki

---

## Quick Start

`bash
git clone https://github.com/0x-Mohammed/ZeroCore.git
cd ZeroCore
pip install -r requirements.txt
export ZEROCORE_API_KEY="your-secret-key"
python main.py

docker-compose up -d

API
All endpoints require X-ZeroCore-API-Key header.
Method
Endpoint
Description
GET
/api/v1/events
Security events
GET
/api/v1/baseline
FIM baseline
POST
/api/v1/mitigation/block
Block IP
POST
/api/v1/mitigation/unblock
Unblock IP
GET
/api/v1/health
Health check
License
MIT — Built by 0x-Mohammed · Iraq 🇮🇶
