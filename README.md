# AbuseIPDB Checker

A desktop threat intelligence tool that checks IP addresses against [AbuseIPDB](https://www.abuseipdb.com/) for abuse reports, confidence scores, and risk classification. Supports single and bulk IP checks with a modern PyQt6 GUI, CLI interface, local SQLite caching, and Excel/CSV export.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)

## Features

- **Single & Bulk IP Checking** — Check one IP or thousands from a text file
- **Risk Classification** — 5-tier system (Critical / High / Medium / Low / Clean) based on AbuseIPDB confidence scores
- **Modern GUI** — Dark-themed PyQt6 desktop interface with tabs for single check, bulk check, live results, and history
- **CLI Mode** — Full-featured command-line interface for scripting and automation
- **SQLite Cache & History** — Local database stores all results; avoids redundant lookups with configurable TTL (default 24h)
- **IP Validation** — Automatically skips private (RFC1918), loopback, reserved, multicast, and link-local addresses
- **Deduplication** — Bulk lists are deduplicated before processing
- **Live CSV Export** — Results are appended to CSV in real-time during bulk checks (prevents data loss)
- **Excel Export** — Final XLSX report generated after bulk checks
- **Concurrent Requests** — Configurable thread pool for parallel lookups
- **Retry & Fallback** — Automatic retries with exponential backoff; optional cloudscraper fallback for anti-bot bypass
- **Rotating Logs** — File-based rotating logs + rich console output

## Screenshots

### GUI — Bulk Check with Live Risk Breakdown
```
┌──────────────────────────────────────────────┐
│  AbuseIPDB Checker — Threat Intelligence     │
├──────────────────────────────────────────────┤
│  [Single IP] [Bulk Check] [Results] [History]│
│                                              │
│  Risk Breakdown (Live):                      │
│   12 Critical  8 High  5 Medium  3 Low  22 Clean
└──────────────────────────────────────────────┘
```

### CLI — Bulk Check with Risk Summary
```
$ python main.py -file ips.txt -output report

Removed 3 duplicate IP(s)
Skipped 2 non-routable/invalid IP(s):
  10.0.0.1 — private (RFC1918)
  192.168.1.1 — private (RFC1918)
5 IP(s) served from cache (TTL=24.0h)

Fetching 42 IPs... ━━━━━━━━━━━━━ 100%

┌─────────── Bulk Check Summary ───────────┐
│ IP         Risk     Confidence  Country   │
│ 1.2.3.4   Critical 95          CN        │
│ 5.6.7.8   Clean    0           US        │
└──────────────────────────────────────────┘

┌── Risk Breakdown ──┐
│ Critical    12     │
│ High         8     │
│ Medium       5     │
│ Clean       22     │
└────────────────────┘
```

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/0x516459465/AbuseIPDB-Checker.git
cd AbuseIPDB-Checker
```

### 2. Create a virtual environment

```bash
python -m venv venv

# Windows
venv\Scripts\activate

# Linux / macOS
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Copy the config file

```bash
cp config.ini.example config.ini
```

Edit `config.ini` to adjust defaults (confidence threshold, concurrency, cache TTL, etc.).

## Usage

### GUI Mode

```bash
python gui.py
```

The GUI has 4 tabs:
- **Single IP** — Enter an IP address and get instant results with risk classification
- **Bulk Check** — Load a text file (one IP per line), configure concurrency/delay, and start. Live risk breakdown updates as results come in
- **Results** — Sortable/filterable table of all results from the current session. Export to CSV or XLSX
- **History** — Search and browse all past checks stored in the local database. View stats (total checks, unique IPs, risk distribution)

### CLI Mode

```bash
# Check a single IP
python main.py -ip 8.8.8.8

# Check with full details
python main.py -ip 8.8.8.8 -details

# Bulk check from file
python main.py -file ips.txt

# Bulk check with custom output name
python main.py -file ips.txt -output my_report

# Skip cache (force fresh lookups)
python main.py -file ips.txt --no-cache

# Custom cache TTL (in hours)
python main.py -file ips.txt -cache-ttl 12

# Adjust concurrency and delay
python main.py -file ips.txt -concurrency 5 -delay 1.5

# Debug mode
python main.py -file ips.txt --debug
```

### CLI Options

| Flag | Description |
|------|-------------|
| `-ip <IP>` | Check a single IP address |
| `-file <path>` | Bulk check from a text file (one IP per line) |
| `-output <base>` | Base name for output files (default: `report`) |
| `-nosave` | Do not save CSV/XLSX output |
| `-details` | Show full details for single IP check |
| `-concurrency N` | Number of concurrent threads (default: 3) |
| `-delay S` | Base delay between requests in seconds (default: 2) |
| `-timeout S` | Read timeout in seconds (default: 20) |
| `-connect-timeout S` | Connect timeout in seconds (default: 10) |
| `-cache-ttl H` | Cache TTL in hours (default: 24) |
| `--no-cache` | Bypass cache, force fresh lookups |
| `--debug` | Enable verbose debug logging |
| `--no-cloudscraper` | Disable cloudscraper fallback |

## Configuration

Edit `config.ini` to change defaults:

```ini
[DEFAULT]
confidencescore = 50
concurrency = 3
delay = 2
timeout = 20
connecttimeout = 10
cachettl = 24
```

| Key | Description | Default |
|-----|-------------|---------|
| `confidencescore` | Minimum confidence score to flag as malicious (CLI display) | 50 |
| `concurrency` | Default number of worker threads for bulk checks | 3 |
| `delay` | Base delay between requests (seconds) | 2 |
| `timeout` | HTTP read timeout (seconds) | 20 |
| `connecttimeout` | HTTP connect timeout (seconds) | 10 |
| `cachettl` | Cache time-to-live in hours | 24 |

## Risk Classification

IPs are classified into 5 tiers based on AbuseIPDB's confidence of abuse score:

| Tier | Confidence Score | Meaning |
|------|-----------------|---------|
| **Critical** | 90–100% | Actively malicious, immediate threat |
| **High** | 70–89% | Strong indicators of abuse |
| **Medium** | 40–69% | Moderate abuse indicators |
| **Low** | 1–39% | Minor or outdated reports |
| **Clean** | 0% | No reports of abuse |

## Project Structure

```
AbuseIPDB-Checker/
├── main.py              # Core scraping engine + CLI interface
├── gui.py               # PyQt6 desktop GUI
├── database.py          # SQLite cache & history layer
├── config.ini.example   # Example configuration file
├── requirements.txt     # Python dependencies
├── LICENSE              # MIT License
└── README.md            # This file
```

## How It Works

1. **Input** — Accepts single IP or a file of IPs
2. **Validation** — Filters out private, reserved, loopback, and invalid addresses
3. **Deduplication** — Removes duplicate entries from bulk lists
4. **Cache Check** — Looks up recent results in local SQLite database (configurable TTL)
5. **Scraping** — For uncached IPs, scrapes AbuseIPDB's public check page using requests (with cloudscraper fallback for anti-bot protection)
6. **Parsing** — Extracts confidence score, report count, ISP, country, timestamps, and more via BeautifulSoup + pre-compiled regex
7. **Risk Classification** — Assigns a 5-tier risk label based on confidence score
8. **Storage** — Saves all results to local SQLite database for history and caching
9. **Export** — Outputs to live-updating CSV and final XLSX report

## Dependencies

- [PyQt6](https://pypi.org/project/PyQt6/) — Desktop GUI framework
- [requests](https://pypi.org/project/requests/) — HTTP client
- [beautifulsoup4](https://pypi.org/project/beautifulsoup4/) + [lxml](https://pypi.org/project/lxml/) — HTML parsing
- [rich](https://pypi.org/project/rich/) — Console formatting and progress bars
- [pandas](https://pypi.org/project/pandas/) + [openpyxl](https://pypi.org/project/openpyxl/) — Excel export
- [cloudscraper](https://pypi.org/project/cloudscraper/) — Anti-bot bypass fallback

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool scrapes publicly available data from AbuseIPDB. It does not use the official API. Use responsibly and in compliance with AbuseIPDB's terms of service. The authors are not responsible for any misuse of this tool.
