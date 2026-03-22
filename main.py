#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AbuseIPDB Scraper — Enhanced & Production Ready
 - requests-first then cloudscraper fallback
 - randomized headers & delays per request
 - robust handling for 403, 429, and timeouts
 - session-level retries with urllib3 Retry & Shared Connection Pooling
 - rotating file logs + rich console logs
 - live-appending CSV export (prevents data loss) + final XLSX export
 - per-IP timing metrics (duration), attempts, and session type
 - parses "not found in our database" pages
 - configurable connect/read timeouts via CLI or config.ini
 - extracts First/Last report timestamps from "IoA Timestamp (UTC)" column
 - handles pagination to fetch earliest (first) report from the last page
 - Pre-compiled Regex and lxml parsing for maximum speed
"""
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
from rich.logging import RichHandler
from rich import print

import argparse
import configparser
import requests
import pandas as pd
import logging
import time
import random
import re
import sys
import datetime
import csv
import ipaddress
from logging.handlers import RotatingFileHandler

# Database layer
import database as db

# Retries/adapter + timeout exceptions
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from requests.exceptions import ReadTimeout, ConnectTimeout, Timeout

# Attempt to import cloudscraper
try:
    import cloudscraper
    HAS_CLOUDSCRAPER = True
except ImportError:
    cloudscraper = None
    HAS_CLOUDSCRAPER = False

# -------------------------
# Pre-compiled Regex Patterns (Performance Optimization)
# -------------------------
RE_REPORTED_TIMES = re.compile(r"\breported\s+[^0-9]*([\d,]+)[^0-9]*\s+times\b", re.IGNORECASE)
RE_CONFIDENCE_TEXT = re.compile(r"Confidence[^0-9]*([0-9]{1,3})\s*%", re.IGNORECASE)
RE_CONFIDENCE_BAR = re.compile(r"([0-9]{1,3})\s*%")
RE_BADGE_CLASS = re.compile(r"(badge|label|count|counter)", re.IGNORECASE)
RE_REPORT_VICINITY = re.compile(r"report", re.IGNORECASE)
RE_TIMESTAMP = re.compile(r"\b(20\d{2}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\b")
RE_TIMESTAMP_HEADER = re.compile(r"timestamp", re.IGNORECASE)
RE_FIRST_REPORTED = re.compile(r"first\s+reported\s+on\s+([A-Za-z]+)\s+(\d{1,2})(?:st|nd|rd|th)?\s+(\d{4})", re.IGNORECASE)
RE_PAGINATION_UL = re.compile(r"pagination", re.IGNORECASE)
RE_PAGE_PARAM = re.compile(r"[?&]page=(\d+)")
RE_NOT_FOUND = re.compile(r"was not found", re.IGNORECASE)
RE_COUNTRY_TH = re.compile(r"Country", re.IGNORECASE)

# -------------------------
# IP Validation & Deduplication
# -------------------------
def validate_ip(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str.strip())
        if addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_multicast or addr.is_link_local:
            return False
        return True
    except ValueError:
        return False

def classify_ip(ip_str: str) -> str | None:
    try:
        addr = ipaddress.ip_address(ip_str.strip())
        if addr.is_loopback:
            return "loopback"
        if addr.is_private:
            return "private (RFC1918)"
        if addr.is_reserved:
            return "reserved"
        if addr.is_multicast:
            return "multicast"
        if addr.is_link_local:
            return "link-local"
        return None
    except ValueError:
        return "invalid format"

def deduplicate_ips(ip_list: list[str]) -> tuple[list[str], int]:
    seen = set()
    unique = []
    for ip in ip_list:
        ip = ip.strip()
        if ip and ip not in seen:
            seen.add(ip)
            unique.append(ip)
    return unique, len(ip_list) - len(unique)

def filter_and_validate_ips(ip_list: list[str]) -> tuple[list[str], list[dict]]:
    valid = []
    skipped = []
    for ip in ip_list:
        ip = ip.strip()
        if not ip:
            continue
        reason = classify_ip(ip)
        if reason:
            skipped.append({"IP": ip, "reason": reason})
        else:
            valid.append(ip)
    return valid, skipped

# -------------------------
# IP Extraction from arbitrary text
# -------------------------
RE_IPV4 = re.compile(
    r'(?<![0-9.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![0-9.])'
)

def extract_ips_from_text(text: str) -> list[str]:
    """Extract all valid IPv4 addresses from arbitrary text using regex."""
    return RE_IPV4.findall(text)

def extract_and_clean(file_path: str, save_path: str | None = None) -> dict:
    """
    Extract IPs from any text file, deduplicate, filter out private/reserved.
    Optionally saves the clean list to save_path.
    Returns a summary dict with the clean IP list and stats.
    """
    fp = Path(file_path)
    if not fp.exists():
        return {"error": f"File not found: {file_path}"}

    text = fp.read_text(encoding="utf-8", errors="ignore")
    raw_ips = extract_ips_from_text(text)

    if not raw_ips:
        return {
            "raw_count": 0,
            "duplicates_removed": 0,
            "skipped": [],
            "clean_ips": [],
            "clean_count": 0,
        }

    unique_ips, dup_count = deduplicate_ips(raw_ips)
    clean_ips, skipped = filter_and_validate_ips(unique_ips)

    result = {
        "raw_count": len(raw_ips),
        "duplicates_removed": dup_count,
        "skipped": skipped,
        "clean_ips": clean_ips,
        "clean_count": len(clean_ips),
    }

    if save_path and clean_ips:
        out = Path(save_path)
        out.write_text("\n".join(clean_ips) + "\n", encoding="utf-8")
        result["saved_to"] = str(out)
        logging.info("Saved %d clean IPs to %s", len(clean_ips), out)

    return result

# -------------------------
# Risk Classification
# -------------------------
RISK_TIERS = [
    {"label": "Critical", "min_confidence": 90, "color": "bold red"},
    {"label": "High",     "min_confidence": 70, "color": "red"},
    {"label": "Medium",   "min_confidence": 40, "color": "yellow"},
    {"label": "Low",      "min_confidence": 1,  "color": "cyan"},
    {"label": "Clean",    "min_confidence": 0,  "color": "green"},
]

def get_risk_tier(confidence: int | None) -> dict:
    score = int(confidence or 0)
    for tier in RISK_TIERS:
        if score >= tier["min_confidence"]:
            return tier
    return RISK_TIERS[-1]

# -------------------------
# Config & Globals
# -------------------------
CONFIG_FILE = Path("config.ini")
LOG_FILE = Path("abuseipdb.log")
console = Console()
config = configparser.ConfigParser()

DEFAULTS = {
    "confidenceScore": "50",
    "showDetails": "False",
    "concurrency": "3",
    "delay": "2",
    "timeout": "20",
    "connectTimeout": "10",
    "cacheTTL": "24",
}

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
]

# -------------------------
# Logging Setup
# -------------------------
def setup_logging(debug: bool = False):
    log_level = logging.DEBUG if debug else logging.INFO
    logger = logging.getLogger()
    logger.setLevel(log_level)

    fh = RotatingFileHandler(LOG_FILE, maxBytes=2 * 1024 * 1024, backupCount=3, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))

    ch = RichHandler(rich_tracebacks=True)
    ch.setLevel(log_level)

    if not any(isinstance(h, RotatingFileHandler) for h in logger.handlers):
        logger.addHandler(fh)
    if not any(isinstance(h, RichHandler) for h in logger.handlers):
        logger.addHandler(ch)

    logging.info("Logging initialized (file=%s)", LOG_FILE)
    if debug:
        logging.debug("Debug mode enabled")
    if not HAS_CLOUDSCRAPER:
        logging.warning("cloudscraper not installed — fallback bypass disabled. Install with: pip install cloudscraper")

# -------------------------
# Config helpers
# -------------------------
def ensure_config():
    if not CONFIG_FILE.exists():
        config["DEFAULT"] = DEFAULTS
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            config.write(f)
        logging.info("Created default config.ini")

    config.read(CONFIG_FILE)
    changed = False
    for k, v in DEFAULTS.items():
        if k not in config["DEFAULT"]:
            config["DEFAULT"][k] = v
            changed = True
    if changed:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            config.write(f)

def banner():
    console.print("\n[bold red]AbuseIPDB Checker — Threat Intelligence Tool[/bold red]\n")

# -------------------------
# Shared Connection Pooling
# -------------------------
def _mount_retries(session: requests.Session, total=4, backoff_factor=1.5):
    retry = Retry(
        total=total,
        connect=total,
        read=total,
        status=total,
        backoff_factor=backoff_factor,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(["HEAD", "GET", "OPTIONS"]),
        raise_on_status=False,
        respect_retry_after_header=True,
    )
    # Increased pool size for concurrent threads
    adapter = HTTPAdapter(max_retries=retry, pool_connections=50, pool_maxsize=100)
    session.mount("https://", adapter)
    session.mount("http://", adapter)

def create_shared_requests_session():
    s = requests.Session()
    s.headers.update({
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Referer": "https://www.google.com/",
        "DNT": "1",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Cache-Control": "max-age=0",
    })
    _mount_retries(s, total=4, backoff_factor=1.5)
    logging.debug("Created shared requests session pool")
    return s

def create_shared_cloudscraper_session():
    if not HAS_CLOUDSCRAPER:
        return None
    s = cloudscraper.create_scraper(browser={"browser": "chrome", "platform": "windows", "mobile": False})
    s.headers.update({
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Referer": "https://www.google.com/",
        "DNT": "1",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Cache-Control": "max-age=0",
    })
    _mount_retries(s, total=4, backoff_factor=1.5)
    logging.debug("Created shared cloudscraper session pool")
    return s

# -------------------------
# Timestamp & pagination helpers
# -------------------------
def _extract_first_last_from_table(soup: BeautifulSoup):
    first_dt = None
    last_dt = None

    for table in soup.find_all("table"):
        header_row = table.find("tr")
        if not header_row:
            continue
        headers = [th.get_text(" ", strip=True) for th in header_row.find_all("th")]
        if not headers:
            continue

        ts_idx = None
        for i, h in enumerate(headers):
            if RE_TIMESTAMP_HEADER.search(h):
                ts_idx = i
                break
        if ts_idx is None:
            continue

        for row in table.find_all("tr")[1:]:
            tds = row.find_all("td")
            if len(tds) <= ts_idx:
                continue
            cell_text = tds[ts_idx].get_text(" ", strip=True)
            for match in RE_TIMESTAMP.findall(cell_text):
                try:
                    dt = datetime.datetime.strptime(match, "%Y-%m-%d %H:%M:%S")
                    if first_dt is None or dt < first_dt:
                        first_dt = dt
                    if last_dt is None or dt > last_dt:
                        last_dt = dt
                except Exception:
                    continue

    return first_dt, last_dt

def _fallback_first_from_summary_text(text: str):
    m = RE_FIRST_REPORTED.search(text)
    if not m:
        return None
    month_name, day, year = m.groups()
    for fmt in ("%d %B %Y", "%d %b %Y"):
        try:
            return datetime.datetime.strptime(f"{int(day)} {month_name} {year}", fmt)
        except Exception:
            continue
    return None

def _find_last_page_number(soup: BeautifulSoup) -> int:
    last_page = 1
    nav = soup.find("ul", class_=RE_PAGINATION_UL)
    if not nav:
        return 1

    for a in nav.find_all("a", href=True):
        m = RE_PAGE_PARAM.search(a["href"])
        if m:
            try:
                p = int(m.group(1))
                if p > last_page:
                    last_page = p
            except Exception:
                pass

    for span in nav.find_all("span"):
        txt = span.get_text(strip=True)
        if txt.isdigit():
            p = int(txt)
            if p > last_page:
                last_page = p

    return last_page

def _fetch_first_report_from_last_page(session: requests.Session,
                                       ip: str,
                                       last_page: int,
                                       connect_timeout: float,
                                       read_timeout: float,
                                       headers: dict) -> str | None:
    if last_page <= 1:
        return None

    url_last = f"https://www.abuseipdb.com/check/{ip}?page={last_page}#report"
    logging.info("%s - fetching last page %d for earliest report: %s", ip, last_page, url_last)
    try:
        resp2 = session.get(url_last, headers=headers, timeout=(connect_timeout, read_timeout))
        if resp2.status_code != 200:
            logging.warning("%s - last page HTTP %d", ip, resp2.status_code)
            return None

        soup2 = BeautifulSoup(resp2.text, "lxml")
        first_dt, _ = _extract_first_last_from_table(soup2)
        if first_dt:
            return first_dt.strftime("%Y-%m-%d %H:%M:%S")
        return None
    except Exception:
        logging.exception("%s - error fetching/parsing last page", ip)
        return None

# -------------------------
# HTML Parser (hardened)
# -------------------------
def parse_abuseipdb_html(html: str, ip: str) -> dict:
    soup = BeautifulSoup(html, "lxml")
    result = {
        "IP": ip,
        "Reports": None,
        "Confidence": None,
        "ISP": "",
        "Usage Type": "",
        "ASN": "",
        "Domain": "",
        "Hostname(s)": "",
        "Country": "",
        "City": "",
        "First Report UTC": None,
        "Last Report UTC": None,
        "Link": f"https://www.abuseipdb.com/check/{ip}",
        "Found": True
    }
    try:
        not_found_header = soup.find("h3", string=RE_NOT_FOUND)
        if not_found_header:
            result["Found"] = False

        ip_header = soup.find("h3")
        if ip_header:
            htxt = ip_header.get_text(" ", strip=True)
            if htxt and ip in htxt:
                result["IP"] = ip.strip()

        full_text = soup.get_text(" ", strip=True)
        m = RE_REPORTED_TIMES.search(full_text)
        if m:
            try:
                result["Reports"] = int(m.group(1).replace(",", ""))
            except ValueError:
                pass

        mc = RE_CONFIDENCE_TEXT.search(full_text)
        if mc:
            try:
                result["Confidence"] = int(mc.group(1))
            except ValueError:
                pass

        if result["Confidence"] is None:
            progress = soup.find("div", class_=re.compile("progress-bar", re.IGNORECASE))
            if progress:
                txt = progress.get_text(strip=True)
                pm = RE_CONFIDENCE_BAR.search(txt)
                if pm:
                    try:
                        result["Confidence"] = int(pm.group(1))
                    except ValueError:
                        pass

        if result["Reports"] is None:
            candidates = []
            for badge_sel in [
                ("span", {"class": RE_BADGE_CLASS}),
                ("div", {"class": RE_BADGE_CLASS}),
                ("strong", {}),
                ("b", {}),
                ("span", {}),
            ]:
                for el in soup.find_all(*badge_sel):
                    txt = el.get_text(strip=True)
                    if txt and re.fullmatch(r"[\d,]+", txt):
                        candidates.append(el)
            for el in candidates:
                vicinity_text = el.parent.get_text(" ", strip=True) if el.parent else ""
                if RE_REPORT_VICINITY.search(vicinity_text):
                    try:
                        result["Reports"] = int(el.get_text(strip=True).replace(",", ""))
                        break
                    except ValueError:
                        continue

        first_dt, last_dt = _extract_first_last_from_table(soup)
        if first_dt:
            result["First Report UTC"] = first_dt.strftime("%Y-%m-%d %H:%M:%S")
        if last_dt:
            result["Last Report UTC"] = last_dt.strftime("%Y-%m-%d %H:%M:%S")

        if result["First Report UTC"] is None:
            maybe_first = _fallback_first_from_summary_text(full_text)
            if maybe_first:
                result["First Report UTC"] = maybe_first.strftime("%Y-%m-%d 00:00:00")

        table = soup.find("table", class_="table")
        if table:
            for row in table.find_all("tr"):
                th = row.find("th")
                td = row.find("td")
                if not th or not td:
                    continue
                key = th.get_text(strip=True)
                val = td.get_text(" ", strip=True)
                k = key.lower()
                if "isp" in k:
                    result["ISP"] = val
                elif "usage" in k:
                    result["Usage Type"] = val
                elif k == "asn" or "asn " in k or k.endswith(" asn"):
                    result["ASN"] = val
                elif "hostname" in k:
                    result["Hostname(s)"] = val
                elif "domain" in k:
                    result["Domain"] = val
                elif "country" in k:
                    result["Country"] = val
                elif "city" in k:
                    result["City"] = val

        if not result["Country"]:
            country_th = soup.find("th", string=RE_COUNTRY_TH)
            if country_th:
                td = country_th.find_next_sibling("td")
                if td:
                    result["Country"] = td.get_text(" ", strip=True)

    except Exception:
        logging.exception("Error parsing HTML for %s", ip)
        result["error"] = "Parsing error"

    logging.debug(
        "Parsed result for %s: Found=%s Confidence=%s Reports=%s First=%s Last=%s",
        ip, result.get("Found"), result.get("Confidence"), result.get("Reports"),
        result.get("First Report UTC"), result.get("Last Report UTC")
    )
    return result

# -------------------------
# Fetch + Retry + Shared Sessions + Headers per Request
# -------------------------
def fetch_and_parse(ip: str,
                    req_session: requests.Session,
                    cs_session,
                    base_delay: float = 1.0,
                    connect_timeout: float = 10.0,
                    read_timeout: float = 20.0,
                    use_cloudscraper_fallback: bool = True):
    url = f"https://www.abuseipdb.com/check/{ip}"
    logging.info("Fetching %s", url)

    start_time = time.time()
    parsed = None
    attempts = 0
    max_attempts = 6
    session_type = "requests"
    session = req_session

    ct_local = float(connect_timeout)
    rt_local = float(read_timeout)

    for attempt in range(1, max_attempts + 1):
        attempts = attempt
        try:
            if attempt > 1:
                jitter = random.uniform(0.5, 2.5)
                logging.debug("%s - jitter sleep %.2fs before attempt %d", ip, jitter, attempt)
                time.sleep(jitter)

            req_headers = {"User-Agent": random.choice(USER_AGENTS)}

            logging.debug("%s - attempting request (session=%s, attempt=%d/%d; ct=%.1f rt=%.1f)",
                          ip, session_type, attempt, max_attempts, ct_local, rt_local)

            resp = session.get(url, headers=req_headers, timeout=(ct_local, rt_local))
            status = resp.status_code
            logging.debug("%s - HTTP %d", ip, status)

            if status == 200:
                parsed = parse_abuseipdb_html(resp.text, ip)
                if not parsed:
                    logging.warning("%s - parsed returned empty, treating as failure", ip)
                    parsed = {"IP": ip, "error": "Parsing returned nothing"}
                    break

                soup_page1 = BeautifulSoup(resp.text, "lxml")
                last_page = _find_last_page_number(soup_page1)
                logging.debug("%s - detected last page: %d", ip, last_page)

                if last_page > 1:
                    earliest_str = _fetch_first_report_from_last_page(
                        session, ip, last_page, ct_local, rt_local, req_headers
                    )
                    if earliest_str:
                        parsed["First Report UTC"] = earliest_str
                        logging.debug("%s - earliest (from page %d): %s", ip, last_page, earliest_str)
                    else:
                        logging.debug("%s - could not fetch earliest report from last page", ip)
                break

            elif status == 403:
                logging.warning("%s - HTTP 403 (Forbidden) on %s (attempt %d/%d)", ip, url, attempt, max_attempts)
                if use_cloudscraper_fallback and cs_session and session_type != "cloudscraper":
                    logging.info("%s - switching to cloudscraper session and retrying", ip)
                    session = cs_session
                    session_type = "cloudscraper"
                time.sleep(min(5 + attempt * 1.5, 30) + random.uniform(0.5, 2.0))
                continue

            elif status == 429:
                retry_after = int(resp.headers.get("Retry-After", 0))
                wait_time = retry_after if retry_after > 0 else (30 + random.randint(10, 40))
                logging.warning("%s - HTTP 429 Too Many Requests. Waiting %ds (attempt %d/%d)",
                                ip, wait_time, attempt, max_attempts)
                time.sleep(wait_time)
                if use_cloudscraper_fallback and cs_session and session_type != "cloudscraper":
                    session = cs_session
                    session_type = "cloudscraper"
                continue

            else:
                logging.warning("%s - HTTP %d returned (attempt %d/%d)", ip, status, attempt, max_attempts)
                parsed = {"IP": ip, "error": f"HTTP {status}"}
                break

        except (ReadTimeout, ConnectTimeout) as exc:
            logging.warning("%s - %s on attempt %d/%d (ct=%.1f rt=%.1f)",
                            ip, exc.__class__.__name__, attempt, max_attempts, ct_local, rt_local)
            rt_local = min(rt_local * 1.5, 90.0)

            if attempt < max_attempts:
                time.sleep(min(5 + attempt * 2, 45) + random.uniform(0.5, 2.0))
                if use_cloudscraper_fallback and cs_session and session_type != "cloudscraper":
                    session = cs_session
                    session_type = "cloudscraper"
                continue
            else:
                parsed = {"IP": ip, "error": f"{exc.__class__.__name__}: timeout"}
                break

        except Timeout:
            logging.warning("%s - General Timeout on attempt %d/%d", ip, attempt, max_attempts)
            rt_local = min(rt_local * 1.5, 90.0)
            if attempt < max_attempts:
                time.sleep(min(5 + attempt * 2, 45) + random.uniform(0.5, 2.0))
                if use_cloudscraper_fallback and cs_session and session_type != "cloudscraper":
                    session = cs_session
                    session_type = "cloudscraper"
                continue
            else:
                parsed = {"IP": ip, "error": "Timeout"}
                break

        except Exception as exc:
            logging.exception("%s - Exception during request (attempt %d/%d): %s", ip, attempt, max_attempts, exc)
            if attempt < max_attempts:
                time.sleep(min(3 + attempt * 2, 60) + random.uniform(0.5, 2.0))
                if use_cloudscraper_fallback and cs_session and session_type != "cloudscraper":
                    session = cs_session
                    session_type = "cloudscraper"
                continue
            parsed = {"IP": ip, "error": str(exc)}
            break

        finally:
            post_wait = base_delay + random.uniform(0.5, 2.5)
            logging.debug("%s - post-attempt wait %.2fs (session=%s)", ip, post_wait, session_type)
            time.sleep(post_wait)

    duration = time.time() - start_time
    if not parsed:
        parsed = {"IP": ip, "error": "Failed after retries"}
    parsed["Duration"] = round(duration, 3)
    parsed["Attempts"] = attempts
    parsed["SessionType"] = session_type
    logging.info("%s - finished (duration=%.2fs attempts=%d session=%s) error=%s",
                 ip, duration, attempts, session_type, parsed.get("error"))
    return parsed

# -------------------------
# CLI helpers & exports
# -------------------------
def check_ip_cli(ip: str,
                 details: bool = False,
                 delay: float = 1.0,
                 use_cloudscraper_fallback: bool = True,
                 connect_timeout: float = 10.0,
                 read_timeout: float = 20.0):
    ip = ip.strip()
    reason = classify_ip(ip)
    if reason:
        print(f"[yellow]Skipping {ip} — {reason}[/yellow]")
        logging.warning("Skipping %s — %s", ip, reason)
        return None

    logging.info("Checking single IP: %s", ip)

    # Check cache first
    cache_ttl = float(config["DEFAULT"].get("cacheTTL", DEFAULTS["cacheTTL"]))
    cached = db.get_cached(ip, ttl_hours=cache_ttl)
    if cached:
        res = cached
        print(f"[dim](cached result from {cached.get('checked_at', '?')})[/dim]")
    else:
        shared_req_session = create_shared_requests_session()
        shared_cs_session = create_shared_cloudscraper_session() if use_cloudscraper_fallback else None

        res = fetch_and_parse(ip,
                              shared_req_session,
                              shared_cs_session,
                              base_delay=delay,
                              connect_timeout=connect_timeout,
                              read_timeout=read_timeout,
                              use_cloudscraper_fallback=use_cloudscraper_fallback)

        if not res:
            print(f"[yellow]No result for {ip}[/yellow]")
            logging.warning("No result for %s", ip)
            return None
        if "error" in res:
            print(f"[red]Error for {ip}:[/red] {res['error']}")
            logging.error("%s - %s", ip, res.get("error"))
            db.store_result(res)
            return None

        # Store in database
        tier = get_risk_tier(res.get("Confidence"))
        res["Risk"] = tier["label"]
        db.store_result(res)

    tier = get_risk_tier(res.get("Confidence"))
    res["Risk"] = tier["label"]
    score = int(res.get("Confidence") or 0)

    if details:
        table = Table(title=f"IP Check: {ip}")
        for k, v in sorted(res.items()):
            table.add_row(k, str(v))
        console.print(table)
    else:
        print(f"[{tier['color']}]{ip}[/{tier['color']}] — {tier['label']} (Confidence: {score}%)")

    return res

def bulkcheck_cli(file_path: str,
                  output_base: str = "report",
                  save_both: bool = True,
                  concurrency: int = 3,
                  delay: float = 2.0,
                  use_cloudscraper_fallback: bool = True,
                  connect_timeout: float = 10.0,
                  read_timeout: float = 20.0):
    fp = Path(file_path)
    if not fp.exists():
        print(f"[red]File not found:[/red] {file_path}")
        logging.error("Input file not found: %s", file_path)
        return

    with open(fp, "r", encoding="utf-8") as f:
        raw_ips = [line.strip() for line in f if line.strip()]

    # Deduplicate
    ips, dup_count = deduplicate_ips(raw_ips)
    if dup_count:
        print(f"[yellow]Removed {dup_count} duplicate IP(s)[/yellow]")
        logging.info("Removed %d duplicate IPs", dup_count)

    # Validate — filter out private/reserved/invalid
    ips, skipped = filter_and_validate_ips(ips)
    if skipped:
        print(f"[yellow]Skipped {len(skipped)} non-routable/invalid IP(s):[/yellow]")
        for s in skipped:
            print(f"  [dim]{s['IP']}[/dim] — {s['reason']}")
        logging.info("Skipped %d non-routable/invalid IPs", len(skipped))

    if not ips:
        print("[red]No valid public IPs to check.[/red]")
        return

    logging.info("Starting bulk check for %d IPs (concurrency=%d delay=%.1f)", len(ips), concurrency, delay)

    # Check cache — split into cached and uncached
    cache_ttl = float(config["DEFAULT"].get("cacheTTL", DEFAULTS["cacheTTL"]))
    cached_results = []
    ips_to_fetch = []
    for ip in ips:
        cached = db.get_cached(ip, ttl_hours=cache_ttl)
        if cached:
            cached_results.append(cached)
        else:
            ips_to_fetch.append(ip)

    if cached_results:
        print(f"[dim]{len(cached_results)} IP(s) served from cache (TTL={cache_ttl}h)[/dim]")
        logging.info("%d IPs served from cache", len(cached_results))

    shared_req_session = create_shared_requests_session()
    shared_cs_session = create_shared_cloudscraper_session() if use_cloudscraper_fallback else None

    results = list(cached_results)

    fieldnames = [
        "IP", "Risk", "Confidence", "Reports", "Country", "ISP", "Usage Type", "ASN",
        "Domain", "Hostname(s)", "City", "First Report UTC", "Last Report UTC",
        "Link", "Found", "Duration", "Attempts", "SessionType", "error"
    ]

    csv_path = Path(f"{output_base}.csv")
    xlsx_path = Path(f"{output_base}.xlsx")

    if save_both:
        try:
            with open(csv_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                writer.writeheader()
            print(f"[green]Created live-updating CSV file:[/green] {csv_path}\n")
        except Exception as e:
            logging.error(f"Failed to create CSV file: {e}")

    # Write cached results to CSV immediately
    if save_both and cached_results:
        try:
            with open(csv_path, "a", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                writer.writerows(cached_results)
        except Exception as e:
            logging.error(f"Failed to write cached results to CSV: {e}")

    total_to_track = len(ips_to_fetch)
    if total_to_track == 0:
        print("[green]All IPs served from cache — no network requests needed.[/green]")
    else:
        with Progress() as progress:
            task = progress.add_task(f"[cyan]Fetching {total_to_track} IPs...", total=total_to_track)
            with ThreadPoolExecutor(max_workers=concurrency) as ex:
                futures = {
                    ex.submit(
                        fetch_and_parse,
                        ip,
                        shared_req_session,
                        shared_cs_session,
                        delay,
                        connect_timeout,
                        read_timeout,
                        use_cloudscraper_fallback
                    ): ip for ip in ips_to_fetch
                }

                for future in as_completed(futures):
                    ip = futures[future]
                    try:
                        res = future.result()
                    except Exception as e:
                        res = {"IP": ip, "error": str(e)}
                        logging.exception("%s - Exception in worker: %s", ip, e)

                    # Assign risk tier
                    if "error" not in res:
                        tier = get_risk_tier(res.get("Confidence"))
                        res["Risk"] = tier["label"]

                    # Store in database
                    db.store_result(res)

                    results.append(res)

                    if save_both:
                        try:
                            with open(csv_path, "a", newline="", encoding="utf-8") as f:
                                writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                                writer.writerow(res)
                        except Exception as e:
                            logging.error(f"Failed to append to CSV for {ip}: {e}")

                    progress.update(task, advance=1)

    # Summary table with risk tiers
    table = Table(title="Bulk Check Summary")
    table.add_column("IP")
    table.add_column("Risk")
    table.add_column("Confidence")
    table.add_column("Reports")
    table.add_column("Country")
    table.add_column("ISP")
    table.add_column("Domain")
    table.add_column("First Report (UTC)")
    table.add_column("Last Report (UTC)")
    table.add_column("Duration(s)")
    table.add_column("Attempts")

    for r in results:
        ip = r.get("IP", "unknown")
        if "error" in r:
            table.add_row(ip, "[red]Error[/red]", "", "", "", "", "", "", "", "", f"[red]{r.get('error')}[/red]")
            continue
        tier = get_risk_tier(r.get("Confidence"))
        color = tier["color"]
        table.add_row(
            f"[{color}]{ip}[/{color}]",
            f"[{color}]{tier['label']}[/{color}]",
            str(r.get("Confidence", "")),
            str(r.get("Reports", "")),
            str(r.get("Country", "")),
            str(r.get("ISP", "")),
            str(r.get("Domain", "")),
            str(r.get("First Report UTC", "")),
            str(r.get("Last Report UTC", "")),
            str(r.get("Duration", "")),
            str(r.get("Attempts", "")),
        )
    console.print(table)

    # Risk breakdown summary
    risk_counts = {}
    for r in results:
        risk = r.get("Risk", "Error" if "error" in r else "Unknown")
        risk_counts[risk] = risk_counts.get(risk, 0) + 1
    summary_table = Table(title="Risk Breakdown")
    summary_table.add_column("Risk Level")
    summary_table.add_column("Count")
    for tier_def in RISK_TIERS:
        count = risk_counts.get(tier_def["label"], 0)
        if count:
            summary_table.add_row(f"[{tier_def['color']}]{tier_def['label']}[/{tier_def['color']}]", str(count))
    if risk_counts.get("Error"):
        summary_table.add_row("[red]Error[/red]", str(risk_counts["Error"]))
    console.print(summary_table)

    if save_both:
        try:
            df = pd.DataFrame(results)
            existing_cols = [c for c in fieldnames if c in df.columns]
            df = df[existing_cols]
            df.to_excel(xlsx_path, index=False)
            print(f"\n[green]Final XLSX report generated:[/green] {xlsx_path}\n")
        except Exception:
            logging.exception("Failed to save report to %s", xlsx_path)

# -------------------------
# Main CLI
# -------------------------
def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-help", action="store_true")
    parser.add_argument("-ip", metavar="IP")
    parser.add_argument("-file", metavar="FILE")
    parser.add_argument("-output", metavar="OUT", help="Base name for output files (without extension). Default: 'report'")
    parser.add_argument("-nosave", action="store_true", help="Do not save XLSX/CSV output even if output base is provided")
    parser.add_argument("-details", action="store_true")
    parser.add_argument("-concurrency", type=int)
    parser.add_argument("-delay", type=float)
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--no-cloudscraper", action="store_true", help="Disable cloudscraper fallback even if installed")
    parser.add_argument("-timeout", type=float, help="Read timeout in seconds (default 20 or from config)")
    parser.add_argument("-connect-timeout", type=float, help="Connect timeout in seconds (default 10 or from config)")
    parser.add_argument("--no-cache", action="store_true", help="Bypass cache and force fresh lookups")
    parser.add_argument("-cache-ttl", type=float, help="Cache TTL in hours (default 24 or from config)")
    parser.add_argument("-extract", metavar="FILE", help="Extract IPs from any file (logs, CSV, raw text), clean, and check")

    args = parser.parse_args()
    setup_logging(debug=args.debug)
    ensure_config()
    db.init_db()
    banner()

    if args.help:
        print("""\
Usage:
 -ip <IP>            Check single IP
 -file <path>        Bulk check list of IPs (one per line)
 -output <base>      Save both XLSX and CSV as <base>.xlsx and <base>.csv (default 'report')
 -nosave             Do not save outputs even if -output provided
 -details            Show full details for single IP
 -concurrency N      Number of worker threads for bulk (default from config)
 -delay S            Base delay between requests (seconds, float)
 -timeout S          Read timeout (seconds), default 20 (or from config)
 -connect-timeout S  Connect timeout (seconds), default 10 (or from config)
 -extract <file>     Extract IPs from any file (logs, CSV, text), clean, and check
 -cache-ttl H        Cache TTL in hours (default 24 or from config)
 --no-cache          Bypass cache and force fresh lookups
 --debug             Enable verbose logging
 --no-cloudscraper   Disable cloudscraper fallback
""")
        sys.exit(0)

    concurrency = args.concurrency or int(config["DEFAULT"].get("concurrency", DEFAULTS["concurrency"]))
    delay = args.delay or float(config["DEFAULT"].get("delay", DEFAULTS["delay"]))
    read_timeout = args.timeout or float(config["DEFAULT"].get("timeout", DEFAULTS["timeout"]))
    connect_timeout = args.connect_timeout or float(config["DEFAULT"].get("connectTimeout", DEFAULTS["connectTimeout"]))
    use_cloudscraper_fallback = not args.no_cloudscraper
    
    if use_cloudscraper_fallback and not HAS_CLOUDSCRAPER:
        logging.warning("cloudscraper fallback requested but cloudscraper package not available")

    # Cache TTL: --no-cache sets it to 0 (always fetch fresh)
    if args.no_cache:
        config["DEFAULT"]["cacheTTL"] = "0"
        logging.info("Cache disabled via --no-cache")
    elif args.cache_ttl is not None:
        config["DEFAULT"]["cacheTTL"] = str(args.cache_ttl)

    if args.extract:
        out_base = args.output or "report"
        save_both = not args.nosave
        clean_list_path = f"{out_base}_clean_ips.txt"

        print(f"[cyan]Extracting IPs from:[/cyan] {args.extract}")
        result = extract_and_clean(args.extract, save_path=clean_list_path)

        if "error" in result:
            print(f"[red]{result['error']}[/red]")
            sys.exit(1)

        print(f"[green]IPs found:[/green]          {result['raw_count']}")
        print(f"[green]Duplicates removed:[/green] {result['duplicates_removed']}")
        if result["skipped"]:
            print(f"[yellow]Skipped {len(result['skipped'])} non-routable/invalid IP(s):[/yellow]")
            for s in result["skipped"]:
                print(f"  [dim]{s['IP']}[/dim] — {s['reason']}")
        print(f"[green]Clean public IPs:[/green]   {result['clean_count']}")

        if result["clean_count"] == 0:
            print("[red]No valid public IPs to check.[/red]")
            sys.exit(0)

        print(f"[green]Clean list saved to:[/green] {clean_list_path}\n")
        print(f"[cyan]Starting bulk check on {result['clean_count']} IPs...[/cyan]\n")

        bulkcheck_cli(clean_list_path,
                      output_base=out_base,
                      save_both=save_both,
                      concurrency=concurrency,
                      delay=delay,
                      use_cloudscraper_fallback=use_cloudscraper_fallback,
                      connect_timeout=connect_timeout,
                      read_timeout=read_timeout)
    elif args.ip:
        check_ip_cli(args.ip,
                     details=args.details,
                     delay=delay,
                     use_cloudscraper_fallback=use_cloudscraper_fallback,
                     connect_timeout=connect_timeout,
                     read_timeout=read_timeout)
    elif args.file:
        out_base = args.output or "report"
        save_both = not args.nosave
        bulkcheck_cli(args.file,
                      output_base=out_base,
                      save_both=save_both,
                      concurrency=concurrency,
                      delay=delay,
                      use_cloudscraper_fallback=use_cloudscraper_fallback,
                      connect_timeout=connect_timeout,
                      read_timeout=read_timeout)
    else:
        print("[cyan]No action specified. Use -help to see options.[/cyan]")

if __name__ == "__main__":
    main()