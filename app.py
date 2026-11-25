#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cybersecurity Radar & CVE Intelligence Dashboard - Backend Service
Powered by Flask, Feedparser, and Requests
"""

import os
import sys
import json
import time
import re
import html
import hashlib
import datetime
import threading
import webbrowser
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

import requests
import feedparser
from flask import Flask, jsonify, request, send_from_directory, render_template, session, redirect, url_for
from datetime import timedelta
from auth import (
    login_required, verify_local_user, verify_ad_user, get_ad_config,
    generate_captcha, verify_captcha, create_default_admin,
    check_rate_limit, record_failed_attempt, clear_failed_attempts
)

# Configure terminal encoding
try:
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')
except AttributeError:
    pass

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RSS_SOURCES_FILE = os.path.join(BASE_DIR, "rss_sources.json")
KEYWORDS_FILE = os.path.join(BASE_DIR, "keywords.json")
CACHE_NEWS_FILE = os.path.join(BASE_DIR, "cache_news.json")
CACHE_CVES_FILE = os.path.join(BASE_DIR, "cache_cves.json")
CACHE_KEV_FILE = os.path.join(BASE_DIR, "cache_kev.json")
CONFIG_FILE = os.path.join(BASE_DIR, "dashboard_config.json")

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 CyberSecDashboard/2.0"

app = Flask(__name__, template_folder=os.path.join(BASE_DIR, "templates"), static_folder=os.path.join(BASE_DIR, "static"))

# Enable CORS for all routes
@app.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type,Authorization'
    response.headers['Access-Control-Allow-Methods'] = 'GET,PUT,POST,DELETE,OPTIONS'
    return response

# Global in-memory cache and locks
data_lock = threading.Lock()
cve_update_lock = threading.Lock()
refresh_lock = threading.Lock()
nvd_status = {"state": "not_synced", "error": None, "total_results": None}
cached_news = []
cached_cves = []
cisa_kev_data = {}  # cveID -> details
last_updated_news = None
last_updated_cves = None
is_refreshing = False

def load_json_file(filepath, default):
    if not os.path.exists(filepath):
        return default
    try:
        with open(filepath, 'r', encoding='utf-8-sig') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading {filepath}: {e}")
        return default

def save_json_file(filepath, data):
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        print(f"Error saving {filepath}: {e}")
        return False

# Default Config
def get_dashboard_config():
    default_config = {
        "refresh_interval_minutes": 10,
        "nvd_api_key": os.environ.get("NVD_API_KEY", ""),
        "max_news_items": 100,
        "max_cves_items": 150,
        "min_severity": "ALL",  # ALL, LOW, MEDIUM, HIGH, CRITICAL
        "auto_open_browser": True,
        "port": 5000
    }
    config = load_json_file(CONFIG_FILE, default_config)
    return {**default_config, **config}

def save_dashboard_config(new_config):
    current = get_dashboard_config()
    current.update(new_config)
    save_json_file(CONFIG_FILE, current)
    return current

# Clean HTML tags and excessive spaces
def clean_html_snippet(text, max_length=240):
    if not text:
        return ""
    text = re.sub(r'<[^>]+>', ' ', text)
    text = html.unescape(text)
    text = re.sub(r'\s+', ' ', text).strip()
    if len(text) > max_length:
        return text[:max_length].rstrip() + "..."
    return text

def extract_image_from_entry(entry):
    # Check media_content
    if 'media_content' in entry and entry.media_content:
        for media in entry.media_content:
            url = media.get('url')
            if url and (url.endswith('.jpg') or url.endswith('.png') or url.endswith('.webp') or 'image' in media.get('type', '')):
                return url
    # Check media_thumbnail
    if 'media_thumbnail' in entry and entry.media_thumbnail:
        for media in entry.media_thumbnail:
            url = media.get('url')
            if url:
                return url
    # Check enclosures
    if 'enclosures' in entry and entry.enclosures:
        for enc in entry.enclosures:
            url = enc.get('href') or enc.get('url')
            if url and ('image' in enc.get('type', '') or any(url.lower().endswith(ext) for ext in ['.jpg', '.jpeg', '.png', '.webp'])):
                return url
    # Check description / content for img tag
    content = ""
    if 'content' in entry and entry.content:
        content = entry.content[0].value
    elif 'description' in entry:
        content = entry.description
    if content:
        img_match = re.search(r'<img[^>]+src=["\']([^"\']+)["\']', content, re.IGNORECASE)
        if img_match:
            return img_match.group(1)
    return None

def fetch_single_feed(source):
    items = []
    source_id = source.get('id', '')
    source_name = source.get('name', 'Fuente RSS')
    source_url = source.get('url', '')
    category = source.get('category', 'Seguridad')
    
    if not source.get('enabled', True) or not source_url:
        return items
        
    try:
        headers = {'User-Agent': USER_AGENT}
        resp = requests.get(source_url, headers=headers, timeout=12)
        if resp.status_code != 200:
            print(f"[{source_name}] Error status {resp.status_code}")
            return items
            
        parsed = feedparser.parse(resp.content)
        for entry in parsed.entries[:25]:
            title = clean_html_snippet(entry.get('title', ''), max_length=200)
            if not title:
                continue
                
            link = entry.get('link', '')
            summary = clean_html_snippet(entry.get('summary', '') or entry.get('description', ''), max_length=280)
            
            # Format published date
            published_dt = None
            if hasattr(entry, 'published_parsed') and entry.published_parsed:
                try:
                    published_dt = datetime.datetime.fromtimestamp(time.mktime(entry.published_parsed), tz=datetime.timezone.utc)
                except Exception:
                    pass
            elif hasattr(entry, 'updated_parsed') and entry.updated_parsed:
                try:
                    published_dt = datetime.datetime.fromtimestamp(time.mktime(entry.updated_parsed), tz=datetime.timezone.utc)
                except Exception:
                    pass
                    
            if not published_dt:
                published_dt = datetime.datetime.now(datetime.timezone.utc)
                
            published_iso = published_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
            image_url = extract_image_from_entry(entry)
            
            # Generate deterministic hash ID
            item_hash = hashlib.md5((link or title).encode('utf-8')).hexdigest()[:12]
            
            items.append({
                "id": f"news_{item_hash}",
                "title": title,
                "link": link,
                "summary": summary,
                "source_id": source_id,
                "source_name": source_name,
                "category": category,
                "image": image_url,
                "published": published_iso,
                "timestamp": int(published_dt.timestamp())
            })
    except Exception as e:
        print(f"Error fetching feed '{source_name}' ({source_url}): {e}")
        
    return items

def update_all_news():
    global cached_news, last_updated_news
    sources = load_json_file(RSS_SOURCES_FILE, [])
    if not sources:
        return
        
    all_items = []
    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = {executor.submit(fetch_single_feed, src): src for src in sources if src.get('enabled', True)}
        for future in as_completed(futures):
            try:
                res = future.result()
                all_items.extend(res)
            except Exception as e:
                print(f"Feed worker error: {e}")
                
    # Sort chronologically (newest first)
    all_items.sort(key=lambda x: x.get('timestamp', 0), reverse=True)
    
    # Deduplicate by link or title
    unique_items = []
    seen = set()
    for item in all_items:
        key = item.get('link') or item.get('title')
        if key not in seen:
            seen.add(key)
            unique_items.append(item)
            
    cfg = get_dashboard_config()
    max_items = cfg.get("max_news_items", 120)
    unique_items = unique_items[:max_items]
    
    with data_lock:
        cached_news = unique_items
        last_updated_news = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        
    save_json_file(CACHE_NEWS_FILE, {
        "last_updated": last_updated_news,
        "items": cached_news
    })
    print(f"News updated: {len(cached_news)} articles collected.")

# ==================== CVE INTELLIGENCE ENGINE ====================

def fetch_cisa_kev():
    """Fetches CISA Known Exploited Vulnerabilities catalog (actively exploited in wild)"""
    global cisa_kev_data
    try:
        resp = requests.get(CISA_KEV_URL, headers={'User-Agent': USER_AGENT}, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            vulns = data.get('vulnerabilities', [])
            kev_map = {}
            for v in vulns:
                cve_id = v.get('cveID')
                if cve_id:
                    kev_map[cve_id] = {
                        "vendor": v.get("vendorProject", ""),
                        "product": v.get("product", ""),
                        "vulnerabilityName": v.get("vulnerabilityName", ""),
                        "dateAdded": v.get("dateAdded", ""),
                        "shortDescription": v.get("shortDescription", ""),
                        "ransomware": v.get("knownRansomwareCampaignUse", "Unknown")
                    }
            with data_lock:
                cisa_kev_data = kev_map
            save_json_file(CACHE_KEV_FILE, cisa_kev_data)
            print(f"CISA KEV updated: {len(cisa_kev_data)} known weaponized vulnerabilities.")
            return kev_map
    except Exception as e:
        print(f"CISA KEV fetch note: {e}")
        # Try loading from local cache
        cached = load_json_file(CACHE_KEV_FILE, {})
        if cached:
            with data_lock:
                cisa_kev_data = cached
    return cisa_kev_data

def detect_poc_and_exploits(cve_item, cve_id):
    """
    Determines if a public PoC / Exploit exists for this CVE:
    1. CISA KEV presence (weaponized in the wild)
    2. NVD Reference tags containing 'Exploit'
    3. Reference URLs pointing to GitHub PoCs, Exploit-DB, PacketStorm, etc.
    4. Text markers in description
    """
    has_poc = False
    is_cisa_kev = cve_id in cisa_kev_data
    kev_info = cisa_kev_data.get(cve_id)
    poc_links = []
    
        
    cve = cve_item.get("cve", {})
    references = cve.get("references", [])
    
    poc_domains = [
        "github.com", "exploit-db.com", "packetstormsecurity.com",
        "0day.today", "vulners.com", "sploitus.com", "rapid7.com/db/modules",
        "project-zero.issues", "seclists.org/fulldisclosure"
    ]
    
    for ref in references:
        url = ref.get("url", "")
        tags = [t.lower() for t in ref.get("tags", [])]
        
        is_exploit_ref = False
        if "exploit" in tags:
            is_exploit_ref = True
            has_poc = True
            
        lower_url = url.lower()
        if any(dom in lower_url for dom in poc_domains):
            # Check if it looks like an exploit or PoC repository/script
            if any(term in lower_url for term in ["poc", "exploit", "payload", "rce"]):
                is_exploit_ref = True
                has_poc = True
                
        if is_exploit_ref and url not in poc_links:
            poc_links.append(url)
            
    # Check description text indicators
    descriptions = cve.get("descriptions", [])
    for d in descriptions:
        val = d.get("value", "").lower()
        if any(phrase in val for phrase in ["proof of concept", "proof-of-concept", "public exploit", "exploit available", "weaponized"]):
            has_poc = True
            break
            
    return has_poc, is_cisa_kev, kev_info, poc_links

def extract_scope_and_vector(cve_item):
    """
    Extracts Attack Vector (scope/reach) and Impact Classification.
    """
    metrics = cve_item.get("cve", {}).get("metrics", {})
    vector_str = ""
    attack_vector = "Desconocido"
    privileges = "N/A"
    complexity = "N/A"
    
    # Look for CVSS v3.1, v4.0, v3.0, v2.0
    for v_key in ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30"]:
        if v_key in metrics and metrics[v_key]:
            m = metrics[v_key][0]
            cvss_data = m.get("cvssData", {})
            vector_str = cvss_data.get("vectorString", "")
            av = cvss_data.get("attackVector", "")
            if av == "NETWORK":
                attack_vector = "Red / Remoto (Network)"
            elif av == "ADJACENT_NETWORK":
                attack_vector = "Red Adyacente (Adjacent)"
            elif av == "LOCAL":
                attack_vector = "Local (Acceso al Host)"
            elif av == "PHYSICAL":
                attack_vector = "Acceso Físico"
            privileges = cvss_data.get("privilegesRequired", "N/A")
            complexity = cvss_data.get("attackComplexity", "N/A")
            break
            
    if attack_vector == "Desconocido":
        # Check description heuristic
        desc = " ".join([d.get("value", "").lower() for d in cve_item.get("cve", {}).get("descriptions", [])])
        if "remote attacker" in desc or "via network" in desc or "unauthenticated remote" in desc or "over the network" in desc:
            attack_vector = "Red / Remoto (Network)"
        elif "local attacker" in desc or "local user" in desc or "locally authenticated" in desc:
            attack_vector = "Local (Acceso al Host)"
            
    # Impact categorization (RCE, PrivEsc, DoS, InfoLeak, Auth Bypass)
    impact_types = []
    desc_full = " ".join([d.get("value", "") for d in cve_item.get("cve", {}).get("descriptions", [])]).lower()
    
    if any(k in desc_full for k in ["remote code execution", "execute arbitrary code", "code injection", "rce", "arbitrary command"]):
        impact_types.append("Ejecución Remota de Código (RCE)")
    if any(k in desc_full for k in ["privilege escalation", "gain elevated privileges", "gain root", "gain administrator", "elevation of privilege"]):
        impact_types.append("Escalación de Privilegios")
    if any(k in desc_full for k in ["denial of service", "crash the system", "dos attack", "resource exhaustion", "infinite loop"]):
        impact_types.append("Denegación de Servicio (DoS)")
    if any(k in desc_full for k in ["information disclosure", "sensitive information", "read arbitrary files", "memory leak", "data exfiltration"]):
        impact_types.append("Fuga de Información")
    if any(k in desc_full for k in ["bypass authentication", "auth bypass", "improper authorization", "bypass security restrictions"]):
        impact_types.append("Bypass de Autenticación")
    if any(k in desc_full for k in ["cross-site scripting", "xss"]):
        impact_types.append("Cross-Site Scripting (XSS)")
    if any(k in desc_full for k in ["sql injection", "sqli"]):
        impact_types.append("SQL Injection")
        
    if not impact_types:
        impact_types.append("Vulnerabilidad General")
        
    return {
        "vector_string": vector_str,
        "attack_vector": attack_vector,
        "privileges_required": privileges,
        "attack_complexity": complexity,
        "impact_types": impact_types
    }

def extract_affected_targets(cve_item, keywords):
    """
    Extracts vendor, product, and matches keywords.
    """
    cve = cve_item.get("cve", {})
    targets = set()
    matched_kws = set()
    
    # Extract from CPE
    configs = cve.get("configurations", [])
    for config in configs:
        for node in config.get("nodes", []):
            for m in node.get("cpeMatch", []):
                crit = m.get("criteria", "")
                parts = crit.split(":")
                if len(parts) >= 5:
                    vendor = parts[3].replace("_", " ").title()
                    product = parts[4].replace("_", " ").title()
                    if vendor and product:
                        targets.add(f"{vendor} {product}")
                    elif product:
                        targets.add(product)
                        
    # Match against user tracked topics/keywords
    desc_text = " ".join([d.get("value", "") for d in cve.get("descriptions", [])]).lower()
    crit_text = " ".join([t.lower() for t in targets])
    combined_text = f"{desc_text} {crit_text}"
    
    for kw in keywords.get("include", []):
        kw_lower = kw.lower().strip()
        if not kw_lower:
            continue
        pattern = rf"(?:^|[^a-zA-Z0-9]){re.escape(kw_lower)}(?:$|[^a-zA-Z0-9])"
        if re.search(pattern, combined_text, re.IGNORECASE):
            matched_kws.add(kw_lower)
            targets.add(kw_lower.capitalize())
            
    target_list = sorted(targets)
    if not target_list:
        target_list = ["No especificado / General"]
        
    return target_list, list(matched_kws)

def extract_cvss_score(cve_item):
    """Extracts score and normalized severity"""
    metrics = cve_item.get("cve", {}).get("metrics", {})
    
    for v_key in ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if v_key in metrics and metrics[v_key]:
            m = next((item for item in metrics[v_key] if item.get("type") == "Primary"), metrics[v_key][0])
            cvss_data = m.get("cvssData", {})
            score = cvss_data.get("baseScore")
            severity = cvss_data.get("baseSeverity") or m.get("baseSeverity", "UNKNOWN")
            
            if score is not None:
                score = float(score)
                if score >= 9.0:
                    severity = "CRITICAL"
                elif score >= 7.0:
                    severity = "HIGH"
                elif score >= 4.0:
                    severity = "MEDIUM"
                elif score > 0:
                    severity = "LOW"
            return score, severity.upper(), cvss_data.get("version", "3.1")
            
    return None, "EN ANÁLISIS", "N/A"

def update_cves():
    with cve_update_lock:
        return _update_cves_locked()


def _update_cves_locked():
    global cached_cves, last_updated_cves
    keywords = load_json_file(KEYWORDS_FILE, {"include": [], "exclude": []})
    
    # 1. Update CISA KEV
    fetch_cisa_kev()
    
    # 2. Check NVD API
    cfg = get_dashboard_config()
    nvd_api_key = os.environ.get("NVD_API_KEY") or cfg.get("nvd_api_key", "")
    
    headers = {'User-Agent': USER_AGENT}
    if nvd_api_key:
        headers["apiKey"] = nvd_api_key
        
    collected_cves = []
    
    # Try querying NVD for recent CVEs
    now_utc = datetime.datetime.now(datetime.timezone.utc)
    start_dt = now_utc - datetime.timedelta(days=7)
    
    params = {
    "pubStartDate": start_dt.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
    "pubEndDate": now_utc.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
    "resultsPerPage": 2000
    }
    
    nvd_status.update(state="syncing", error=None)
    try:
        print(f"[NVD] Querying {params['pubStartDate']} to {params['pubEndDate']} UTC")
        start_index = 0
        total = None
        received = 0
        while True:
            params["startIndex"] = start_index
            resp = requests.get(NVD_API_URL, params=params, headers=headers, timeout=60)
            if resp.status_code in [403, 404] and "apiKey" in headers:
                print(f"[NVD] Advertencia: La API Key fue rechazada por NIST (HTTP {resp.status_code}). Continuando en modo publico...")
                headers.pop("apiKey", None)
                resp = requests.get(NVD_API_URL, params=params, headers=headers, timeout=60)
            if resp.status_code != 200:
                raise RuntimeError(f"NVD HTTP {resp.status_code}")
            payload = resp.json()
            vulns = payload["vulnerabilities"]
            total = int(payload["totalResults"])
            if int(payload["startIndex"]) != start_index:
                raise RuntimeError("Unexpected NVD page index")
            if not isinstance(vulns, list) or (not vulns and start_index < total):
                raise RuntimeError("Incomplete NVD page")
            received += len(vulns)
            print(f"[NVD] Page start={start_index}: {len(vulns)} received; totalResults={total}")
            for v in vulns:
                cve_obj = v.get("cve", {})
                cve_id = cve_obj.get("id")
                if not cve_id or str(cve_obj.get("vulnStatus", "")).lower() == "rejected":
                    continue
                    
                score, severity, cvss_ver = extract_cvss_score(v)
                has_poc, is_kev, kev_info, poc_links = detect_poc_and_exploits(v, cve_id)
                vector_info = extract_scope_and_vector(v)
                targets, matched_kws = extract_affected_targets(v, keywords)
                
                # Filter by exclude keywords
                desc = " ".join([d.get("value", "") for d in cve_obj.get("descriptions", [])])
                exclude_hit = False
                for ex in keywords.get("exclude", []):
                    if ex.lower() in desc.lower() or any(ex.lower() in t.lower() for t in targets):
                        exclude_hit = True
                        break
                if exclude_hit:
                    continue
                    
                collected_cves.append({
                    "id": cve_id,
                    "score": score,
                    "severity": severity,
                    "cvss_version": cvss_ver,
                    "published": cve_obj.get("published", ""),
                    "last_modified": cve_obj.get("lastModified", ""),
                    "description": desc,
                    "affected_targets": targets,
                    "matched_keywords": matched_kws,
                    "attack_vector": vector_info["attack_vector"],
                    "impact_types": vector_info["impact_types"],
                    "has_poc": has_poc,
                    "is_cisa_kev": is_kev,
                    "kev_info": kev_info,
                    "poc_links": poc_links,
                    "references": [{"url": r.get("url"), "tags": r.get("tags", [])} for r in cve_obj.get("references", [])[:6]]
                })
            start_index += len(vulns)
            if start_index >= total:
                break
            time.sleep(6)
    except Exception as e:
        nvd_status.update(state="error", error=str(e))
        print(f"[NVD] Sync failed: {e}; retaining previous cache and timestamp.")
        return False

    # Deduplicate by ID
    unique_cves = {}
    for item in collected_cves:
        c_id = item.get("id")
        if c_id not in unique_cves:
            unique_cves[c_id] = item
            
    final_list = list(unique_cves.values())
    
    # Sort: Critical first, then with PoC, then by date
    def cve_sort_key(c):
        score_val = c.get("score") or 0.0
        poc_val = 1 if c.get("has_poc") else 0
        return (score_val, poc_val, c.get("published", ""))
        
    final_list.sort(key=cve_sort_key, reverse=True)
    
    updated = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    with data_lock:
        cached_cves = final_list
        last_updated_cves = updated
        nvd_status.update(state="ok", error=None, total_results=total,
                          received=received, retained=len(final_list),
                          latest_published=max((c.get("published", "") for c in final_list), default=None))
    if not save_json_file(CACHE_CVES_FILE, {
        "source": "NVD", "last_updated": updated, "items": final_list
    }):
        print("[NVD] Warning: cache could not be saved to disk.")
    print(f"[NVD] CVEs updated: {len(final_list)} retained / {received} received / {total} available. Latest published: {nvd_status['latest_published']}")
    return True

def run_refresh():
    global is_refreshing
    try:
        update_all_news()
        success = update_cves()
        print("[Refresh] Sync complete." if success else "[Refresh] NVD sync failed; see previous error.")
    except Exception as e:
        print(f"[Refresh] Error: {e}")
    finally:
        is_refreshing = False
        refresh_lock.release()


def background_worker():
    global is_refreshing
    while True:
        if refresh_lock.acquire(blocking=False):
            is_refreshing = True
            run_refresh()
        cfg = get_dashboard_config()
        time.sleep(max(1, cfg.get("refresh_interval_minutes", 10)) * 60)

# ==================== REST API ROUTES ====================

@app.route("/")
@login_required
def index():
    return render_template("index.html")

@app.route("/dashboard.html")
def dashboard_html():
    return render_template("index.html")

@app.route("/api/stats")
@login_required
def api_stats():
    with data_lock:
        news_count = len(cached_news)
        cve_count = len(cached_cves)
        critical_count = sum(1 for c in cached_cves if (c.get("score") or 0) >= 9.0 or c.get("severity") == "CRITICAL")
        poc_count = sum(1 for c in cached_cves if c.get("has_poc"))
        kev_count = sum(1 for c in cached_cves if c.get("is_cisa_kev"))
        
    cfg = get_dashboard_config()
    return jsonify({
        "success": True,
        "news_count": news_count,
        "cve_count": cve_count,
        "critical_count": critical_count,
        "poc_count": poc_count,
        "kev_count": kev_count,
        "last_updated_news": last_updated_news,
        "last_updated_cves": last_updated_cves,
        "is_refreshing": is_refreshing,
        "nvd_status": dict(nvd_status),
        "refresh_interval_minutes": cfg.get("refresh_interval_minutes", 10)
    })

@app.route("/api/news")
@login_required
def api_news():
    source_filter = request.args.get("source", "").strip()
    search = request.args.get("search", "").strip().lower()
    limit = request.args.get("limit", default=100, type=int)
    
    with data_lock:
        items = list(cached_news)
        
    if source_filter:
        items = [i for i in items if i.get("source_id") == source_filter or i.get("source_name") == source_filter]
        
    if search:
        items = [i for i in items if search in i.get("title", "").lower() or search in i.get("summary", "").lower()]
        
    return jsonify({
        "success": True,
        "count": len(items[:limit]),
        "total": len(items),
        "last_updated": last_updated_news,
        "items": items[:limit]
    })


def match_topic_smart(topic, cve_item):
    """Whole-word boundary and synonym matcher for CVE topics"""
    if not topic:
        return True
    t_lower = topic.lower().strip()
    
    synonyms = {
        'rdp': ['rdp', 'remote desktop', 'remote desktop protocol', 'freerdp', 'rdesktop', 'ms-rdp', 'terminal services'],
        'ssh': ['ssh', 'openssh', 'secure shell', 'libssh'],
        'vpn': ['vpn', 'virtual private network', 'openvpn', 'wireguard'],
        'sap': ['sap', 'netweaver', 's/4hana', 'sap erp'],
        'citrix': ['citrix', 'netscaler', 'xenapp', 'xendesktop'],
        'teams': ['teams', 'microsoft teams'],
        'edge': ['microsoft edge', 'msedge'],
        'firefox': ['firefox', 'mozilla firefox']
    }
    terms = synonyms.get(t_lower, [t_lower])
    
    if t_lower in [k.lower() for k in cve_item.get("matched_keywords", [])]:
        return True
        
    def test_wb(term, text):
        if not text:
            return False
        pattern = rf"(?:^|[^a-zA-Z0-9]){re.escape(term)}(?:$|[^a-zA-Z0-9])"
        return bool(re.search(pattern, text, re.IGNORECASE))
        
    for target in cve_item.get("affected_targets", []):
        for term in terms:
            if test_wb(term, target):
                return True
                
    desc = cve_item.get("description", "")
    for term in terms:
        if test_wb(term, desc):
            return True
            
    return False

@app.route("/api/cves")
@login_required
def api_cves():
    severity_filter = request.args.get("severity", "").strip().upper()
    topic_filter = request.args.get("topic", "").strip().lower()
    poc_only = request.args.get("poc_only", "false").lower() in ["true", "1", "yes"]
    search = request.args.get("search", "").strip().lower()
    sort_by = request.args.get("sort_by", "score").strip()  # score, date, poc
    
    with data_lock:
        items = list(cached_cves)
        
    if severity_filter and severity_filter != "ALL":
        items = [i for i in items if i.get("severity", "").upper() == severity_filter]
        
    if topic_filter:
        items = [i for i in items if match_topic_smart(topic_filter, i)]
        
    if poc_only:
        items = [i for i in items if i.get("has_poc")]
        
    if search:
        items = [
            i for i in items if search in i.get("id", "").lower() or
            search in i.get("description", "").lower() or
            any(search in t.lower() for t in i.get("affected_targets", []))
        ]
        
    if sort_by == "date":
        items.sort(key=lambda x: x.get("published", ""), reverse=True)
    elif sort_by == "poc":
        items.sort(key=lambda x: (1 if x.get("has_poc") else 0, x.get("score") or 0.0), reverse=True)
    else:  # score
        items.sort(key=lambda x: (x.get("score") or 0.0, 1 if x.get("has_poc") else 0), reverse=True)
        
    keywords_data = load_json_file(KEYWORDS_FILE, {"include": [], "exclude": []})
    
    return jsonify({
        "success": True,
        "count": len(items),
        "last_updated": last_updated_cves,
        "nvd_status": dict(nvd_status),
        "keywords": keywords_data.get("include", []),
        "items": items
    })

@app.route("/api/sources", methods=["GET", "POST", "DELETE"])
@login_required
def api_sources():
    sources = load_json_file(RSS_SOURCES_FILE, [])
    
    if request.method == "GET":
        return jsonify({"success": True, "sources": sources})
        
    if request.method == "POST":
        data = request.json or {}
        action = data.get("action", "add")
        
        if action == "add":
            name = data.get("name", "").strip()
            url = data.get("url", "").strip()
            category = data.get("category", "General").strip()
            
            if not name or not url:
                return jsonify({"success": False, "error": "Nombre y URL requeridos"}), 400
                
            source_id = re.sub(r'[^a-zA-Z0-9]', '_', name.lower())[:16]
            # Check duplicate
            if any(s.get("url") == url for s in sources):
                return jsonify({"success": False, "error": "La URL ya está registrada"}), 400
                
            new_source = {
                "id": source_id,
                "name": name,
                "url": url,
                "category": category,
                "enabled": True
            }
            sources.append(new_source)
            save_json_file(RSS_SOURCES_FILE, sources)
            
            # Fetch this new source right away in background
            threading.Thread(target=lambda: [cached_news.extend(fetch_single_feed(new_source))]).start()
            
            return jsonify({"success": True, "source": new_source, "sources": sources})
            
        elif action == "toggle":
            source_id = data.get("id")
            for s in sources:
                if s.get("id") == source_id:
                    s["enabled"] = not s.get("enabled", True)
                    break
            save_json_file(RSS_SOURCES_FILE, sources)
            return jsonify({"success": True, "sources": sources})
            
        elif action == "delete":
            source_id = data.get("id")
            sources = [s for s in sources if s.get("id") != source_id]
            save_json_file(RSS_SOURCES_FILE, sources)
            return jsonify({"success": True, "sources": sources})
            
    return jsonify({"success": False, "error": "Acción no reconocida"}), 400

@app.route("/api/sources/test", methods=["POST"])
@login_required
def api_test_source():
    data = request.json or {}
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"valid": False, "error": "URL vacía"}), 400
        
    try:
        headers = {'User-Agent': USER_AGENT}
        resp = requests.get(url, headers=headers, timeout=8)
        if resp.status_code != 200:
            return jsonify({"valid": False, "error": f"Error HTTP {resp.status_code}"})
            
        parsed = feedparser.parse(resp.content)
        if not parsed.entries:
            return jsonify({"valid": False, "error": "No se encontraron artículos en este feed RSS/Atom"})
            
        feed_title = parsed.feed.get("title", "Feed RSS Válido")
        return jsonify({
            "valid": True,
            "title": feed_title,
            "items_count": len(parsed.entries),
            "sample_title": parsed.entries[0].get("title", "")
        })
    except Exception as e:
        return jsonify({"valid": False, "error": str(e)})

@app.route("/api/keywords", methods=["GET", "POST"])
@login_required
def api_keywords():
    keywords = load_json_file(KEYWORDS_FILE, {"include": [], "exclude": []})
    
    if request.method == "GET":
        return jsonify({"success": True, "keywords": keywords})
        
    if request.method == "POST":
        data = request.json or {}
        include = data.get("include")
        exclude = data.get("exclude")
        
        if include is not None:
            keywords["include"] = [k.strip().lower() for k in include if k.strip()]
        if exclude is not None:
            keywords["exclude"] = [k.strip().lower() for k in exclude if k.strip()]
            
        save_json_file(KEYWORDS_FILE, keywords)
        
        # Trigger re-evaluation of CVEs
        threading.Thread(target=update_cves, daemon=True).start()
        
        return jsonify({"success": True, "keywords": keywords})

@app.route("/api/config", methods=["GET", "POST"])
@login_required
def api_config():
    if request.method == "GET":
        return jsonify({"success": True, "config": get_dashboard_config()})
        
    if request.method == "POST":
        data = request.json or {}
        saved = save_dashboard_config(data)
        return jsonify({"success": True, "config": saved})

@app.route("/api/refresh", methods=["POST"])
@login_required
def api_refresh():
    global is_refreshing
    if not refresh_lock.acquire(blocking=False):
        return jsonify({"success": False, "message": "Ya hay una actualización en curso..."})
    is_refreshing = True
    threading.Thread(target=run_refresh, daemon=True).start()
    return jsonify({"success": True, "message": "Actualización iniciada en segundo plano"})


# ═══════════════════════════════════════════════════════
# AUTENTICACIÓN
# ═══════════════════════════════════════════════════════

@app.route("/login", methods=["GET", "POST"])
def login_page():
    """Página de login con CAPTCHA matemático y soporte AD."""
    cfg = get_dashboard_config()

    # Si ya está logueado, redirigir al dashboard
    if session.get("logged_in"):
        return redirect(url_for("index"))

    # Rate limiting por IP
    client_ip = request.remote_addr or "unknown"
    allowed, locked_seconds = check_rate_limit(client_ip)

    # Generar CAPTCHA nuevo en GET o si no hay uno en sesión
    if request.method == "GET" or not session.get("captcha_answer"):
        captcha = generate_captcha()
        session["captcha_answer"] = captcha["answer"]
        session["captcha_question"] = captcha["question"]

    captcha_question = session.get("captcha_question", "¿Cuánto es 1 + 1?")

    if request.method == "POST":
        if not allowed:
            return render_template("login.html",
                error=None,
                locked=True,
                locked_seconds=locked_seconds,
                captcha_question=captcha_question,
                ad_enabled=cfg.get("ad_enabled", False),
                ad_domain=cfg.get("ad_domain", "")
            )

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        captcha_input = request.form.get("captcha_answer", "").strip()

        # Regenerar CAPTCHA después de cada intento
        captcha_ok = verify_captcha(session.get("captcha_answer"), captcha_input)
        captcha = generate_captcha()
        session["captcha_answer"] = captcha["answer"]
        session["captcha_question"] = captcha["question"]
        captcha_question = captcha["question"]

        if not captcha_ok:
            record_failed_attempt(client_ip)
            return render_template("login.html",
                error="Verificación matemática incorrecta. Intenta de nuevo.",
                locked=False, locked_seconds=0,
                captcha_question=captcha_question,
                username_prefill=username,
                ad_enabled=cfg.get("ad_enabled", False),
                ad_domain=cfg.get("ad_domain", "")
            )

        # 1. Intentar autenticación AD (si está habilitado)
        user_info = None
        ad_config = get_ad_config(cfg)
        if ad_config.get("enabled") and ad_config.get("server"):
            user_info = verify_ad_user(username, password, ad_config)

        # 2. Fallback: autenticación local
        if user_info is None:
            user_info = verify_local_user(username, password)

        if user_info:
            clear_failed_attempts(client_ip)
            session.permanent = True
            session["logged_in"] = True
            session["username"] = user_info["username"]
            session["role"] = user_info.get("role", "user")
            session["auth_type"] = user_info.get("auth_type", "local")
            session["display_name"] = user_info.get("display_name", username)
            print(f"[Auth] ✅ Login exitoso: {username} ({user_info['auth_type']}) desde {client_ip}")
            next_url = request.args.get("next", url_for("index"))
            return redirect(next_url)
        else:
            record_failed_attempt(client_ip)
            _, locked_seconds = check_rate_limit(client_ip)
            allowed_now, _ = check_rate_limit(client_ip)
            print(f"[Auth] ❌ Login fallido: {username} desde {client_ip}")
            return render_template("login.html",
                error="Usuario o contraseña incorrectos.",
                locked=not allowed_now,
                locked_seconds=locked_seconds,
                captcha_question=captcha_question,
                username_prefill=username,
                ad_enabled=cfg.get("ad_enabled", False),
                ad_domain=cfg.get("ad_domain", "")
            )

    return render_template("login.html",
        error=None, locked=not allowed, locked_seconds=locked_seconds,
        captcha_question=captcha_question,
        ad_enabled=cfg.get("ad_enabled", False),
        ad_domain=cfg.get("ad_domain", "")
    )


@app.route("/logout")
def logout():
    """Cierra la sesión del usuario."""
    username = session.get("username", "desconocido")
    session.clear()
    print(f"[Auth] 👋 Logout: {username}")
    return redirect(url_for("login_page"))


@app.route("/api/auth/status")
def api_auth_status():
    """Retorna el estado de autenticación actual (sin login_required)."""
    return jsonify({
        "logged_in": bool(session.get("logged_in")),
        "username": session.get("username", ""),
        "display_name": session.get("display_name", ""),
        "role": session.get("role", ""),
        "auth_type": session.get("auth_type", "")
    })


@app.route("/api/auth/change-password", methods=["POST"])
@login_required
def api_change_password():
    """Permite cambiar la contraseña del usuario local actual."""
    from auth import load_users, save_users, verify_password, hash_password
    if session.get("auth_type") != "local":
        return jsonify({"success": False, "error": "Solo usuarios locales pueden cambiar contraseña aquí."}), 400

    data = request.json or {}
    current_pass = data.get("current_password", "")
    new_pass = data.get("new_password", "")

    if len(new_pass) < 8:
        return jsonify({"success": False, "error": "La nueva contraseña debe tener al menos 8 caracteres."}), 400

    users = load_users()
    username = session.get("username")
    if username not in users:
        return jsonify({"success": False, "error": "Usuario no encontrado."}), 404

    if not verify_password(current_pass, users[username]["password_hash"]):
        return jsonify({"success": False, "error": "Contraseña actual incorrecta."}), 403

    users[username]["password_hash"] = hash_password(new_pass)
    save_users(users)
    print(f"[Auth] ✅ Contraseña cambiada para: {username}")
    return jsonify({"success": True, "message": "Contraseña cambiada correctamente."})


_initialized = False

def initialize():
    """Initial boot sequence"""
    global _initialized, cached_news, cached_cves, last_updated_news, last_updated_cves
    if _initialized:
        return
    _initialized = True

    # Create templates directory if not exists
    os.makedirs(os.path.join(BASE_DIR, "templates"), exist_ok=True)
    os.makedirs(os.path.join(BASE_DIR, "static"), exist_ok=True)
    
    # Load from cache first for instant UI response
    news_cache = load_json_file(CACHE_NEWS_FILE, {})
    if news_cache and "items" in news_cache:
        cached_news = news_cache.get("items", [])
        last_updated_news = news_cache.get("last_updated")
        print(f"Loaded {len(cached_news)} news items from cache.")
        
    cve_cache = load_json_file(CACHE_CVES_FILE, {})
    if cve_cache.get("source") == "NVD" and "items" in cve_cache:
        cached_cves = cve_cache.get("items", [])
        last_updated_cves = cve_cache.get("last_updated")
        nvd_status.update(state="cached")
        print(f"Loaded {len(cached_cves)} CVE items from verified-source cache.")
    else:
        print("[NVD] Legacy or missing cache ignored; waiting for real NVD data.")

    # Start background updater
    # Configurar secret_key y session lifetime (get_dashboard_config ya disponible aqui)
    _auth_cfg = get_dashboard_config()
    app.secret_key = _auth_cfg.get('secret_key') or os.urandom(32)
    _lifetime = _auth_cfg.get('session_lifetime_hours', 1)
    app.permanent_session_lifetime = timedelta(hours=_lifetime)

    # Crear admin por defecto si no hay usuarios
    create_default_admin()

    t = threading.Thread(target=background_worker, daemon=True)
    t.start()

initialize()

if __name__ == "__main__":
    cfg = get_dashboard_config()
    port = cfg.get("port", 5000)
    
    print("\n" + "="*70)
    print("🚀 PANEL DE CONTROL DE CIBERSEGURIDAD Y CVES INICIADO")
    print(f"📡 Acceso en el navegador: http://127.0.0.1:{port}")
    print("⚡ Presiona CTRL+C en esta ventana para detener el servidor.")
    print("="*70 + "\n")
    
    if cfg.get("auto_open_browser", True):
        threading.Timer(1.2, lambda: webbrowser.open(f"http://127.0.0.1:{port}")).start()
        
    app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)
