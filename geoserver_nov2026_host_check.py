#!/usr/bin/env python3
"""
geoserver_nov2026_host_check.py
Topology Defense - read-only self-check, run ON the GeoServer server
(Linux or Windows), for the November 2026 GeoServer flaws
(CVE-2026-120705, CVE-2026-129243, CVE-2026-129244, CVE-2026-129245,
 CVE-2026-120704, CVE-2026-129242).

Checks (nothing is changed):
  [1] Version   - from gs-main / gs-wfs-core / gs-ows jars in WEB-INF/lib
  [2] Remember-me signing key - default key "geoserver" in security/config.xml
                  and whether "rememberme" is in a filter chain (CVE-2026-129245)
  [3] Stored queries - files in wfs/query and workspaces/*/wfs/query
                  (anonymous create/drop via CVE-2026-129243)
  [4] JDBC security services - JDBC user/group/role services, SQLite or
                  extension loading, UNC paths (CVE-2026-120704 / -129242)
  [5] Uploaded binaries - native libraries and database files in the data
                  directory changed in the last N days
  [6] Logs      - geoserver.log and optional web/proxy access logs for
                  exploitation leads (prefixed service names, stored query
                  create/drop, GetFeatureById with XInclude/entities,
                  overlong stored query ids, REST security/resource calls)

Usage:
  python3 geoserver_nov2026_host_check.py --data-dir /opt/geoserver/data_dir \
      --webapp /opt/tomcat/webapps/geoserver --days 90 \
      --access-log /var/log/nginx/access.log --json report.json
  python  geoserver_nov2026_host_check.py --data-dir "C:\\GeoServer\\data_dir" --webapp "C:\\GeoServer\\webapps\\geoserver"

Python 3.6+, standard library only. Hits are leads, not proof of compromise.
"""

import argparse
import glob
import gzip
import json
import os
import re
import sys
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from urllib.parse import unquote_plus

FIXED = {(2, 27): 7, (2, 28): 6, (3, 0): 2}
LEADS = []


def lead(section, text):
    LEADS.append({"section": section, "lead": text})
    print("    LEAD: " + text)


def mtime(p):
    try:
        return datetime.fromtimestamp(os.path.getmtime(p)).strftime("%Y-%m-%d %H:%M")
    except OSError:
        return "?"


def recent(p, days):
    try:
        return os.path.getmtime(p) >= time.time() - days * 86400
    except OSError:
        return False


# ---------------------------------------------------------------- [1] version
def check_version(webapp):
    print("[1] GeoServer version")
    lib = os.path.join(webapp, "WEB-INF", "lib") if webapp else None
    found = {}
    if lib and os.path.isdir(lib):
        for name in os.listdir(lib):
            m = re.match(r"(gs-main|gs-wfs-core|gs-wfs|gs-ows|gt-metadata)-([0-9][\w.\-]*)\.jar$", name)
            if m:
                found[m.group(1)] = m.group(2)
    else:
        print("    --webapp not given or WEB-INF/lib not found; version cannot be read from jars.")
        return {"verdict": "REVIEW", "reason": "pass --webapp <geoserver webapp folder>"}
    for k in sorted(found):
        print("    {:<12} {}".format(k, found[k]))
    ver = found.get("gs-main") or found.get("gs-ows") or found.get("gs-wfs-core") or found.get("gs-wfs")
    verdict, reason = "REVIEW", "gs-main jar not found"
    if ver:
        m = re.match(r"(\d+)\.(\d+)(?:\.(\d+))?(.*)", ver)
        if m:
            key = (int(m.group(1)), int(m.group(2)))
            patch = int(m.group(3) or 0)
            if "SNAPSHOT" in (m.group(4) or "").upper():
                verdict, reason = "REVIEW", "development build {}".format(ver)
            elif key in FIXED:
                need = FIXED[key]
                if patch >= need:
                    verdict, reason = "PATCHED", "{} >= {}.{}.{}".format(ver, key[0], key[1], need)
                else:
                    verdict, reason = "VULNERABLE", "{} < {}.{}.{}".format(ver, key[0], key[1], need)
            elif key < (2, 27):
                verdict, reason = "VULNERABLE", "{} is an unsupported line".format(ver)
            elif key > (3, 0):
                verdict, reason = "PATCHED", "{} is newer than the affected lines".format(ver)
    print("    Verdict: {}  ({})".format(verdict, reason))
    return {"verdict": verdict, "reason": reason, "jars": found}


# --------------------------------------------------------- [2] remember-me key
def check_rememberme(dd):
    print("\n[2] Remember-me signing key (CVE-2026-129245)")
    cfg = os.path.join(dd, "security", "config.xml")
    res = {"config": cfg}
    if not os.path.isfile(cfg):
        print("    security/config.xml not found (patched releases no longer store the key there).")
        return res
    try:
        root = ET.parse(cfg).getroot()
    except ET.ParseError as e:
        print("    Could not parse {}: {}".format(cfg, e)); return res
    rms = root.find(".//rememberMeService")
    key = rms.findtext("key") if rms is not None else None
    res["key_present"] = key is not None
    res["key_is_default"] = (key or "").strip() == "geoserver"
    if key is None:
        print("    No key in rememberMeService (expected on fixed releases).")
    elif res["key_is_default"]:
        lead("rememberme", "default remember-me key 'geoserver' in {} - admin sessions can be forged on unpatched versions".format(cfg))
    else:
        print("    Key is set to a non-default value ({} characters).".format(len(key.strip())))
    chains = []
    for fl in root.iter():
        if fl.tag.endswith("filters") or fl.tag.endswith("filterChain"):
            names = [c.text for c in fl.iter() if c.text and c.text.strip() == "rememberme"]
            if names:
                if fl.get("name"): chains.append(fl.get("name"))
    res["rememberme_in_chains"] = sorted(set(chains))
    if chains:
        print("    'rememberme' filter is in chain(s): {}".format(", ".join(res["rememberme_in_chains"])))
    else:
        print("    'rememberme' filter not found in any filter chain.")
    print("    config.xml last modified: {}".format(mtime(cfg)))
    return res


# ------------------------------------------------------------ [3] stored queries
def check_stored_queries(dd, days):
    print("\n[3] WFS stored queries (unexpected ones may be from CVE-2026-129243 probing)")
    files = glob.glob(os.path.join(dd, "wfs", "query", "*")) + \
        glob.glob(os.path.join(dd, "workspaces", "*", "wfs", "query", "*"))
    files = [f for f in files if os.path.isfile(f)]
    if not files:
        print("    No custom stored queries found.")
    for f in sorted(files):
        flag = " (changed in last {} days)".format(days) if recent(f, days) else ""
        print("    {}  {}{}".format(mtime(f), f, flag))
        if recent(f, days):
            lead("stored_queries", "recent stored query file {} - confirm someone in your team created it".format(f))
    return [{"path": f, "mtime": mtime(f)} for f in files]


# ------------------------------------------------------ [4] JDBC security services
def check_jdbc(dd):
    print("\n[4] JDBC user/group and role services (CVE-2026-120704, CVE-2026-129242)")
    out = []
    for kind in ("usergroup", "role", "auth"):
        for cfg in glob.glob(os.path.join(dd, "security", kind, "*", "config.xml")):
            try:
                txt = open(cfg, encoding="utf-8", errors="replace").read()
            except OSError:
                continue
            if "jdbc" not in txt.lower():
                continue
            url = re.search(r"<connectURL>(.*?)</connectURL>", txt, re.S)
            drv = re.search(r"<driverClassName>(.*?)</driverClassName>", txt, re.S)
            url = url.group(1).strip() if url else ""
            drv = drv.group(1).strip() if drv else ""
            entry = {"config": cfg, "kind": kind, "driver": drv, "url": url, "mtime": mtime(cfg)}
            out.append(entry)
            print("    {} service: {}  driver={}  url={}".format(kind, os.path.basename(os.path.dirname(cfg)), drv, url))
            low = (url + drv).lower()
            if "sqlite" in low or "load_extension" in txt.lower():
                lead("jdbc", "SQLite JDBC / extension loading in {}".format(cfg))
            if "\\\\" in url or url.lower().startswith("jdbc:sqlite://"):
                lead("jdbc", "UNC/remote path in JDBC URL in {}".format(cfg))
            if "hsqldb" in low and "file:" in low:
                lead("jdbc", "HSQLDB file database used by a security service in {} - check it was set up by your team".format(cfg))
    if not out:
        print("    No JDBC-based security services configured.")
    return out


# ------------------------------------------------------------ [5] uploaded files
def check_binaries(dd, days):
    print("\n[5] Native libraries / database files in the data directory changed in the last {} days".format(days))
    exts = (".so", ".dll", ".dylib", ".sqlite", ".sqlite3", ".db", ".script", ".properties.sql")
    hits = []
    for rootdir, _dirs, files in os.walk(dd):
        for n in files:
            p = os.path.join(rootdir, n)
            if n.lower().endswith(exts) and recent(p, days):
                hits.append(p)
    for p in sorted(hits)[:200]:
        print("    {}  {}".format(mtime(p), p))
        if p.lower().endswith((".so", ".dll", ".dylib")):
            lead("binaries", "native library in data directory: {}".format(p))
    if not hits:
        print("    None.")
    return hits


# --------------------------------------------------------------------- [6] logs
PATTERNS = [
    ("prefixed service name (CVE-2026-129243)", re.compile(r"service=[A-Za-z0-9_.\-]+/(?:WFS|WMS|WCS|WPS|WMTS|CSW)\b|service\s*=\s*\"[^\"]+/(?:WFS|WMS|WCS|WPS)\"", re.I)),
    ("stored query create/drop", re.compile(r"request=(?:CreateStoredQuery|DropStoredQuery)|<(?:\w+:)?(?:CreateStoredQuery|DropStoredQuery)\b", re.I)),
    ("GetFeatureById with XInclude/entity/file (CVE-2026-120705)", re.compile(r"GetFeatureById.*(?:xi:include|XInclude|<!ENTITY|<!DOCTYPE|file:/|xmlns:xi)|(?:xi:include|<!ENTITY).*GetFeatureById", re.I)),
    ("overlong stored query id / path disclosure (CVE-2026-129244)", re.compile(r"File name too long|filename.*too long|StoredQuery.*(?:FileSystemException|InvalidPathException)", re.I)),
    ("REST security/resource access", re.compile(r"\"(?:GET|POST|PUT|DELETE) [^\"]*/rest/(?:security|resource)\b", re.I)),
    ("security file names in requests", re.compile(r"users\.xml|security/config\.xml|masterpw", re.I)),
]


def scan_log(path, days):
    if not recent(path, days):
        return []
    opener = gzip.open if path.endswith(".gz") else open
    hits = []
    try:
        with opener(path, "rt", encoding="utf-8", errors="replace") as fh:
            for i, line in enumerate(fh, 1):
                dec = unquote_plus(line) if "%" in line or "+" in line else line
                for label, rx in PATTERNS:
                    if rx.search(dec):
                        hits.append((label, path, i, line.strip()[:300]))
                        break
    except OSError as e:
        print("    cannot read {}: {}".format(path, e))
    return hits


def check_logs(dd, extra, days):
    print("\n[6] Log leads (last {} days of files)".format(days))
    logs = glob.glob(os.path.join(dd, "logs", "geoserver*.log*"))
    for x in extra:
        logs += glob.glob(x)
    if not logs:
        print("    No logs found. Pass --access-log for your Tomcat/Jetty/nginx/IIS logs.")
        return []
    allhits = []
    for p in sorted(set(logs)):
        h = scan_log(p, days)
        print("    {} : {} hit(s)".format(p, len(h)))
        allhits += h
    summary = {}
    for label, *_ in allhits:
        summary[label] = summary.get(label, 0) + 1
    for label, n in summary.items():
        lead("logs", "{}: {} line(s)".format(label, n))
    for label, p, i, line in allhits[:40]:
        print("      [{}] {}:{}  {}".format(label, os.path.basename(p), i, line))
    if len(allhits) > 40:
        print("      ... {} more (see JSON)".format(len(allhits) - 40))
    return [{"type": l, "file": p, "line": i, "text": t} for l, p, i, t in allhits]


def main():
    ap = argparse.ArgumentParser(description="Read-only GeoServer Nov 2026 host self-check")
    ap.add_argument("--data-dir", required=True, help="GeoServer data directory (GEOSERVER_DATA_DIR)")
    ap.add_argument("--webapp", help="GeoServer web application folder (contains WEB-INF)")
    ap.add_argument("--access-log", action="append", default=[], help="extra access log path or glob (repeatable)")
    ap.add_argument("--days", type=int, default=90)
    ap.add_argument("--json")
    a = ap.parse_args()
    if not os.path.isdir(a.data_dir):
        ap.error("data directory not found: " + a.data_dir)

    print("Topology Defense | GeoServer Nov 2026 host self-check | {} UTC".format(
        datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")))
    print("Data dir: {}   Lookback: {} days".format(a.data_dir, a.days))
    print("-" * 78)
    report = {
        "version": check_version(a.webapp),
        "rememberme": check_rememberme(a.data_dir),
        "stored_queries": check_stored_queries(a.data_dir, a.days),
        "jdbc_services": check_jdbc(a.data_dir),
        "recent_binaries": check_binaries(a.data_dir, a.days),
        "log_hits": check_logs(a.data_dir, a.access_log, a.days),
        "leads": LEADS,
    }
    print("-" * 78)
    print("RESULT: version verdict {} | {} lead(s)".format(report["version"]["verdict"], len(LEADS)))
    if a.json:
        with open(a.json, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        print("JSON written to {}".format(a.json))
    sys.exit(1 if report["version"]["verdict"] == "VULNERABLE" else 0)


if __name__ == "__main__":
    main()
