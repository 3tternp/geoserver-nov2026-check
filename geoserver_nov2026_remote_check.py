#!/usr/bin/env python3
"""
geoserver_nov2026_remote_check.py
Topology Defense - read-only remote exposure check for the November 2026
GeoServer flaws (CVE-2026-120705, CVE-2026-129243, CVE-2026-129244,
CVE-2026-129245, CVE-2026-120704, CVE-2026-129242).

What it does (read-only, no exploit payloads):
  1. Reads the GeoServer version from the REST "about" endpoint (with
     optional credentials) or, if that is refused, from the public
     "About GeoServer" web page.
  2. Compares it with the fixed releases 2.27.7, 2.28.6 and 3.0.2.
  3. Checks whether WFS answers anonymous GetCapabilities and whether the
     built-in GetFeatureById stored query is listed (ListStoredQueries).
     Anonymous WFS is the precondition for CVE-2026-120705.

It does NOT send XML injection, XInclude, prefixed service names
(x/WFS) or stored-query create/drop requests.

Verdicts:
  VULNERABLE  version is in an affected range
  PATCHED     version is 2.27.7+, 2.28.6+ or 3.0.2+
  REVIEW      version could not be read; check "About GeoServer" manually
  ERROR       no answer / not GeoServer

Usage:
  python3 geoserver_nov2026_remote_check.py https://maps.example.com/geoserver
  python3 geoserver_nov2026_remote_check.py -f targets.txt --json report.json
  python3 geoserver_nov2026_remote_check.py https://gs.local/geoserver --user admin --password '***'

Python 3.6+, standard library only.
"""

import argparse
import base64
import json
import re
import ssl
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone

FIXED = {(2, 27): 7, (2, 28): 6, (3, 0): 2}
UA = "TD-GeoServer-Nov2026-check/1.0"


def fetch(url, timeout, auth=None, insecure=True):
    headers = {"User-Agent": UA}
    if auth:
        headers["Authorization"] = "Basic " + base64.b64encode(auth.encode()).decode()
    req = urllib.request.Request(url, headers=headers)
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, r.read(400000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(20000).decode("utf-8", "replace")


def get_version(base, timeout, auth, insecure):
    # 1) REST about/version (usually needs admin; works anonymously on some setups)
    st, body = fetch(base + "/rest/about/version.json", timeout, auth, insecure)
    if st == 200:
        try:
            for res in json.loads(body)["about"]["resource"]:
                if str(res.get("@name", "")).lower() == "geoserver":
                    return str(res.get("Version", "")), "REST /rest/about/version.json"
        except (ValueError, KeyError, TypeError):
            pass
    # 2) Public About page
    st, body = fetch(base + "/web/wicket/bookmarkable/org.geoserver.web.AboutGeoServerPage",
                     timeout, None, insecure)
    if st == 200:
        m = re.search(r'id="version"[^>]*>\s*([0-9][0-9A-Za-z.\-]*)', body) or \
            re.search(r'GeoServer\s+(?:Version\s*)?</?[^>]*>?\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?(?:-[A-Za-z0-9]+)?)', body) or \
            re.search(r'\b(3\.0(?:\.[0-9]+)?(?:-SNAPSHOT|-M[0-9]+|-RC[0-9]*)?|2\.[0-9]{2}(?:\.[0-9]+)?(?:-SNAPSHOT|-M[0-9]+|-RC[0-9]*)?)\b', body)
        if m:
            return m.group(1), "About GeoServer page"
    return None, None


def classify(version):
    if not version:
        return "REVIEW", "version not readable remotely; open About GeoServer > Build Information"
    m = re.match(r"(\d+)\.(\d+)(?:\.(\d+))?(.*)", version)
    if not m:
        return "REVIEW", "unrecognised version string '{}'".format(version)
    maj, minr = int(m.group(1)), int(m.group(2))
    patch = int(m.group(3)) if m.group(3) else 0
    suffix = m.group(4) or ""
    if "SNAPSHOT" in suffix.upper():
        return "REVIEW", "development build {}; confirm the commit includes the fixes".format(version)
    key = (maj, minr)
    if key in FIXED:
        need = FIXED[key]
        if patch >= need:
            return "PATCHED", "{} >= {}.{}.{}".format(version, maj, minr, need)
        return "VULNERABLE", "{} is below the fixed release {}.{}.{}".format(version, maj, minr, need)
    if (maj, minr) < (2, 27):
        return "VULNERABLE", "{} is an old, unsupported line; upgrade to 2.28.6 or 3.0.2".format(version)
    if (maj, minr) > (3, 0):
        return "PATCHED", "{} is newer than the affected lines".format(version)
    return "REVIEW", "line {}.{} not in reference table".format(maj, minr)


def wfs_exposure(base, timeout, insecure):
    out = {}
    st, body = fetch(base + "/ows?service=WFS&version=2.0.0&request=GetCapabilities", timeout, None, insecure)
    out["anonymous_wfs"] = bool(st == 200 and "WFS_Capabilities" in body)
    st, body = fetch(base + "/ows?service=WFS&version=2.0.0&request=ListStoredQueries", timeout, None, insecure)
    ok = st == 200 and "ListStoredQueriesResponse" in body
    out["getfeaturebyid_listed"] = bool(ok and "GetFeatureById" in body)
    ids = re.findall(r'<(?:wfs:)?StoredQuery[^>]*\bid="([^"]+)"', body) if ok else []
    out["stored_queries"] = ids
    out["non_default_stored_queries"] = [i for i in ids if "GetFeatureById" not in i]
    return out


def norm(t):
    t = t.strip().rstrip("/")
    if not re.match(r"^https?://", t):
        t = "https://" + t
    if not re.search(r"/geoserver$", t) and t.count("/") == 2:
        t += "/geoserver"
    return t


def main():
    ap = argparse.ArgumentParser(description="Read-only GeoServer Nov 2026 exposure check")
    ap.add_argument("targets", nargs="*", help="GeoServer base URL, e.g. https://host/geoserver")
    ap.add_argument("-f", "--file", help="file with one URL per line")
    ap.add_argument("--user"); ap.add_argument("--password")
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--verify-tls", action="store_true", help="verify TLS certificates")
    ap.add_argument("--json")
    a = ap.parse_args()

    targets = list(a.targets)
    if a.file:
        with open(a.file, encoding="utf-8") as fh:
            targets += [l.strip() for l in fh if l.strip() and not l.strip().startswith("#")]
    if not targets:
        ap.error("give at least one URL or -f FILE")
    auth = "{}:{}".format(a.user, a.password) if a.user else None

    print("Topology Defense | GeoServer Nov 2026 remote check | {} UTC".format(
        datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")))
    print("-" * 78)
    results = []
    for t in targets:
        base = norm(t)
        r = {"target": base}
        try:
            ver, src = get_version(base, a.timeout, auth, not a.verify_tls)
            r["version"], r["version_source"] = ver, src
            r["verdict"], r["reason"] = classify(ver)
            r.update(wfs_exposure(base, a.timeout, not a.verify_tls))
        except Exception as e:  # noqa: BLE001
            r["verdict"], r["reason"] = "ERROR", "{}: {}".format(type(e).__name__, e)
        results.append(r)
        print("{:<11} {}".format(r["verdict"], base))
        if r.get("version"):
            print("            version {} (from {})".format(r["version"], r["version_source"]))
        print("            {}".format(r["reason"]))
        if "anonymous_wfs" in r:
            print("            anonymous WFS: {}   GetFeatureById listed: {}".format(
                r["anonymous_wfs"], r["getfeaturebyid_listed"]))
            if r["non_default_stored_queries"]:
                print("            LEAD: non-default stored queries: {}".format(
                    ", ".join(r["non_default_stored_queries"][:10])))
    print("-" * 78)
    counts = {}
    for r in results:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    print("Summary: " + ", ".join("{}={}".format(k, v) for k, v in sorted(counts.items())))
    if a.json:
        with open(a.json, "w", encoding="utf-8") as fh:
            json.dump({"check": "GeoServer-Nov-2026", "results": results}, fh, indent=2)
        print("JSON written to {}".format(a.json))
    sys.exit(1 if counts.get("VULNERABLE") else 0)


if __name__ == "__main__":
    main()
