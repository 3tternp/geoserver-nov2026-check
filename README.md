# 🛡️ geoserver-nov2026-check

![Python](https://img.shields.io/badge/python-3.6%2B-3776AB?logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-lightgrey)
![Mode](https://img.shields.io/badge/mode-read--only-success)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)
![Status](https://img.shields.io/badge/exploited-in%20the%20wild-critical)

🔍 Read-only self-detection scripts for the GeoServer flaws disclosed in November 2026. Two of them are exploited in the wild and can be chained into unauthenticated remote code execution:

| 🆔 CVE | 🐞 Issue | 📊 CVSS | 🚦 Status |
|---|---|---|---|
| CVE-2026-120705 | WFS `GetFeatureById` XML injection: file read and SSRF | 8.6 | 🔴 **Exploited** |
| CVE-2026-129243 | Service security bypass via prefixed service name (`x/WFS`) | 8.8 | 🔴 **Exploited** |
| CVE-2026-129244 | Overlong stored query id reveals data directory path | 6.9 | 🟠 Chain step |
| CVE-2026-129245 | Default "remember me" key allows admin session forgery | 9.2 | 🟠 Chain step |
| CVE-2026-120704 | JDBC security service loads attacker library (SQLite) | 7.2 | 🟠 Chain step |
| CVE-2026-129242 | Deserialization in JDBC user and role services | 8.6 | 🟠 Chain step |


> [!NOTE]
> ✅ The scripts send no exploit payloads and change nothing. They confirm the version and exposure, and they look for traces the flaws leave. A lead is not proof of compromise.

## 📦 Contents

| 📄 File | 🖥️ Runs on | 🎯 Purpose |
|---|---|---|
| `geoserver_nov2026_remote_check.py` | 🌐 Any host that can reach GeoServer | Version check, anonymous WFS exposure, list of stored queries |
| `geoserver_nov2026_host_check.py` | 🗄️ The GeoServer server (Linux or Windows) | Version from jar files, signing key, stored queries, JDBC services, uploaded files, log leads |

## 🩹 Fixed releases

| 🏷️ Line | ❌ Affected | ✅ Fixed |
|---|---|---|
| GeoServer 3.0.x | 3.0.0 to 3.0.1 | **3.0.2** |
| GeoServer 2.28.x | 2.28.0 to 2.28.5 | **2.28.6** |
| GeoServer 2.27.x and older | 2.27.6 and earlier | **2.27.7** ⚠️ (unsupported line; move to 2.28.6 or 3.0.2) |
| GeoTools gt-metadata | 35.0 to 35.1, 34.0 to 34.5, 33.6 and earlier | 35.2, 34.6, 33.7 |

## 🌐 1. Remote check

🐍 This needs Python 3.6 or later and uses only the standard library.

```bash
python3 geoserver_nov2026_remote_check.py https://maps.example.gov.np/geoserver
python3 geoserver_nov2026_remote_check.py -f geoservers.txt --json report.json
python3 geoserver_nov2026_remote_check.py https://gis.local/geoserver --user admin --password '<pw>'
```

| ⚙️ Option | 💬 Meaning |
|---|---|
| `targets` | GeoServer base URLs (if no path is given, `/geoserver` is added) |
| `-f FILE` | File with one URL per line |
| `--user / --password` | Optional admin credentials, used to read the version from the REST API |
| `--verify-tls` | Verify TLS certificates (off by default) |
| `--timeout SEC` | Per-request timeout (default 10) |
| `--json FILE` | Write results as JSON |

📡 The script sends three kinds of request, all read-only:

1. `GET /rest/about/version.json`, falling back to the public **About GeoServer** page
2. `GET /ows?service=WFS&version=2.0.0&request=GetCapabilities`
3. `GET /ows?service=WFS&version=2.0.0&request=ListStoredQueries`

## 🗄️ 2. Host check

🔑 Run it as a user that can read the GeoServer data directory.

```bash
# 🐧 Linux
python3 geoserver_nov2026_host_check.py \
    --data-dir /opt/geoserver/data_dir \
    --webapp /opt/tomcat/webapps/geoserver \
    --access-log "/var/log/nginx/access.log*" \
    --days 90 --json report.json
```

```powershell
# 🪟 Windows
python geoserver_nov2026_host_check.py --data-dir "C:\GeoServer\data_dir" --webapp "C:\GeoServer\webapps\geoserver" --access-log "C:\inetpub\logs\LogFiles\W3SVC1\*.log"
```

| ⚙️ Option | 💬 Meaning |
|---|---|
| `--data-dir` | GeoServer data directory (`GEOSERVER_DATA_DIR`). Required. |
| `--webapp` | GeoServer web application folder (the one that contains `WEB-INF`) |
| `--access-log` | Extra access log path or glob from Tomcat, Jetty, nginx, Apache or IIS. Repeatable; `.gz` files are supported. |
| `--days N` | Lookback period for file changes and logs (default 90) |
| `--json FILE` | Write the full report, including every log hit, as JSON |

| 🔎 Section | 👀 What it checks | 🆔 Related CVE |
|---|---|---|
| 🏷️ [1] Version | `gs-main`, `gs-wfs-core`, `gs-ows`, `gt-metadata` jars in `WEB-INF/lib` | All |
| 🔑 [2] Remember-me key | Default key `geoserver` in `security/config.xml`; `rememberme` in filter chains | CVE-2026-129245 |
| 📝 [3] Stored queries | `wfs/query` and `workspaces/*/wfs/query` files and their dates | CVE-2026-129243 |
| 🗃️ [4] JDBC services | JDBC user, group and role services; SQLite, `enable_load_extension`, UNC paths, HSQLDB files | CVE-2026-120704, CVE-2026-129242 |
| 📥 [5] Uploaded files | `.so`, `.dll`, `.dylib` and database files changed in the data directory | CVE-2026-120704 |
| 📜 [6] Logs | Prefixed service names, `CreateStoredQuery`/`DropStoredQuery`, `GetFeatureById` with XInclude or entities, "File name too long", REST security/resource calls | All |

💡 Before matching, the script URL-decodes log lines, so patterns such as `x%2FWFS` and `%3Cxi%3Ainclude` are also found.

## 🚦 Verdicts

| Verdict | 💬 Meaning |
|---|---|
| 🔴 `VULNERABLE` | The version is in an affected range. Upgrade it. |
| 🟢 `PATCHED` | The version is 3.0.2, 2.28.6, 2.27.7 or later. |
| 🟡 `REVIEW` | The version could not be read, or it is a development (SNAPSHOT) build. Check **About GeoServer > Build Information**. |
| ⚫ `ERROR` | No answer, or the URL is not GeoServer (remote check only). |
| 🔎 `LEAD: ...` | Something to investigate, such as an unknown stored query, a default key, a SQLite JDBC service or a suspicious log line. |

🔢 Both scripts exit with code `1` if the result is VULNERABLE and `0` otherwise.

## 🚨 If you find leads

- ⬆️ Upgrade to 3.0.2 or 2.28.6. After the upgrade the remember-me key is random and existing cookies stop working. In a cluster, set `GEOSERVER_REMEMBERME_KEY`.
- 🔐 Change the passwords of all GeoServer administrators and users, because `users.xml` hashes may have been read.
- 🧹 Remove stored queries, JDBC services and admin accounts that your team did not create.
- 💀 If you find unexpected native libraries, treat the server as compromised and rebuild it.

⏳ Until you can upgrade:

- 🚫 Block `service` values that contain `/` at the proxy, in both the query string and the XML `service` attribute.
- 🔒 Restrict anonymous WFS.
- ✂️ Remove `rememberme` from the `web` filter chain.
- 🧱 Restrict the admin console and `/rest/security` and `/rest/resource` to trusted networks.

## ⚠️ Limitations

- 🧪 The scripts were tested against simulated GeoServer responses and a sample data directory, not a live server. Test them on a non-production server first.
- 📄 The layout of the About page differs between releases. If the remote check returns REVIEW, read the version manually or rerun with admin credentials.
- 🕵️ No indicators of compromise were published for these flaws, so the log patterns are based on behaviour.
- 🙅 The remote check does not actively test the `x/WFS` bypass or the XML injection.

## 📚 References

- 📰 The Hacker News: https://thehackernews.com/2026/11/hackers-exploit-two-geoserver-flaws-as.html
- 🔬 Eye Security: https://labs.eye.security/unauthenticated-remote-code-execution-vulnerability-in-geoserver/
- 📋 GHSA-39mw-5chv-jh47 (CVE-2026-120705): https://github.com/geoserver/geoserver/security/advisories/GHSA-39mw-5chv-jh47
- 📋 GHSA-rv5g-g2r9-58rj (CVE-2026-129243): https://github.com/geoserver/geoserver/security/advisories/GHSA-rv5g-g2r9-58rj
- 📋 GHSA-hgm3-wq4h-8vvq (CVE-2026-129245): https://github.com/geoserver/geoserver/security/advisories/GHSA-hgm3-wq4h-8vvq
- 🗂️ All GeoServer advisories: https://github.com/geoserver/geoserver/security/advisories

## ⚖️ Disclaimer

The scripts are provided as-is for defensive use on systems you own or are authorised to assess.
