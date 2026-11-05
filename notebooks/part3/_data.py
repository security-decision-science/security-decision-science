"""Public data loaders for the Part 3 notebooks.

KEV (CISA, public domain), VCDB (CC BY-SA 4.0) and a deps.dev dependency
graph (CC BY 4.0) ship as committed snapshots in data/ (see data/README.md);
pass refresh=True to download the current data instead.

The EPSS/CVSS/KEV join used by 3.5 is *not* committed: it is rebuilt on
demand from public sources by load_epss()/save_epss_snapshot().

Ransomware.live is always downloaded live and never committed: its terms
(https://www.ransomware.live/t&c) forbid republishing the raw data; the data
is free for non-commercial use (personal research, academic, open source), and
the anonymous API is rate limited to 1 request per minute. Responses
are cached in .cache/ (gitignored) so reruns don't hit the API again.
"""
import gzip
import io
import json
import subprocess
import time
import zipfile
from pathlib import Path
from urllib.parse import quote

import pandas as pd
import requests

HERE = Path(__file__).parent
KEV_SNAPSHOT = HERE / "data" / "kev_snapshot.csv"
CACHE = HERE / ".cache"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_COLUMNS = ["cveID", "vendorProject", "product", "dateAdded", "knownRansomwareCampaignUse"]
VCDB_SNAPSHOT = HERE / "data" / "vcdb_snapshot.csv"
VCDB_URL = "https://github.com/vz-risk/VCDB/raw/master/data/joined/vcdb.json.zip"
EPSS_SNAPSHOT = HERE / "data" / "cve_epss_snapshot.csv.gz"
EPSS_META = HERE / "data" / "cve_epss_snapshot.meta.json"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
CVELIST_URL = "https://github.com/CVEProject/cvelistV5.git"
USER_AGENT = "security-decision-science-notebooks"


def _get(url):
    for attempt in range(4):
        r = requests.get(url, timeout=120, headers={"User-Agent": USER_AGENT})
        if r.status_code != 429:
            break
        time.sleep(int(r.headers.get("Retry-After", 60)))  # rate limited: wait, then retry
    r.raise_for_status()
    return r


def load_kev(refresh=False):
    """CISA KEV catalog as a DataFrame (snapshot unless refresh=True)."""
    if not refresh:
        return pd.read_csv(KEV_SNAPSHOT, parse_dates=["dateAdded"])
    kev = pd.DataFrame(_get(KEV_URL).json()["vulnerabilities"])[KEV_COLUMNS]
    kev["dateAdded"] = pd.to_datetime(kev["dateAdded"])
    return kev


def save_kev_snapshot():
    """Overwrite the committed KEV snapshot with the current catalog."""
    KEV_SNAPSHOT.parent.mkdir(exist_ok=True)
    load_kev(refresh=True).to_csv(KEV_SNAPSHOT, index=False, date_format="%Y-%m-%d")


def _vcdb_row(inc):
    conf = inc.get("attribute", {}).get("confidentiality", {})
    state = set(conf.get("state", []))
    return {
        "incident_id": inc["incident_id"],
        "year": inc.get("timeline", {}).get("incident", {}).get("year"),
        "industry": str(inc.get("victim", {}).get("industry", ""))[:2],
        "actions": ";".join(sorted(inc.get("action", {}))),
        "data_disclosure": conf.get("data_disclosure"),
        "stored_encrypted": "Stored encrypted" in state,
        "stored_unencrypted": "Stored unencrypted" in state,
    }


def load_vcdb(refresh=False):
    """VERIS Community Database, one row per VCDB record (snapshot unless refresh=True)."""
    if not refresh:
        return pd.read_csv(VCDB_SNAPSHOT)
    with zipfile.ZipFile(io.BytesIO(_get(VCDB_URL).content)) as z:
        incidents = json.loads(z.read(z.namelist()[0]))
    return pd.DataFrame([_vcdb_row(inc) for inc in incidents])


def save_vcdb_snapshot():
    """Overwrite the committed VCDB snapshot with the current database."""
    load_vcdb(refresh=True).to_csv(VCDB_SNAPSHOT, index=False)


def load_epss():
    """EPSS + CVSS + KEV join, one row per CVE.

    Columns: cve, year, epss, cvss_base, is_kev. The snapshot is not
    committed; if it is absent it is rebuilt from public sources first
    (see save_epss_snapshot).
    """
    if not EPSS_SNAPSHOT.exists():
        save_epss_snapshot()
    return pd.read_csv(EPSS_SNAPSHOT)


def load_epss_meta():
    """EPSS model_version and score_date of the local snapshot ({} if unknown)."""
    if not EPSS_META.exists():
        return {}
    return json.loads(EPSS_META.read_text())


def _epss_header(line):
    """'#model_version:v...,score_date:...' -> {'model_version': ..., 'score_date': ...}."""
    if not line.startswith("#"):
        return {}
    return dict(kv.split(":", 1) for kv in line[1:].strip().split(",") if ":" in kv)


def save_epss_snapshot():
    """Rebuild cve_epss_snapshot.csv.gz from public sources.

    Columns: cve, year, epss, cvss_base, is_kev. The EPSS file's header
    (model_version, score_date) is saved next to it (see load_epss_meta).

    - epss: FIRST EPSS current scores (public CSV, no auth).
    - year: parsed from the CVE id (CVE-YYYY-NNNN), i.e. the ID's assignment
      year, not the publication date.
    - cvss_base: CVSS base score from the CVE List (cvelistV5).
    - is_kev: membership in the committed KEV snapshot (data/kev_snapshot.csv),
      so 3.2, 3.4 and 3.5 use the same KEV version.

    The EPSS score changes daily, so a rebuild differs slightly from any
    previously saved snapshot; the relative shares are stable.
    """
    raw = _get(EPSS_URL).content
    if raw[:2] == b"\x1f\x8b":  # gzip magic; skip if already decoded in transit
        raw = gzip.decompress(raw)
    text = raw.decode()
    meta = _epss_header(text.split("\n", 1)[0])
    epss = pd.read_csv(io.StringIO(text), comment="#")
    epss = epss[["cve", "epss"]].copy()
    epss["year"] = epss["cve"].str.extract(r"^CVE-(\d{4})-")[0].astype(int)
    kev = set(load_kev()["cveID"])
    epss["is_kev"] = epss["cve"].isin(kev)
    cvss = _cvss_base_scores()
    epss["cvss_base"] = epss["cve"].map(cvss)
    epss.to_csv(EPSS_SNAPSHOT, index=False, compression="gzip")
    EPSS_META.write_text(json.dumps(meta, indent=1) + "\n")


def _cvss_base_scores():
    """{cve: CVSS base score} from the CVE List (cvelistV5).

    Clones cvelistV5 shallowly into .cache/ (gitignored) on first use, then
    prefers the CVSS v3.1 base score, falling back to v3.0 and v2.0 (v4.0 is
    not used). Reads
    the CNA container only (ADP scores, e.g. CISA Vulnrichment, are not used).
    """
    repo = CACHE / "cvelistV5"
    if not repo.exists():
        subprocess.run(
            ["git", "clone", "--depth", "1", "--filter=blob:none", "--sparse",
             CVELIST_URL, str(repo)],
            check=True,
        )
        subprocess.run(["git", "-C", str(repo), "sparse-checkout", "set", "cves"], check=True)
    scores = {}
    for path in repo.glob("cves/**/*.json"):
        try:
            data = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            continue
        cve = (data.get("cveMetadata") or {}).get("cveId")
        if not cve:
            continue
        metrics = (data.get("containers", {}).get("cna", {}) or {}).get("metrics", [])
        for key in ("cvssV3_1", "cvssV3_0", "cvssV2_0"):
            score = next((m[key]["baseScore"] for m in metrics
                          if "baseScore" in m.get(key, {})), None)
            if score is not None:
                scores[cve] = score
                break
    return scores


def _graph_paths(system, name, version):
    stem = f"deps_{system}_{name.replace('/', '_').replace('@', '')}_{version}"
    return HERE / "data" / f"{stem}_nodes.csv", HERE / "data" / f"{stem}_edges.csv"


def load_dependency_graph(system, name, version, refresh=False):
    """Resolved dependency graph of one package version from deps.dev.

    Returns (nodes, edges). nodes: index = node id, columns name, version,
    relation (SELF / DIRECT / INDIRECT). edges: from_node depends on to_node.
    """
    nodes_path, edges_path = _graph_paths(system, name, version)
    if not refresh:
        return pd.read_csv(nodes_path, index_col="node"), pd.read_csv(edges_path)
    url = (f"https://api.deps.dev/v3/systems/{system}/packages/{quote(name, safe='')}"
           f"/versions/{quote(version, safe='')}:dependencies")
    graph = _get(url).json()
    nodes = pd.DataFrame([{"node": i, "name": n["versionKey"]["name"],
                           "version": n["versionKey"]["version"], "relation": n["relation"]}
                          for i, n in enumerate(graph["nodes"])]).set_index("node")
    edges = pd.DataFrame([{"from_node": e["fromNode"], "to_node": e["toNode"]}
                          for e in graph["edges"]])
    return nodes, edges


def save_dependency_graph_snapshot(system, name, version):
    """Overwrite the committed snapshot of one dependency graph."""
    nodes, edges = load_dependency_graph(system, name, version, refresh=True)
    nodes_path, edges_path = _graph_paths(system, name, version)
    nodes.to_csv(nodes_path)
    edges.to_csv(edges_path, index=False)


def ransomware_monthly_counts(months):
    """Victims posted per month on Ransomware.live (live API, cached locally).

    months: a pandas PeriodIndex with monthly frequency.
    Source: Ransomware.live. Free for non-commercial use (personal research,
    academic, open source); see https://www.ransomware.live/t&c
    """
    CACHE.mkdir(exist_ok=True)
    counts = []
    for m in months:
        path = CACHE / f"ransomware_live_{m}.json"
        if not path.exists():
            r = _get(f"https://api.ransomware.live/v2/victims/{m.year}/{m.month:02d}")
            path.write_text(r.text)
            time.sleep(60)  # the anonymous v2 API allows 1 request per minute per endpoint
        counts.append(len(json.loads(path.read_text())))
    return pd.Series(counts, index=months)
