"""Public data loaders for the Part 3 notebooks.

KEV (CISA, public domain), VCDB (CC BY-SA 4.0) and a deps.dev dependency
graph (CC BY 4.0) ship as committed snapshots in data/ (see data/README.md);
pass refresh=True to download the current data instead.

Ransomware.live is always downloaded live and never committed: its terms
(https://www.ransomware.live/t&c) forbid republishing the raw data, the free
API is for personal, non-commercial use only and is rate limited. Responses
are cached in .cache/ (gitignored) so reruns don't hit the API again.
"""
import io
import json
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
    """VERIS Community Database, one row per incident (snapshot unless refresh=True)."""
    if not refresh:
        return pd.read_csv(VCDB_SNAPSHOT)
    with zipfile.ZipFile(io.BytesIO(_get(VCDB_URL).content)) as z:
        incidents = json.loads(z.read(z.namelist()[0]))
    return pd.DataFrame([_vcdb_row(inc) for inc in incidents])


def save_vcdb_snapshot():
    """Overwrite the committed VCDB snapshot with the current database."""
    load_vcdb(refresh=True).to_csv(VCDB_SNAPSHOT, index=False)


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
    Source: Ransomware.live. Personal, non-commercial use only.
    """
    CACHE.mkdir(exist_ok=True)
    counts = []
    for m in months:
        path = CACHE / f"ransomware_live_{m}.json"
        if not path.exists():
            r = _get(f"https://api.ransomware.live/v2/victims/{m.year}/{m.month:02d}")
            path.write_text(r.text)
            time.sleep(0.5)  # be polite to the free API
        counts.append(len(json.loads(path.read_text())))
    return pd.Series(counts, index=months)
