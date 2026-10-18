# Data snapshots for Part 3

Committed snapshots keep the notebooks reproducible. Each loader in `../_data.py`
takes `refresh=True` to download the current data instead, and has a
`save_..._snapshot()` function to update the file here.

| File | Source | Licence | Used in |
|---|---|---|---|
| `kev_snapshot.csv` | [CISA Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), 5 columns | Public domain (US government work) | 3.2, 3.4 |
| `vcdb_snapshot.csv` | [VERIS Community Database](https://github.com/vz-risk/VCDB), one row per incident, 7 derived columns | [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/); this derived file is shared under the same licence | 3.1 |
| `deps_npm_react-scripts_5.0.1_*.csv` | [deps.dev](https://deps.dev) resolved dependency graph of npm `react-scripts` 5.0.1 | [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) (deps.dev generated data) | 3.3 |

Snapshots taken 18 October 2026.

**Not stored here:** Ransomware.live data (used in 3.4). Its
[terms](https://www.ransomware.live/t&c) forbid republishing the raw data; the
data is free for non-commercial use (personal research, academic, open source). The notebook downloads it
live and caches it in `../.cache/` (gitignored). Source: Ransomware.live.
