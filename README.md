# Security Decision Science

Built and maintained by Laura Voicu ([LinkedIn](https://www.linkedin.com/in/voiculaura/) · [ORCID](https://orcid.org/0009-0008-4623-2532)).
Free notebooks for Monte Carlo, Bayesian updates, Survival Analysis, Causal inference, Game Theory — turning security data into **decisions**.

[![Docs](https://github.com/security-decision-science/security-decision-science/actions/workflows/book.yml/badge.svg)](https://github.com/security-decision-science/security-decision-science/actions/workflows/book.yml)
[![PyPI](https://img.shields.io/pypi/v/decision-security?label=decision-security&include_prereleases)](https://pypi.org/project/decision-security/)
[![Link Check](https://github.com/security-decision-science/security-decision-science/actions/workflows/links.yml/badge.svg)](https://github.com/security-decision-science/security-decision-science/actions/workflows/links.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Linkedin Badge](https://img.shields.io/badge/-LinkedIn-blue?style=flat-square&logo=Linkedin&logoColor=white&link=https://www.linkedin.com/in/voiculaura/)](https://www.linkedin.com/in/voiculaura/)

**Live docs:** https://security-decision-science.github.io/security-decision-science/

---

## What this is

A practical curriculum for **decision science in security** — 21 interactive notebooks across 4 parts:

| Part | Notebooks | Focus                                                                                                                                |
|------|-----------|--------------------------------------------------------------------------------------------------------------------------------------|
| **Part 0 — Prerequisites** | 8 | Stats, distributions, Monte Carlo, decision theory, behavior, optimization, survival analysis, causal reasoning                      |
| **Part 1 — Decision Frameworks** | 4 | Calculations vs decisions, Bayesian thinking, value of information, McNamara Fallacy                                                 |
| **Part 2 — Behavioral Traps** | 4 | Confirmation bias, normalization of deviance, framing effects, advocacy vs inquiry                                                   |
| **Part 3 — Causal & Strategic Reasoning** | 5 | Control effectiveness measurement, attacker-defender game theory, supply chain risk, overdispersion on real data, backlog triage by hazard |

Everything is free: **notebooks and a set of open tools**.

---

## Quick links

- **Hub:** https://apropos-security.com
- **Docs (this site):** https://security-decision-science.github.io/security-decision-science/
- **Tools:** https://github.com/security-decision-science/security-decision-labs
- **Library (pip):** https://github.com/security-decision-science/decision-security · PyPI → https://pypi.org/project/decision-security/
- **Related:** [Agent-based FAIR-CAM simulation](https://github.com/security-decision-science/security-decision-labs/blob/main/tools/control-systems-agent-based-model/) ([paper](https://arxiv.org/abs/2605.26597))
- **Blog (Medium):** https://medium.com/apropos-security
- **Author:** [Laura Voicu](https://www.linkedin.com/in/voiculaura/)

---

## Use the library (pip)

```bash
pip install decision-security
```

```python
from decision_security.synth import sample
x = sample("poisson", 10, lam=1.2)
print(x)
```

---

## Run the notebooks locally

Python 3.9+.

```bash
git clone https://github.com/security-decision-science/security-decision-science.git
cd security-decision-science
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
jupyter lab notebooks/
```

---

## Build the docs locally

```bash
python -m venv .book && source .book/bin/activate
pip install -U pip
pip install -r requirements-docs.txt
jupyter-book build docs
open docs/_build/html/index.html
```

---

## Repo layout

```
notebooks/
  part0/          8 prerequisite notebooks
  part1/          4 decision framework notebooks
  part2/          4 behavioral trap notebooks
  part3/          5 causal & strategic notebooks
  part3/data/     Part 3 data, downloaded on first run (sources and licences in its README)
docs/
  _config.yml     Jupyter Book configuration
  _toc.yml        Table of contents (points to notebooks/)
  index.md        Landing page
  _static/        Logo, OG card
.github/workflows/
  book.yml        Builds & deploys Jupyter Book to GitHub Pages
  ci.yml          pre-commit checks
  links.yml       Link check (lychee)
  codeql.yml, sast.yml, scorecard.yml   CodeQL, Semgrep, OpenSSF Scorecard
requirements.txt        Packages to run the notebooks
requirements-docs.txt   Packages to build the docs (same versions as book.yml)
```

---

## Contributing & issues

- Ideas, fixes, and typos: open an **Issue** or PR.
- For sensitive topics (no data, please), contact via **LinkedIn**.

---

## License

Code and text: MIT ([LICENSE](LICENSE)). No third-party data is committed; Part 3 downloads its public data on first run, under the source licences listed in [its README](notebooks/part3/data/README.md).

---
