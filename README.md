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

A practical curriculum for **decision science in security** — 19 interactive notebooks across 4 parts:

| Part | Notebooks | Focus |
|------|-----------|-------|
| **Part 0 — Prerequisites** | 8 | Stats, distributions, Monte Carlo, decision theory, behavior, optimization, survival analysis, causal reasoning |
| **Part 1 — Decision Frameworks** | 4 | Calculations vs decisions, Bayesian threat intel, value of information, McNamara Fallacy |
| **Part 2 — Behavioral Traps** | 4 | Confirmation bias in IR, normalization of deviance, framing effects, advocacy vs inquiry |
| **Part 3 — Causal & Strategic** | 3 | Control effectiveness measurement, attacker-defender game theory, supply chain risk |

Everything is free: **notebooks and a small playground app** powered by the companion library.

---

## Quick links

- **Hub:** https://apropos-security.com
- **Docs (this site):** https://security-decision-science.github.io/security-decision-science/
- **Playground app:** https://github.com/security-decision-science/security-decision-labs
- **Library (pip):** https://github.com/security-decision-science/decision-security · PyPI → https://pypi.org/project/decision-security/
- **Related:** [control-systems-agent-based-model]([https://github.com/security-decision-science/control-systems-agent-based-model](https://github.com/security-decision-science/security-decision-labs/blob/main/tools/control-systems-agent-based-model/) — agent-based FAIR-CAM simulation ([paper](https://arxiv.org/abs/2605.26597))
- **Blog (Medium):** https://medium.com/apropos-security
- **Author:** [Laura Voicu](https://www.linkedin.com/in/voiculaura/)

---

## Use the library (pip)

```bash
pip install --pre decision-security
```

```python
from decision_security.synth import sample
x = sample("poisson", 10, lam=1.2)
print(x)
```

The playground app (`security-decision-labs`) imports the same library so notebooks ↔ app stay consistent.

---

## Run the notebooks locally

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
pip install -U pip jupyter-book
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
  part3/          3 causal & strategic notebooks
docs/
  _config.yml     Jupyter Book configuration
  _toc.yml        Table of contents (points to notebooks/)
  index.md        Landing page
  _static/        Logo, OG card
.github/workflows/
  book.yml        Builds & deploys Jupyter Book to GitHub Pages
```

---

## Contributing & issues

- Ideas, fixes, and typos: open an **Issue** or PR.
- For sensitive topics (no data, please), contact via **LinkedIn**.

---
