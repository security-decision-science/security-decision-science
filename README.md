# Security Decision Science

_Free notebooks & a playground app for Monte Carlo, Bayesian updates, Survival Analysis, Causal basics — turning security data into **decisions**._

[![Docs](https://github.com/security-decision-science/security-decision-science/actions/workflows/book.yml/badge.svg)](https://github.com/security-decision-science/security-decision-science/actions/workflows/book.yml)
[![PyPI](https://img.shields.io/pypi/v/decision-security?label=decision-security&include_prereleases)](https://pypi.org/project/decision-security/)
[![Link Check](https://github.com/security-decision-science/security-decision-science/actions/workflows/links.yml/badge.svg)](https://github.com/security-decision-science/security-decision-science/actions/workflows/links.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Linkedin Badge](https://img.shields.io/badge/-LinkedIn-blue?style=flat-square&logo=Linkedin&logoColor=white&link=https://www.linkedin.com/in/voiculaura/)](https://www.linkedin.com/in/voiculaura/)

**Live docs:** https://security-decision-science.github.io/security-decision-science/

---

## What this is

A practical path for **decision science in security**:

- **Monte Carlo risk bands** (heavy tails, Poisson/lognormal)  
- **Bayesian triage & calibration** (priors → likelihoods → decisions)  
- **Survival / time-to-event** (KM/Weibull; time-to-exploit/patch)  
- **Causal basics** (DAG intuition, confounding, quick checks)

Everything is free: **articles, notebooks, and a small playground app** powered by the companion library.

---

## Quick links

- **Docs (this site):** https://security-decision-science.github.io/security-decision-science/  
- **Playground app:** https://github.com/security-decision-science/security-decision-labs  
- **Library (pip):** https://github.com/security-decision-science/decision-security · PyPI → https://pypi.org/project/decision-security/  
- **Blog (Medium):** https://medium.com/apropos-security  
- **Contact:** LinkedIn (preferred)

---

## Part 1 — Foundations

These set up metrics & scaffolding reused in later modules.

1. **Research mindset for security decisions**  
   Decision statements, payoff/uncertainty, hypotheses/priors, assumptions log.
2. **From concepts to metrics**  
   Binary/count/rate/**time-to-event**, heavy tails, guardrails, sampling windows.
3. **Experiment designs you can actually run**  
   A/B, switchback, staggered; threats to validity; minimal “ship/no-ship” rule.

_Read them in the left sidebar, or start at the [landing page](https://security-decision-science.github.io/security-decision-science/)._

> Next: **Part 2** (Monte Carlo risk bands) → **Part 3** (Bayesian triage) → **Part 4** (Survival).

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

## Run the docs locally

```bash
# in this repo
python -m venv .book && source .book/bin/activate
python -m pip install -U pip jupyter-book
jupyter-book build docs
open docs/_build/html/index.html
```

Execution is off initially (`execute_notebooks: "off"` in `_config.yml`). Turn it on later when examples are stable.

---

## Repo layout

```
docs/
  _config.yml
  _toc.yml
  index.md
  part1-01-research-mindset.md
  part1-02-operationalization-metrics.md
  part1-03-experimental-design-basics.md
.github/workflows/book.yml   # builds & deploys Jupyter Book to GitHub Pages
```

---

## Contributing & issues

- Ideas, fixes, and typos: open an **Issue** or PR.  
- For sensitive topics (no data, please), contact via **LinkedIn**.

---

