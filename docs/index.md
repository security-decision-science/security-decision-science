# Security Decision Science

By [Laura Voicu](https://www.linkedin.com/in/voiculaura/) — practical notebooks for turning security data into decisions. Each notebook combines explanatory prose with runnable Python code using the companion `decision-security` library.

- **Hub:** [apropos-security.com](https://apropos-security.com)
- **Library (pip):** `decision-security`
- **Playground:** security-decision-labs
- **Blog (Medium):** [Apropos Security](https://medium.com/apropos-security)
- **Related:** [Control Physiology ABM](https://github.com/security-decision-science/control-systems-agent-based-model) (agent-based FAIR-CAM simulation)

## Part 0 — Prerequisites

The statistical and decision-theory building blocks reused throughout the series.

- [0.1: Stats 101](part0/01-stats101.ipynb) — mean vs median, quantiles, rates, confidence intervals, base-rate neglect
- [0.2: Probability distributions](part0/02-distributions.ipynb) — Poisson, lognormal, Pareto, mixtures, expert elicitation
- [0.3: Monte Carlo primer](part0/03-monte-carlo.ipynb) — compound Poisson, risk bands, VaR/ES, sensitivity analysis
- [0.4: Decision theory](part0/04-decision-trees.ipynb) — expected utility, decision trees, EVPI, EVSI, control selection
- [0.5: Behavioral basics](part0/05-behavior.ipynb) — anchoring, overconfidence, calibration, framing, premortems
- [0.6: Optimization & MCDA](part0/06-mcda-lp.ipynb) — weighted scoring, greedy selection, LP, efficient frontier
- [0.7: Survival analysis](part0/07-survival.ipynb) — Kaplan-Meier, Nelson-Aalen, censoring, group comparison
- [0.8: Causal reasoning](part0/08-causal.ipynb) — Simpson's paradox, DAGs, confounders, backdoor criterion

## Part 1 — Decision Frameworks

How security teams make (and fail to make) decisions under uncertainty.

- [1.1: Calculations vs decisions](part1/01-calculations-vs-decisions.ipynb) — the boundary, decision quality vs outcome quality, anxiety reduction
- [1.2: Bayesian threat intelligence](part1/02-bayes-threat-intel.ipynb) — prior elicitation, sequential updating, likelihood ratios, calibration
- [1.3: Value of information](part1/03-value-of-information.ipynb) — EVPI, EVSI, zero-value information, VOI vs test quality
- [1.4: The McNamara Fallacy](part1/04-mcnamara-fallacy.ipynb) — easy vs important metrics, Goodhart's Law, metric quality scorecard

## Part 2 — Behavioral Traps in Security Decisions

Deep dives into specific cognitive traps with realistic security scenarios.

- [2.1: Confirmation bias in IR](part2/01-confirmation-bias-ir.ipynb) — belief perseverance, sunk cost, resulting, analysis of competing hypotheses
- [2.2: Normalization of deviance](part2/02-normalization-of-deviance.ipynb) — policy drift, near misses, threshold erosion, reset cost analysis
- [2.3: Framing effects](part2/03-framing-risk-communication.ipynb) — loss/gain framing, denominator neglect, risk matrix distortion, anchoring
- [2.4: Advocacy vs inquiry](part2/04-advocacy-vs-inquiry.ipynb) — HiPPO effect, hidden profiles, constructive disagreement protocols

## Part 3 — Causal & Strategic Reasoning

Applying causal inference and game theory to security problems.

- [3.1: Measuring control effectiveness](part3/01-measuring-control-effectiveness.ipynb) — selection bias, stratified analysis, difference-in-differences, Bayesian evidence
- [3.2: Attacker-defender game theory](part3/02-attacker-defender-game-theory.ipynb) — Nash equilibria, Colonel Blotto, moving target defense, free-rider problem
- [3.3: Supply chain & interdependent security](part3/03-supply-chain-interdependent-security.ipynb) — compound exposure, correlated failures, cascade dynamics, vendor investment

## Use the library

```bash
pip install --pre decision-security
```

```python
from decision_security.synth import sample
x = sample("poisson", 10, lam=1.2)
print(x)
```
