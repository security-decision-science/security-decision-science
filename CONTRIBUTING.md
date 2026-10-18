# Contributing

Thanks for helping improve **Security Decision Science**  
This repo hosts the notebooks and the Jupyter Book (docs site). Most content lives in the notebooks under `notebooks/`; `docs/` links to them.

## How to propose a change
1. Create a branch from **main** (e.g., `docs/fix-typo` or `docs/part1-add-example`).
2. Edit the notebooks in `notebooks/` or the pages in `docs/` (don’t commit `docs/_build/`).
3. (Optional) Preview locally:
   ```bash
   python -m venv .book && source .book/bin/activate
   python -m pip install -U pip "jupyter-book==1.0.0"
   jupyter-book build docs
   open docs/_build/html/index.html
   ```
