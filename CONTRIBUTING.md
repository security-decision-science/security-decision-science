# Contributing

Thanks for helping improve **Security Decision Science**  
This repo hosts the Jupyter Book (docs site). Edits are mostly Markdown pages under `docs/`.

## How to propose a change
1. Create a branch from **main** (e.g., `docs/fix-typo` or `docs/part1-add-example`).
2. Edit or add pages in `docs/` (don’t commit `docs/_build/`).
3. (Optional) Preview locally:
   ```bash
   python -m venv .book && source .book/bin/activate
   python -m pip install -U pip "jupyter-book==1.0.0"
   jupyter-book build docs
   open docs/_build/html/index.html
