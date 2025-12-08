# Working on EPSS-MCP

- Always run tests inside a project-local virtual environment to avoid picking up user/global packages (e.g., pytest plugins that can break runs).
  - `python -m venv .venv`
  - `source .venv/bin/activate`
  - `pip install -r requirements.txt`
  - `pytest -q`
- Env overrides for EPSS client:
  - `EPSS_API_BASE` (default `https://api.cisa.gov/epss`)
  - `EPSS_API_VERSION` (default `v2`)
- Cache: set `CACHE_FOLDER` if you want response caching.
