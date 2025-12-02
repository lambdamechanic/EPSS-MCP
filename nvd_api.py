from typing import Any, Dict
import httpx
from httpx_retry import AsyncRetryTransport
from httpx_retry.policies import RetryPolicy
from aiolimiter import AsyncLimiter
from dotenv import load_dotenv
import hashlib
import json
import logging
import os
import time
from pathlib import Path

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="

# Load environment variables from .env file
load_dotenv()

logger = logging.getLogger(__name__)

# Fetch API key from environment variables
API_KEY = os.getenv("NVD_API_KEY")
CACHE_FOLDER = os.getenv("CACHE_FOLDER")

BASE_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'
}

# NVD rate limits: 50 requests per 30s with an API key, 5 without one
_limiter_with_key = AsyncLimiter(50, 30)
_limiter_no_key = AsyncLimiter(5, 30)

# Retry policy: handle rate limits and transient server errors with backoff
_retry_policy = RetryPolicy(
    max_retries=5,
    initial_delay=1.0,
    multiplier=2.0,
    retry_on={429, 500, 502, 503, 504}
)


def _cache_path(url: str) -> Path:
    return Path(CACHE_FOLDER) / f"nvd_{hashlib.sha256(url.encode()).hexdigest()}.json"


def _load_cache(url: str) -> Dict[str, Any] | None:
    if not CACHE_FOLDER:
        return None
    path = _cache_path(url)
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text())
        if payload.get("expires_at", 0) > time.time():
            return payload.get("data")
        path.unlink(missing_ok=True)
    except Exception:
        logger.exception("Failed reading cache for %s", url)
    return None


def _store_cache(url: str, headers: Dict[str, Any], data: Dict[str, Any], default_ttl: int | None = None) -> None:
    if not CACHE_FOLDER:
        return
    cache_control = headers.get("cache-control", "")
    ttl = None
    if "max-age" in cache_control:
        try:
            ttl = int(cache_control.split("max-age=")[1].split(",")[0])
        except Exception:
            ttl = None
    if ttl is None:
        ttl = default_ttl
    if ttl is None or ttl <= 0:
        return
    try:
        Path(CACHE_FOLDER).mkdir(parents=True, exist_ok=True)
        path = _cache_path(url)
        path.write_text(json.dumps({
            "expires_at": time.time() + ttl,
            "data": data
        }))
    except Exception:
        logger.exception("Failed writing cache for %s", url)


def _normalize_nvd(data: Dict[str, Any]) -> Dict[str, Any]:
    vulnerabilities = data.get("vulnerabilities", []) if isinstance(data, dict) else []
    if not vulnerabilities:
        return {
            "description": "No description available",
            "cwe": "N/A",
            "cvss_score": "N/A"
        }

    cve_data = vulnerabilities[0].get("cve", {})
    cve_description = cve_data.get("descriptions", [{}])[0].get("value", "No description available")
    cwe = cve_data.get("weaknesses", [{}])[0].get("description", [{}])[0].get("value", "N/A")
    cvss_score = cve_data.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseScore", "N/A")

    return {
        "description": cve_description,
        "cwe": cwe,
        "cvss_score": cvss_score
    }

async def fetch_cve_details(cve_id: str, api_key: str | None = None) -> Dict[str, Any] | None:
    """Fetch CVE details from the NVD API.

    Returns a dict with description, cwe, cvss_score and optionally an
    "error" field when the request fails, following the MCP error-handling
    guidance (log internal details; return safe, actionable messages).
    """
    key = api_key if api_key is not None else API_KEY
    return await fetch_cve_details_with_key(cve_id, api_key=key)


async def fetch_cve_details_with_key(cve_id: str, api_key: str | None = None) -> Dict[str, Any] | None:
    """Same as fetch_cve_details but allows providing a per-call API key."""
    url = f"{NVD_API_BASE}{cve_id}"

    cached = _load_cache(url)
    if cached:
        return _normalize_nvd(cached)

    headers = dict(BASE_HEADERS)
    if api_key:
        headers['apiKey'] = api_key

    limiter = _limiter_with_key if api_key else _limiter_no_key

    transport = AsyncRetryTransport(policy=_retry_policy)

    async with limiter:
        async with httpx.AsyncClient(headers=headers, transport=transport) as client:
            try:
                response = await client.get(url, timeout=30.0)
                response.raise_for_status()
                data = response.json()
                _store_cache(url, response.headers, data, default_ttl=600)

                return _normalize_nvd(data)
            except httpx.RequestError as exc:
                logger.exception("NVD request error for %s", cve_id)
                return {
                    "description": "No description available",
                    "cwe": "N/A",
                    "cvss_score": "N/A",
                    "error": f"NVD request failed: {exc.__class__.__name__}"
                }
            except httpx.HTTPStatusError as exc:
                logger.exception("NVD HTTP status error for %s", cve_id)
                return {
                    "description": "No description available",
                    "cwe": "N/A",
                    "cvss_score": "N/A",
                    "error": f"NVD service returned status {exc.response.status_code}"
                }
            except ValueError:
                logger.exception("NVD JSON decoding error for %s", cve_id)
                return {
                    "description": "No description available",
                    "cwe": "N/A",
                    "cvss_score": "N/A",
                    "error": "NVD response was not valid JSON"
                }
            except Exception:
                logger.exception("Unexpected error fetching NVD data for %s", cve_id)
                return {
                    "description": "No description available",
                    "cwe": "N/A",
                    "cvss_score": "N/A",
                    "error": "Unexpected error fetching NVD data"
                }
            return {
                "description": "No description available",
                "cwe": "N/A",
                "cvss_score": "N/A",
                "error": "NVD data unavailable"
            }
