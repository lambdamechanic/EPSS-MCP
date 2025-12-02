from typing import Any, Dict
import httpx
from httpx_retry import AsyncRetryTransport
from httpx_retry.policies import RetryPolicy
import hashlib
import json
import logging
import os
import time
from pathlib import Path

# Constants
EPSS_API_BASE = "https://api.first.org/data/v1/epss?cve="

logger = logging.getLogger(__name__)

CACHE_FOLDER = os.getenv("CACHE_FOLDER")

_retry_policy = RetryPolicy(
    max_retries=5,
    initial_delay=1.0,
    multiplier=2.0,
    retry_on={429, 500, 502, 503, 504}
)


def _cache_path(url: str) -> Path:
    return Path(CACHE_FOLDER) / f"epss_{hashlib.sha256(url.encode()).hexdigest()}.json"


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


def _store_cache(url: str, headers: Dict[str, Any], data: Dict[str, Any]) -> None:
    if not CACHE_FOLDER:
        return
    cache_control = headers.get("cache-control", "")
    ttl = None
    if "max-age" in cache_control:
        try:
            ttl = int(cache_control.split("max-age=")[1].split(",")[0])
        except Exception:
            ttl = None
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


def _normalize_epss(data: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(data, dict) or "data" not in data or not data.get("data"):
        return {"epss_percentile": "N/A", "epss_score": "N/A"}

    epss_data = data["data"][0]
    return {
        "epss_percentile": epss_data.get("percentile", "N/A"),
        "epss_score": epss_data.get("epss", "N/A")
    }

async def fetch_epss_data(cve_id: str) -> Dict[str, Any] | None:
    """Fetch the EPSS percentile and score for a given CVE ID."""
    url = f"{EPSS_API_BASE}{cve_id}"
    cached = _load_cache(url)
    if cached:
        return _normalize_epss(cached)

    transport = AsyncRetryTransport(policy=_retry_policy)

    async with httpx.AsyncClient(transport=transport) as client:
        try:
            response = await client.get(url, timeout=30.0)
            response.raise_for_status()
            data = response.json()
            _store_cache(url, response.headers, data)

            return _normalize_epss(data)
        except httpx.RequestError as exc:
            logger.exception("EPSS request error for %s", cve_id)
            return {
                "epss_percentile": "N/A",
                "epss_score": "N/A",
                "error": f"EPSS request failed: {exc.__class__.__name__}"
            }
        except httpx.HTTPStatusError as exc:
            logger.exception("EPSS HTTP status error for %s", cve_id)
            return {
                "epss_percentile": "N/A",
                "epss_score": "N/A",
                "error": f"EPSS service returned status {exc.response.status_code}"
            }
        except ValueError:
            logger.exception("EPSS JSON decoding error for %s", cve_id)
            return {
                "epss_percentile": "N/A",
                "epss_score": "N/A",
                "error": "EPSS response was not valid JSON"
            }
        except Exception:
            logger.exception("Unexpected error fetching EPSS data for %s", cve_id)
            return {
                "epss_percentile": "N/A",
                "epss_score": "N/A",
                "error": "Unexpected error fetching EPSS data"
            }
