from typing import Any, Dict
import httpx
import logging

# Constants
EPSS_API_BASE = "https://api.first.org/data/v1/epss?cve="

logger = logging.getLogger(__name__)

async def fetch_epss_data(cve_id: str) -> Dict[str, Any] | None:
    """Fetch the EPSS percentile and score for a given CVE ID."""
    url = f"{EPSS_API_BASE}{cve_id}"
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url, timeout=30.0)
            response.raise_for_status()
            data = response.json()

            # Validate the JSON structure
            if not isinstance(data, dict) or "data" not in data or not data["data"]:
                return {"epss_percentile": "N/A", "epss_score": "N/A"}

            epss_data = data["data"][0]
            return {
                "epss_percentile": epss_data.get("percentile", "N/A"),
                "epss_score": epss_data.get("epss", "N/A")
            }
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
