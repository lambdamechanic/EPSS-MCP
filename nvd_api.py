from typing import Any, Dict
import httpx
from aiolimiter import AsyncLimiter
from dotenv import load_dotenv
import logging
import os

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="

# Load environment variables from .env file
load_dotenv()

logger = logging.getLogger(__name__)

# Fetch API key from environment variables
API_KEY = os.getenv("NVD_API_KEY")

headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'
}

# Only send apiKey when it is actually provided
if API_KEY:
    headers['apiKey'] = API_KEY

# NVD rate limits: 50 requests per 30s with an API key, 5 without one
rate_limiter = AsyncLimiter(50 if API_KEY else 5, 30)

async def fetch_cve_details(cve_id: str) -> Dict[str, Any] | None:
    """Fetch CVE details from the NVD API.

    Returns a dict with description, cwe, cvss_score and optionally an
    "error" field when the request fails, following the MCP error-handling
    guidance (log internal details; return safe, actionable messages).
    """
    url = f"{NVD_API_BASE}{cve_id}"
    async with rate_limiter:
        async with httpx.AsyncClient(headers=headers) as client:
            try:
                response = await client.get(url, timeout=30.0)
                response.raise_for_status()
                data = response.json()

                # Extract relevant information
                vulnerabilities = data.get("vulnerabilities", [])
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
