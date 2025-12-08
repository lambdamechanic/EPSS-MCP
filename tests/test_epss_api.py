import importlib

import pytest
import respx
from httpx import Response


@pytest.mark.asyncio
async def test_fetch_epss_default_url(monkeypatch):
    monkeypatch.delenv("EPSS_API_BASE", raising=False)
    monkeypatch.delenv("EPSS_API_VERSION", raising=False)

    import epss_api

    importlib.reload(epss_api)

    cve_id = "CVE-2023-0001"
    expected_url = "https://api.cisa.gov/epss/v2/epss?cve=CVE-2023-0001"

    with respx.mock(assert_all_called=True) as router:
        router.get(expected_url).mock(
            return_value=Response(
                200,
                json={"data": [{"percentile": 0.3, "epss": 0.4}]},
                headers={"cache-control": "max-age=1"},
            )
        )

        result = await epss_api.fetch_epss_data(cve_id)

    assert result["epss_percentile"] == 0.3
    assert result["epss_score"] == 0.4


@pytest.mark.asyncio
async def test_fetch_epss_custom_url(monkeypatch):
    monkeypatch.setenv("EPSS_API_BASE", "https://example.test/epss-api")
    monkeypatch.setenv("EPSS_API_VERSION", "v9")

    import epss_api

    importlib.reload(epss_api)

    cve_id = "CVE-2023-0002"
    expected_url = "https://example.test/epss-api/v9/epss?cve=CVE-2023-0002"

    with respx.mock(assert_all_called=True) as router:
        router.get(expected_url).mock(
            return_value=Response(200, json={"data": [{"percentile": 0.1, "epss": 0.2}]})
        )

        result = await epss_api.fetch_epss_data(cve_id)

    assert result["epss_percentile"] == 0.1
    assert result["epss_score"] == 0.2
