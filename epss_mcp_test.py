import pytest

from epss_mcp import get_cve_info


@pytest.mark.asyncio
async def test_get_cve_info_renders_values(monkeypatch):
    cve_id = "CVE-2023-9999"

    async def fake_nvd(*_args, **_kwargs):
        return {
            "description": "Example issue",
            "cwe": "CWE-79",
            "cvss_score": 7.5,
        }

    async def fake_epss(*_args, **_kwargs):
        return {
            "epss_percentile": 0.25,
            "epss_score": 0.1234,
        }

    monkeypatch.setattr("epss_mcp.fetch_cve_details", fake_nvd)
    monkeypatch.setattr("epss_mcp.fetch_epss_data", fake_epss)

    result = await get_cve_info(cve_id)

    assert "CVE-2023-9999" in result
    assert "Example issue" in result
    assert "CWE-79" in result
    assert "7.5" in result
    assert "25.00%" in result
    assert "0.1234" in result
