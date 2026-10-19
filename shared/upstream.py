import httpx
from fastapi import HTTPException


class UpstreamClient:
    """HTTP integration adapter. Never substitutes fabricated data for an unavailable service."""

    def __init__(self, transport=None):
        self.transport = transport

    def get_json(self, url: str, token: str, source: str, missing_is_404=False):
        if not url:
            raise HTTPException(503, f"{source} service URL is not configured")
        try:
            with httpx.Client(timeout=5, follow_redirects=False, transport=self.transport) as client:
                response = client.get(url, headers={"Authorization": f"Bearer {token}"})
            if missing_is_404 and response.status_code == 404:
                raise HTTPException(404, "Affected asset not found")
            response.raise_for_status()
            return response.json()
        except (httpx.HTTPError, ValueError):
            raise HTTPException(503, f"{source} service unavailable or returned invalid JSON")

    def asset(self, url_template, asset_id, token):
        if not url_template or "{id}" not in url_template:
            raise HTTPException(503, "Asset detail URL must be configured with an {id} placeholder")
        data = self.get_json(url_template.replace("{id}", str(asset_id)), token, "Assets", missing_is_404=True)
        if isinstance(data, dict) and "data" in data:
            data = data["data"]
        if not isinstance(data, dict) or type(data.get("id")) is not int or data["id"] != asset_id:
            raise HTTPException(503, "Assets service returned an invalid asset record")
        return data
