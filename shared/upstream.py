import logging

import httpx
from fastapi import HTTPException
from pydantic import ValidationError


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
        except (httpx.HTTPError, httpx.InvalidURL, ValueError):
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

    def user(self, list_url, user_id, token):
        data = self.get_json(list_url, token, "Users")
        if isinstance(data, dict) and "data" in data:
            data = data["data"]
        if not isinstance(data, list):
            raise HTTPException(503, "Users service returned an invalid user list")
        for record in data:
            if isinstance(record, dict) and record.get("id") == user_id:
                return record
        raise HTTPException(404, "Recipient user not found")

    def notify(self, url, token, user_id, title, message, notification_type, severity="Medium"):
        """Best effort: a failed notification is logged and never fails the caller's request."""
        if not url:
            return False
        try:
            with httpx.Client(timeout=3, follow_redirects=False, transport=self.transport) as client:
                client.post(url, headers={"Authorization": f"Bearer {token}"}, json={
                    "user_id": user_id, "title": title, "message": message,
                    "notification_type": notification_type, "severity": severity}).raise_for_status()
            return True
        except (httpx.HTTPError, httpx.InvalidURL):
            logging.getLogger(__name__).warning("Notification for user %s was not delivered", user_id)
            return False

    def records(self, url, token, source, model):
        data = self.get_json(url, token, source)
        if isinstance(data, dict):
            if (data.get("next") or data.get("has_more") or data.get("pagination")
                    or data.get("total_pages", 1) != 1):
                raise HTTPException(503, f"{source} service must return a complete, unpaginated dataset")
            records = data.get("data")
            if not isinstance(records, list) or ("total" in data and data["total"] != len(records)):
                raise HTTPException(503, f"{source} service returned incomplete or invalid records")
            data = records
        if not isinstance(data, list):
            raise HTTPException(503, f"{source} service must return a JSON array or data array")
        try:
            records = [model.model_validate(row) for row in data]
        except (ValidationError, TypeError, ValueError):
            raise HTTPException(503, f"{source} service returned invalid record fields")
        ids = [str(row.id) for row in records]
        if len(ids) != len(set(ids)):
            raise HTTPException(503, f"{source} service returned duplicate record identifiers")
        return records
