import asyncio
import json
import logging
import os

import httpx
from mythic_container.EventingBase import (
    Eventing,
    NewCustomEventingMessage,
    NewCustomEventingMessageResponse,
)

logger = logging.getLogger("sphinx")

MYTHIC_HOST = os.getenv("MYTHIC_SERVER_HOST", "127.0.0.1")
MYTHIC_PORT = int(os.getenv("MYTHIC_SERVER_PORT", "7443"))

_QUERY_PAYLOAD = """
query SphinxPayload($uuid: String!) {
    payload(where: {uuid: {_eq: $uuid}}) {
        id
        filemeta { agent_file_id filename }
    }
}
"""

_QUERY_TAGTYPE = """
query SphinxGetTagtype($name: String!) {
    tagtype(where: {name: {_eq: $name}}) { id }
}
"""

_INSERT_TAGTYPE = """
mutation SphinxCreateTagtype($name: String!, $color: String!, $description: String!) {
    insert_tagtype_one(object: {name: $name, color: $color, description: $description}) { id }
}
"""

_INSERT_TAG = """
mutation SphinxInsertTag(
    $tagtype_id: Int!, $payload_id: Int!,
    $source: String!, $url: String!, $data: jsonb!
) {
    insert_tag_one(object: {
        tagtype_id: $tagtype_id,
        payload_id: $payload_id,
        source: $source,
        url: $url,
        data: $data
    }) { id }
}
"""

_VERDICT_MAP = {
    "low":      ("Sphinx: Clean",         "#4CAF50"),
    "medium":   ("Sphinx: Medium Risk",   "#FF9800"),
    "high":     ("Sphinx: High Risk",     "#f44336"),
    "critical": ("Sphinx: Critical Risk", "#9C27B0"),
}

_POLL_START   = 2.0
_POLL_MAX     = 15.0
_POLL_BACKOFF = 1.5


class SphinxEventing(Eventing):
    name = "sphinx"

    async def execute_script(self, msg: NewCustomEventingMessage) -> NewCustomEventingMessageResponse:
        try:
            payload_uuid  = msg.Inputs.get("payload_uuid", "").strip()
            lb_url        = (msg.Inputs.get("litterbox_url") or os.getenv("LITTERBOX_URL", "")).rstrip("/")
            scan_type     = msg.Inputs.get("scan_type", "static").lower()
            mythic_token  = msg.Inputs.get("mythic_api_token", "")
            poll_timeout  = int(msg.Inputs.get("timeout", "120"))

            if not payload_uuid:
                return NewCustomEventingMessageResponse(Success=False, Message="payload_uuid input missing")
            if not lb_url:
                return NewCustomEventingMessageResponse(
                    Success=False,
                    Message="litterbox_url missing — set via workflow input or LITTERBOX_URL env var"
                )
            if scan_type not in ("static", "dynamic", "both"):
                return NewCustomEventingMessageResponse(
                    Success=False,
                    Message=f"scan_type must be static|dynamic|both, got: {scan_type!r}"
                )

            mythic_base  = f"https://{MYTHIC_HOST}:{MYTHIC_PORT}"
            auth_headers = {"Authorization": f"Bearer {mythic_token}"}

            payload_int_id, agent_file_id, filename = await _query_payload(mythic_base, auth_headers, payload_uuid)
            if agent_file_id is None:
                return NewCustomEventingMessageResponse(
                    Success=False,
                    Message=f"Payload {payload_uuid!r} not found in Mythic"
                )

            payload_bytes = await _download_file(mythic_base, auth_headers, agent_file_id)
            md5           = await _lb_upload(lb_url, payload_bytes, filename)

            await _lb_trigger_scans(lb_url, md5, scan_type)

            label, color, risk_data = await _lb_poll_verdict(lb_url, md5, scan_type, poll_timeout)

            await _mythic_tag_payload(
                mythic_base, auth_headers,
                payload_int_id, label, color,
                risk_data, md5, lb_url, scan_type
            )

            score = risk_data.get("risk_score", "N/A")
            return NewCustomEventingMessageResponse(
                Success=True,
                Message=f"Sphinx: {label} | risk_score={score} | hash={md5}"
            )

        except Exception as exc:
            logger.exception("Sphinx eventing failed")
            return NewCustomEventingMessageResponse(Success=False, Message=f"Sphinx error: {exc}")


# ---------------------------------------------------------------------------
# Mythic helpers
# ---------------------------------------------------------------------------

async def _gql(base: str, headers: dict, query: str, variables: dict) -> dict:
    async with httpx.AsyncClient(verify=False, timeout=15) as client:
        r = await client.post(
            f"{base}/graphql",
            headers=headers,
            json={"query": query, "variables": variables},
        )
        r.raise_for_status()
        body = r.json()
        if "errors" in body:
            raise RuntimeError(f"GraphQL error: {body['errors']}")
        return body.get("data", {})


async def _query_payload(base: str, headers: dict, uuid: str):
    data     = await _gql(base, headers, _QUERY_PAYLOAD, {"uuid": uuid})
    payloads = data.get("payload", [])
    if not payloads:
        return None, None, "payload.bin"
    p        = payloads[0]
    fm       = p.get("filemeta") or {}
    return p["id"], fm.get("agent_file_id"), fm.get("filename", "payload.bin")


async def _download_file(base: str, headers: dict, agent_file_id: str) -> bytes:
    async with httpx.AsyncClient(verify=False, timeout=60) as client:
        r = await client.get(f"{base}/direct/download/{agent_file_id}", headers=headers)
        r.raise_for_status()
        return r.content


async def _mythic_tag_payload(
    base: str, headers: dict,
    payload_id: int, label: str, color: str,
    risk_data: dict, md5: str, lb_url: str, scan_type: str
) -> None:
    # Find or create tagtype for this verdict label
    data      = await _gql(base, headers, _QUERY_TAGTYPE, {"name": label})
    tagtypes  = data.get("tagtype", [])
    if tagtypes:
        tagtype_id = tagtypes[0]["id"]
    else:
        result     = await _gql(base, headers, _INSERT_TAGTYPE, {
            "name": label, "color": color, "description": "Sphinx AV scan verdict"
        })
        tagtype_id = result["insert_tagtype_one"]["id"]

    tag_data = {
        "risk_score":   risk_data.get("risk_score"),
        "risk_level":   risk_data.get("risk_level"),
        "risk_factors": risk_data.get("risk_factors", []),
        "hash":         md5,
        "scan_type":    scan_type,
        "results_url":  f"{lb_url}/results/{md5}",
    }
    await _gql(base, headers, _INSERT_TAG, {
        "tagtype_id": tagtype_id,
        "payload_id": payload_id,
        "source":     "sphinx",
        "url":        f"{lb_url}/results/{md5}",
        "data":       tag_data,
    })


# ---------------------------------------------------------------------------
# LitterBox helpers
# ---------------------------------------------------------------------------

async def _lb_upload(lb_url: str, data: bytes, filename: str) -> str:
    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.post(
            f"{lb_url}/upload",
            files={"file": (filename, data, "application/octet-stream")},
        )
        r.raise_for_status()
        return r.json()["file_info"]["md5"]


async def _lb_trigger_scans(lb_url: str, md5: str, scan_type: str) -> None:
    async with httpx.AsyncClient(timeout=30) as client:
        tasks = []
        if scan_type in ("static", "both"):
            tasks.append(client.post(f"{lb_url}/analyze/static/{md5}"))
        if scan_type in ("dynamic", "both"):
            tasks.append(client.post(f"{lb_url}/analyze/dynamic/{md5}"))
        responses = await asyncio.gather(*tasks)
        for r in responses:
            r.raise_for_status()


async def _lb_poll_verdict(lb_url: str, md5: str, scan_type: str, timeout: int):
    if scan_type == "static":
        # Static analysis is synchronous — short wait then fetch risk
        await asyncio.sleep(3)
        risk = await _lb_fetch_risk(lb_url, md5)
        level         = (risk.get("risk_level") or "low").lower()
        label, color  = _VERDICT_MAP.get(level, ("Sphinx: Unknown", "#9E9E9E"))
        return label, color, risk

    # dynamic or both — poll dynamic results until terminal state
    interval = _POLL_START
    elapsed  = 0.0

    while elapsed < timeout:
        await asyncio.sleep(interval)
        elapsed += interval

        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.get(f"{lb_url}/api/results/dynamic/{md5}")
        except httpx.HTTPError:
            interval = min(interval * _POLL_BACKOFF, _POLL_MAX)
            continue

        if r.status_code != 200:
            interval = min(interval * _POLL_BACKOFF, _POLL_MAX)
            continue

        result = r.json()
        status = result.get("status", "")

        if status == "blocked_by_av":
            risk = await _lb_fetch_risk(lb_url, md5)
            return "Sphinx: AV Detected", "#f44336", risk

        if status == "completed":
            risk         = await _lb_fetch_risk(lb_url, md5)
            level        = (risk.get("risk_level") or "low").lower()
            label, color = _VERDICT_MAP.get(level, ("Sphinx: Unknown", "#9E9E9E"))
            return label, color, risk

        interval = min(interval * _POLL_BACKOFF, _POLL_MAX)

    risk = await _lb_fetch_risk(lb_url, md5)
    return "Sphinx: Scan Timeout", "#9E9E9E", risk


async def _lb_fetch_risk(lb_url: str, md5: str) -> dict:
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(f"{lb_url}/api/results/risk/{md5}")
            if r.status_code == 200:
                return r.json()
    except httpx.HTTPError:
        pass
    return {}
