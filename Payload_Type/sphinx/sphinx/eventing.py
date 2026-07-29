import asyncio
import logging
import os

import httpx
from mythic_container.EventingBase import (
    CustomFunctionDefinition,
    Eventing,
    NewCustomEventingMessage,
    NewCustomEventingMessageResponse,
)

logger = logging.getLogger("sphinx")

MYTHIC_GRAPHQL = os.getenv("MYTHIC_GRAPHQL", "http://mythic_graphql:8080/v1/graphql")
MYTHIC_SERVER = os.getenv("MYTHIC_SERVER", "http://mythic_server:17443")

_QUERY_PAYLOAD = """
query SphinxPayload($uuid: String!) {
    payload(where: {uuid: {_eq: $uuid}}) {
        id
        filemetum { agent_file_id filename }
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


async def execute_script(msg: NewCustomEventingMessage) -> NewCustomEventingMessageResponse:
    try:
        payload_uuid  = msg.Inputs.get("payload_uuid", "").strip()
        lb_url        = (msg.Inputs.get("litterbox_url") or os.getenv("LITTERBOX_URL", "")).rstrip("/")
        scan_type     = msg.Inputs.get("scan_type", "static").lower()
        edr_profile   = msg.Inputs.get("edr_profile", "").strip()
        mythic_token  = msg.Inputs.get("mythic_api_token", "")
        poll_timeout  = int(msg.Inputs.get("timeout", "120"))

        _VALID_SCANS = {"static", "dynamic", "both", "holygrail", "edr", "all"}

        if not payload_uuid:
            return NewCustomEventingMessageResponse(Success=False, Message="payload_uuid input missing")
        if not lb_url:
            return NewCustomEventingMessageResponse(
                Success=False,
                Message="litterbox_url missing — set via workflow input or LITTERBOX_URL env var"
            )
        if scan_type not in _VALID_SCANS:
            return NewCustomEventingMessageResponse(
                Success=False,
                Message=f"scan_type must be one of {_VALID_SCANS}, got: {scan_type!r}"
            )
        if scan_type == "edr" and not edr_profile:
            return NewCustomEventingMessageResponse(
                Success=False,
                Message="edr_profile input required when scan_type is 'edr'"
            )

        auth_headers = {"Authorization": f"Bearer {mythic_token}"}

        payload_int_id, agent_file_id, filename = await _query_payload(auth_headers, payload_uuid)
        if agent_file_id is None:
            return NewCustomEventingMessageResponse(
                Success=False,
                Message=f"Payload {payload_uuid!r} not found in Mythic"
            )

        payload_bytes = await _download_file(auth_headers, agent_file_id)
        md5           = await _lb_upload(lb_url, payload_bytes, filename)

        needed = await _lb_scans_needed(lb_url, md5, scan_type, edr_profile)
        if needed:
            logger.info("Triggering scans for %s: %s", md5, needed)
            await _lb_trigger_scans(lb_url, md5, needed, edr_profile)
            await _lb_poll_verdict_risk(lb_url, md5, needed, poll_timeout, edr_profile)
        else:
            logger.info("LitterBox already has all results for %s, skipping scans", md5)

        risk_data    = await _lb_fetch_risk(lb_url, md5)
        edr_data     = await _lb_fetch_edr_summary(lb_url, md5)
        logger.warning("EDR summary for %s: %s", md5, edr_data)
        if edr_data:
            risk_data["risk_factors_edr"] = edr_data

        level        = (risk_data.get("risk_level") or "low").lower()
        label, color = _VERDICT_MAP.get(level, ("Sphinx: Unknown", "#9E9E9E"))

        await _mythic_tag_payload(
            auth_headers, payload_int_id, label, color,
            risk_data, md5, lb_url, scan_type,
        )

        score = risk_data.get("risk_score", "N/A")
        return NewCustomEventingMessageResponse(
            Success=True,
            Message=f"{label} | risk_score={score} | hash={md5}",
        )

    except Exception as exc:
        logger.exception("Sphinx eventing failed")
        return NewCustomEventingMessageResponse(Success=False, Message=f"Sphinx error: {exc}")


# ---------------------------------------------------------------------------
# Mythic helpers
# ---------------------------------------------------------------------------

async def _gql(headers: dict, query: str, variables: dict) -> dict:
    async with httpx.AsyncClient(verify=False, timeout=15) as client:
        r = await client.post(
            MYTHIC_GRAPHQL,
            headers=headers,
            json={"query": query, "variables": variables},
        )
        r.raise_for_status()
        body = r.json()
        if "errors" in body:
            raise RuntimeError(f"GraphQL error: {body['errors']}")
        return body.get("data", {})


async def _query_payload(headers: dict, uuid: str):
    data     = await _gql(headers, _QUERY_PAYLOAD, {"uuid": uuid})
    payloads = data.get("payload", [])
    if not payloads:
        return None, None, "payload.bin"
    p        = payloads[0]
    fm       = p.get("filemetum") or {}
    filename = _decode_bytea(fm.get("filename", "")) or "payload.bin"
    return p["id"], fm.get("agent_file_id"), filename


def _decode_bytea(val: str) -> str:
    if not val:
        return ""
    if val.startswith("\\x") or val.startswith("x"):
        hex_str = val.lstrip("\\").lstrip("x")
        try:
            return bytes.fromhex(hex_str).decode("utf-8", errors="replace")
        except ValueError:
            return val
    return val


async def _download_file(headers: dict, agent_file_id: str) -> bytes:
    async with httpx.AsyncClient(verify=False, timeout=60) as client:
        r = await client.get(f"{MYTHIC_SERVER}/direct/download/{agent_file_id}", headers=headers)
        r.raise_for_status()
        return r.content


async def _mythic_tag_payload(
    headers: dict, payload_id: int, label: str, color: str,
    risk_data: dict, md5: str, lb_url: str, scan_type: str
) -> None:
    data      = await _gql(headers, _QUERY_TAGTYPE, {"name": label})
    tagtypes  = data.get("tagtype", [])
    if tagtypes:
        tagtype_id = tagtypes[0]["id"]
    else:
        result     = await _gql(headers, _INSERT_TAGTYPE, {
            "name": label, "color": color, "description": "Sphinx AV scan verdict"
        })
        tagtype_id = result["insert_tagtype_one"]["id"]

    tag_data = {
        "risk_score":   risk_data.get("risk_score"),
        "risk_level":   risk_data.get("risk_level"),
        "risk_factors": risk_data.get("risk_factors", []),
        "risk_factors_edr": risk_data.get("risk_factors_edr", []),
        "hash":         md5,
        "scan_type":    scan_type,
        "results_url":  f"{lb_url}/results/info/{md5}",
    }
    await _gql(headers, _INSERT_TAG, {
        "tagtype_id": tagtype_id,
        "payload_id": payload_id,
        "source":     "sphinx",
        "url":        f"{lb_url}/results/info/{md5}",
        "data":       tag_data,
    })


# ---------------------------------------------------------------------------
# LitterBox helpers
# ---------------------------------------------------------------------------

_ALLOWED_EXT = {"exe", "dll", "sys", "scr", "com", "bat", "ps1", "vbs", "js",
                "doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf", "lnk"}


async def _lb_upload(lb_url: str, data: bytes, filename: str) -> str:
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext not in _ALLOWED_EXT:
        filename = filename + ".exe"
    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.post(
            f"{lb_url}/upload",
            files={"file": (filename, data, "application/octet-stream")},
        )
        if r.status_code != 200:
            logger.error("LitterBox upload failed (%s): %s", r.status_code, r.text)
            r.raise_for_status()
        return r.json()["file_info"]["md5"]


async def _lb_scans_needed(lb_url: str, md5: str, scan_type: str, edr_profile: str = "") -> set:
    check = set()
    if scan_type in ("static", "both", "all"):
        check.add("static")
    if scan_type in ("dynamic", "both", "all"):
        check.add("dynamic")
    if scan_type == "holygrail":
        check.add("holygrail")
    if scan_type in ("edr", "all"):
        check.add("edr")

    needed = set()
    async with httpx.AsyncClient(timeout=10) as client:
        for st in check:
            if st == "edr":
                profiles = [edr_profile] if edr_profile else await _lb_get_edr_profiles(lb_url)
                logger.info("EDR profiles found: %s", profiles)
                for p in profiles:
                    try:
                        r = await client.get(f"{lb_url}/api/results/edr/{p}/{md5}")
                        logger.info("EDR %s results check: %s", p, r.status_code)
                        if r.status_code != 200:
                            needed.add("edr")
                    except httpx.HTTPError:
                        needed.add("edr")
            else:
                try:
                    r = await client.get(f"{lb_url}/api/results/{st}/{md5}")
                    logger.info("%s results check: %s", st, r.status_code)
                    if r.status_code != 200:
                        needed.add(st)
                except httpx.HTTPError:
                    needed.add(st)
    logger.info("Scans needed: %s (requested: %s)", needed, scan_type)
    return needed


async def _lb_trigger_scans(lb_url: str, md5: str, needed, edr_profile: str = "") -> None:
    if isinstance(needed, str):
        needed = {needed}
    async with httpx.AsyncClient(timeout=120) as client:
        tasks = []
        if "static" in needed:
            tasks.append(client.post(f"{lb_url}/analyze/static/{md5}"))
        if "dynamic" in needed:
            tasks.append(client.post(f"{lb_url}/analyze/dynamic/{md5}"))
        if "holygrail" in needed:
            tasks.append(client.post(f"{lb_url}/analyze/holygrail/{md5}"))
        if "edr" in needed:
            profiles = [edr_profile] if edr_profile else await _lb_get_edr_profiles(lb_url)
            for p in profiles:
                tasks.append(client.post(f"{lb_url}/analyze/edr/{p}/{md5}"))
        logger.info("Triggering %d scan(s): %s", len(tasks), needed)
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        for i, r in enumerate(responses):
            if isinstance(r, Exception):
                logger.error("Scan trigger %d failed: %r", i, r)
            else:
                logger.info("Scan trigger %d: %s", i, r.status_code)


async def _lb_poll_verdict_risk(lb_url: str, md5: str, needed,
                                timeout: int, edr_profile: str = "") -> dict:
    if isinstance(needed, str):
        needed = {needed}

    sync_only = needed <= {"static", "holygrail"}
    if sync_only:
        await asyncio.sleep(3)
        return await _lb_fetch_risk(lb_url, md5)

    poll_urls = []
    if "dynamic" in needed:
        poll_urls.append(f"{lb_url}/api/results/dynamic/{md5}")
    if "edr" in needed:
        profiles = [edr_profile] if edr_profile else await _lb_get_edr_profiles(lb_url)
        for p in profiles:
            poll_urls.append(f"{lb_url}/api/results/edr/{p}/{md5}")

    _TERMINAL = {"completed", "blocked_by_av", "partial", "error", "agent_unreachable"}

    interval = _POLL_START
    elapsed  = 0.0

    while elapsed < timeout:
        await asyncio.sleep(interval)
        elapsed += interval

        all_done = True
        for url in poll_urls:
            try:
                async with httpx.AsyncClient(timeout=10) as client:
                    r = await client.get(url)
            except httpx.HTTPError:
                all_done = False
                continue

            if r.status_code != 200:
                all_done = False
                continue

            status = r.json().get("status", "")
            if status not in _TERMINAL:
                all_done = False

        if all_done and poll_urls:
            return await _lb_fetch_risk(lb_url, md5)

        interval = min(interval * _POLL_BACKOFF, _POLL_MAX)

    return await _lb_fetch_risk(lb_url, md5)


async def _lb_get_edr_profiles(lb_url: str) -> list[str]:
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(f"{lb_url}/api/edr/profiles")
            if r.status_code == 200:
                return [p["name"] for p in r.json().get("profiles", [])]
    except httpx.HTTPError:
        pass
    return []


def _summarize_alert(alert: dict) -> dict:
    title = alert.get("title") or alert.get("raw", {}).get("message", "Unknown alert")
    severity = alert.get("severity", "unknown")
    details = alert.get("details", {})
    proc = details.get("process", {}) if details else {}
    return {
        "severity": severity,
        "rule": title,
        "process": proc.get("name"),
        "detected_at": alert.get("detected_at"),
    }


async def _lb_fetch_edr_summary(lb_url: str, md5: str) -> list:
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(f"{lb_url}/api/results/edr/{md5}")
            if r.status_code != 200:
                return []
            body = r.json()
            profiles = body.get("profiles", [])
            results = []
            for p in profiles:
                name = p if isinstance(p, str) else p.get("name", "")
                if not name:
                    continue
                pr = await client.get(f"{lb_url}/api/results/edr/{name}/{md5}")
                if pr.status_code == 200:
                    data = pr.json()
                    results.append({
                        "profile": name,
                        "status": data.get("status"),
                        "total_alerts": data.get("total_alerts"),
                        "alerts": [_summarize_alert(a) for a in data.get("alerts", [])],
                    })
            return results
    except Exception as exc:
        logger.error("EDR summary fetch failed: %r", exc)
    return []


async def _lb_fetch_risk(lb_url: str, md5: str) -> dict:
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(f"{lb_url}/api/results/risk/{md5}")
            if r.status_code == 200:
                return r.json()
    except httpx.HTTPError:
        pass
    return {}


class SphinxEventing(Eventing):
    name = "sphinx"
    description = "Submit payloads to LitterBox for analysis and tag with verdict"
    custom_functions = [
        CustomFunctionDefinition(
            Name="execute_script",
            Description="Upload a Mythic payload to LitterBox, run scans, and tag with the verdict",
            Function=execute_script,
        ),
    ]
