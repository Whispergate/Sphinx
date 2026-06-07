# Sphinx

A [LitterBox](https://github.com/BlackSnufkin/LitterBox) integration for the [Mythic](https://github.com/its-a-feature/Mythic) Command and Control framework.

Sphinx is a Mythic **eventing container**. Every time a payload finishes building, Sphinx fetches it, submits it to a self-hosted LitterBox sandbox for AV/detection analysis, and tags the payload in Mythic with the verdict — so you know whether a payload is clean or burned before you ever deploy it.

> **Lab use only.** Sphinx is a red-team automation tool. LitterBox has no authentication and is designed for isolated analyst networks — never expose it (or this workflow) to untrusted networks.

## How it works

```
Payload build completes
        │
        ▼
Mythic eventing workflow fires ──► Sphinx (execute_script)
        │
        ├─ 1. Resolve payload UUID → Mythic GraphQL → file id
        ├─ 2. Download payload bytes from Mythic
        ├─ 3. POST bytes to LitterBox /upload → MD5
        ├─ 4. Trigger scan(s): /analyze/static|dynamic/<md5>
        ├─ 5. Poll results until terminal state
        ├─ 6. Map LitterBox risk_level → verdict label
        └─ 7. Tag the payload in Mythic (verdict + full risk data)
```

### Verdict tags

| LitterBox result | Mythic tag | Color |
|---|---|---|
| `risk_level: low` | `Sphinx: Clean` | green |
| `risk_level: medium` | `Sphinx: Medium Risk` | orange |
| `risk_level: high` | `Sphinx: High Risk` | red |
| `risk_level: critical` | `Sphinx: Critical Risk` | purple |
| status `blocked_by_av` | `Sphinx: AV Detected` | red |
| poll timeout | `Sphinx: Scan Timeout` | grey |

The tag's `data` field carries the full context: `risk_score`, `risk_level`, `risk_factors`, LitterBox `hash`, `scan_type`, and a `results_url` link back to the LitterBox report.

## Requirements

- A running Mythic server (with `mythic-cli`)
- A reachable LitterBox instance (default port `1337`)
- A Mythic API token (Settings → API Tokens)

## Install

From your Mythic server directory:

```bash
# Install from a local clone
./mythic-cli install folder /path/to/Sphinx

# ...or from GitHub
./mythic-cli install github https://github.com/hunterino-sec/Sphinx

# Start the container
./mythic-cli start sphinx
```

Before installing, set the RabbitMQ password in `Payload_Type/sphinx/rabbitmq_config.json` to match your Mythic `.env` (`RABBITMQ_PASSWORD`).

Confirm the container shows up under **Settings → Services** in the Mythic UI.

## Configure the eventing workflow

In the Mythic UI go to **Eventing → New Workflow** and add a step:

| Field | Value |
|---|---|
| Trigger | `payload_build_complete` |
| Step type | Custom Function |
| Container | `sphinx` |
| Function | `execute_script` |

Step inputs:

| Key | Value | Notes |
|---|---|---|
| `payload_uuid` | `{{payload.uuid}}` | resolved from the build event |
| `mythic_api_token` | *your token* | used for GraphQL + file download |
| `litterbox_url` | `http://<litterbox-ip>:1337` | trailing slash optional |
| `scan_type` | `static` \| `dynamic` \| `both` | default `static` |
| `timeout` | `120` | seconds, dynamic poll cap |

`litterbox_url` can also be supplied via the `LITTERBOX_URL` environment variable instead of a step input.

Save and **enable** the workflow.

## Scan types

| Type | Behavior |
|---|---|
| `static` | YARA / PE / string analysis. Fast, effectively synchronous. |
| `dynamic` | Behavioral + memory + EDR analysis. Polled until `completed` / `blocked_by_av`. |
| `both` | Runs static and dynamic concurrently; verdict driven by the dynamic result. |

## Test

Build any payload in Mythic. Within ~30s (static) the payload should gain a `Sphinx: …` tag — view it under **Payloads → (payload) → Tags**. The tag data field links back to the full LitterBox report.

## Project layout

```
config.json                          Mythic container registration
documentation-wrapper/               placeholder (required by mythic-cli)
Payload_Type/sphinx/
  Dockerfile                         Alpine Python 3.11, multi-stage
  main.py                            container entry point
  rabbitmq_config.json               broker config
  .docker/requirements.txt           mythic-container, mythic, httpx
  sphinx/
    __init__.py
    eventing.py                      SphinxEventing — core logic
```

## Credits

- [Mythic](https://github.com/its-a-feature/Mythic) by @its-a-feature
- [LitterBox](https://github.com/BlackSnufkin/LitterBox) by @BlackSnufkin
- Structure modeled on [Hydra](https://github.com/MythicAgents/hydra)
