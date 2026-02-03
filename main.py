import os
import json
import sys
import logging
import requests
from typing import Dict, Any, List

try:
    from mcp.server.fastmcp import FastMCP
except ImportError as e:
    logging.basicConfig(level=logging.ERROR)
    logging.error("Could not import FastMCP from mcp.server.fastmcp. Is the mcp-server package installed?")
    logging.error(e)
    sys.exit(1)

logging.basicConfig(level=logging.INFO)
logging.info("Starting har_mcp.py with FastMCP integration...")

mcp = FastMCP("har_mcp")

class HarState:
    def __init__(self):
        self.har_data: Dict[str, Any] = {}
        self.id_map: Dict[str, str] = {}

state = HarState()

SENSITIVE_HEADERS = {
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "x-auth-token",
    "cookie",
    "set-cookie",
}

def redact_headers(headers: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [
        {**h, "value": "[REDACTED]"}
        if h.get("name", "").lower() in SENSITIVE_HEADERS
        else h
        for h in headers
    ]

@mcp.tool()
def import_har(sources: List[str]) -> Dict[str, Any]:
    """
    Load one or more HAR files from local paths or URLs into memory.
    Assigns a unique MCP ID to each request entry for later analysis.
    Returns load status and entry counts per source.
    """
    results = []

    for source in sources:
        try:
            if source.startswith(("http://", "https://")):
                resp = requests.get(source, timeout=20)
                resp.raise_for_status()
                har_data = json.loads(resp.text)
            else:
                with open(source, "r", encoding="utf-8") as f:
                    har_data = json.load(f)

            if "log" not in har_data or "entries" not in har_data["log"]:
                results.append({"source": source, "error": "Invalid HAR format"})
                continue

        except Exception as e:
            results.append({"source": source, "error": str(e)})
            continue

        file_name = os.path.basename(source)

        if file_name in state.har_data:
            results.append({"source": source, "error": f"File {file_name} already loaded"})
            continue

        entries = har_data.get("log", {}).get("entries", [])
        logging.info(f"Loaded {len(entries)} entries from {file_name}")

        state.har_data[file_name] = har_data
        state.id_map[file_name] = {}

        for i, entry in enumerate(entries):
            entry_id = f"{file_name}:req_{i}"
            entry["mcp_id"] = entry_id

            if "request" in entry and "headers" in entry["request"]:
                entry["request"]["headers"] = redact_headers(entry["request"]["headers"])
            if "response" in entry and "headers" in entry["response"]:
                entry["response"]["headers"] = redact_headers(entry["response"]["headers"])

            state.id_map[file_name][entry_id] = entry

        results.append({"source": source, "status": "loaded", "num_entries": len(entries)})

    return {"results": results}
