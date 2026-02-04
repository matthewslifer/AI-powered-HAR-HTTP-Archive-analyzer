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

@mcp.tool()
def trace_summary(
    request_ids: Optional[List[str]] = None,
    file_name: Optional[str] = None
) -> Dict[str, Any]:
    """
    Summarizes specified requests, or all error requests if not specified, with URL, status, request headers, body, response headers, response cookies, and a narrative.
    Args:
        request_ids: list of request ID strings. If None or empty, returns all HTTP errors in range 400-599.
        file_name: (optional) Only include errors for this HAR file name if specified.
    Returns:
        Dict with summaries: list of summary dicts
    """
    # Helper to find entry given a request_id
    def find_entry(request_id):
        for file_entries in state.id_map.values():
            if request_id in file_entries:
                return file_entries[request_id]
        return None

    # Collect all error request ids if none specified
    all_ids = []
    if not request_ids:
        if file_name and file_name in state.har_data:
            har_data = state.har_data[file_name]
            entries = har_data.get("log", {}).get("entries",[])
            for entry in entries:
                status = entry.get("response",{}).get("status",0)
                if 400 <= status <= 599:
                    all_ids.append(entry.get("mcp_id", ""))
        else:
            for har_data in state.har_data.values():
                entries = har_data.get("log", {}).get("entries",[])
                for entry in entries:
                    status = entry.get("response", {}).get("status", 0)
                    if 400 <= status <= 599:
                        all_ids.append(entry.get("mcp_id", ""))
        request_ids = all_ids

    summaries = []
    for reqid in request_ids:
        entry = find_entry(reqid)
        if entry is None:
            summaries.append({"request_id": reqid, "error": "Not found"})
            continue

        request = entry.get("request", {})
        response = entry.get("response", {})

        request_headers = redact_headers(request.get("headers", []))
        response_headers = redact_headers(response.get("headers", []))

        req_body = request.get("postData", {}).get("text", "") if "postData" in request else ""
        resp_cookies = response.get("cookies",[])
        status = response.get("status", 0)
        status_text = response.get("statusText", "")
        url = request.get("url", "")

        ip = entry.get("serverIPAddress", "unknown")
        method = request.get("method", "unknown")
        timings = entry.get("timings", {})

        narrative_lines = []
        def pretty_trace():
            steps = []

            if 400 <= status <= 599:
                steps.append("1. **Browser Initiation:**\n   - The user of their application initiates a web or API request via browser, script, or HTTP client.")
                steps.append(f"    - Target URL: {url}")
                steps.append(f"    - HTTP Method: {method}")
            else:
                steps.append("1. **Request Initiation:**\n   - An HTTP request was triggered by the user or client.")

            proto = "HTTPS" if url.lower().startswith("https://") else "HTTP"
            steps.append(f"2. **Network Transmission**\n   - The request is sent to {ip} over {proto}.")

            reason = {
                400: "Bad Request: The server could not understand the request due to invalid syntax.",
                401: "Unauthorized: Authentication is required or has failed.",
                403: "Forbidden: The client does not have access rights to the content.",
                404: "Not Found: The server cannot find the requested resource.",
                408: "Request Timeout: The server timed out waiting for the request.",
                429: "Too Many Requests: Rate limiting was applied.",
                500: "Internal Server Error: The server encountered an unexpected condition.",
                502: "Bad Gateway: The server, while acting as a gateway, got an invalid response from the backend.",
                503: "Service Unavailable: The server is not ready to handle the request.",
                504: "Gateway Timeout: The upstream server failed to spend a request in time."
            }
            info = reason.get(status, "")
