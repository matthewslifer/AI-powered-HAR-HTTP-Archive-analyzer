import os
import json
import sys
import logging
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
