# CSP Guardian v2 – services/notifier.py
# Real-time WebSocket notifications for CSP violations

import logging
import json
from typing import Dict, Set
from fastapi import WebSocket

logger = logging.getLogger("csp-guardian.notifier")


class ViolationNotifier:
    """
    Manages WebSocket connections and broadcasts violation events.
    Clients (popup/devtools) connect to /ws/violations to receive real-time alerts.
    """

    def __init__(self):
        # domain -> set of connected WebSocket clients
        self._connections: Dict[str, Set[WebSocket]] = {}
        # global listeners (receive all violations)
        self._global: Set[WebSocket] = set()

    async def connect(self, websocket: WebSocket, domain: str = None):
        await websocket.accept()
        if domain:
            if domain not in self._connections:
                self._connections[domain] = set()
            self._connections[domain].add(websocket)
            logger.info(f"WS client connected for domain: {domain}")
        else:
            self._global.add(websocket)
            logger.info("WS global client connected")

    def disconnect(self, websocket: WebSocket, domain: str = None):
        if domain and domain in self._connections:
            self._connections[domain].discard(websocket)
        self._global.discard(websocket)
        logger.info(f"WS client disconnected (domain={domain})")

    async def broadcast_violation(self, violation: dict):
        """Send violation to all relevant WebSocket clients."""
        domain = violation.get("domain")
        message = json.dumps({
            "type": "violation",
            "data": violation,
        })

        dead = set()

        # Send to domain-specific listeners
        if domain and domain in self._connections:
            for ws in self._connections[domain].copy():
                try:
                    await ws.send_text(message)
                except Exception:
                    dead.add(("domain", domain, ws))

        # Send to global listeners
        for ws in self._global.copy():
            try:
                await ws.send_text(message)
            except Exception:
                dead.add(("global", None, ws))

        # Cleanup dead connections
        for kind, d, ws in dead:
            if kind == "domain" and d:
                self._connections.get(d, set()).discard(ws)
            else:
                self._global.discard(ws)

    async def broadcast_analysis(self, analysis: dict):
        """Notify clients when a new analysis is saved."""
        message = json.dumps({
            "type": "analysis_complete",
            "data": analysis,
        })
        for ws in self._global.copy():
            try:
                await ws.send_text(message)
            except Exception:
                self._global.discard(ws)

    def connection_count(self) -> int:
        total = len(self._global)
        for s in self._connections.values():
            total += len(s)
        return total


# Singleton instance
notifier = ViolationNotifier()