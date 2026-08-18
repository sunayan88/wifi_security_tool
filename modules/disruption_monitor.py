import threading
import time
from collections import deque

from database.db_manager import save_alert
from modules.arp_monitor import take_gateway_snapshot
from modules.wifi_analyzer import get_current_network


def _signal_value(value):
    try:
        return int(str(value).replace("%", "").strip())
    except:
        return None


class SymptomDisruptionMonitor:
    """
    Windows-friendly WiFi disruption monitor.

    This does not claim packet-level proof of deauth/DoS. It watches the best
    practical symptoms available from normal Windows APIs:
      1. frequent disconnect/reconnect
      2. same SSID with BSSID/gateway identity changes
      3. sudden signal-quality drop
    """

    def __init__(self, on_update, interval_seconds=5, window_seconds=300):
        self.on_update = on_update
        self.interval = interval_seconds
        self.window_seconds = window_seconds
        self.running = False
        self.thread = None
        self._stop_event = threading.Event()
        self.events = deque()
        self.last_state = None
        self.alerted_level = None

    def start(self):
        if self.running:
            return False, "Disruption Watch is already running."
        self.running = True
        self._stop_event.clear()
        self.events.clear()
        self.last_state = None
        self.alerted_level = None
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()
        return True, "Monitoring WiFi disruption symptoms..."

    def stop(self):
        self.running = False
        self._stop_event.set()

    def snapshot(self):
        self._trim()
        score = 0
        reasons = []

        disconnects = self._count("disconnect")
        reconnects = self._count("reconnect")
        bssid_changes = self._count("bssid_change")
        gateway_changes = self._count("gateway_change")
        signal_drops = self._count("signal_drop")

        if disconnects >= 3 or reconnects >= 3:
            score += 5
            reasons.append(f"Frequent disconnect/reconnect events ({disconnects}/{reconnects})")
        elif disconnects or reconnects:
            score += 1
            reasons.append(f"Recent disconnect/reconnect event ({disconnects}/{reconnects})")

        if bssid_changes:
            score += 3
            reasons.append(f"Same SSID but BSSID changed {bssid_changes} time(s)")
        if gateway_changes:
            score += 3
            reasons.append(f"Gateway identity changed {gateway_changes} time(s)")

        if signal_drops:
            score += 2
            reasons.append(f"Sudden signal drop detected {signal_drops} time(s)")

        if score >= 8:
            status = "high_risk"
            message = "High-risk WiFi disruption symptoms detected."
        elif score >= 5:
            status = "suspicious"
            message = "Suspicious WiFi instability detected."
        elif score >= 2:
            status = "unstable"
            message = "WiFi looks unstable."
        else:
            status = "normal"
            message = "No unusual disruption symptoms detected."

        if reasons:
            message = f"{message} " + " | ".join(reasons)

        return {
            "status": status,
            "score": score,
            "message": message,
            "disconnects": disconnects,
            "reconnects": reconnects,
            "bssid_changes": bssid_changes,
            "gateway_changes": gateway_changes,
            "signal_drops": signal_drops,
            "recent": list(self.events)[-10:],
        }

    def _count(self, kind):
        return sum(1 for event in self.events if event["kind"] == kind)

    def _trim(self):
        cutoff = time.time() - self.window_seconds
        while self.events and self.events[0]["time"] < cutoff:
            self.events.popleft()

    def _record(self, kind, message):
        self.events.append({
            "time": time.time(),
            "kind": kind,
            "message": message,
        })
        self._trim()

    def _read_state(self):
        network = get_current_network()
        gateway = take_gateway_snapshot()
        state = str(network.get("state", "Unknown")).lower()
        connected = "connected" in state and "disconnected" not in state
        ssid = network.get("ssid", "Unknown") if connected else None
        bssid = network.get("bssid", "Unknown") if connected else None
        signal = _signal_value(network.get("signal"))

        return {
            "connected": connected,
            "ssid": ssid,
            "bssid": bssid,
            "signal": signal,
            "gateway_ip": gateway.get("ip") if gateway else None,
            "gateway_mac": gateway.get("mac") if gateway else None,
        }

    def _compare(self, previous, current):
        if not previous:
            return

        if previous["connected"] and not current["connected"]:
            self._record("disconnect", "WiFi disconnected.")

        if not previous["connected"] and current["connected"]:
            self._record("reconnect", f"WiFi reconnected to {current['ssid']}.")

        same_ssid = (
            previous.get("ssid")
            and current.get("ssid")
            and previous["ssid"] == current["ssid"]
        )
        if same_ssid:
            if previous.get("bssid") and current.get("bssid") and previous["bssid"] != current["bssid"]:
                self._record(
                    "bssid_change",
                    f"SSID {current['ssid']} changed BSSID from {previous['bssid']} to {current['bssid']}.",
                )

            prev_gateway = (previous.get("gateway_ip"), previous.get("gateway_mac"))
            curr_gateway = (current.get("gateway_ip"), current.get("gateway_mac"))
            if all(prev_gateway) and all(curr_gateway) and prev_gateway != curr_gateway:
                self._record(
                    "gateway_change",
                    f"Gateway changed from {prev_gateway[0]} / {prev_gateway[1]} "
                    f"to {curr_gateway[0]} / {curr_gateway[1]}.",
                )

        if previous.get("signal") is not None and current.get("signal") is not None:
            drop = previous["signal"] - current["signal"]
            if drop >= 30:
                self._record(
                    "signal_drop",
                    f"Signal dropped sharply from {previous['signal']}% to {current['signal']}%.",
                )

    def _maybe_alert(self, snapshot):
        level = snapshot["status"]
        if level not in {"suspicious", "high_risk"}:
            self.alerted_level = None
            return
        if self.alerted_level == level:
            return
        save_alert("WIFI", f"Possible WiFi disruption: {snapshot['message']}")
        self.alerted_level = level

    def _loop(self):
        while self.running:
            current = self._read_state()
            self._compare(self.last_state, current)
            self.last_state = current
            snapshot = self.snapshot()
            self._maybe_alert(snapshot)
            self.on_update(snapshot)
            self._stop_event.wait(self.interval)
