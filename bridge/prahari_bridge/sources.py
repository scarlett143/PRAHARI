"""Telemetry sources for the aircraft agent.

Two implementations share one interface so the encrypted link can be exercised with or
without an autopilot present:

* :class:`MavlinkSource` -- a real MAVLink 2 stream from ArduPilot/PX4 SITL or hardware.
* :class:`SyntheticSource` -- a deterministic synthetic flight, for CI and for demos on a
  machine with no autopilot installed.

Both emit plain dictionaries. The agent serialises and encrypts them; nothing here ever
touches the network path to the server.
"""
from __future__ import annotations

import math
import time
from abc import ABC, abstractmethod
from base64 import b64encode
from typing import Iterator


class TelemetrySource(ABC):
    """A stream of decoded telemetry frames."""

    @abstractmethod
    def frames(self) -> Iterator[dict]:
        """Yield telemetry frames until the source is closed."""

    def send_command(self, command: dict) -> bool:
        """Deliver a decrypted uplink command toward the autopilot.

        Returns True when the command was accepted by the underlying transport.
        """
        return False

    def close(self) -> None:  # pragma: no cover - trivial default
        pass


class SyntheticSource(TelemetrySource):
    """A repeatable orbit, useful when no autopilot is available."""

    def __init__(
        self,
        *,
        rate_hz: float = 2.0,
        centre: tuple[float, float] = (12.9716, 77.5946),
        radius_m: float = 400.0,
        duration_s: float | None = None,
    ):
        self.interval = 1.0 / max(rate_hz, 0.1)
        self.centre = centre
        self.radius_m = radius_m
        self.duration_s = duration_s
        self._accepted: list[dict] = []

    @property
    def accepted_commands(self) -> list[dict]:
        return list(self._accepted)

    def send_command(self, command: dict) -> bool:
        self._accepted.append(command)
        return True

    def frames(self) -> Iterator[dict]:
        started = time.monotonic()
        tick = 0
        while True:
            elapsed = time.monotonic() - started
            if self.duration_s is not None and elapsed >= self.duration_s:
                return
            angle = (elapsed / 30.0) * 2 * math.pi
            # ~111 320 m per degree of latitude; longitude scaled by cos(lat).
            lat = self.centre[0] + (self.radius_m * math.cos(angle)) / 111_320.0
            lon = self.centre[1] + (self.radius_m * math.sin(angle)) / (
                111_320.0 * math.cos(math.radians(self.centre[0]))
            )
            yield {
                "type": "telemetry",
                "source": "synthetic",
                "seq": tick,
                "t": time.time(),
                "lat": round(lat, 7),
                "lon": round(lon, 7),
                "alt_m": round(120 + 10 * math.sin(angle * 2), 2),
                "heading_deg": round((math.degrees(angle) + 90) % 360, 1),
                "groundspeed_ms": round(18 + 2 * math.cos(angle), 2),
                "battery_pct": max(5, 100 - int(elapsed / 6)),
                "mode": "AUTO",
                "armed": True,
            }
            tick += 1
            time.sleep(self.interval)


class MavlinkSource(TelemetrySource):
    """Real MAVLink 2 from SITL (``udpin:127.0.0.1:14550``) or a serial radio."""

    #: Messages worth forwarding over a bandwidth-constrained C2 link.
    DEFAULT_MESSAGES = (
        "HEARTBEAT",
        "GLOBAL_POSITION_INT",
        "ATTITUDE",
        "VFR_HUD",
        "SYS_STATUS",
        "GPS_RAW_INT",
        "STATUSTEXT",
    )

    def __init__(
        self,
        device: str = "udpin:127.0.0.1:14550",
        *,
        messages: tuple[str, ...] = DEFAULT_MESSAGES,
        include_raw: bool = True,
        source_system: int = 255,
    ):
        try:
            from pymavlink import mavutil
        except ImportError as exc:  # pragma: no cover - depends on optional extra
            raise RuntimeError(
                "pymavlink is not installed. Install bridge/requirements.txt, or run with "
                "--source synthetic to exercise the link without an autopilot."
            ) from exc
        self._mavutil = mavutil
        self.device = device
        self.messages = messages
        self.include_raw = include_raw
        self._connection = mavutil.mavlink_connection(device, source_system=source_system)
        self._seq = 0
        self._closed = False

    def wait_heartbeat(self, timeout: float = 30.0) -> bool:
        return self._connection.wait_heartbeat(timeout=timeout) is not None

    def frames(self) -> Iterator[dict]:
        while not self._closed:
            message = self._connection.recv_match(
                type=list(self.messages), blocking=True, timeout=1.0
            )
            if message is None:
                continue
            payload = {
                "type": "mavlink",
                "source": "sitl",
                "seq": self._seq,
                "t": time.time(),
                "message": message.get_type(),
                "fields": _jsonable(message.to_dict()),
            }
            if self.include_raw:
                # Carrying the wire frame makes this a true encrypted MAVLink tunnel
                # rather than a re-encoding of decoded fields.
                raw = message.get_msgbuf()
                payload["raw_b64"] = b64encode(bytes(raw)).decode("ascii")
            self._seq += 1
            yield payload

    def send_command(self, command: dict) -> bool:
        """Inject a decrypted uplink command into the autopilot stream."""
        raw_b64 = command.get("raw_b64")
        if raw_b64:
            from base64 import b64decode

            self._connection.write(b64decode(raw_b64))
            return True

        name = command.get("command")
        if name == "ARM" or name == "DISARM":
            self._connection.mav.command_long_send(
                self._connection.target_system,
                self._connection.target_component,
                self._mavutil.mavlink.MAV_CMD_COMPONENT_ARM_DISARM,
                0,
                1 if name == "ARM" else 0,
                0, 0, 0, 0, 0, 0,
            )
            return True
        if name == "SET_MODE" and "mode" in command:
            self._connection.set_mode(command["mode"])
            return True
        if name == "RTL":
            self._connection.set_mode("RTL")
            return True
        return False

    def close(self) -> None:
        self._closed = True
        try:
            self._connection.close()
        except Exception:  # pragma: no cover - best effort
            pass


def _jsonable(value):
    """MAVLink dicts carry bytes and enum wrappers that json cannot encode directly."""
    if isinstance(value, dict):
        return {key: _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    if isinstance(value, (bytes, bytearray)):
        return value.decode("utf-8", "replace")
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def build_source(kind: str, **kwargs) -> TelemetrySource:
    if kind == "synthetic":
        return SyntheticSource(
            **{k: v for k, v in kwargs.items() if k in {"rate_hz", "duration_s", "centre", "radius_m"}}
        )
    if kind == "sitl":
        return MavlinkSource(
            **{k: v for k, v in kwargs.items() if k in {"device", "messages", "include_raw"}}
        )
    raise ValueError(f"unknown telemetry source {kind!r}; expected 'sitl' or 'synthetic'")
