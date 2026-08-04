"""Command line entry point: ``python -m prahari_bridge``."""
from __future__ import annotations

import argparse
import logging
import os
import signal
import sys

from .agent import AgentConfig, BridgeAgent
from .api import PrahariClient
from .link import LinkError
from .sources import build_source


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="prahari-bridge",
        description=(
            "Encrypted MAVLink bridge. Wraps every telemetry frame in a PRAHARI "
            "AES-256-GCM envelope derived from an X25519 + ML-KEM-768 hybrid session."
        ),
    )
    parser.add_argument(
        "--api", default=os.getenv("PRAHARI_API_URL", "http://localhost:8000"),
        help="PRAHARI API base URL (env: PRAHARI_API_URL)",
    )
    parser.add_argument(
        "--callsign", default=os.getenv("PRAHARI_CALLSIGN"), required=not os.getenv("PRAHARI_CALLSIGN"),
        help="aircraft callsign as provisioned (env: PRAHARI_CALLSIGN)",
    )
    parser.add_argument(
        "--enrollment-token", default=os.getenv("PRAHARI_ENROLLMENT_TOKEN"),
        help="single-use provisioning token, required only on first run "
             "(env: PRAHARI_ENROLLMENT_TOKEN)",
    )
    parser.add_argument(
        "--channel-id", default=os.getenv("PRAHARI_CHANNEL_ID"),
        help="link channel id from POST /api/v2/fleet/uavs/<callsign>/link "
             "(env: PRAHARI_CHANNEL_ID)",
    )
    parser.add_argument(
        "--keystore", default=os.getenv("PRAHARI_KEYSTORE", "./uav-keystore.json"),
        help="path to the on-aircraft key file (env: PRAHARI_KEYSTORE)",
    )
    parser.add_argument(
        "--source", choices=("sitl", "synthetic"), default=os.getenv("PRAHARI_SOURCE", "sitl"),
        help="telemetry source: real MAVLink from SITL/hardware, or a synthetic flight",
    )
    parser.add_argument(
        "--device", default=os.getenv("PRAHARI_MAVLINK_DEVICE", "udpin:127.0.0.1:14550"),
        help="MAVLink endpoint for --source sitl (env: PRAHARI_MAVLINK_DEVICE)",
    )
    parser.add_argument("--rate-hz", type=float, default=2.0, help="synthetic frame rate")
    parser.add_argument(
        "--max-frames", type=int, default=None, help="stop after N frames (for smoke tests)"
    )
    parser.add_argument(
        "--log-level", default=os.getenv("PRAHARI_LOG_LEVEL", "INFO"),
        choices=("DEBUG", "INFO", "WARNING", "ERROR"),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )
    log = logging.getLogger("prahari_bridge")

    source = build_source(args.source, device=args.device, rate_hz=args.rate_hz)
    config = AgentConfig(
        base_url=args.api,
        callsign=args.callsign,
        keystore_path=args.keystore,
        enrollment_token=args.enrollment_token,
        channel_id=args.channel_id,
    )

    with PrahariClient(args.api) as client:
        agent = BridgeAgent(config, source, client)

        def handle_signal(signum, _frame):
            log.info("signal %s received; shutting down", signum)
            agent.stop()

        signal.signal(signal.SIGINT, handle_signal)
        signal.signal(signal.SIGTERM, handle_signal)

        try:
            agent.bootstrap()
            agent.run(max_frames=args.max_frames)
        except LinkError as error:
            log.error("%s", error)
            return 2
        except KeyboardInterrupt:  # pragma: no cover
            agent.stop()

        log.info(
            "shut down after %d encrypted frames sent, %d commands received",
            agent.frames_sent,
            agent.commands_received,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
