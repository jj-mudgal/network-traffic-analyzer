"""Dev entry point for the Network Traffic Analyzer."""

import argparse
import os

from dotenv import load_dotenv

load_dotenv()

import database  # noqa: E402
from app import create_app  # noqa: E402
from backend.security import (  # noqa: E402
    start_detection_loop,
    stop_detection_loop,
)


def main():
    parser = argparse.ArgumentParser(
        description="Network Traffic Analyzer"
    )
    parser.add_argument(
        "--seed",
        action="store_true",
        help="Insert sample packets if the table is empty",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.getenv("PORT", 5000)),
    )
    args = parser.parse_args()

    database.init_db()

    if args.seed:
        database.seed_sample_data()

    # Start one background worker for periodic security detection.
    start_detection_loop()

    try:
        create_app().run(
            host="0.0.0.0",
            port=args.port,
            debug=False,
            use_reloader=False,
        )
    finally:
        stop_detection_loop()


if __name__ == "__main__":
    main()