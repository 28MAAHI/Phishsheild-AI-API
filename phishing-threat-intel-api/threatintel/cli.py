"""Command line interface.

    python -m threatintel init-db                 create tables (dev; use `alembic upgrade head` for PostgreSQL)
    python -m threatintel sources                 show sources and whether they are configured
    python -m threatintel collect [-s NAME] [--force]   collect once, print a JSON summary
    python -m threatintel scheduler               run periodic collection (blocking)
    python -m threatintel serve [--host H] [--port P]   run the API with uvicorn
"""

import argparse
import json
import sys

from .config import get_settings
from .db import session as db_session
from .logging_config import configure_logging


def _setup():
    settings = get_settings()
    configure_logging(settings.log_level, settings.log_format, settings.secret_values())
    db_session.init_engine(settings.database_url, settings.database_echo)
    return settings


def cmd_init_db(_args) -> int:
    from .db import models  # noqa: F401  (register tables)
    _setup()
    db_session.Base.metadata.create_all(db_session.get_engine())
    print("Database tables created (or already present).")
    return 0


def cmd_sources(_args) -> int:
    from .collectors.registry import build_collectors
    settings = get_settings()
    enabled = set(settings.enabled_source_names)
    for name, c in sorted(build_collectors(settings).items()):
        problem = c.configuration_problem()
        state = "enabled " if name in enabled else "disabled"
        print(f"{name:<12} {state}  {'ok' if problem is None else 'NOT CONFIGURED: ' + problem}"
              f"  (min interval {c.min_interval_minutes} min)  {c.homepage}")
    return 0


def cmd_collect(args) -> int:
    from .services.collection import CollectionService, UnknownSourceError
    settings = _setup()
    service = CollectionService(settings)
    try:
        results = service.collect(args.source or None, trigger="cli", force=args.force)
    except UnknownSourceError as e:
        print(f"error: {e}. Enabled sources: {', '.join(service.enabled_names()) or '(none)'}", file=sys.stderr)
        return 2
    print(json.dumps([r.to_dict() for r in results], indent=2, default=str))
    return 1 if any(r.status == "failed" for r in results) else 0


def cmd_scheduler(_args) -> int:
    from .scheduler import build_scheduler
    from .services.collection import CollectionService
    settings = _setup()
    scheduler = build_scheduler(settings, CollectionService(settings), blocking=True)
    try:
        scheduler.start()
    except (KeyboardInterrupt, SystemExit):
        pass
    return 0


def cmd_serve(args) -> int:
    import uvicorn
    settings = get_settings()
    configure_logging(settings.log_level, settings.log_format, settings.secret_values())
    uvicorn.run("threatintel.api.app:app", host=args.host, port=args.port, log_config=None,
                proxy_headers=settings.trust_proxy_headers)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m threatintel", description="Phishing URL threat-intelligence collector/API")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init-db", help="create database tables").set_defaults(func=cmd_init_db)
    sub.add_parser("sources", help="list sources and configuration status").set_defaults(func=cmd_sources)

    p = sub.add_parser("collect", help="run collection once")
    p.add_argument("-s", "--source", action="append", help="source name (repeatable); default: all enabled")
    p.add_argument("--force", action="store_true", help="ignore per-source minimum interval")
    p.set_defaults(func=cmd_collect)

    sub.add_parser("scheduler", help="run periodic collection until stopped").set_defaults(func=cmd_scheduler)

    p = sub.add_parser("serve", help="run the REST API")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8000)
    p.set_defaults(func=cmd_serve)

    args = parser.parse_args(argv)
    return args.func(args)
