"""python -m fairewall.lab: run the Lab (respects PORT, as Cloud Run sets it)."""
import argparse
import os


def main() -> None:
    ap = argparse.ArgumentParser(description="fAIrewall Lab")
    ap.add_argument("--host", default=os.environ.get("HOST", "127.0.0.1"))
    ap.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8080")))
    ap.add_argument("--data", default=None, help="Data directory or postgresql:// URL "
                                                 "(else FAIREWALL_DATABASE_URL or LAB_DATA_DIR)")
    job = ap.add_mutually_exclusive_group()
    job.add_argument("--migrate", action="store_true",
                     help="Create every table and schema, seed the synthetic evidence, then exit (deploy step)")
    job.add_argument("--anchor", action="store_true", help="Seal and publish Lab audit records, then exit")
    args = ap.parse_args()
    if args.data:
        os.environ["LAB_DATA_DIR" if "://" not in args.data else "FAIREWALL_DATABASE_URL"] = args.data
    if args.anchor:
        from .runtime import run_anchor_from_env
        raise SystemExit(run_anchor_from_env())
    if args.migrate:
        from .runtime import from_env
        lab = from_env()
        print("[fAIrewall Lab] schemas ready; synthetic evidence batches: %d" % len(lab.anchorer.anchors()))
        return
    import uvicorn
    from . import create_app
    app = create_app()
    print("[fAIrewall Lab] http://%s:%d" % ("127.0.0.1" if args.host in ("0.0.0.0", "::") else args.host, args.port))
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
