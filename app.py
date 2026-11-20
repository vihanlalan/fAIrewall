"""Vercel entry point (FastAPI preset): the fAIrewall Lab. See deploy/vercel/README.md.

Locally, run the Lab with `python -m fairewall.lab` instead.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from fairewall.vercel import build_app  # noqa: E402

app = build_app()
