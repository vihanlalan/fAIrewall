"""The fAIrewall Lab: a judge-facing sandbox that runs the real SDK end to end.

    python -m fairewall.lab --port 8080            # local, recorded agent, no Google credentials
    fairewall lab --port 8080 --data lab-data

See deploy/gcp/README.md for running it on Google Cloud with Vertex AI Gemini,
Model Armor, Cloud SQL, two gateways and scheduled anchoring.
"""

from .runtime import Lab, LabError, from_env


def create_app(lab=None):
    from .app import create_lab_app
    return create_lab_app(lab or from_env())


__all__ = ["Lab", "LabError", "from_env", "create_app"]
