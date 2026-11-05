"""
FastAPI implementation of cert-info tool.
"""

import uvicorn
from fastapi import FastAPI, Path, Query

from src.certificate_info import CertificateInformation

app = FastAPI(title="cert-info API", description="Certificate chain verification API")


@app.get("/certinfo/{domain}", response_model=dict)
def get_cert_info(
    domain: str = Path(..., description="Domain to analyze"),
    showcert: bool = Query(False, description="Show certificate fields"),
    force: bool = Query(False, description="Force analysis if unreachable"),
) -> dict:
    """Analyze the certificate chain of a domain."""
    return CertificateInformation().analyze(domain, showcert, force)


@app.get("/health")
def health() -> dict:
    """Liveness check used by the Docker HEALTHCHECK."""
    return {"status": "ok"}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=6010, workers=4)
