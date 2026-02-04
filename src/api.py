"""
FastAPI implementation of cert-info tool.
"""

import json
import uvicorn
from fastapi import FastAPI, Path, Query
from pydantic import BaseModel

from src.certificate_info import CertificateInformation

app = FastAPI(title="cert-info API", description="Certificate chain verification API")

class CertResponse(BaseModel):
    """Response model matching CLI output."""
    result: dict  # Adjust based on analyze() return type

@app.get("/certinfo/{domain}", response_model=dict)
def get_cert_info(
    domain: str = Path(..., description="Domain to analyze"),
    showcert: bool = Query(False, description="Show certificate fields"),
    force: bool = Query(False, description="Force analysis if unreachable"),
):
    """
    Analyze certificate chain for a domain.
    """
    # Initialize the CertificateInformation class
    cert_info = CertificateInformation()
    # Run the analysis
    result = cert_info.analyze(domain, showcert, force)
    # Check if the result is an error dictionary
    if isinstance(result, dict) and "error" in result:
        return result
    # Convert to dict
    result = json.loads(result)
    # Return the result
    return result

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=6010)
