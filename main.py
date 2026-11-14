from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from cryptography.hazmat.primitives import serialization
import json
import base64
from pydantic import BaseModel
from cryptography.exceptions import InvalidSignature
import binascii

app = FastAPI(
    title="ProofID API",
    description="Privacy-preserving identity verification infrastructure",
    version="1.0.0"
)
verification_requests = {}
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Load the issuer's private key
import os

private_key_data = os.getenv("ISSUER_PRIVATE_KEY")

if private_key_data:
    private_key = serialization.load_pem_private_key(
        private_key_data.encode(),
        password=None
    )
else:
    with open("issuer_private.pem", "rb") as file:
        private_key = serialization.load_pem_private_key(
            file.read(),
            password=None
        )
    
    class VerifyRequest(BaseModel):
        credential: dict
        signature: str
    class VerificationRequest(BaseModel):
        exchange_name: str
        requested_claim: str

# Load the issuer's public key
with open("issuer_public.pem", "rb") as file:
    public_key = serialization.load_pem_public_key(file.read())


@app.get("/")
def home():
    return {
        "message": "Welcome to ProofID",
        "status": "running"
    }


@app.post("/issue-credential")
def issue_credential():
    credential = {
        "credential_type": "KYC",
        "kyc_verified": True,
        "country": "NG",
        "assurance_level": "basic"
    }

    # Convert the credential into bytes
    credential_bytes = json.dumps(
        credential,
        sort_keys=True
    ).encode("utf-8")

    # Sign the credential
    signature = private_key.sign(credential_bytes)

    return {
        "credential": credential,
        "signature": base64.b64encode(signature).decode("utf-8"),
        "issuer": "ProofID Test Issuer"
    }
@app.post("/verify-credential")
def verify_credential(request: VerifyRequest):

    credential_bytes = json.dumps(
        request.credential,
        sort_keys=True
    ).encode("utf-8")

    try:
        signature_bytes = base64.b64decode(
            request.signature,
            validate=True
        )

        public_key.verify(
            signature_bytes,
            credential_bytes
        )

        return {
            "verified": True,
            "message": "Credential is authentic"
        }

    except (InvalidSignature, ValueError, binascii.Error):
        return {
            "verified": False,
            "message": "Credential verification failed"
        }

@app.post("/create-verification-request")
def create_verification_request(request: VerificationRequest):

    request_id = "REQ-" + base64.b64encode(
        __import__("secrets").token_bytes(6)
    ).decode("utf-8").rstrip("=")

    new_request = {
        "request_id": request_id,
        "exchange": request.exchange_name,
        "requested_claim": request.requested_claim,
        "status": "pending"
    }

    verification_requests[request_id] = new_request

    return {
        **new_request,
        "message": "Verification request created successfully"
    }

@app.get("/verification-requests")
def get_verification_requests():

    return {
        "requests": list(verification_requests.values())
    }
@app.post("/verification-requests/{request_id}/decision")
def decide_verification_request(request_id: str, decision: str):

    if request_id not in verification_requests:
        return {
            "success": False,
            "message": "Verification request not found"
        }

    if decision not in ["approved", "rejected"]:
        return {
            "success": False,
            "message": "Invalid decision"
        }

    verification_requests[request_id]["status"] = decision

    return {
        "success": True,
        "request": verification_requests[request_id],
        "message": "Request decision updated successfully"
    }

@app.post("/verification-requests/{request_id}/verify")
def verify_approved_request(request_id: str, request: VerifyRequest):

    if request_id not in verification_requests:
        return {
            "success": False,
            "message": "Verification request not found"
        }

    saved_request = verification_requests[request_id]

    if saved_request["status"] != "approved":
        return {
            "success": False,
            "message": "User has not approved this request"
        }

    credential_bytes = json.dumps(
        request.credential,
        sort_keys=True
    ).encode("utf-8")

    try:
        signature_bytes = base64.b64decode(
            request.signature,
            validate=True
        )

        public_key.verify(
            signature_bytes,
            credential_bytes
        )

    except (InvalidSignature, ValueError, binascii.Error):
        return {
            "success": False,
            "verified": False,
            "message": "Credential verification failed"
        }

    requested_claim = saved_request["requested_claim"]

    if requested_claim not in request.credential:
        return {
            "success": False,
            "message": "Requested claim not found"
        }

    return {
        "success": True,
        "request_id": request_id,
        "verified": True,
        "claim": requested_claim,
        "value": request.credential[requested_claim],
        "message": "Approved credential successfully verified"
    }
