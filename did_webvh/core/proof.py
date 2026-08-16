"""Document proof generation and verification."""

from copy import deepcopy
from datetime import datetime
from hashlib import sha256, sha384
from typing import Optional

import jcs
from multiformats import multibase

from ..askar import AskarVerifyingKey
from .date_utils import make_timestamp
from .types import SigningKey, VerifyingKey

# Supported Data Integrity suites
DI_SUPPORTED = [
    {
        "cryptosuite": "eddsa-jcs-2022",
        "multicodec_name": "ed25519-pub",
        "hash": sha256,
    },
    {
        "cryptosuite": "ecdsa-jcs-2019",
        "multicodec_name": "p256-pub",
        "hash": sha256,
    },
    {
        "cryptosuite": "ecdsa-jcs-2019",
        "multicodec_name": "p384-pub",
        "hash": sha384,
    },
]


def di_jcs_sign(
    proof_input: dict,
    sk: SigningKey,
    *,
    purpose: str = "assertionMethod",
    challenge: Optional[str] = None,
    timestamp: Optional[datetime] = None,
    kid: Optional[str] = None,
) -> dict:
    """Sign a dictionary value with a signing key."""
    codec = sk.multicodec_name
    suite = None
    for opt in DI_SUPPORTED:
        if opt["multicodec_name"] == codec:
            suite = opt
            break
    if kid is None:
        if not sk.kid:
            raise ValueError("Missing key ID for signing")
        kid = sk.kid
        if not kid.startswith("did:"):
            kid = f"did:key:{kid}#{kid}"
    if not suite:
        raise ValueError(f"Unsupported key type: {codec}")
    options = {
        "type": "DataIntegrityProof",
        "cryptosuite": suite["cryptosuite"],
        "verificationMethod": kid,
        "created": make_timestamp(timestamp)[1],
        "proofPurpose": purpose,
    }
    if challenge:
        options["challenge"] = challenge
    hash_fn = suite["hash"]
    data_hash = hash_fn(di_jcs_canonicalize_input(proof_input)).digest()
    options_hash = hash_fn(jcs.canonicalize(options)).digest()
    sig_input = options_hash + data_hash
    options["proofValue"] = multibase.encode(sk.sign_message(sig_input), "base58btc")
    return options


def di_jcs_verify(proof_input: dict, proof: dict, method: VerifyingKey | dict):
    """Verify a proof against a dictionary value."""
    if proof.get("type") != "DataIntegrityProof":
        raise ValueError("Unsupported proof type")
    if "proofValue" not in proof or not isinstance(proof["proofValue"], str):
        raise ValueError("Missing or invalid 'proofValue'")
    created = proof.get("created")
    if created:
        make_timestamp(created)  # validate timestamp formatting only

    if isinstance(method, dict):
        vkey = AskarVerifyingKey.from_multikey(method.get("publicKeyMultibase"))
    else:
        vkey = method
    codec = vkey.multicodec_name

    suite_name = proof.get("cryptosuite")
    suite = None
    for opt in DI_SUPPORTED:
        if opt["cryptosuite"] == suite_name and opt["multicodec_name"] == codec:
            suite = opt
            break
    if not suite:
        raise ValueError(f"Unsupported cryptosuite for proof: {suite_name}/{codec}")

    hash_fn = suite["hash"]
    data_hash = hash_fn(di_jcs_canonicalize_input(proof_input)).digest()
    proof = proof.copy()
    signature = multibase.decode(proof.pop("proofValue"))
    options_hash = hash_fn(jcs.canonicalize(proof)).digest()
    sig_input = options_hash + data_hash
    vkey.verify_signature(sig_input, signature)


def di_jcs_canonicalize_input(proof_input: dict) -> bytes:
    """Canonicalize a proof input according to JCS."""
    proof_input = deepcopy(proof_input)
    if "proof" in proof_input:
        del proof_input["proof"]
    return jcs.canonicalize(proof_input)


def resolve_did_key(method_id: str) -> dict:
    """Resolve a public key from a did:key key reference."""
    if not isinstance(method_id, str):
        raise ValueError(f"Invalid proof verification method: {type(method_id)}")
    if "#" not in method_id:
        raise ValueError("Expected verification method reference with fragment")
    if method_id.startswith("#"):
        raise ValueError("Relative reference not supported for verification method")
    else:
        fpos = method_id.find("#")
        method_ctl = method_id[:fpos]
        fpos = fpos + 1
        method_fragment = method_id[fpos:]
    if not method_ctl.startswith("did:key:"):
        raise ValueError(f"Unsupported verification method: {method_id}")
    method_key = method_ctl.removeprefix("did:key:")
    if method_key != method_fragment:
        raise ValueError(
            f"Verification method fragment does not match public key: {method_id}"
        )
    return {"type": "Multikey", "publicKeyMultibase": method_key}
