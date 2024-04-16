from abc import ABC, abstractmethod
from datetime import datetime
from hashlib import sha256
from typing import Optional

import aries_askar
import jsoncanon

from did_history.date_utils import make_timestamp
from did_history.did import DIDUrl
from did_history.state import DocumentState
from multiformats import multibase, multicodec

from .const import METHOD_NAME


class VerifyingKey(ABC):
    @property
    @abstractmethod
    def kid(self) -> Optional[str]: ...

    @property
    @abstractmethod
    def algorithm(self) -> str: ...

    @property
    @abstractmethod
    def public_key_bytes(self) -> bytes: ...


class SigningKey(VerifyingKey):
    @abstractmethod
    def sign_message(self, message: bytes) -> bytes: ...


class AskarSigningKey(SigningKey):
    def __init__(self, key: aries_askar.Key, *, kid: str = None):
        self._kid = kid
        self.key = key

    @property
    def algorithm(self) -> str:
        return self.key.algorithm.value

    @property
    def kid(self) -> Optional[str]:
        return self._kid

    @kid.setter
    def kid(self, value: str):
        self._kid = value

    @property
    def public_key_bytes(self) -> bytes:
        return self.key.get_public_bytes()

    def sign_message(self, message: bytes) -> bytes:
        return self.key.sign_message(message)


def eddsa_jcs_sign(
    state: DocumentState, sk: SigningKey, timestamp: datetime = None
) -> dict:
    return eddsa_jcs_sign_raw(
        state.document,
        sk,
        purpose="authentication",
        challenge=state.version_hash,
        timestamp=timestamp,
    )


def eddsa_jcs_sign_raw(
    document: dict,
    sk: SigningKey,
    purpose: str,
    challenge: str = None,
    timestamp: datetime = None,
) -> dict:
    proof = {
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-jcs-2022",
        "verificationMethod": sk.kid,
        "created": make_timestamp(timestamp)[1],
        "proofPurpose": purpose,
    }
    if challenge:
        proof["challenge"] = challenge
    data_hash = sha256(jsoncanon.canonicalize(document)).digest()
    options_hash = sha256(jsoncanon.canonicalize(proof)).digest()
    sig_input = data_hash + options_hash
    proof["proofValue"] = multibase.encode(sk.sign_message(sig_input), "base58btc")
    return proof


def eddsa_jcs_verify(state: DocumentState, proof: dict, method: dict):
    if proof.get("type") != "DataIntegrityProof":
        raise ValueError("Unsupported proof type")
    if proof.get("proofPurpose") != "authentication":
        raise ValueError("Expected proof purpose: 'authentication'")
    if proof.get("cryptosuite") != "eddsa-jcs-2022":
        raise ValueError("Unsupported cryptosuite for proof")
    key_mc = multibase.decode(method.get("publicKeyMultibase"))
    (codec, key_bytes) = multicodec.unwrap(key_mc)
    if codec.name != "ed25519-pub":
        raise ValueError(f"Unsupported key type: {codec.name}")
    key = aries_askar.Key.from_public_bytes("ed25519", key_bytes)
    data_hash = sha256(jsoncanon.canonicalize(state.document)).digest()
    proof = proof.copy()
    signature = multibase.decode(proof.pop("proofValue"))
    options_hash = sha256(jsoncanon.canonicalize(proof)).digest()
    sig_input = data_hash + options_hash
    if not key.verify_signature(sig_input, signature):
        raise ValueError("Invalid signature for proof")


def verify_document_id(doc_id: str, scid: str):
    url = DIDUrl.decode(doc_id)
    if url.root != url:
        raise ValueError("Document identifier must be a DID")
    if url.method != METHOD_NAME:
        raise ValueError(f"Expected DID method to be '{METHOD_NAME}'")
    domain, *path = url.identifier.split(":")
    domain = domain.split(".")
    dom_c = domain.count(scid)
    path_c = path.count(scid)
    if dom_c + path_c != 1:
        raise ValueError("SCID must occur exactly once in document id")
    if dom_c and scid in domain[-2:]:
        raise ValueError("SCID must be a subdomain when it occurs in the domain name")


def verify_proofs(state: DocumentState, prev_state: DocumentState = None):
    doc_id = state.document_id
    proofs = state.proofs
    if not proofs:
        raise ValueError("Missing history version proof(s)")
    controllers = (prev_state or state).controllers()
    auth_keys = (prev_state or state).authentication_keys()
    for proof in proofs:
        method_id = proof.get("verificationMethod")
        if not isinstance(method_id, str):
            raise ValueError(f"Invalid proof verification method: {type(method_id)}")
        if "#" not in method_id:
            raise ValueError("Expected verification method reference with fragment")
        if method_id.startswith("#"):
            method_id = doc_id + method_id
            method_ctl = doc_id
        else:
            fpos = method_id.find("#")
            method_ctl = method_id[:fpos]
        if method_id not in auth_keys:
            raise ValueError(f"Cannot resolve verification method: {method_id}")
        if method_ctl not in controllers:
            raise ValueError(f"Controller is not authorized: {method_ctl}")
        vmethod = auth_keys[method_id]
        eddsa_jcs_verify(
            state=state,
            proof=proof,
            method=vmethod,
        )


def verify_all(state: DocumentState, prev_state: DocumentState = None):
    verify_document_id(state.document_id, state.params["scid"])
    verify_proofs(state, prev_state)
