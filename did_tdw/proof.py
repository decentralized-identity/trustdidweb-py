from abc import ABC, abstractmethod
from datetime import datetime
from hashlib import sha256, sha384
from typing import Optional

import aries_askar
import jsoncanon

from did_history.date_utils import make_timestamp
from did_history.did import DIDUrl
from did_history.key import MultiKey
from did_history.state import DocumentState
from multiformats import multibase

from .const import METHOD_NAME, METHOD_VERSION

DI_SUPPORTED = [
    {
        "cryptosuite": "eddsa-jcs-2022",
        "algorithm": "ed25519",
        "multicodec_name": "ed25519-pub",
        "hash": sha256,
    },
    {
        "cryptosuite": "ecdsa-jcs-2019",
        "algorithm": "p256",
        "multicodec_name": "p256-pub",
        "hash": sha256,
    },
    {
        "cryptosuite": "ecdsa-jcs-2019",
        "algorithm": "p384",
        "multicodec_name": "p384-pub",
        "hash": sha384,
    },
]


class VerifyingKey(ABC):
    @property
    @abstractmethod
    def kid(self) -> Optional[str]: ...

    @property
    @abstractmethod
    def algorithm(self) -> str: ...

    @property
    @abstractmethod
    def multicodec_name(self) -> Optional[str]: ...

    @property
    @abstractmethod
    def public_key_bytes(self) -> bytes: ...

    @property
    def multikey(self) -> MultiKey:
        return MultiKey.from_public_key(self.multicodec_name, self.public_key_bytes)


class SigningKey(VerifyingKey):
    @abstractmethod
    def sign_message(self, message: bytes) -> bytes: ...


class AskarSigningKey(SigningKey):
    def __init__(self, key: aries_askar.Key, *, kid: str = None):
        self.key = key
        self._kid = kid or self.multikey

    @classmethod
    def generate(cls, alg: str) -> "AskarSigningKey":
        return AskarSigningKey(aries_askar.Key.generate(alg))

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
    def multicodec_name(self) -> Optional[str]:
        match self.key.algorithm:
            case aries_askar.KeyAlg.ED25519:
                return "ed25519-pub"
            case aries_askar.KeyAlg.P256:
                return "p256-pub"
            case aries_askar.KeyAlg.P384:
                return "p384-pub"

    @property
    def public_key_bytes(self) -> bytes:
        return self.key.get_public_bytes()

    def sign_message(self, message: bytes) -> bytes:
        return self.key.sign_message(message)


def di_jcs_sign(
    state: DocumentState, sk: SigningKey, *, timestamp: datetime = None, kid: str = None
) -> dict:
    return di_jcs_sign_raw(
        state.document,
        sk,
        purpose="authentication",
        challenge=state.version_id,
        timestamp=timestamp,
        kid=kid,
    )


def di_jcs_sign_raw(
    document: dict,
    sk: SigningKey,
    purpose: str,
    *,
    challenge: str = None,
    timestamp: datetime = None,
    kid: str = None,
) -> dict:
    alg = sk.algorithm
    suite = None
    for opt in DI_SUPPORTED:
        if opt["algorithm"] == alg:
            suite = opt
            break
    if kid is None:
        if not sk.kid:
            raise ValueError("Missing key ID for signing")
        kid = f"did:key:{sk.kid}#{sk.kid}"
    if not suite:
        raise ValueError(f"Unsupported key algorithm: {alg}")
    proof = {
        "type": "DataIntegrityProof",
        "cryptosuite": suite["cryptosuite"],
        "verificationMethod": kid,
        "created": make_timestamp(timestamp)[1],
        "proofPurpose": purpose,
    }
    if challenge:
        proof["challenge"] = challenge
    hash_fn = suite["hash"]
    data_hash = hash_fn(jsoncanon.canonicalize(document)).digest()
    options_hash = hash_fn(jsoncanon.canonicalize(proof)).digest()
    sig_input = data_hash + options_hash
    proof["proofValue"] = multibase.encode(sk.sign_message(sig_input), "base58btc")
    return proof


def di_jcs_verify(state: DocumentState, proof: dict, method: dict):
    if proof.get("type") != "DataIntegrityProof":
        raise ValueError("Unsupported proof type")
    if proof.get("proofPurpose") != "authentication":
        raise ValueError("Expected proof purpose: 'authentication'")
    created = proof.get("created")
    if created:
        make_timestamp(created)  # validate timestamp formatting only

    (codec, key_bytes) = MultiKey(method.get("publicKeyMultibase")).decode()
    suite_name = proof.get("cryptosuite")
    suite = None
    for opt in DI_SUPPORTED:
        if opt["cryptosuite"] == suite_name and opt["multicodec_name"] == codec.name:
            suite = opt
            break
    if not suite:
        raise ValueError(f"Unsupported cryptosuite for proof: {suite_name}/{codec}")
    key = aries_askar.Key.from_public_bytes(suite["algorithm"], key_bytes)
    hash_fn = suite["hash"]
    data_hash = hash_fn(jsoncanon.canonicalize(state.document)).digest()
    proof = proof.copy()
    signature = multibase.decode(proof.pop("proofValue"))
    options_hash = hash_fn(jsoncanon.canonicalize(proof)).digest()
    sig_input = data_hash + options_hash
    if not key.verify_signature(sig_input, signature):
        raise ValueError("Invalid signature for proof")


def check_document_id_format(doc_id: str, scid: str):
    url = DIDUrl.decode(doc_id)
    if url.root != url:
        raise ValueError("Document identifier must be a DID")
    if url.method != METHOD_NAME:
        raise ValueError(f"Expected DID method to be '{METHOD_NAME}'")
    check_scid, *path = url.identifier.split(":")
    if check_scid != scid:
        raise ValueError("SCID must be the first component of the method-specific ID")
    if not path:
        raise ValueError("Missing domain from method-specific ID")
    domain, *path = path
    check_valid_domain(domain)


def check_valid_domain(domain: str):
    domain = domain.split(".")
    if len(domain) < 2 or not all(len(s) >= 2 and s[:1].isalpha() for s in domain):
        raise ValueError("Invalid domain name in method-specific ID")


def verify_proofs(state: DocumentState, prev_state: DocumentState, is_final: bool):
    doc_id = state.document_id
    proofs = state.proofs
    if not proofs:
        raise ValueError("Missing history version proof(s)")
    update_keys = (prev_state or state).update_keys
    for proof in proofs:
        method_id = proof.get("verificationMethod")
        if not isinstance(method_id, str):
            raise ValueError(f"Invalid proof verification method: {type(method_id)}")
        if "#" not in method_id:
            raise ValueError("Expected verification method reference with fragment")
        if method_id.startswith("#"):
            method_fragment = method_id[1:]
            method_id = doc_id + method_id
            method_ctl = doc_id
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
        if method_key not in update_keys:
            raise ValueError(f"Cannot resolve verification method: {method_id}")
        vmethod = {"type": "Multikey", "publicKeyMultibase": method_key}
        di_jcs_verify(
            state=state,
            proof=proof,
            method=vmethod,
        )


def verify_params(state: DocumentState, prev_state: DocumentState, is_final: bool):
    check_document_id_format(state.document_id, state.params["scid"])
    method = state.params.get("method")
    if method != f"did:{METHOD_NAME}:{METHOD_VERSION}":
        raise ValueError(f"Unexpected value for method parameter: {method}")


def verify_all(state: DocumentState, prev_state: DocumentState, is_final: bool):
    # FIXME add resolution context instead of is_final flag?
    verify_params(state, prev_state, is_final)
    if state.version_id == 1 or state.is_auth_event or is_final:
        verify_proofs(state, prev_state, is_final)
