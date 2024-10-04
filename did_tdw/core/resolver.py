"""Support for DID resolution."""

import json
from collections.abc import AsyncIterator
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Union

from .date_utils import make_timestamp
from .loader import VerifyState, load_history


class ResolutionError(Exception):
    """An error raised during DID resolution."""

    error: str
    message: Optional[str] = None

    def __init__(
        self,
        error: str,
        message: str = None,
        status_code: int = 400,
    ):
        """Initializer."""
        super().__init__()
        self.error = error
        self.message = message
        self.status_code = status_code

    def serialize(self) -> dict:
        """Serialize this error to a JSON-compatible dictionary."""
        return {
            "error": self.error,
            "errorMessage": self.message,
            "contentType": "application/did+ld+json",
        }


@dataclass
class ResolutionResult:
    """The result of a DID resolution operation."""

    document: Optional[dict] = None
    document_metadata: Optional[dict] = None
    resolution_metadata: Optional[dict] = None

    def serialize(self) -> dict:
        """Serialize this result to a JSON-compatible dictionary."""
        return {
            "@context": "https://w3id.org/did-resolution/v1",
            "didDocument": self.document,
            "didDocumentMetadata": self.document_metadata,
            "didResolutionMetadata": self.resolution_metadata,
        }


@dataclass
class DereferencingResult:
    """The result of a DID dereferencing operation."""

    dereferencing_metadata: dict
    content: str = ""
    content_metadata: Optional[dict] = None

    def serialize(self) -> dict:
        """Serialize this result to a JSON-compatible dictionary."""
        return {
            "@context": "https://w3id.org/did-resolution/v1",
            "dereferencingMetadata": self.dereferencing_metadata,
            "content": self.content,
            "contentMetadata": self.content_metadata or {},
        }


async def resolve_history(
    document_id: str,
    history: AsyncIterator[str],
    verify_state: VerifyState = None,
    *,
    version_id: Union[int, str] = None,
    version_time: Union[datetime, str] = None,
) -> ResolutionResult:
    """Resolve a `ResolutionResult` from an async log iterator.

    Params:
        document_id: the DID to be resolved
        history: an async string iterator over ordered log lines
        version_id: stop parsing at the requested versionId
        version_time: stop parsing at the most recent entry before
            or exactly matching the requested versionTime
        verify_state: verification to perform on each intermediate state
    """
    if isinstance(version_id, str):
        # FIXME handle conversion error
        version_id = int(str)
    if isinstance(version_time, str):
        # FIXME handle conversion error
        version_time = make_timestamp(version_time)[0]
    try:
        state, meta = await load_history(
            history,
            version_id=version_id,
            version_time=version_time,
            verify_state=verify_state,
        )
    except ValueError as err:
        return ResolutionResult(
            resolution_metadata=ResolutionError("invalidDid", str(err)).serialize()
        )
    if state.document_id != document_id:
        return ResolutionResult(
            resolution_metadata=ResolutionError(
                "invalidDid", "Document @id mismatch"
            ).serialize()
        )
    return ResolutionResult(document=state.document, document_metadata=meta.serialize())


def _add_ref(doc_id: str, node: dict, refmap: dict, all: set):
    reft = node.get("id")
    if not isinstance(reft, str):
        return
    if reft.startswith("#"):
        reft = doc_id + reft
    elif "#" not in reft:
        return
    if reft in all:
        raise ValueError(f"Duplicate reference: {reft}")
    all.add(reft)
    refmap[reft] = node


def reference_map(document: dict) -> dict[str, dict]:
    """Collect identified fragments (#ids) in a DID Document."""
    # indexing top-level collections only
    doc_id = document.get("id")
    if not isinstance(doc_id, str):
        raise ValueError("Missing document id")
    all = set()
    res = {}
    for k, v in document.items():
        if k == "@context":
            continue
        if isinstance(v, dict):
            res[k] = {}
            _add_ref(doc_id, v, res[k], all)
        elif isinstance(v, list):
            res[k] = {}
            for vi in v:
                if isinstance(vi, dict):
                    _add_ref(doc_id, vi, res[k], all)
    return res


def normalize_services(document: dict) -> list[dict]:
    """Normalize a `service` block to a list of dicts."""
    svcs = document.get("service", [])
    if not isinstance(svcs, list):
        svcs = [svcs]
    for svc in svcs:
        if not isinstance(svc, dict):
            raise ValueError("Expected map or list of map entries for 'service' property")
        svc_id = svc.get("id")
        if not svc_id or not isinstance(svc_id, str) or "#" not in svc_id:
            raise ValueError(f"Invalid service entry id: {svc_id}")
    return svcs


def dereference_fragment(document: dict, reft: str) -> DereferencingResult:
    """Dereference a fragment identifier within a document."""
    res = None
    try:
        if not reft.startswith("#"):
            raise ValueError("Expected reference to begin with '#'")
        refts = reference_map(document)
        reft = document["id"] + reft
        for blk in refts.values():
            if reft in blk:
                res = deepcopy(blk[reft])
                break
    except ValueError as err:
        return DereferencingResult(
            dereferencing_metadata=ResolutionError("notFound", str(err)).serialize(),
        )
    if not res:
        return DereferencingResult(
            dereferencing_metadata=ResolutionError(
                "notFound", f"Reference not found: {reft}"
            ).serialize()
        )
    ctx = []
    doc_ctx = document.get("@context")
    if isinstance(doc_ctx, str):
        ctx.append(doc_ctx)
    elif isinstance(doc_ctx, list):
        ctx.extend(doc_ctx)
    node_ctx = res.get("@context")
    if isinstance(node_ctx, str):
        ctx.append(node_ctx)
    elif isinstance(node_ctx, list):
        ctx.extend(node_ctx)
    if ctx:
        res = {"@context": ctx, **res}
    return DereferencingResult(dereferencing_metadata={}, content=json.dumps(res))
