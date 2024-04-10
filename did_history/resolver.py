import json

from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime
from typing import AsyncIterator, Optional, Union

from .date_utils import make_timestamp
from .loader import VerifyState, load_history


class ResolutionError(Exception):
    error: str
    message: Optional[str] = None

    def __init__(
        self,
        error: str,
        message: str = None,
        status_code: int = 400,
    ):
        super().__init__()
        self.error = error
        self.message = message
        self.status_code = status_code

    def serialize(self) -> dict:
        return {
            "error": self.error,
            "errorMessage": self.message,
            "contentType": "application/did+ld+json",
        }


@dataclass
class ResolutionResult:
    document: Optional[dict] = None
    document_metadata: Optional[dict] = None
    resolution_metadata: Optional[dict] = None

    def serialize(self) -> dict:
        return {
            "@context": "https://w3id.org/did-resolution/v1",
            "didDocument": self.document,
            "didDocumentMetadata": self.document_metadata,
            "didResolutionMetadata": self.resolution_metadata,
        }


@dataclass
class DereferencingResult:
    dereferencing_metadata: dict
    content: str = ""
    content_metadata: Optional[dict] = None

    def serialize(self) -> dict:
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


def add_ref(doc_id: str, node: dict, refmap: dict):
    reft = node.get("id")
    if not isinstance(reft, str):
        return
    if reft.startswith("#"):
        reft = doc_id + reft
    elif "#" not in reft:
        return
    if reft in refmap:
        raise ValueError(f"Duplicate reference: {reft}")
    refmap[reft] = node


def ref_map(document: dict) -> dict[str, dict]:
    # indexing top-level collections only
    doc_id = document.get("id")
    if not isinstance(doc_id, str):
        raise ValueError("Missing document id")
    res = {}
    for v in document.values():
        if isinstance(v, dict):
            add_ref(doc_id, v, res)
        elif isinstance(v, list):
            for vi in v:
                if isinstance(vi, dict):
                    add_ref(doc_id, vi, res)
    return res


def dereference(document: dict, reft: str) -> DereferencingResult:
    try:
        if not reft.startswith("#"):
            raise ValueError("Expected reference to begin with '#'")
        refts = ref_map(document)
        reft = document["id"] + reft
        if reft not in refts:
            return DereferencingResult(
                dereferencing_metadata=ResolutionError(
                    "notFound", f"Reference not found: {reft}"
                )
            )
    except ValueError as err:
        return DereferencingResult(
            dereferencing_metadata=ResolutionError("notFound", str(err)).serialize(),
        )
    res = deepcopy(refts[reft])
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
