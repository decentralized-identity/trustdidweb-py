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
