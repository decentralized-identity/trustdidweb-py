import json

from datetime import datetime
from typing import AsyncIterator, Callable, Optional, TypeVar, Tuple

from .state import DocumentMetadata, DocumentState

VerifyState = TypeVar(
    "VerifyState", bound=Callable[[DocumentState, Optional[DocumentState]], None]
)


async def load_history(
    history: AsyncIterator[str],
    *,
    version_id: int = None,
    version_time: datetime = None,
    verify_hash: bool = True,
    verify_state: VerifyState = None,
) -> Tuple[DocumentState, DocumentMetadata]:
    created = None
    prev = None

    # iterator is guaranteed to return at least one state, or raise ValueError
    states = iter_history(history, verify_hash=verify_hash, verify_state=verify_state)

    async for latest in states:
        if not created:
            created = latest.timestamp
        if version_id and version_id == latest.version_id:
            break
        if version_time and version_time < latest.timestamp:
            if not prev:
                raise ValueError(f"Cannot resolve versionTime: {version_time}")
            latest = prev
            break
        prev = latest

    if version_id and version_id != latest.version_id:
        raise ValueError(f"Cannot resolve versionId: {version_id}")

    return latest, DocumentMetadata(
        created=created,
        updated=latest.timestamp,
        deactivated=latest.deactivated,
        version_id=latest.version_id,
    )


async def iter_history(
    history: AsyncIterator[str],
    verify_hash: bool = True,
    verify_state: VerifyState = None,
) -> AsyncIterator[DocumentState]:
    prev_state = None

    async for line in history:
        if not line:
            continue
        try:
            parts = json.loads(line)
        except ValueError as e:
            raise ValueError(f"Invalid history JSON: {e}")
        state = DocumentState.load_history_line(parts, prev_state)

        if verify_hash:
            if state.calculate_hash() != state.version_hash:
                raise ValueError("Invalid history version hash")
        if verify_state:
            verify_state(state, prev_state)

        yield state
        prev_state = state

    if not prev_state:
        raise ValueError("Empty document history")
