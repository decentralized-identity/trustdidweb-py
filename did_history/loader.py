"""Methods to iterate through a DID log."""

import json

from datetime import datetime
from typing import AsyncIterator, Callable, Optional, TypeAlias, Tuple

from .state import DocumentMetadata, DocumentState

VerifyState: TypeAlias = Callable[[DocumentState, Optional[DocumentState], bool], None]


async def load_history(
    history: AsyncIterator[str],
    *,
    version_id: int = None,
    version_time: datetime = None,
    verify_state: VerifyState = None,
) -> Tuple[DocumentState, DocumentMetadata]:
    """Resolve a document state and metadata from an async log iterator.

    Params:
        history: an async string iterator over ordered log lines
        version_id: stop parsing at the requested versionId
        version_time: stop parsing at the most recent entry before
            or exactly matching the requested versionTime
        verify_state: verification to perform on each intermediate state
    """
    created = None

    states = iter_history(
        history,
        version_id=version_id,
        version_time=version_time,
        verify_state=verify_state,
    )

    # iterator is guaranteed to return at least one state, or raise ValueError
    async for latest in states:
        if not created:
            created = latest.timestamp

    return latest, DocumentMetadata(
        created=created,
        updated=latest.timestamp,
        deactivated=latest.deactivated,
        version_id=latest.version_id,
        version_number=latest.version_number,
    )


async def iter_history(
    history: AsyncIterator[str],
    *,
    version_id: int = None,
    version_time: datetime = None,
    verify_state: VerifyState = None,
) -> AsyncIterator[DocumentState]:
    """Iterate through each intermediate state in a DID log.

    Params:
        history: an async string iterator over ordered log lines
        version_id: stop parsing at the requested versionId
        version_time: stop parsing at the most recent entry before
            or exactly matching the requested versionTime
        verify_state: verification to perform on each intermediate state
    """
    prev_state = None
    state = None
    next_state = None
    history = history.__aiter__()
    done = False

    while not done:
        state = next_state

        try:
            line = await anext(history)
            parts = json.loads(line)
        except StopAsyncIteration:
            next_state = None
        except ValueError as e:
            raise ValueError(f"Invalid history JSON: {e}") from None
        else:
            next_state = DocumentState.load_history_line(parts, state)
            if version_time and version_time < next_state.timestamp:
                done = True

        if state:
            if state.version_id == version_id or not next_state:
                done = True
            state.check_version_id()
            if verify_state:
                verify_state(state, prev_state, done)
            yield state
            prev_state = state

    if not state:
        if version_id:
            raise ValueError(f"Cannot resolve versionId: {version_id}")
        elif version_time:
            raise ValueError(f"Cannot resolve versionTime: {version_time}")
        raise ValueError("Empty document history")
