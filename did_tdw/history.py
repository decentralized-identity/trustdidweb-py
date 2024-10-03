"""History file management."""

import json
from datetime import datetime
from pathlib import Path
from typing import Optional, Union

import aiofiles

from did_history.loader import load_history
from did_history.state import DocumentMetadata, DocumentState

from .const import HISTORY_FILENAME
from .proof import SigningKey, di_jcs_sign, verify_all, verify_params


def write_document_state(
    doc_dir: Path,
    state: DocumentState,
):
    """Append a new document state to a history log file."""
    history_path = doc_dir.joinpath(HISTORY_FILENAME)
    if state.version_number > 1:
        mode = "a"
        if not history_path.exists():
            raise RuntimeError(f"History path does not exist: {history_path}")
    else:
        mode = "w"

    with history_path.open(mode) as out:
        print(
            json.dumps(state.history_line()),
            file=out,
        )


async def load_history_path(
    path: Union[str, Path],
    *,
    version_id: Optional[int] = None,
    version_time: Optional[datetime] = None,
    verify_proofs: bool = True,
) -> tuple[DocumentState, DocumentMetadata]:
    """Load a history log file into a final document state and metadata."""
    verify_state = verify_all if verify_proofs else verify_params
    async with aiofiles.open(path) as history:
        return await load_history(
            history,
            version_id=version_id,
            version_time=version_time,
            verify_state=verify_state,
        )


def update_document_state(
    prev_state: DocumentState,
    update_key: SigningKey,
    document: Optional[dict] = None,
    params_update: Optional[dict] = None,
    timestamp: Union[str, datetime, None] = None,
) -> DocumentState:
    """Update a document state, including a new signed proof."""
    state = prev_state.create_next(
        document=document,
        params_update=params_update,
        timestamp=timestamp,
    )
    # FIXME ensure the signing key is present in updateKeys
    state.proofs.append(di_jcs_sign(state, update_key, timestamp=state.timestamp))
    return state
