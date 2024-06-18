import json

from datetime import datetime
from pathlib import Path
from typing import Tuple, Union

import aiofiles

from did_history.loader import load_history
from did_history.state import DocumentMetadata, DocumentState

from .const import HISTORY_FILENAME
from .proof import SigningKey, di_jcs_sign, verify_document_id, verify_all


def write_document_state(
    doc_dir: Path,
    state: DocumentState,
):
    history_path = doc_dir.joinpath(HISTORY_FILENAME)
    if state.version_id > 1:
        mode = "a"
        if not history_path.exists():
            raise RuntimeError(f"History path does not exist: {history_path}")
    else:
        mode = "w"

    with open(history_path, mode) as out:
        print(
            json.dumps(state.history_line()),
            file=out,
        )


async def load_history_path(
    path: Union[str, Path],
    *,
    version_id: int = None,
    version_time: datetime = None,
    verify_proofs: bool = True,
) -> Tuple[DocumentState, DocumentMetadata]:
    verify_state = verify_all if verify_proofs else verify_document_id
    async with aiofiles.open(path, "r") as history:
        return await load_history(
            history,
            version_id=version_id,
            version_time=version_time,
            verify_hash=True,
            verify_state=verify_state,
        )


def update_document_state(
    prev_state: DocumentState,
    update_key: SigningKey,
    document_update: dict = None,
    params_update: dict = None,
    timestamp: Union[str, datetime] = None,
) -> DocumentState:
    state = prev_state.create_next(
        document_update=document_update,
        params_update=params_update,
        timestamp=timestamp,
    )
    state.proofs.append(di_jcs_sign(state, update_key, timestamp=state.timestamp))
    return state
