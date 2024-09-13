from did_history.resolver import ResolutionResult
from did_tdw.resolver import resolve_did


async def test_resolve_did_failed_request():
    # Fail due to connection error
    result = await resolve_did(
        "did:tdw:QmWtQu5Vwi5n7oTz1NHKPtRJuBQmNneLXBGkQW9YBaGYk4:example.com%3A5000"
    )
    assert isinstance(result, ResolutionResult)
    assert result.resolution_metadata["error"] is not None
