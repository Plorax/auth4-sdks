"""The shared verdicts from packages/sdk-dotnet/tests/fixtures/conformance.json, which
@auth4/sdk-server and the C# SDK also reach (tests/integration/auth4d-169.dotnet-sdk.test.ts)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from auth4 import Auth4ServerClient, Auth4TokenError, HttpRequest, HttpResponse

FIXTURE = json.loads(
    (
        Path(__file__).parents[2] / "sdk-dotnet" / "tests" / "fixtures" / "conformance.json"
    ).read_text("utf-8")
)


def client() -> Auth4ServerClient:
    def transport(request: HttpRequest) -> HttpResponse:
        assert request.url == f"{FIXTURE['issuer']}/.well-known/jwks.json"
        return HttpResponse(200, json.dumps(FIXTURE["jwks"]).encode())

    return Auth4ServerClient(
        tenant_id=FIXTURE["tenantId"],
        issuer=FIXTURE["issuer"],
        audience=FIXTURE["audience"],
        transport=transport,
        now=lambda: FIXTURE["now"],
    )


@pytest.mark.parametrize("case", FIXTURE["cases"], ids=[case["name"] for case in FIXTURE["cases"]])
def test_shared_verdict(case: dict) -> None:
    verifier = client()
    if case["kind"] == "access":
        verify = lambda: verifier.validate_access_token(case["token"])  # noqa: E731
    else:
        verify = lambda: verifier.validate_id_token(case["token"], FIXTURE["audience"])  # noqa: E731
    if case["valid"]:
        assert verify().subject == "usr_player0000000001"
    else:
        with pytest.raises(Auth4TokenError) as caught:
            verify()
        assert caught.value.code == "invalid_token"


def test_fixture_has_cases_of_both_kinds() -> None:
    kinds = {case["kind"] for case in FIXTURE["cases"]}
    assert kinds == {"access", "id"}
    assert len(FIXTURE["cases"]) >= 10
