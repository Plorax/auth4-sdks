from __future__ import annotations

import base64
import json
import threading
import time
from typing import Any
from urllib.parse import parse_qs

import pytest

from auth4 import (
    Auth4ServerClient,
    Auth4TokenError,
    HttpRequest,
    HttpResponse,
    IntrospectionOptions,
)
from conftest import (
    INTROSPECTION_URL,
    NOW,
    SERVER_CLIENT_ID,
    SERVER_CLIENT_SECRET,
    TENANT_ID,
    FakeServer,
    access_claims,
    sign,
)


def active_answer(**overrides: Any) -> dict[str, Any]:
    answer: dict[str, Any] = {
        "active": True,
        "sub": "usr_player0000000001",
        "client_id": "cli_gameclient000001",
        "jti": "jti_token000000000001",
        "tenant_id": TENANT_ID,
        "exp": NOW + 300,
    }
    answer.update(overrides)
    return answer


class Answers:
    def __init__(self, *answers: Any) -> None:
        self.answers: list[Any] = list(answers)
        self.calls: list[HttpRequest] = []

    def __call__(self, request: HttpRequest) -> HttpResponse:
        self.calls.append(request)
        answer = self.answers[min(len(self.calls), len(self.answers)) - 1]
        if isinstance(answer, HttpResponse):
            return answer
        if isinstance(answer, BaseException):
            raise answer
        return HttpResponse(200, json.dumps(answer).encode())


def introspecting(server: FakeServer, answers: Answers, **options: Any) -> Auth4ServerClient:
    server.introspection = answers
    return server.client(
        introspection=IntrospectionOptions(
            client_id=SERVER_CLIENT_ID, client_secret=SERVER_CLIENT_SECRET, **options
        )
    )


def code_of(client: Auth4ServerClient, token: str) -> str:
    with pytest.raises(Auth4TokenError) as caught:
        client.validate_access_token(token)
    return caught.value.code


def test_off_by_default(server: FakeServer) -> None:
    client = server.client()
    assert client.introspection_url is None
    client.validate_access_token(sign(access_claims()))
    assert server.count(INTROSPECTION_URL) == 0


def test_active_session_passes_and_request_is_well_formed(server: FakeServer) -> None:
    answers = Answers(active_answer())
    client = introspecting(server, answers)
    token = sign(access_claims())
    assert client.introspection_url == INTROSPECTION_URL
    assert client.validate_access_token(token).subject == "usr_player0000000001"
    request = answers.calls[0]
    assert request.method == "POST"
    assert request.url == INTROSPECTION_URL
    assert request.headers["Content-Type"] == "application/x-www-form-urlencoded"
    assert parse_qs(request.body.decode()) == {"token": [token]}
    scheme, encoded = request.headers["Authorization"].split(" ")
    assert scheme == "Basic"
    assert base64.b64decode(encoded).decode() == f"{SERVER_CLIENT_ID}:{SERVER_CLIENT_SECRET}"


def test_credentials_are_form_encoded() -> None:
    server = FakeServer(clock=[float(NOW)])
    secret = "a:b c+d/é" + "x" * 32
    answers = Answers(active_answer())
    server.introspection = answers
    client = server.client(
        introspection=IntrospectionOptions(client_id=SERVER_CLIENT_ID, client_secret=secret)
    )
    client.validate_access_token(sign(access_claims()))
    encoded = answers.calls[0].headers["Authorization"].split(" ")[1]
    assert (
        base64.b64decode(encoded).decode() == f"{SERVER_CLIENT_ID}:a%3Ab%20c%2Bd%2F%C3%A9{'x' * 32}"
    )


def test_revoked_session_is_invalid_and_remembered(server: FakeServer) -> None:
    answers = Answers({"active": False})
    client = introspecting(server, answers)
    token = sign(access_claims())
    assert code_of(client, token) == "invalid_token"
    server.advance(120)
    assert code_of(client, token) == "invalid_token"
    assert len(answers.calls) == 1


def test_active_answer_is_reused_for_cache_ttl(server: FakeServer) -> None:
    answers = Answers(active_answer(), {"active": False})
    client = introspecting(server, answers, cache_ttl=5)
    token = sign(access_claims())
    client.validate_access_token(token)
    server.advance(4)
    client.validate_access_token(token)
    assert len(answers.calls) == 1
    server.advance(2)
    assert code_of(client, token) == "invalid_token"
    assert len(answers.calls) == 2


def test_zero_cache_ttl_checks_every_time(server: FakeServer) -> None:
    answers = Answers(active_answer())
    client = introspecting(server, answers, cache_ttl=0)
    token = sign(access_claims())
    for _ in range(3):
        client.validate_access_token(token)
    assert len(answers.calls) == 3


@pytest.mark.parametrize(
    "answer",
    [
        active_answer(sub="usr_player0000000002"),
        active_answer(client_id="cli_other000000000001"),
        active_answer(jti="jti_token000000000009"),
        active_answer(tenant_id="ten_qrstuvwxyzabcdef"),
    ],
)
def test_mismatched_answers_are_invalid(server: FakeServer, answer: dict) -> None:
    assert code_of(introspecting(server, Answers(answer)), sign(access_claims())) == "invalid_token"


@pytest.mark.parametrize(
    "answer",
    [
        HttpResponse(503, b""),
        HttpResponse(401, b'{"error":"invalid_client"}'),
        HttpResponse(200, b"not json"),
        HttpResponse(200, b"[]"),
        {"active": "true"},
        {},
        TimeoutError("timed out"),
    ],
)
def test_unavailable_or_unexpected_answers_fail_closed(server: FakeServer, answer: Any) -> None:
    client = introspecting(server, Answers(answer))
    assert code_of(client, sign(access_claims())) == "introspection_unavailable"


def test_invalid_tokens_are_not_introspected(server: FakeServer) -> None:
    answers = Answers(active_answer())
    client = introspecting(server, answers)
    assert code_of(client, sign(access_claims(aud="cli_other000000000001"))) == "invalid_token"
    assert answers.calls == []


def test_concurrent_checks_share_one_request(server: FakeServer) -> None:
    class Slow(Answers):
        def __call__(self, request: HttpRequest) -> HttpResponse:
            time.sleep(0.2)
            return super().__call__(request)

    answers = Slow(active_answer())
    client = introspecting(server, answers)
    token = sign(access_claims())
    client._jwks.get_key("key-1")  # warm the key cache, so only introspection is concurrent
    threads = [
        threading.Thread(target=client.validate_access_token, args=(token,)) for _ in range(6)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(answers.calls) == 1


@pytest.mark.parametrize(
    "options",
    [
        {"client_id": "server", "client_secret": SERVER_CLIENT_SECRET},
        {"client_id": SERVER_CLIENT_ID, "client_secret": "short"},
        {"client_id": SERVER_CLIENT_ID, "client_secret": SERVER_CLIENT_SECRET, "cache_ttl": 61},
        {"client_id": SERVER_CLIENT_ID, "client_secret": SERVER_CLIENT_SECRET, "timeout": 0},
    ],
)
def test_options_are_checked(server: FakeServer, options: dict) -> None:
    with pytest.raises(ValueError):
        server.client(introspection=IntrospectionOptions(**options))


def test_secret_never_appears_in_reprs(server: FakeServer) -> None:
    options = IntrospectionOptions(client_id=SERVER_CLIENT_ID, client_secret=SERVER_CLIENT_SECRET)
    client = server.client(introspection=options)
    for text in (repr(options), str(options), repr(client), repr(vars(client))):
        assert SERVER_CLIENT_SECRET not in text
    assert base64.b64encode(
        f"{SERVER_CLIENT_ID}:{SERVER_CLIENT_SECRET}".encode()
    ).decode() not in repr(vars(client))
