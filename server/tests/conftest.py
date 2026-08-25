"""pytest fixtures.

각 테스트 세션은 임시 디렉터리에 자체 SQLite DB 와 자체 서버 서명키를 만든다.
저장소에 커밋되는 키/DB 를 만들지 않는다.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

SERVER_ROOT = Path(__file__).resolve().parents[1]
if str(SERVER_ROOT) not in sys.path:
    sys.path.insert(0, str(SERVER_ROOT))


@pytest.fixture(scope="session", autouse=True)
def _test_environment(tmp_path_factory: pytest.TempPathFactory) -> Iterator[None]:
    workdir = tmp_path_factory.mktemp("boundauth")
    os.environ["BOUNDAUTH_ENV"] = "test"
    os.environ["BOUNDAUTH_DATABASE_URL"] = f"sqlite:///{(workdir / 'test.db').as_posix()}"
    os.environ["BOUNDAUTH_SIGNING_KEY_PATH"] = str(workdir / "server_es256.pem")
    os.environ["BOUNDAUTH_DETAILED_ERRORS"] = "true"
    os.environ["BOUNDAUTH_SEED_PASSWORD"] = ""
    os.environ["BOUNDAUTH_ISSUER"] = "https://boundauth.test"

    from app.core.config import reset_settings_cache
    from app.core.db import reset_engine
    from app.core.keys import reset_key_cache

    reset_settings_cache()
    reset_engine()
    reset_key_cache()
    yield


@pytest.fixture()
def client(_test_environment) -> Iterator["TestClient"]:  # noqa: F821
    from fastapi.testclient import TestClient

    from app.main import create_app

    with TestClient(create_app(), base_url="https://boundauth.test") as test_client:
        yield test_client


@pytest.fixture()
def user_factory(client):
    """테스트용 사용자를 직접 DB 에 만든다 (가입 API 는 범위 밖)."""
    from app.auth.passwords import hash_password
    from app.core.db import get_sessionmaker
    from app.core.models import User

    created: list[str] = []
    counter = {"n": 0}

    def _create(password: str = "correct horse battery staple") -> tuple[str, str]:
        counter["n"] += 1
        username = f"user{counter['n']}-{os.urandom(4).hex()}"
        session = get_sessionmaker()()
        try:
            session.add(User(username=username, password_hash=hash_password(password)))
            session.commit()
        finally:
            session.close()
        created.append(username)
        return username, password

    return _create
