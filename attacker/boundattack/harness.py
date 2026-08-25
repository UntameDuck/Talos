"""Experiment harness.

서버를 **실제 uvicorn 인스턴스**로 백그라운드 스레드에서 띄운다. 127.0.0.1 의 임의
포트에 바인딩하고, 정상/공격 클라이언트 모두 실제 HTTP 로 붙는다. 이렇게 하면:

* "다른 기기에서의 replay" 를 충실히 모사한다 (서버는 두 클라이언트를 구분 못 함).
* Phase 7 latency 측정이 실제 HTTP 왕복을 포함한다.

각 harness 는 격리된 임시 DB + 임시 서버 서명키를 쓴다 (저장소 오염 없음).
"""

from __future__ import annotations

import importlib
import os
import socket
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

import httpx

REPO_ROOT = Path(__file__).resolve().parents[2]
SERVER_ROOT = REPO_ROOT / "server"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@dataclass
class Harness:
    workdir: Path
    app: object
    base_url: str
    _server: object = field(default=None, repr=False)
    _thread: threading.Thread | None = field(default=None, repr=False)

    def client(self, signer=None):
        from .client import BoundAuthClient

        return BoundAuthClient(self.base_url, signer=signer)

    def cleanup(self) -> None:
        if self._server is not None:
            self._server.should_exit = True
        if self._thread is not None:
            self._thread.join(timeout=10)
        try:
            from app.core.db import reset_engine

            reset_engine()
        except Exception:
            pass


def _ensure_server_on_path() -> None:
    if str(SERVER_ROOT) not in sys.path:
        sys.path.insert(0, str(SERVER_ROOT))


def build_harness(
    *, seed_user: str = "demo", seed_password: str = "demo-password-123"
) -> tuple[Harness, str, str]:
    """격리된 uvicorn 서버를 띄우고 (harness, username, password) 를 돌려준다."""
    import uvicorn

    _ensure_server_on_path()
    workdir = Path(tempfile.mkdtemp(prefix="boundattack_"))
    port = _free_port()
    base_url = f"http://127.0.0.1:{port}"

    os.environ["BOUNDAUTH_ENV"] = "test"
    os.environ["BOUNDAUTH_DATABASE_URL"] = f"sqlite:///{(workdir / 'run.db').as_posix()}"
    os.environ["BOUNDAUTH_SIGNING_KEY_PATH"] = str(workdir / "server_es256.pem")
    os.environ["BOUNDAUTH_DETAILED_ERRORS"] = "true"
    os.environ["BOUNDAUTH_ISSUER"] = base_url
    os.environ["BOUNDAUTH_PUBLIC_BASE_URL"] = base_url
    os.environ["BOUNDAUTH_SEED_USERNAME"] = seed_user
    os.environ["BOUNDAUTH_SEED_PASSWORD"] = seed_password
    os.environ.setdefault("BOUNDAUTH_LOG_LEVEL", "WARNING")

    for mod_name in ("app.core.config", "app.core.db", "app.core.keys"):
        importlib.import_module(mod_name)
    from app.core.config import reset_settings_cache
    from app.core.db import reset_engine
    from app.core.keys import reset_key_cache

    reset_settings_cache()
    reset_engine()
    reset_key_cache()

    from app.main import create_app

    app = create_app()

    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning", lifespan="on")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    _wait_until_ready(base_url)

    return Harness(workdir=workdir, app=app, base_url=base_url, _server=server, _thread=thread), seed_user, seed_password


def _wait_until_ready(base_url: str, timeout: float = 15.0) -> None:
    deadline = time.time() + timeout
    last_err: Exception | None = None
    while time.time() < deadline:
        try:
            response = httpx.get(f"{base_url}/health", timeout=1.0)
            if response.status_code == 200:
                return
        except Exception as exc:  # 서버가 아직 안 뜬 상태
            last_err = exc
        time.sleep(0.05)
    raise RuntimeError(f"server did not become ready at {base_url}: {last_err}")
