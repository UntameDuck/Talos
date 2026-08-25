"""Runtime configuration.

모든 보안 관련 값은 환경변수/.env 에서 온다. 비밀값은 소스에 하드코딩하지 않는다
(지시서 §20, §34). `.env.example` 참조.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

REPO_ROOT = Path(__file__).resolve().parents[3]
SERVER_ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="BOUNDAUTH_",
        env_file=(REPO_ROOT / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- environment -------------------------------------------------
    env: Literal["dev", "test", "prod"] = "dev"

    #: 오류 응답에 내부 error code 를 포함할지 여부.
    #: dev/test 에서는 실험 계측을 위해 켠다. prod 에서는 끈다 (지시서 §2 실패사유).
    detailed_errors: bool = True

    # --- storage -----------------------------------------------------
    database_url: str = Field(default="")

    # --- server signing key -----------------------------------------
    #: Access/Refresh 토큰 서명용 P-256 개인키 (PEM). 파일이 없고 env != prod 이면
    #: 개발 편의를 위해 자동 생성한다. prod 에서는 반드시 사전 프로비저닝해야 한다.
    signing_key_path: Path = Field(default_factory=lambda: SERVER_ROOT / ".keys" / "server_es256.pem")
    issuer: str = "https://boundauth.local"

    #: htu 정규화 기준이 되는 외부 공개 base URL. 리버스 프록시 뒤에서 필수.
    #: 비어 있으면 요청 자체의 scheme/host 를 사용한다.
    public_base_url: str = ""

    # --- token lifetimes ---------------------------------------------
    access_token_ttl_seconds: int = 900
    refresh_token_ttl_seconds: int = 60 * 60 * 24 * 14

    # --- DPoP --------------------------------------------------------
    #: iat 허용 오차 (앞/뒤 공통). 지시서 §3 "clock skew 허용 범위 설정 가능".
    dpop_iat_skew_seconds: int = 60
    #: jti 를 replay cache 에 보관하는 기간. iat 창보다 넉넉해야 한다.
    dpop_replay_ttl_seconds: int = 300
    #: True 이면 nonce 없는 proof 를 401 + DPoP-Nonce 챌린지로 거부한다.
    dpop_require_nonce: bool = False
    nonce_ttl_seconds: int = 300
    #: proof JWT 최대 바이트 (strict parser, 지시서 §20).
    dpop_max_proof_bytes: int = 4096

    # --- experiment knobs --------------------------------------------
    #: 실험 재현성을 위해 최초 부팅 시 만들 데모 계정. 비밀번호는 env 로만 주입한다.
    seed_username: str = "demo"
    seed_password: str = ""

    @property
    def resolved_database_url(self) -> str:
        if self.database_url:
            return self.database_url
        db_path = SERVER_ROOT / ".data" / f"boundauth_{self.env}.db"
        db_path.parent.mkdir(parents=True, exist_ok=True)
        return f"sqlite:///{db_path.as_posix()}"

    @property
    def is_prod(self) -> bool:
        return self.env == "prod"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


def reset_settings_cache() -> None:
    """테스트에서 환경변수를 바꾼 뒤 호출한다."""
    get_settings.cache_clear()
