"""Server signing key management.

키를 소스에 하드코딩하지 않는다 (지시서 §34).

* 파일이 존재하면 로드한다.
* 없고 `env != prod` 이면 P-256 키를 새로 만들어 저장한다 (0600 권한 시도).
* 없고 `env == prod` 이면 부팅을 거부한다. 조용한 fallback 을 두지 않는다 (§19).
"""

from __future__ import annotations

import logging
import os
import stat
from functools import lru_cache
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .config import get_settings

logger = logging.getLogger("boundauth.keys")


class KeyProvisioningError(RuntimeError):
    pass


def _restrict_permissions(path: Path) -> None:
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:  # Windows 등에서 실패할 수 있다. 치명적이지 않다.
        logger.warning("could not restrict permissions on %s", path)


def _generate(path: Path) -> ec.EllipticCurvePrivateKey:
    key = ec.generate_private_key(ec.SECP256R1())
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    _restrict_permissions(path)
    logger.warning(
        "generated a new development signing key at %s - do not use in production", path
    )
    return key


def _load(path: Path) -> ec.EllipticCurvePrivateKey:
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(
        key.curve, ec.SECP256R1
    ):
        raise KeyProvisioningError(f"{path} is not a P-256 private key")
    return key


@lru_cache(maxsize=1)
def get_signing_key() -> ec.EllipticCurvePrivateKey:
    settings = get_settings()
    path = Path(settings.signing_key_path)
    if path.exists():
        return _load(path)
    if settings.is_prod:
        raise KeyProvisioningError(
            f"signing key {path} is missing; provision it before starting in prod"
        )
    return _generate(path)


def get_verifying_key() -> ec.EllipticCurvePublicKey:
    return get_signing_key().public_key()


def reset_key_cache() -> None:
    get_signing_key.cache_clear()
