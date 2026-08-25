"""Password hashing (지시서 §20: "password hashing은 안전한 라이브러리 사용").

Argon2id (argon2-cffi) 를 쓴다. 직접 구현하지 않는다.
"""

from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

#: 연구용 기본 파라미터. 프로덕션에서는 하드웨어에 맞춰 재조정해야 한다.
_hasher = PasswordHasher(time_cost=2, memory_cost=64 * 1024, parallelism=2)

#: 존재하지 않는 사용자에 대해서도 동일한 비용을 치르기 위한 더미 해시.
#: 사용자 존재 여부가 응답 시간으로 새는 것을 줄인다.
_DUMMY_HASH = _hasher.hash("boundauth-dummy-password-not-a-secret")


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str | None) -> bool:
    """검증 실패를 예외가 아닌 False 로 정규화한다.

    `password_hash` 가 None 이면(=사용자 없음) 더미 해시로 검증해 타이밍을 맞춘다.
    """
    target = password_hash or _DUMMY_HASH
    try:
        _hasher.verify(target, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False
    return password_hash is not None


def needs_rehash(password_hash: str) -> bool:
    try:
        return _hasher.check_needs_rehash(password_hash)
    except InvalidHashError:
        return True
