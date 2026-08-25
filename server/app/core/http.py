"""HTTP request normalization helpers.

`htu` 정규화 규칙은 서버·SDK·펌웨어·공격도구가 **글자 단위로 동일**해야 한다.
한쪽이라도 다르면 정상 요청이 `DPOP_HTU_MISMATCH` 로 실패한다.
규칙은 `docs/dpop-mapping.md` 에 문서화한다.

규칙 (RFC 9449 §4.2, RFC 3986 §6.2.2 기반):

1. scheme, host 는 소문자.
2. 기본 포트(http:80, https:443)는 생략한다.
3. query string 과 fragment 는 제거한다.
4. path 는 비어 있으면 `/` 로 둔다. 그 외에는 요청 경로를 **그대로** 쓴다
   (퍼센트 인코딩을 임의로 정규화하지 않는다 - 양쪽이 동일 문자열을 보게 하는 것이 목적).
"""

from __future__ import annotations

from urllib.parse import urlsplit

_DEFAULT_PORTS = {"http": "80", "https": "443"}


def normalize_htu(url: str) -> str:
    parts = urlsplit(url)
    scheme = (parts.scheme or "").lower()
    hostname = (parts.hostname or "").lower()
    if not scheme or not hostname:
        raise ValueError(f"htu must be an absolute URL with scheme and host: {url!r}")

    authority = hostname
    port = parts.port
    if port is not None and str(port) != _DEFAULT_PORTS.get(scheme):
        authority = f"{hostname}:{port}"

    path = parts.path or "/"
    return f"{scheme}://{authority}{path}"


def request_htu(request, public_base_url: str = "") -> str:
    """들어온 요청으로부터 기대되는 `htu` 를 만든다.

    리버스 프록시 뒤에서는 요청의 host/scheme 가 외부에서 본 값과 다를 수 있으므로
    `public_base_url` 이 설정되어 있으면 그 origin 을 권위로 삼는다.
    프록시 헤더(`X-Forwarded-*`)는 **신뢰하지 않는다** - 공격자가 조작 가능하다.
    """
    path = request.url.path or "/"
    if public_base_url:
        base = urlsplit(public_base_url)
        if not base.scheme or not base.hostname:
            raise ValueError("public_base_url must be absolute")
        return normalize_htu(f"{base.scheme}://{base.netloc}{path}")
    return normalize_htu(f"{request.url.scheme}://{request.url.netloc}{path}")
