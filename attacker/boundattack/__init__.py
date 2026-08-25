"""BoundAttack — token replay / DPoP attack simulator and experiment runner.

지시서 §6, §21, §34.

핵심 원칙:
* 모든 공격 결과는 **실제 실행 결과**에서만 나온다. 결과를 미리 만들지 않는다.
* 공격 기능은 여기(BoundAttack)에만 둔다. 데모 앱에는 두지 않는다 (§15).
"""

__all__ = ["__version__"]
__version__ = "0.1.0"
