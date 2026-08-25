# BoundKey firmware host tests

순수 C 모듈(policy, approval)을 ESP-IDF 없이 검증한다.

```bash
cmake -S . -B build && cmake --build build && ctest --test-dir build --output-on-failure
```

> 이 개발 환경에는 C 컴파일러/cmake 가 없어 아직 실행되지 않았다.
> golden 동작은 Python `attacker/tests/test_boundkey_sim.py` 와 일치해야 한다.
