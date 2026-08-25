# BoundAuth server image.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# 의존성 먼저 (레이어 캐시)
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# 서버 소스
COPY server /app/server

# 비루트 사용자
RUN useradd -m boundauth && chown -R boundauth /app
USER boundauth

EXPOSE 8000

# 키/DB 는 볼륨으로 주입한다. 비밀은 이미지에 굽지 않는다.
CMD ["python", "-m", "uvicorn", "app.main:app", "--app-dir", "server", "--host", "0.0.0.0", "--port", "8000"]
