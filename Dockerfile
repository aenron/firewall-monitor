FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    TZ=Asia/Shanghai

# The official Debian-based Python image includes timezone data.
RUN test -f /usr/share/zoneinfo/Asia/Shanghai

WORKDIR /app
COPY requirements.txt ./
ARG PIP_INDEX_URL=https://pypi.org/simple
RUN pip install --no-cache-dir --index-url "$PIP_INDEX_URL" -r requirements.txt
COPY firewall.py storage.py ./
RUN mkdir -p /app/log /banlogs

CMD ["python", "firewall.py"]
