FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    TZ=Asia/Shanghai

# The official Debian-based Python image includes timezone data.
RUN test -f /usr/share/zoneinfo/Asia/Shanghai

WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY firewall.py ./
RUN mkdir -p /app/log /banlogs

CMD ["python", "firewall.py"]
