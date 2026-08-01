FROM mobile-base:latest

WORKDIR /app

RUN pip install --no-cache-dir apkid

COPY services/shared ./shared
COPY services/apkid ./apkid
COPY backend ./backend

ENV PYTHONPATH=/app

WORKDIR /app/apkid

RUN chmod +x entrypoint.sh

ENTRYPOINT ["./entrypoint.sh"]
