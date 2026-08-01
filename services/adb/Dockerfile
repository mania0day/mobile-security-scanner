FROM mobile-base:latest

WORKDIR /app

COPY services/shared ./shared
COPY services/adb ./adb
COPY backend ./backend

ENV PYTHONPATH=/app

WORKDIR /app/adb

RUN chmod +x entrypoint.sh

ENTRYPOINT ["./entrypoint.sh"]
