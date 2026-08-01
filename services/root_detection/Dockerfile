FROM mobile-base:latest

WORKDIR /app

COPY services/shared ./shared
COPY services/root_detection ./root_detection
COPY backend ./backend

ENV PYTHONPATH=/app

WORKDIR /app/root_detection

RUN chmod +x entrypoint.sh

ENTRYPOINT ["./entrypoint.sh"]
