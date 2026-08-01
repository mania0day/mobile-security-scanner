FROM mobile-base:latest

WORKDIR /app

COPY services/shared ./shared
COPY services/apk_inventory ./apk_inventory
COPY backend ./backend

ENV PYTHONPATH=/app

WORKDIR /app/apk_inventory

RUN chmod +x entrypoint.sh

ENTRYPOINT ["./entrypoint.sh"]
