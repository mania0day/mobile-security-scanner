FROM mobile-base:latest

WORKDIR /app

COPY services/shared ./shared
COPY services/permission_analyzer ./permission_analyzer
COPY backend ./backend

ENV PYTHONPATH=/app

WORKDIR /app/permission_analyzer

RUN chmod +x entrypoint.sh

USER appuser
ENTRYPOINT ["./entrypoint.sh"]
