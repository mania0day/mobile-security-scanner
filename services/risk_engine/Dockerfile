FROM mobile-base:latest

WORKDIR /app

COPY services/shared ./shared
COPY services/risk_engine ./risk_engine
COPY backend ./backend

ENV PYTHONPATH=/app

WORKDIR /app/risk_engine

RUN chmod +x entrypoint.sh

USER appuser
ENTRYPOINT ["./entrypoint.sh"]
