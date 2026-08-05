FROM mobile-base:latest

WORKDIR /app

COPY services/shared ./shared
COPY services/cve_checker ./cve_checker
COPY backend ./backend

ENV PYTHONPATH=/app

WORKDIR /app/cve_checker

RUN chmod +x entrypoint.sh

USER appuser
ENTRYPOINT ["./entrypoint.sh"]
