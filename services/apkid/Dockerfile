FROM mobile-base:latest

WORKDIR /app

COPY services/shared ./shared
COPY services/apkid ./apkid
COPY backend ./backend

ENV PYTHONPATH=/app

WORKDIR /app/apkid

RUN if [ -s requirements.txt ]; then pip install --no-cache-dir -r requirements.txt; fi
RUN chmod +x entrypoint.sh

USER appuser
ENTRYPOINT ["./entrypoint.sh"]
