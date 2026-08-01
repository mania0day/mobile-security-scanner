FROM mobile-base:latest

WORKDIR /app

RUN pip install --no-cache-dir requests

COPY services/shared ./shared
COPY services/hash_lookup ./hash_lookup
COPY backend ./backend

ENV PYTHONPATH=/app

WORKDIR /app/hash_lookup

RUN chmod +x entrypoint.sh

ENTRYPOINT ["./entrypoint.sh"]
