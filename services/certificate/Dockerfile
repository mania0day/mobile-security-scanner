FROM mobile-base:latest

WORKDIR /app

RUN pip install --no-cache-dir cryptography pyOpenSSL

COPY services/shared ./shared
COPY services/certificate ./certificate
COPY backend ./backend

ENV PYTHONPATH=/app

WORKDIR /app/certificate

RUN chmod +x entrypoint.sh

ENTRYPOINT ["./entrypoint.sh"]
