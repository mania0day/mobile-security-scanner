FROM mobile-base:latest

WORKDIR /app

RUN pip install --no-cache-dir androguard==3.4.0a1

COPY services/shared ./shared
COPY services/androguard ./androguard
COPY backend ./backend

ENV PYTHONPATH=/app

WORKDIR /app/androguard

RUN chmod +x entrypoint.sh

ENTRYPOINT ["./entrypoint.sh"]
