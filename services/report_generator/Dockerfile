FROM mobile-base:latest

WORKDIR /app

COPY services/shared ./shared
COPY services/report_generator ./report_generator
COPY backend ./backend

ENV PYTHONPATH=/app

WORKDIR /app/report_generator

RUN pip install --no-cache-dir -r requirements.txt

RUN chmod +x entrypoint.sh

USER appuser
ENTRYPOINT ["./entrypoint.sh"]
