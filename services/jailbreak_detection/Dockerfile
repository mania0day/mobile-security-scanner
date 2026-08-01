FROM mobile-base:latest

WORKDIR /app

COPY services/shared ./shared
COPY services/jailbreak_detection ./jailbreak_detection
COPY backend ./backend

ENV PYTHONPATH=/app

WORKDIR /app/jailbreak_detection

RUN if [ -s requirements.txt ]; then pip install --no-cache-dir -r requirements.txt; fi
RUN chmod +x entrypoint.sh

ENTRYPOINT ["./entrypoint.sh"]
