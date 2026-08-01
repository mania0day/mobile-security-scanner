FROM mobile-base:latest

WORKDIR /app

# MobSF client only needs requests — the actual MobSF server
# runs as a separate persistent Docker service
COPY services/shared ./shared
COPY services/mobsf ./mobsf
COPY backend ./backend

ENV PYTHONPATH=/app

WORKDIR /app/mobsf

RUN pip install --no-cache-dir -r requirements.txt

RUN chmod +x entrypoint.sh

ENTRYPOINT ["./entrypoint.sh"]
