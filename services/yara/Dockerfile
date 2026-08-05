FROM mobile-base:latest
WORKDIR /app
RUN apt-get update && apt-get install -y build-essential libssl-dev libffi-dev && rm -rf /var/lib/apt/lists/*
COPY services/shared ./shared
COPY services/yara ./yara
COPY backend ./backend
ENV PYTHONPATH=/app
WORKDIR /app/yara
RUN pip install --no-cache-dir -r requirements.txt
RUN chmod +x entrypoint.sh
USER appuser
ENTRYPOINT ["./entrypoint.sh"]
