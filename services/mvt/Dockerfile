FROM mobile-base:latest
WORKDIR /app
RUN apt-get update && apt-get install -y libusb-1.0-0 && rm -rf /var/lib/apt/lists/*
COPY services/shared ./shared
COPY services/mvt ./mvt
COPY backend ./backend
ENV PYTHONPATH=/app
WORKDIR /app/mvt
RUN pip install --no-cache-dir -r requirements.txt
RUN chmod +x entrypoint.sh
ENTRYPOINT ["./entrypoint.sh"]
