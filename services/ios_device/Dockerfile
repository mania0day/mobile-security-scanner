FROM mobile-base:latest

WORKDIR /app

RUN apt-get update && apt-get install -y libimobiledevice-utils usbmuxd && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir pymobiledevice3

COPY services/shared ./shared
COPY services/ios_device ./ios_device
COPY backend ./backend

ENV PYTHONPATH=/app

WORKDIR /app/ios_device

RUN chmod +x entrypoint.sh

ENTRYPOINT ["./entrypoint.sh"]
