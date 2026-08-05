FROM mobile-base:latest

WORKDIR /app

RUN apt-get update && apt-get install -y libimobiledevice-utils usbmuxd && rm -rf /var/lib/apt/lists/*

COPY services/shared ./shared
COPY services/ios_device ./ios_device
COPY backend ./backend

ENV PYTHONPATH=/app

WORKDIR /app/ios_device

RUN if [ -s requirements.txt ]; then pip install --no-cache-dir -r requirements.txt; fi
RUN chmod +x entrypoint.sh

ENTRYPOINT ["./entrypoint.sh"]
