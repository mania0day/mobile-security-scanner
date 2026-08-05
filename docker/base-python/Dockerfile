FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update && \
    apt-get install -y \
        adb \
        git \
        curl \
        unzip \
        zip \
        wget \
        ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Non-root user for the compute-only services (no USB/privileged access needed).
# The 7 services that require /dev/bus/usb access run as root instead — see
# the `# privileged: requires root for /dev/bus/usb access` comments in
# compose.yaml next to those service definitions.
RUN useradd --create-home --shell /bin/bash appuser

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

ENTRYPOINT ["/bin/bash"]