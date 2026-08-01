import os

OUTPUT_DIR = os.environ.get("OUTPUT_DIR", "/app/backend/output/ios_device")
IOS_TIMEOUT = int(os.environ.get("IOS_TIMEOUT", "30"))
