import os

INPUT_FILE = os.getenv("INPUT_FILE", "/app/backend/output/ios_device/device.json")
OUTPUT_FILE = os.getenv("OUTPUT_FILE", "/app/backend/output/jailbreak_detection/results.json")

JAILBREAK_PATHS = [
    "/Applications/Cydia.app",
    "/Applications/Sileo.app",
    "/Applications/Zebra.app",
    "/var/binpack",
    "/Applications/FlyJB.app"
]

BIN_PATHS = [
    "/usr/sbin/sshd",
    "/usr/bin/sshd",
    "/bin/bash",
    "/etc/apt",
    "/private/var/lib/apt"
]

DYLIBS = [
    "MobileSubstrate",
    "SubstrateLoader.dylib",
    "TweakInject.dylib",
    "ellekit"
]

WRITE_TEST_PATHS = [
    "/private/jb_test.txt",
    "/sys/test.txt"
]

OPEN_PORTS = [22, 4444]
