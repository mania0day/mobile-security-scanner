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

# Known jailbreak-tool bundle IDs — these apps are visible via the standard
# installation proxy (no jailbreak needed to enumerate installed apps), so
# this is the one reachable-over-USB signal that actually works.
JAILBREAK_BUNDLE_IDS = [
    "com.saurik.Cydia",
    "org.coolstar.sileo",
    "xyz.willy.Zebra",
    "com.opa334.Dopamine",
    "org.crd.filza",
    "com.linusyang.PPApp",
    "com.ex.substitute",
    "science.cydia.installer",
    "org.thebigboss.iCleaner",
    "com.tigisoftware.filza",
]
