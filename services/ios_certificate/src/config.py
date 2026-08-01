import os

class Config:
    INPUT_JSON = os.getenv("INPUT_JSON", "/app/backend/output/ipa_inventory/extracted.json")
    INPUT_DIR = os.getenv("INPUT_DIR", "/app/backend/output/ipas")
    OUTPUT_FILE = os.getenv("OUTPUT_FILE", "/app/backend/output/ios_certificate/results.json")
