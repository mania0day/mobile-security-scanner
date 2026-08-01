import os

class Config:
    INPUT_JSON_EXTRACTED = os.getenv('INPUT_JSON_EXTRACTED', '/app/backend/output/ipa_inventory/extracted.json')
    INPUT_JSON_IOS = os.getenv('INPUT_JSON_IOS', '/app/backend/output/ios_inventory/apps.json')
    INPUT_IPA_DIR = os.getenv('INPUT_IPA_DIR', '/app/backend/output/ipas/')
    OUTPUT_DIR = os.getenv('OUTPUT_DIR', '/app/backend/output/macho_analyzer/')
    OUTPUT_JSON = os.path.join(OUTPUT_DIR, 'results.json')

config = Config()
