import os
import json
import glob
from config import config
from service import MachoAnalyzerService

def load_json_list(filepath):
    if not os.path.exists(filepath):
        return []
    with open(filepath, 'r') as f:
        try:
            data = json.load(f)
            if isinstance(data, list):
                return data
            return [data]
        except:
            return []

def main():
    os.makedirs(config.OUTPUT_DIR, exist_ok=True)
    service = MachoAnalyzerService()
    results = []

    # Strategy 1: Read from JSON inputs
    extracted_data = load_json_list(config.INPUT_JSON_EXTRACTED)
    ios_data = load_json_list(config.INPUT_JSON_IOS)

    files_to_scan = set()
    for item in extracted_data + ios_data:
        if isinstance(item, dict):
            if 'ipa_path' in item:
                files_to_scan.add(item['ipa_path'])
            elif 'path' in item:
                files_to_scan.add(item['path'])

    # Strategy 2: Direct IPA/Mach-O in input dir
    if os.path.exists(config.INPUT_IPA_DIR):
        for ext in ('*.ipa', '*.bin', '*.macho'):
            for f in glob.glob(os.path.join(config.INPUT_IPA_DIR, ext)):
                files_to_scan.add(f)

    for file_path in files_to_scan:
        if not os.path.exists(file_path):
            continue

        if file_path.endswith('.ipa'):
            res = service.analyze_ipa(file_path)
        else:
            res = service.analyze_binary_file(file_path)

        results.append(res.to_dict())

    with open(config.OUTPUT_JSON, 'w') as f:
        json.dump(results, f, indent=4)

    print(f"MachoAnalyzer finished. Processed {len(results)} files.")

if __name__ == "__main__":
    main()
