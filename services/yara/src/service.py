import yara
import os
from config import RULES_PATH
from shared.logger import get_logger

logger = get_logger("Yara")


def compile_rules():
    try:
        return yara.compile(filepath=RULES_PATH)
    except Exception as e:
        logger.error(f"Failed to compile yara rules: {e}")
        return None


def scan_apk(rules, apk_path: str, package_name: str):
    matches_list = []
    error = ""
    try:
        if not os.path.exists(apk_path):
            raise FileNotFoundError(f"APK not found: {apk_path}")

        matches = rules.match(apk_path)
        for m in matches:
            description = m.meta.get('description', '')
            severity = m.meta.get('severity', 'low')

            matched_strings = []
            if hasattr(m, 'strings'):
                for s in m.strings:
                    if hasattr(s, 'instances'):
                        for inst in s.instances:
                            if hasattr(inst, 'matched_data'):
                                data = inst.matched_data
                                matched_strings.append(data.decode('utf-8', errors='ignore') if isinstance(data, bytes) else str(data))
                            else:
                                matched_strings.append(str(inst))
                    elif isinstance(s, (tuple, list)):
                        if len(s) >= 3:
                            data = s[2]
                            matched_strings.append(data.decode('utf-8', errors='ignore') if isinstance(data, bytes) else str(data))
                        else:
                            matched_strings.append(str(s))
                    else:
                        matched_strings.append(str(s))

            matches_list.append({
                "rule": m.rule,
                "severity": severity,
                "description": description,
                "matched_strings": list(set(matched_strings))
            })
    except Exception as e:
        logger.error(f"Error scanning {apk_path}: {e}")
        error = str(e)

    return {
        "package_name": package_name,
        "apk_path": apk_path,
        "matches": matches_list,
        "match_count": len(matches_list),
        "error": error
    }
