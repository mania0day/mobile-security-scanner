import os
import zipfile
from src.models import MachoAnalysisResult
from src.exceptions import BinaryParsingError

class MachoAnalyzerService:
    WEAK_CRYPTO_PATTERNS = [b'md5', b'sha1', b'CC_MD5', b'CC_SHA1', b'rand', b'srand']

    def __init__(self):
        pass

    def analyze_ipa(self, ipa_path: str) -> MachoAnalysisResult:
        result = MachoAnalysisResult(filename=os.path.basename(ipa_path))
        try:
            with zipfile.ZipFile(ipa_path, 'r') as z:
                app_folder = None
                for name in z.namelist():
                    if name.startswith('Payload/') and name.endswith('.app/'):
                        app_folder = name
                        break
                
                if not app_folder:
                    raise BinaryParsingError("Could not find Payload/*.app/ in IPA")
                
                app_name = app_folder.split('/')[1].replace('.app', '')
                executable_path = f"{app_folder}{app_name}"
                
                if executable_path not in z.namelist():
                    candidates = [n for n in z.namelist() if n.startswith(app_folder) and '/' not in n[len(app_folder):] and not n.endswith('/')]
                    if not candidates:
                        raise BinaryParsingError("Could not find executable in .app folder")
                    executable_path = candidates[0]
                
                with z.open(executable_path) as f:
                    content = f.read()
                    self._analyze_binary_content(content, result)
        except Exception as e:
            result.error = str(e)
            
        return result
        
    def analyze_binary_file(self, file_path: str) -> MachoAnalysisResult:
        result = MachoAnalysisResult(filename=os.path.basename(file_path))
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
                self._analyze_binary_content(content, result)
        except Exception as e:
            result.error = str(e)
        return result

    def _analyze_binary_content(self, content: bytes, result: MachoAnalysisResult):
        if b'_objc_release' in content or b'_objc_autorelease' in content or b'_objc_retain' in content:
            result.has_arc = True
            
        if b'__stack_chk_fail' in content or b'__stack_chk_guard' in content:
            result.has_canary = True
            
        if b'@rpath' in content or b'LC_RPATH' in content:
            result.has_rpath = True
            
        for pattern in self.WEAK_CRYPTO_PATTERNS:
            if pattern in content:
                result.weak_crypto_calls.append(pattern.decode('ascii'))
        
        if b'cryptid' in content:
            result.is_encrypted = True
            
        if b'LC_DYLD_INFO' in content or b'LC_MAIN' in content:
            result.is_pie = True

