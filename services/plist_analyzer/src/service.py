import plistlib
import logging
from pathlib import Path
from typing import Dict, Any, List

from src.models import (
    AnalyzerResult, PlistInfo, ATSInfo, PrivacyPermissions, EntitlementsInfo
)

logger = logging.getLogger(__name__)

class PlistAnalyzerService:
    def __init__(self):
        pass

    def analyze_app(self, app_id: str, app_dir: Path) -> AnalyzerResult:
        result = AnalyzerResult(app_id=app_id)
        
        info_plist_path = self._find_file(app_dir, "Info.plist")
        if info_plist_path:
            try:
                result.plist_info = self._parse_info_plist(info_plist_path)
            except Exception as e:
                result.errors.append(f"Failed to parse Info.plist: {str(e)}")
        else:
            result.errors.append("Info.plist not found")
            
        entitlements_path = self._find_file(app_dir, "*.xcent") or self._find_file(app_dir, "archived-expanded-entitlements.xcent")
        if entitlements_path:
            try:
                result.entitlements_info = self._parse_entitlements(entitlements_path)
            except Exception as e:
                result.errors.append(f"Failed to parse Entitlements: {str(e)}")
                
        return result

    def _find_file(self, start_dir: Path, filename_pattern: str) -> Path:
        for path in start_dir.rglob(filename_pattern):
            return path
        return None

    def _parse_info_plist(self, plist_path: Path) -> PlistInfo:
        with open(plist_path, 'rb') as f:
            plist = plistlib.load(f)
            
        ats = ATSInfo()
        if "NSAppTransportSecurity" in plist:
            ats_dict = plist["NSAppTransportSecurity"]
            ats.allows_arbitrary_loads = ats_dict.get("NSAllowsArbitraryLoads", False)
            ats.exception_domains = ats_dict.get("NSExceptionDomains", {})
            
        privacy = PrivacyPermissions(
            camera=plist.get("NSCameraUsageDescription"),
            microphone=plist.get("NSMicrophoneUsageDescription"),
            location_always=plist.get("NSLocationAlwaysUsageDescription"),
            contacts=plist.get("NSContactsUsageDescription")
        )
        
        url_schemes = []
        if "CFBundleURLTypes" in plist:
            for url_type in plist["CFBundleURLTypes"]:
                if "CFBundleURLSchemes" in url_type:
                    url_schemes.extend(url_type["CFBundleURLSchemes"])
                    
        background_modes = plist.get("UIBackgroundModes", [])
        
        return PlistInfo(
            bundle_id=plist.get("CFBundleIdentifier", ""),
            version=plist.get("CFBundleShortVersionString", ""),
            ats=ats,
            privacy=privacy,
            url_schemes=url_schemes,
            background_modes=background_modes
        )

    def _parse_entitlements(self, entitlements_path: Path) -> EntitlementsInfo:
        # Note: sometimes xcent files are just plists, sometimes they have a binary header.
        # Let's try basic plist parsing first.
        try:
            with open(entitlements_path, 'rb') as f:
                content = f.read()
                # strip potential xml header trash if it's an xcent
                start_idx = content.find(b'<?xml')
                if start_idx != -1:
                    content = content[start_idx:]
                entitlements = plistlib.loads(content)
        except Exception as e:
            logger.error(f"Error reading entitlements as pure plist: {e}")
            entitlements = {}
            
        return EntitlementsInfo(
            keychain_groups=entitlements.get("keychain-access-groups", []),
            app_groups=entitlements.get("com.apple.security.application-groups", []),
            icloud_containers=entitlements.get("com.apple.developer.ubiquity-container-identifiers", []),
            push_notifications="aps-environment" in entitlements,
            task_allow=entitlements.get("get-task-allow", False)
        )
