import os
import sys
from config import OUTPUT_DIR, IOS_TIMEOUT
from models import IOSDeviceInfo
from shared.logger import get_logger
from shared.json_writer import write_json
from shared.ios_utils import get_ios_device_info, get_installed_app_bundle_ids

logger = get_logger("IOSDevice")


class IOSDeviceService:
    """
    Detects connected iOS devices over USB using pymobiledevice3 / libimobiledevice.
    Outputs device details to backend/output/ios_device/device.json.
    """

    def run(self) -> IOSDeviceInfo:
        logger.info("Detecting connected iOS device...")
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        output_file = os.path.join(OUTPUT_DIR, "device.json")

        success, dev_dict, err = get_ios_device_info()

        if not success:
            logger.warning(f"iOS Device Detection: {err}")
            info = IOSDeviceInfo(is_connected=False, error=err)
            write_json(output_file, {
                "platform": "ios",
                "is_connected": False,
                "udid": "",
                "device_name": "",
                "product_type": "",
                "product_version": "",
                "error": err
            })
            return info

        info = IOSDeviceInfo(
            udid=dev_dict.get("udid", ""),
            device_name=dev_dict.get("device_name", "iPhone"),
            device_class=dev_dict.get("device_class", "iPhone"),
            product_type=dev_dict.get("product_type", ""),
            product_version=dev_dict.get("product_version", ""),
            build_version=dev_dict.get("build_version", ""),
            is_connected=True,
            raw=dev_dict.get("raw", {})
        )

        bundle_ids = get_installed_app_bundle_ids()

        out_data = {
            "platform": "ios",
            "is_connected": True,
            "udid": info.udid,
            "device_name": info.device_name,
            "device_class": info.device_class,
            "product_type": info.product_type,
            "product_version": info.product_version,
            "build_version": info.build_version,
            "installed_app_bundle_ids": bundle_ids,
            "error": ""
        }

        write_json(output_file, out_data)
        logger.info(f"iOS Device Detected: {info.device_name} ({info.product_version}) - UDID: {info.udid}")
        return info
