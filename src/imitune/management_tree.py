"""
A helper class for maintaining the management tree
"""
import importlib.resources
import json
import os
import shutil

from datetime import datetime, timezone, timedelta

CERT_STRING = "./Device/Vendor/MSFT/ClientCertificateInstall/PFXCertInstall"


class ManagementTree:
    """
    Acts as a dummy representation of a management tree
    """

    def __init__(self, device_name: str, user_prompt: bool):
        self._data = {}
        self.user_prompt = user_prompt

        self._data['node_ids'] = {}
        self._data['uris'] = {}

        management_tree_path = os.path.join(
            os.getcwd(),
            device_name,
            "managementTree.json")

        if not os.path.exists(management_tree_path):
            print("[*] management tree no found. copying from template")
            template_path = importlib.resources.files(
                'imitune.data').joinpath(
                    'managementTree.json.template')

            with importlib.resources.as_file(template_path) as path:
                shutil.copyfile(path, management_tree_path)

            print(f"[!] template file copied to {management_tree_path}. \
 populate it with values and re-run")

            raise ValueError("template copied but not initialized")

        print(f"[*] loading existing data from {management_tree_path}")
        with open(management_tree_path, 'r', encoding="utf-8") as f:
            text = f.read()
            json_data = json.loads(text)

            for key, value in json_data.items():
                self._data["uris"][key] = value

        self._data["uris"]["./Vendor/MSFT/NodeCache/MS%20DM%20Server"] = \
            "CacheVersion/Nodes/ChangedNodes/ChangedNodesData"
        self._data["uris"]["./DevDetail/SwV"] = "10.0.22621.525"
        self._data["uris"]["./Vendor/MSFT/WindowsLicensing/Edition"] = 72
        self._data["uris"]["./Vendor/MSFT/DeviceStatus/OS/Mode"] = 0

    def get(self, key: str, default=None):
        """
        Get a value from the management tree. Returns default
        if value not found
        """

        if key == "./DevDetail/Ext/Microsoft/LocalTime":
            # Get current local time with timezone
            now = datetime.now().astimezone()

            # Format the time, ensuring 7 digits for fractional seconds
            formatted_time = now.strftime('%Y-%m-%dT%H:%M:%S.%f')
            # Add 1 extra digit to match .NET-style 7 digits
            formatted_time = formatted_time + "0"

            # Add timezone offset (formatted as -04:00)
            offset = now.strftime('%z')  # e.g., -0400
            offset = offset[:3] + ":" + offset[3:]  # Convert -0400 -> -04:00

            final_time = formatted_time + offset
            return final_time

        if key == "./Vendor/MSFT/Update/LastSuccessfulScanTime":
            one_hour_ago = datetime.now(timezone.utc) - timedelta(hours=1)
            # Format as ISO 8601 with 'Z'
            formatted = one_hour_ago.strftime('%Y-%m-%dT%H:%M:%SZ')
            return formatted

        if key not in self._data['uris']:
            # We don't want a 404, we want 0 based on observed
            # conversations
            if key.startswith(CERT_STRING):
                print(f"[*] got a request for {key}. sending 0")
                return 0
            if self.user_prompt:
                value = input(
                    f"[*] {key} not in management tree. Enter it here: ")
                if value:
                    self._data['uris'][key] = value

        return self._data['uris'].get(key, default)

    def set(self, key: str, data):
        """
        Sets a value in the management tree
        """
        self._data["uris"][key] = data

    def delete(self, key: str):
        """
        Removes a value from the management tree
        """
        self._data["uris"].pop(key)

    def keys(self):
        return self._data["uris"].keys()

    def items(self):
        return self._data["uris"].items()
