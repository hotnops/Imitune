"""
A helper class for maintaining the management tree
"""
import json
import os
from datetime import datetime, timezone, timedelta

CERT_STRING = "./Device/Vendor/MSFT/ClientCertificateInstall/PFXCertInstall"


class ManagementTree:
    """
    Acts as a dummy representation of a management tree
    """

    def __init__(self, node_cache_path: str, user_prompt: bool):
        self._data = {}
        self.user_prompt = user_prompt
        with open(node_cache_path, 'r', encoding="utf-8") as f:
            text = f.read()
            json_data = json.loads(text)

            # Keep the structure of node_ids
            self._data['node_ids'] = json_data['node_ids']
            self._data['uris'] = {}

            # Only grab the value from the reg structure
            for key, value in json_data['uris'].items():
                self._data['uris'][key] = value.get(
                    "ExpectedValue", {}).get("data")

        if os.path.exists("managementTree.json"):
            print("[*] loading existing data from managementTree.json")
            with open('managementTree.json', 'r', encoding="utf-8") as f:
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
                print(f"[*] got q reuest for {key}. sending 0")
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
