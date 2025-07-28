"""
oma_dm_client.py
================

The class definition and SSL helper functions for
OMA DM client
"""
import json
import os
import random
import ssl
import tempfile

from cryptography.hazmat.primitives.serialization \
    import Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.serialization.pkcs12 \
    import load_key_and_certificates
import requests

from .management_tree import ManagementTree
from .oma_dm_session import OMADMSession
from .oma_dm_commands import OMAAlertCommand, OMAReplaceCommand

INTUNE_HOST = 'https://r.manage.microsoft.com'
PATH = '/devicegatewayproxy/cimhandler.ashx'
INTUNE_TARGET = f'{INTUNE_HOST}{PATH}'
INTUNE_ENDPOINT = f'{INTUNE_HOST}{PATH}?mode=Maintenance&Platform=WoA'


def create_mtls_session(pfx_path: str,
                        pfx_password: str
                        ) -> requests.Session | None:
    """
    Creates a requests.Session configured for mTLS using a PFX (PKCS#12)
    certificate and includes intermediate certificates in the chain.

    :param pfx_path: Path to the .pfx file.
    :param pfx_password: Password for the .pfx file.
    :return: requests.Session object configured with the client cert and key.
    """
    # Load PFX
    with open(pfx_path, 'rb') as pfx_file:
        pfx_data = pfx_file.read()

    try:
        private_key, certificate, additional_certs = load_key_and_certificates(
            pfx_data,
            pfx_password.encode() if pfx_password else None
        )
    except ValueError:
        print("[!] Invalid pfx password")
        return None

    if not private_key or not certificate:
        raise ValueError(
            "The PFX file does not contain a private key and certificate.")

    # Convert to PEM
    private_key_pem = private_key.private_bytes(
        Encoding.PEM,
        PrivateFormat.TraditionalOpenSSL,
        NoEncryption()
    )
    cert_pem = certificate.public_bytes(Encoding.PEM)

    # Append additional certs to form a full chain
    if additional_certs:
        for cert in additional_certs:
            cert_pem += cert.public_bytes(Encoding.PEM)

    # Write temp files for requests
    cert_file = tempfile.NamedTemporaryFile(delete=False)
    key_file = tempfile.NamedTemporaryFile(delete=False)
    cert_file.write(cert_pem)
    key_file.write(private_key_pem)
    cert_file.close()
    key_file.close()

    # Setup session
    session = requests.Session()
    session.cert = (cert_file.name, key_file.name)
    session.headers.update({
        "Content-Type": "application/vnd.syncml.dm+xml; charset=utf-8",
        "Accept": "application/vnd.syncml.dm+xml, application/octet-stream",
        "Accept-Charset": "UTF-8",
        "User-Agent": "MSFT OMA DM Client/1.2.0.1",
        "Accept-Encoding": "identity",
        "Expect": "100-Continue"
    })

    context = ssl.create_default_context()
    context.load_cert_chain(
        certfile=cert_file.name,
        keyfile=key_file.name,
        password=None)
    return session


class OMADMClient:
    """
    A class to manage and generate OMA-DM sessions to interact
    with Intune
    """

    def __init__(self,
                 device_name: str,
                 pfx_file_path: str,
                 pfx_password: str,
                 node_cache_path: str,
                 dummy_data_path: str = "",
                 should_user_prompt: bool = False):
        self.deviceName = device_name
        self.managementTree = ManagementTree(
                node_cache_path,
                should_user_prompt)

        self.sessions = {}
        self.current_session = None
        self.mtls_session = create_mtls_session(pfx_file_path, pfx_password)
        if not self.mtls_session:
            raise ValueError("mtls session not established")
        self.dummy_path = dummy_data_path
        self.user_prompt = should_user_prompt

        os.makedirs("./traces", exist_ok=True)

    def newSession(self):
        sessionId = random.randint(50000, 100000)
        session = OMADMSession(sessionId, self.deviceName)
        self.sessions[sessionId] = session
        self.current_session = session

    def initCommands(self, device_name):
        init_commands = []
        init_commands.append(
            OMAAlertCommand({"Data": 1201})
        )
        init_commands.append(
            OMAAlertCommand(
                {'Data': '1224', 'Item':
                 {'Meta':
                  {'Type':
                   {'@xmlns': 'syncml:metinf',
                    '#text': 'com.microsoft/MDM/LoginStatus'
                    }
                   },
                  'Data': 'user'
                  }
                 })
        )
        init_commands.append(
            OMAReplaceCommand({
                "Item": {
                    "Source": {
                        "LocURI": "./DevInfo/DevId"
                    },
                    "Data": self.managementTree.get("./DevInfo/DevId")
                }
            })
        )
        init_commands.append(
            OMAReplaceCommand({
                "Item": {
                    "Source": {
                        "LocURI": "./DevInfo/Man"
                    },
                    "Data": self.managementTree.get("./DevInfo/Man")
                }
            })
        )
        init_commands.append(
            OMAReplaceCommand({
                "Item": {
                    "Source": {
                        "LocURI": "./DevInfo/Mod"
                    },
                    "Data": self.managementTree.get("./DevInfo/Mod")
                }
            })
        )
        init_commands.append(
            OMAReplaceCommand({
                "Item": {
                    "Source": {
                        "LocURI": "./DevInfo/DmV"
                    },
                    "Data": self.managementTree.get("./DevInfo/DmV")
                }
            })
        )
        init_commands.append(
            OMAReplaceCommand({
                "Item": {
                    "Source": {
                        "LocURI": "./DevInfo/Lang"
                    },
                    "Data": self.managementTree.get("./DevInfo/Lang")
                }
            })
        )
        init_commands.append(
            OMAReplaceCommand({
                "Item": {
                    "Source": {
                        "LocURI": "./Vendor/MSFT/DMClient/HWDevID"
                    },
                    "Data": self.managementTree.get(
                        "./Vendor/MSFT/DMClient/HWDevID")
                }
            })
        )

        return init_commands

    def intuneInit(self):
        self.newSession()

        # Send the initial message
        self.prepInitialCommands()
        self.sendRequest()

        # Do all the things the intune server asked of us
        while len(self.current_session.commands) > 0:
            self.executeCommands()
            self.sendRequest()

        with open("managementTree.json", 'w', encoding="utf-8") as f:
            f.write(json.dumps(self.managementTree._data["uris"]))

    def executeCommands(self):

        for command in self.current_session.commands:
            command.execute(self)

    def load_dummy_response(self):
        file_path = os.path.join(
            self.dummy_path,
            f"{self.current_session.message_id}_response.txt")
        print(f"[*] loading response from: {file_path}")
        with open(file_path, 'rb') as f:
            text = f.read()
            return text
        return None

    def sendRequest(self):
        oma_request_message = self.current_session.buildRequestMessage()
        http_body = oma_request_message.to_xml(
            self.deviceName,
            INTUNE_TARGET,
            self.current_session.session_id)

        # Save the file off
        directory = f"./traces/{self.current_session.session_id}"
        os.makedirs(directory, exist_ok=True)
        request_file_path = os.path.join(
            directory,
            f"{self.current_session.message_id}_request.txt"
        )

        with open(request_file_path, 'wb') as f:
            f.write(http_body)

        if not self.dummy_path:
            resp = self.sendSyncMLMessage(http_body)
        else:
            resp = self.load_dummy_response()
        if not resp:
            return

        request_file_path = os.path.join(
            directory,
            f"{self.current_session.message_id}_response.txt"
        )

        with open(request_file_path, 'wb') as f:
            f.write(resp)

        self.current_session.parseAndStoreResponse(resp)

    def sendSyncMLMessage(self, syncMLBody):
        if self.user_prompt:
            input("[*] Send it? Press any key to continue")
        resp = self.mtls_session.post(INTUNE_ENDPOINT, data=syncMLBody)
        if resp.status_code != 200:
            print("[!] error sending request to Intune")
            return None
        return resp.content

    def prepInitialCommands(self):
        self.current_session.commands = self.initCommands(self.deviceName)
