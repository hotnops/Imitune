"""
oma_dm_client.py
================

The class definition and SSL helper functions for
OMA DM client
"""
import base64
import html
import json
import os
import random
import ssl
import tempfile

from lxml import etree

from cryptography.hazmat.primitives.serialization \
    import Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.serialization.pkcs12 \
    import load_key_and_certificates
import requests

from asn1crypto import cms
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, ciphers
from cryptography.hazmat.backends import default_backend

from .management_tree import ManagementTree
from .oma_dm_session import OMADMSession
from .oma_dm_commands import OMAAlertCommand, OMAReplaceCommand

from datetime import datetime

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
                 output_directory: str,
                 dummy_data_path: str = "",
                 should_user_prompt: bool = False,
                 user_jwt: str = ""):
        self.deviceName = device_name
        self.managementTree = ManagementTree(should_user_prompt)
        self.user_jwt = user_jwt
        self.output_directory = os.path.join(os.getcwd(), output_directory)
        os.makedirs(self.output_directory, exist_ok=True)
        self.sessions = {}
        self.current_session = None
        self.mtls_session = create_mtls_session(pfx_file_path, pfx_password)
        self.pfx_file_path = pfx_file_path
        self.pfx_password = pfx_password
        if not self.mtls_session:
            raise ValueError("mtls session not established")
        self.dummy_path = dummy_data_path
        self.user_prompt = should_user_prompt

        trace_path = os.path.join(self.output_directory, "traces")

        os.makedirs(trace_path, exist_ok=True)

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
        if self.user_jwt:
            init_commands.append(
                OMAAlertCommand(
                    {'Data': '1224',
                     'Item': {
                         'Meta': {
                             'Type': {
                                 '@xmlns': 'syncml:metinf',
                                 '#text': 'com.microsoft/MDM/AADUserToken'
                                 }
                                 },
                         'Data': self.user_jwt
                        }})
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

        self.extract_credentials()
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
        oma_request_message = self.current_session.buildRequestMessage(
            self.user_jwt)
        http_body = oma_request_message.to_xml(
            self.deviceName,
            INTUNE_TARGET,
            self.current_session.session_id)

        # Save the file off
        dir_path = os.path.join(
            *[self.output_directory,
              "traces",
              str(self.current_session.session_id)])

        os.makedirs(dir_path, exist_ok=True)
        request_file_path = os.path.join(
            dir_path,
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
            dir_path,
            f"{self.current_session.message_id}_response.txt"
        )

        with open(request_file_path, 'wb') as f:
            f.write(resp)

        self.current_session.parseAndStoreResponse(resp)

    def extract_pkcs_certificates(self):
        for key, value in self.managementTree.items():
            if "PFXCertBlob" in key:
                print(f"[*] obtained pfx credentials at {key}. extracting")
                password_path = key.replace("PFXCertBlob", "PFXCertPassword")
                encrypted_password = self.managementTree.get(
                    password_path,
                    None)
                if not encrypted_password:
                    print(
                        "[!] unable to locate encryped password \
                            for certificate")
                cert_name = key.split("/")[-2]
                cert_password = self.decrypt_p7m_with_pfx(base64.b64decode(encrypted_password))
                self.decrypt_pfx_with_password(cert_name, base64.b64decode(value), cert_password)

    def extract_vpn_profiles(self):
        return None

    def extract_wifi_profiles(self):
        for key, value in self.managementTree.items():
            if "WlanXml" in key:
                print(f"[*] obtained wifi credentials at {key}. parsing")
                decoded_xml = html.unescape(value)
                root = etree.fromstring(decoded_xml.encode('utf-8'))
                nsmap = {
                    'v1': 'http://www.microsoft.com/networking/WLAN/profile/v1',
                    'v2': 'http://www.microsoft.com/networking/WLAN/profile/v2',
                }
                key_material_element = root.xpath('//v1:sharedKey/v1:keyMaterial', namespaces=nsmap)
                ssid_name_element = root.xpath('//v1:SSIDConfig/v1:SSID/v1:name', namespaces=nsmap)
                ssid_name = ssid_name_element[0].text if ssid_name_element else None
                auth_element = root.xpath('//v1:MSM/v1:security/v1:authEncryption/v1:authentication', namespaces=nsmap)
                authentication = auth_element[0].text if auth_element else None
                if not key_material_element:
                    # Fallback in case namespace is from v2 instead
                    key_material_element = root.xpath('//v2:sharedKey/v2:keyMaterial', namespaces=nsmap)

                key_material = key_material_element[0].text if key_material_element else None
                # Print result
                print(f"\t[*] wifi config: {ssid_name} : {authentication} : {key_material}")

    def extract_credentials(self):
        self.extract_pkcs_certificates()
        self.extract_wifi_profiles()
        self.extract_vpn_profiles()

    def decrypt_pfx_with_password(self, certName: str, pfx_data: bytes, password: bytes):

        private_key, cert, ca_certs = pkcs12.load_key_and_certificates(
            pfx_data,
            password
        )

        now_utc = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")

        pem_filename = f"{certName}_{now_utc}_private.pem"
        pfx_filename = f"{certName}_{now_utc}.pfx"
        pem_path = os.path.join(self.output_directory, pem_filename)
        pfx_path = os.path.join(self.output_directory, pfx_filename)

        with open(pem_path, 'wb') as pem_file:
            if private_key:
                pem_file.write(private_key.private_bytes(
                    encoding=Encoding.PEM,
                    format=PrivateFormat.TraditionalOpenSSL,  # "BEGIN RSA PRIVATE KEY"
                    encryption_algorithm=NoEncryption()       # Same as -nodes
                ))
            if cert:
                pem_file.write(cert.public_bytes(Encoding.PEM))
            if ca_certs:
                for cert in ca_certs:
                    pem_file.write(cert.public_bytes(Encoding.PEM))

        pfx_bytes = pkcs12.serialize_key_and_certificates(
            name=b"friendly_name",  # Friendly name for the key/cert
            key=private_key,
            cert=cert,
            cas=ca_certs,
            encryption_algorithm=NoEncryption()
        )

        with open(pfx_path, 'wb') as pfx_file:
            pfx_file.write(pfx_bytes)

    def decrypt_p7m_with_pfx(self, p7m_bytes: bytes) -> bytes:
        """
        Decrypt a PKCS#7/CMS P7M file using a private key from a PFX file.

        :param p7m_bytes: The raw P7M file content (DER format).
        :param pfx_bytes: The raw PFX file content.
        :param pfx_password: Password for the PFX file (if any).
        :return: Decrypted plaintext bytes.
        """
        # Load private key and cert from PFX
        with open(self.pfx_file_path, 'rb') as f:
            pfx_bytes = f.read()

        private_key, certificate, _ = pkcs12.load_key_and_certificates(
            pfx_bytes,
            self.pfx_password.encode() if self.pfx_password else None,
            backend=default_backend()
        )
        if private_key is None:
            raise ValueError("No private key found in the PFX file.")

        # Parse CMS ContentInfo
        content_info = cms.ContentInfo.load(p7m_bytes)
        if content_info['content_type'].native != 'enveloped_data':
            raise ValueError("P7M does not contain EnvelopedData.")

        enveloped_data = content_info['content']
        encrypted_content_info = enveloped_data['encrypted_content_info']

        # Extract encrypted CEK from recipient info
        recipient_info = enveloped_data['recipient_infos'][0].chosen
        encrypted_key = recipient_info['encrypted_key'].native

        # Determine key transport algorithm
        key_enc_algo = recipient_info['key_encryption_algorithm']['algorithm'].native
        if key_enc_algo == 'rsaes_oaep':
            # RSAES-OAEP padding
            cek = private_key.decrypt(
                encrypted_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA1()),
                    algorithm=hashes.SHA1(),
                    label=None
                )
            )
        elif key_enc_algo == 'rsa':
            # PKCS#1 v1.5
            cek = private_key.decrypt(
                encrypted_key,
                padding.PKCS1v15()
            )
        else:
            raise NotImplementedError(f"Unsupported key encryption algorithm: {key_enc_algo}")

        # Symmetric decryption of the content
        content_enc_algo = encrypted_content_info['content_encryption_algorithm']['algorithm'].native
        enc_params = encrypted_content_info['content_encryption_algorithm']['parameters'].native
        encrypted_content = encrypted_content_info['encrypted_content'].native

        if content_enc_algo in ('aes128_cbc', 'aes192_cbc', 'aes256_cbc'):
            cipher = ciphers.Cipher(
                ciphers.algorithms.AES(cek),
                ciphers.modes.CBC(enc_params),
                backend=default_backend()
            )
        elif content_enc_algo == 'des_ede3_cbc':
            cipher = ciphers.Cipher(
                ciphers.algorithms.TripleDES(cek),
                ciphers.modes.CBC(enc_params),
                backend=default_backend()
            )
        else:
            raise NotImplementedError(f"Unsupported content encryption algorithm: {content_enc_algo}")

        decryptor = cipher.decryptor()
        plaintext = decryptor.update(encrypted_content) + decryptor.finalize()

        # Remove PKCS#7 padding
        pad_len = plaintext[-1]
        plaintext = plaintext[:-pad_len]

        return plaintext

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
