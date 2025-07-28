"""
omadm_message.py
==============

Models a full OMA-DM message and keeps track of cmdIds and message ids
"""
# System imports
from enum import Enum

from lxml import etree
import xmltodict

from .oma_dm_commands import OMAGetCommand, OMASyncHdrCommand, xml_to_commands


class MessageType(Enum):
    """
    An enumeration type to reprsent if the OMA
    Message is a client-to-server request or
    a servero-to-client repsonse
    """
    REQUEST = 1
    RESPONSE = 2


class OMADMMessage:
    """
    A class structure to assist in keeping a consistent
    and well formatted OMA-DM message
    """
    def __init__(self, commands: list, message_id):
        self.message_id = message_id
        self.commands = commands
        self.sync_status = None

    def addCommand(self, command):
        self.commands.append(command)

    def addCommands(self, commands):
        self.commands += commands

    @staticmethod
    def from_xml(xmlString: str):
        data = xmltodict.parse(xmlString)
        header = data.get('SyncML', {}).get('SyncHdr')
        message_id = int(header.get('MsgID'))
        body = data.get('SyncML', {}).get('SyncBody')
        syncStatus = OMASyncHdrCommand(header)
        syncStatus.cmd_ref = 0
        syncStatus.msg_ref = message_id

        commands = []
        xml_to_commands(body, commands)
        for command in commands:
            command.msg_ref = message_id

        newOMADMMessage = OMADMMessage(commands, message_id)
        newOMADMMessage.sync_status = syncStatus

        return newOMADMMessage

    def to_xml(self, source: str, target: str, sessionId):
        # Build the SyncHdr first
        self.build_sync_hdr(source, target, sessionId)

        # Create root <SyncML xmlns="SYNCML:SYNCML1.2">
        nsmap = {None: "SYNCML:SYNCML1.2"}  # Default namespace
        root = etree.Element("SyncML", nsmap=nsmap)

        # ---- Build SyncHdr ----
        hdr = etree.SubElement(root, "SyncHdr")
        for key, value in self.syncHdr.items():
            if isinstance(value, dict):
                sub_elem = etree.SubElement(hdr, key)
                for sub_key, sub_value in value.items():
                    etree.SubElement(sub_elem, sub_key).text = str(sub_value)
            else:
                etree.SubElement(hdr, key).text = str(value)

        # ---- Build SyncBody ----
        nsmap_msft = {"msft": "http://schemas.microsoft.com/MobileDevice/MDM"}
        body = etree.SubElement(root, "SyncBody", nsmap=nsmap_msft)

        # Append all commands
        cmdId = 1

        if self.sync_status:
            body.append(self.sync_status.to_status_xml(cmdId))
            cmdId += 1

        for command in self.commands:
            if command.msg_ref:
                # A MsgRef implies it's a response to a command
                # issued by the intune server
                body.append(command.to_status_xml(cmdId))
                cmdId += 1
                # To my knowledge, Get is the only one that returns
                # results but this may need to be revisited
                if isinstance(command, OMAGetCommand):
                    resultsBody = command.to_results_xml(cmdId)
                    if resultsBody is not None:
                        body.append(resultsBody)
                        cmdId += 1
            else:
                body.append(command.to_xml(cmdId))
                cmdId += 1

        body.append(etree.Element("Final"))

        # Pretty-print with CRLF line endings
        xml_bytes = etree.tostring(
            root,
            pretty_print=True,
            encoding='utf-8',
            xml_declaration=False)

        xml_bytes = xml_bytes.decode('utf-8')
        formatted_xml = xml_bytes.replace("\n", "\r\n").encode('utf-8').strip()
        return formatted_xml

    def build_sync_hdr(self, source: str, target: str, sessionId):
        self.syncHdr = {
                    'VerDTD': '1.2',
                    'VerProto': 'DM/1.2',
                    'SessionID': sessionId,
                    'MsgID': self.message_id,
                    'Target':
                    {
                        'LocURI': target
                    },
                    'Source':
                    {
                        'LocURI': source
                    }
                }
