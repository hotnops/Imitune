"""
Manage an OMA DM Session
"""
from .omadm_message import MessageType, OMADMMessage


class OMADMSession:
    """
    A class to manage an OMA DM session. Keeps track of session ID's,
    message IDs, and populates certain values.
    """

    def __init__(self, session_id: int, device_nane: str):
        self.message_id = 0
        self.messages = {}
        self.session_id = session_id
        self.deviceName = device_nane
        # A list of commands that we need to addres in our next response
        self.commands = []

    def addMessage(self, message_id: int, message, msg_type: MessageType):
        if self.messages.get(message_id, {}).get(msg_type, None):
            print("[!] message id already exists for this session")
            return
        if message_id not in self.messages:
            self.messages[message_id] = {}

        self.messages[message_id][msg_type] = message

        if msg_type == MessageType.RESPONSE:
            self.commands = message.commands

    def parseAndStoreResponse(self, responseXml: str):
        # First, get the msg id this response is to
        response = OMADMMessage.from_xml(responseXml)
        self.addMessage(response.message_id, response, MessageType.RESPONSE)

    def buildRequestMessage(self) -> OMADMMessage:
        oldMessageId = self.message_id
        self.message_id += 1
        newMessage = OMADMMessage(self.commands, self.message_id)
        # We need to populate the sync header status if it's not the initial
        prevMsg = self.messages.get(oldMessageId, {}).get(MessageType.RESPONSE)
        if prevMsg:
            newMessage.sync_status = prevMsg.sync_status
        self.addMessage(self.message_id, newMessage, MessageType.REQUEST)
        self.commands = []
        return newMessage
