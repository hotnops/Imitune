"""
The commands in this file represent all the different types of OMA-DM
commands that make up an OMA DM message. Each class inherits from the
base OMACommand class. Any class can implement its own to_xml functions
"""
from collections import OrderedDict
from lxml import etree
import xmltodict


class OMACommand:
    """
    Base class representing the OMA DM command
    """

    def __init__(self, command: dict):
        self.cmd_ref = command.get("CmdID")
        self.msg_ref = None
        self.target = command.get("Item", {}).get("Target", {}).get("LocURI")
        self.type = None
        self._command = command
        self.status = 0
        self.command = ""
        self.data = None

    def add_msg_ref(self, message_id):
        """
        Populate the msg_ref member variable with the passed in
        message_id
        """
        self.msg_ref = message_id

    def add_cmd_id(self, command_id):
        """
        Add the CMD id node to the message in the
        order that Intune accepts, which is the first
        node of the command node
        """
        # We need to do this because CmdID has to be
        # first or else Intune complains
        new_dict = OrderedDict()
        new_dict['CmdID'] = command_id
        for key, value in self._command.items():
            new_dict[key] = value

        self._command = new_dict

    def to_xml(self, command_id):
        """
        Convert the OMACommand class to its
        XML representation
        """
        self.add_cmd_id(command_id)
        # Generate the XML string
        ret_xml = xmltodict.unparse(
            {self.command: self._command}, pretty=False)
        # Parse the string into an Element
        return etree.fromstring(ret_xml.encode('utf-8'))

    def to_status_xml(self, command_id):
        """
        Produce the status results xml for the command
        based on the status field
        """
        status_elem = etree.Element("Status")
        etree.SubElement(status_elem, "CmdID").text = str(command_id)
        etree.SubElement(status_elem, "MsgRef").text = str(self.msg_ref)
        etree.SubElement(status_elem, "CmdRef").text = str(self.cmd_ref)
        etree.SubElement(status_elem, "Cmd").text = str(self.command)
        data_elem = etree.SubElement(status_elem, "Data")
        data_elem.text = str(self.status)
        if self.status == 404:
            data_elem.set(
                "{http://schemas.microsoft.com/MobileDevice/MDM}originalerror",
                "0x86000002")
        elif self.status == 500:
            data_elem.set(
                "{http://schemas.microsoft.com/MobileDevice/MDM}originalerror",
                "0x800710DF")

        # Return a pretty-printed XML string
        return status_elem

    def to_results_xml(self, command_id):
        """
        Produce the results xml for the command
        based on the data field. Currently, only get
        commands produce a results field based on observations
        """
        if self.status != 200:
            return None  # No results if status is not 200

        # <Results>
        results_elem = etree.Element("Results")
        etree.SubElement(results_elem, "CmdID").text = str(command_id)
        etree.SubElement(results_elem, "MsgRef").text = str(self.msg_ref)
        etree.SubElement(results_elem, "CmdRef").text = str(self.cmd_ref)

        # <Item>
        item_elem = etree.SubElement(results_elem, "Item")
        source_elem = etree.SubElement(item_elem, "Source")
        etree.SubElement(source_elem, "LocURI").text = str(self.target)

        # <Data>
        etree.SubElement(item_elem, "Data").text = str(self.data)

        return results_elem


class OMAGetCommand(OMACommand):
    """
    Represents an OMA DM Get command
    """

    def __init__(self, command: dict):
        super().__init__(command)
        self.command = "Get"

    def execute(self, client):
        """
        Execute a get command by updating values in the
        management tree
        """
        self.data = client.managementTree.get(self.target, None)
        if self.data is None:
            self.status = 404
        else:
            self.status = 200


class OMAAddCommand(OMACommand):
    """
    Represents an OMA DM Add command
    """

    def __init__(self, command: dict):
        super().__init__(command)
        self.command = "Add"
        self.data = command.get("Item", {}).get("Data", '')

    def execute(self, client):
        """
        Execute an add command by updating values in the
        management tree
        """
        client.managementTree.set(self.target, self.data)
        self.status = 200


class OMAReplaceCommand(OMACommand):
    """
    Represents an OMA DM Replace command
    """

    def __init__(self, command: dict):
        super().__init__(command)
        self.command = "Replace"
        self.data = command.get("Item", {}).get("Data", '')

    def execute(self, client):
        """
        Execute a replace command by updating values in the
        management tree
        """
        client.managementTree.set(self.target, self.data)
        self.data = None
        self.status = 200


class OMADeleteCommand(OMACommand):
    """
    Represents an OMA DM Delete command
    """

    def __init__(self, command: dict):
        super().__init__(command)
        self.command = "Delete"

    def execute(self, client):
        """
        Execute a delete command by updating values in the
        management tree
        """
        if self.target not in client.managementTree._data:
            self.status = 404
        else:
            client.managementTree.delete(self.target)


class OMAExecCommand(OMACommand):
    """
    Represents an OMA DM Exec command
    """

    def __init__(self, command: dict):
        super().__init__(command)
        self.command = "Exec"

    def execute(self, client):
        """
        Execute an execute command by simply
        returning a 200 status
        """
        self.status = 200


class OMAStatusCommand(OMACommand):

    def __init__(self, command: dict):
        super().__init__(command)
        self.command = "Status"

    def execute(self, client):
        self.status = 200


class OMAAtomicCommand(OMACommand):

    def __init__(self, command: dict):
        super().__init__(command)
        self.command = "Atomic"

    def execute(self, client):
        self.status = 200


class OMAAlertCommand(OMACommand):

    def __init__(self, command: dict):
        super().__init__(command)
        self.command = "Alert"
        self.data = command['Data']
        self.item = command.get("Item", {})


class OMASequenceCommand(OMAAddCommand):

    def __init__(self, command: dict):
        super().__init__(command)
        self.command = "Sequence"

    def execute(self, client):
        self.status = 200


class OMASyncHdrCommand(OMAAddCommand):

    def __init__(self, command: dict):
        super().__init__(command)
        self.cmdId = 0
        self.command = "SyncHdr"
        self.status = 200

    def execute(self, client):
        self.status = 200


def xml_to_commands(xml_dict: dict, commands: list):
    for key, values in xml_dict.items():
        # These don't have to be enumerable, so
        # this is a hacky way to keep the code clean
        if not isinstance(values, list):
            values = [values]
        for value in values:
            if key == "Get":
                command = OMAGetCommand(value)
            elif key == "Add":
                command = OMAAddCommand(value)
            elif key == "Replace":
                command = OMAReplaceCommand(value)
            elif key == "Delete":
                command = OMADeleteCommand(value)
            elif key == "Exec":
                command = OMAExecCommand(value)
            elif key == "Status":
                # This is status from Intune
                continue
            elif key == "Atomic":
                command = OMAAtomicCommand(value)
                # We don't need CmdID for recursive processing
                value.pop("CmdID")
                xml_to_commands(value, commands)
            elif key == "Sequence":
                command = OMASequenceCommand(value)
                value.pop("CmdID")
                xml_to_commands(value, commands)
            elif key == "Final":
                continue
            else:
                print(f"[!] Unknown OMA command: {value}")
                return
            commands.append(command)
