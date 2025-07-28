function Read-Accesstoken
{
<#
    .SYNOPSIS
    Extract details from the given Access Token

    .DESCRIPTION
    Extract details from the given Access Token and returns them as PS Object

    .Parameter AccessToken
    The Access Token.
    
    .Example
    PS C:\>$token=Get-AADIntReadAccessTokenForAADGraph
    PS C:\>Parse-AADIntAccessToken -AccessToken $token

    aud                 : https://graph.windows.net
    iss                 : https://sts.windows.net/f2b2ba53-ed2a-4f4c-a4c3-85c61e548975/
    iat                 : 1589477501
    nbf                 : 1589477501
    exp                 : 1589481401
    acr                 : 1
    aio                 : ASQA2/8PAAAALe232Yyx9l=
    amr                 : {pwd}
    appid               : 1b730954-1685-4b74-9bfd-dac224a7b894
    appidacr            : 0
    family_name         : company
    given_name          : admin
    ipaddr              : 107.210.220.129
    name                : admin company
    oid                 : 1713a7bf-47ba-4826-a2a7-bbda9fabe948
    puid                : 100354
    rh                  : 0QfALA.
    scp                 : user_impersonation
    sub                 : BGwHjKPU
    tenant_region_scope : NA
    tid                 : f2b2ba53-ed2a-4f4c-a4c3-85c61e548975
    unique_name         : admin@company.onmicrosoft.com
    upn                 : admin@company.onmicrosoft.com
    uti                 : -EWK6jMDrEiAesWsiAA
    ver                 : 1.0

    .Example
    PS C:\>Parse-AADIntAccessToken -AccessToken $token -Validate

    Read-Accesstoken : Access Token is expired
    At line:1 char:1
    + Read-Accesstoken -AccessToken $at -Validate -verbose
    + ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        + CategoryInfo          : NotSpecified: (:) [Write-Error], WriteErrorException
        + FullyQualifiedErrorId : Microsoft.PowerShell.Commands.WriteErrorException,Read-Accesstoken

    aud                 : https://graph.windows.net
    iss                 : https://sts.windows.net/f2b2ba53-ed2a-4f4c-a4c3-85c61e548975/
    iat                 : 1589477501
    nbf                 : 1589477501
    exp                 : 1589481401
    acr                 : 1
    aio                 : ASQA2/8PAAAALe232Yyx9l=
    amr                 : {pwd}
    appid               : 1b730954-1685-4b74-9bfd-dac224a7b894
    appidacr            : 0
    family_name         : company
    given_name          : admin
    ipaddr              : 107.210.220.129
    name                : admin company
    oid                 : 1713a7bf-47ba-4826-a2a7-bbda9fabe948
    puid                : 100354
    rh                  : 0QfALA.
    scp                 : user_impersonation
    sub                 : BGwHjKPU
    tenant_region_scope : NA
    tid                 : f2b2ba53-ed2a-4f4c-a4c3-85c61e548975
    unique_name         : admin@company.onmicrosoft.com
    upn                 : admin@company.onmicrosoft.com
    uti                 : -EWK6jMDrEiAesWsiAA
    ver                 : 1.0
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True,ValueFromPipeline)]
        [String]$AccessToken,
        [Parameter()]
        [Switch]$ShowDate,
        [Parameter()]
        [Switch]$Validate

    )
    Process
    {
        # Token sections
        $sections =  $AccessToken.Split(".")
        if($sections.Count -eq 5)
        {
            Write-Warning "JWE token, expected JWS. Unable to parse."
            return
        }
        $header =    $sections[0]
        $payload =   $sections[1]
        $signature = $sections[2]

        # Convert the token to string and json
        $payloadString = Convert-B64ToText -B64 $payload
        $payloadObj=$payloadString | ConvertFrom-Json

        if($ShowDate)
        {
            # Show dates
            $payloadObj.exp=($epoch.Date.AddSeconds($payloadObj.exp)).toString("yyyy-MM-ddTHH:mm:ssZ").Replace(".",":")
            $payloadObj.iat=($epoch.Date.AddSeconds($payloadObj.iat)).toString("yyyy-MM-ddTHH:mm:ssZ").Replace(".",":")
            $payloadObj.nbf=($epoch.Date.AddSeconds($payloadObj.nbf)).toString("yyyy-MM-ddTHH:mm:ssZ").Replace(".",":")
        }

        if($Validate)
        {
            # Check the signature
            if((Is-AccessTokenValid -AccessToken $AccessToken))
            {
                Write-Verbose "Access Token signature successfully verified"
            }
            else
            {
                Write-Error "Access Token signature could not be verified"
            }

            # Check the timestamp
            if((Is-AccessTokenExpired -AccessToken $AccessToken))
            {
                Write-Error "Access Token is expired"
            }
            else
            {
                Write-Verbose "Access Token is not expired"
            }

        }

        # Debug
        Write-Debug "PARSED ACCESS TOKEN: $($payloadObj | Out-String)"
        
        # Return
        $payloadObj
    }
}

Function Convert-B64ToByteArray
{

    [cmdletbinding()]

    param(
        [parameter(Mandatory=$true,ValueFromPipeline)]
        [String]
        $B64
    )
    $B64 = $B64.Replace("_","/").Replace("-","+").TrimEnd(0x00,"=")

    # Fill the header with padding for Base 64 decoding
    while ($B64.Length % 4)
    {
        $B64 += "="
    }

    return [convert]::FromBase64String($B64)
}

Function Convert-B64ToText
{

    [cmdletbinding()]

    param(
        [parameter(Mandatory=$true)]
        [String]
        $B64
    )

    return [text.encoding]::UTF8.GetString(([byte[]](Convert-B64ToByteArray -B64 $B64)))
}

Function Convert-ByteArrayToB64
{

    [cmdletbinding()]

    param(
        [parameter(Mandatory=$true,ValueFromPipeline)]
        [Byte[]]$Bytes,
        [Switch]$UrlEncode,
        [Switch]$NoPadding
    )

    $b64 = [convert]::ToBase64String($Bytes);

    if($UrlEncode)
    {
        $b64 = $b64.Replace("/","_").Replace("+","-")
    }

    if($NoPadding -or $UrlEncode)
    {
        $b64 = $b64.Replace("=","")
    }

    return $b64
}

function Get-MDMEnrollmentService
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$UserName="user@alt.none"
    )
    Process
    {
        $messageId =          $(New-Guid).ToString()
        $deviceType =         "CIMClient_Windows"
        $applicationVersion = "10.0.18363.0"
        $OSEdition =          "4"
        
        $body=@"
<s:Envelope xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:s="http://www.w3.org/2003/05/soap-envelope">
	<s:Header>
		<a:Action s:mustUnderstand="1">http://schemas.microsoft.com/windows/management/2012/01/enrollment/IDiscoveryService/Discover</a:Action>
		<a:MessageID>urn:uuid:$messageId</a:MessageID>
		<a:ReplyTo>
			<a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
		</a:ReplyTo>
		<a:To s:mustUnderstand="1">https://enrollment.manage.microsoft.com:443/enrollmentserver/discovery.svc</a:To>
	</s:Header>
	<s:Body>
		<Discover xmlns="http://schemas.microsoft.com/windows/management/2012/01/enrollment">
			<request xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
				<EmailAddress>$UserName</EmailAddress>
                <RequestVersion>4.0</RequestVersion>
				<DeviceType>$deviceType</DeviceType>
				<ApplicationVersion>$applicationVersion</ApplicationVersion>
				<OSEdition>$OSEdition</OSEdition>
				<AuthPolicies>
					<AuthPolicy>OnPremise</AuthPolicy>
					<AuthPolicy>Federated</AuthPolicy>
				</AuthPolicies>
			</request>
		</Discover>
	</s:Body>
</s:Envelope>
"@
        $headers=@{
            "Content-Type" = "application/soap+xml; charset=utf-8"
            "User-Agent"   = "ENROLLClient"
        }

        $response = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "https://enrollment.manage.microsoft.com/enrollmentserver/discovery.svc" -Body $body -ContentType "application/soap+xml; charset=utf-8" -Headers $headers

        # Get the data
        $activityId = $response.Envelope.Header.ActivityId.'#text'
        $serviceUri = $response.Envelope.Body.DiscoverResponse.DiscoverResult.EnrollmentServiceUrl

        if(!$serviceUri.EndsWith($activityId))
        {
            $serviceUri += "?client-request-id=$activityId"
        }

        # Return
        return $serviceUri
            
    }
}


function Get-MDMRecoveryCert
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        [String]$DeviceName,
        [Parameter(Mandatory=$True)]
        [bool]$BPRT
    )
    Process
    {
        # Get the claims from the access token
        $claims = Read-Accesstoken -AccessToken $AccessToken

        # Construct the values
        #$enrollmentUrl =       Get-MDMEnrollmentService -UserName $claims.upn
        $enrollmentUrl = "https://fef.msua09.manage.microsoft.com:443/StatelessEnrollmentService/DeviceEnrollment.svc"
        $binarySecurityToken = Convert-ByteArrayToB64 -Bytes ([text.encoding]::UTF8.GetBytes($AccessToken))

        $HWDevID = "$($claims.deviceid)$($claims.tid)".Replace("-","")
        $deviceId = $claims.deviceid.Replace("-","")

        # Create a private key
        $rsa = [System.Security.Cryptography.RSA]::Create(2048)

        # Initialize the Certificate Signing Request object
        $CN = "CN=$($claims.deviceid)" 
        $req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new($CN, $rsa, [System.Security.Cryptography.HashAlgorithmName]::SHA256,[System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        
        # Create the signing request
        $csr = Convert-ByteArrayToB64 -Bytes $req.CreateSigningRequest()
        
        $headers=@{
            "Content-Type" = "application/soap+xml; charset=utf-8"
            "User-Agent"   = "ENROLLClient"
        }

        # Create the CSR request body
        $csrBody=@"
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512" xmlns:ac="http://schemas.xmlsoap.org/ws/2006/12/authorization">
	<s:Header>
		<a:Action s:mustUnderstand="1">http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RST/wstep</a:Action>
		<a:MessageID>urn:uuid:$((New-Guid).ToString())</a:MessageID>
		<a:ReplyTo>
			<a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
		</a:ReplyTo>
		<a:To s:mustUnderstand="1">$enrollmentUrl</a:To>
		<wsse:Security s:mustUnderstand="1">
			<wsse:BinarySecurityToken ValueType="urn:ietf:params:oauth:token-type:jwt" EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary">$binarySecurityToken</wsse:BinarySecurityToken>
		</wsse:Security>
	</s:Header>
	<s:Body>
		<wst:RequestSecurityToken>
			<wst:TokenType>http://schemas.microsoft.com/5.0.0.0/ConfigurationManager/Enrollment/DeviceEnrollmentToken</wst:TokenType>
			<wst:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Recovery</wst:RequestType>
			<wsse:BinarySecurityToken ValueType="http://schemas.microsoft.com/windows/pki/2009/01/enrollment#PKCS10" EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary">$csr</wsse:BinarySecurityToken>
            <ac:AdditionalContext xmlns="http://schemas.xmlsoap.org/ws/2006/12/authorization">
				<ac:ContextItem Name="UXInitiated">
					<ac:Value>(($BPRT -eq $false).ToString().ToLower())</ac:Value>
				</ac:ContextItem>
				<ac:ContextItem Name="HWDevID">
					<ac:Value>$HWDevID</ac:Value>
				</ac:ContextItem>
                <ac:ContextItem Name="BulkAADJ">
					<ac:Value>$($BPRT.ToString().ToLower())</ac:Value>
				</ac:ContextItem>
				<ac:ContextItem Name="Locale">
					<ac:Value>en-US</ac:Value>
				</ac:ContextItem>
				<ac:ContextItem Name="TargetedUserLoggedIn">
					<ac:Value>$(($BPRT -eq $false).ToString().ToLower())</ac:Value>
				</ac:ContextItem>
				<ac:ContextItem Name="EnrollmentData">
					<ac:Value></ac:Value>
				</ac:ContextItem>
				<ac:ContextItem Name="OSEdition">
					<ac:Value>4</ac:Value>
				</ac:ContextItem>
				<ac:ContextItem Name="DeviceName">
					<ac:Value>$DeviceName</ac:Value>
				</ac:ContextItem>
				<ac:ContextItem Name="MAC">
					<ac:Value>00-00-00-00-00-00</ac:Value>
				</ac:ContextItem>
				<ac:ContextItem Name="DeviceID">
					<ac:Value>$deviceId</ac:Value>
				</ac:ContextItem>
				<ac:ContextItem Name="EnrollmentType">
					<ac:Value>Device</ac:Value>
				</ac:ContextItem>
				<ac:ContextItem Name="DeviceType">
					<ac:Value>CIMClient_Windows</ac:Value>
				</ac:ContextItem>
				<ac:ContextItem Name="OSVersion">
					<ac:Value>10.0.18363.0</ac:Value>
				</ac:ContextItem>
				<ac:ContextItem Name="ApplicationVersion">
					<ac:Value>10.0.18363.0</ac:Value>
				</ac:ContextItem>
			</ac:AdditionalContext>
		</wst:RequestSecurityToken>
	</s:Body>
</s:Envelope>
"@

        # Clean the url
        $url=$enrollmentUrl.Replace(":443","")

        try {
            $response = Invoke-RestMethod -UseBasicParsing -Method Post -Uri $url -Body $csrBody -ContentType "application/soap+xml; charset=utf-8" -Headers $headers -Debug -ErrorVariable restError
        } catch {
            Write-Host "Error Status Code:" $_.Exception.Response.StatusCode.value__
            Write-Host "Error Status Description:" $_.Exception.Response.StatusDescription
            Write-Host "Message:" $_.Exception.Message
            Write-Host "Raw response:" $_.Exception.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
            $reader.BaseStream.Position = 0
            $reader.DiscardBufferedData()
            Write-Host "Response body:" $reader.ReadToEnd()
        }


        # Get the data
        $binSecurityToken = $response.Envelope.Body.RequestSecurityTokenResponseCollection.RequestSecurityTokenResponse.RequestedSecurityToken.BinarySecurityToken.'#text'
        $xmlSecurityToken = [xml][text.encoding]::UTF8.GetString((Convert-B64ToByteArray -B64 $binSecurityToken))

        Write-Debug "BinarySecurityToken: $($xmlSecurityToken.OuterXml)"

        # Get the certificates
        $CA =       $xmlSecurityToken.'wap-provisioningdoc'.characteristic[0].characteristic[0].characteristic.characteristic.Parm.value
        $IntMedCA = $xmlSecurityToken.'wap-provisioningdoc'.characteristic[0].characteristic[1].characteristic.characteristic.Parm.value
        $binCert =  [byte[]](Convert-B64ToByteArray -B64 ($xmlSecurityToken.'wap-provisioningdoc'.characteristic[0].characteristic[2].characteristic.characteristic.Parm.value))

        # Create a new x509certificate 
        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($binCert,"",[System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet -bor [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)

        # Store the private key to so that it can be exported
        $cspParameters = [System.Security.Cryptography.CspParameters]::new()
        $cspParameters.ProviderName =    "Microsoft Enhanced RSA and AES Cryptographic Provider"
        $cspParameters.ProviderType =    24
        $cspParameters.KeyContainerName ="AADInternals"
            
        # Set the private key
        $privateKey = [System.Security.Cryptography.RSACryptoServiceProvider]::new(2048,$cspParameters)
        $privateKey.ImportParameters($rsa.ExportParameters($true))
        $cert.PrivateKey = $privateKey

        # Generate the return value
        $joinInfo = @(
            $CA,
            $IntMedCA,
            $cert
        )

        return $joinInfo
            
    }
}