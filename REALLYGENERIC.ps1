#requires -version 3.0


####Powershell: Various Generic Samples (see $sampleType below).

####BeyondInsight and Password Safe API: 6.4.4+
####Workflow: Sign in, Execute sample type, Sign out
####Permissions: Dependent on sample type

#### Script Version: 1.2
#### Modified: 29-Jun-2018


cls;


#Secure Connection
$baseUrl = "https://your_BT_server/BeyondTrust/api/public/v3/";


# OAuth 2.0 Client Credentials
$clientId = "your_client_id"  # Set your client_id
$clientSecret = "your_client_secret"  # Set your client_secret
$script:accessToken = $null



#Client Certificate Parameters:
#Type of certificate. Possible values:
#None
#BICertificate
#SmartCardLogon
$clientCertificateType = "None";

#Verbose logging?
$verbose = $True;



#region Trust All Certificates
#Uncomment the following block if you want to trust an unsecure connection.

#The Invoke-RestMethod CmdLet does not currently have an option for ignoring SSL warnings (i.e self-signed CA certificates).
#This policy is a temporary workaround to allow that for development purposes.
#Warning: If using this policy, be absolutely sure the host is secure.
add-type "
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(ServicePoint srvPoint, X509Certificate certificate, WebRequest request, int certificateProblem)
    {
        return true;
    }
}
";
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy;

#endregion

$cert= PSafe-FindBICertificate
#Script-level Client Certificate
[System.Security.Cryptography.X509Certificates.X509Certificate2]$script:authCert = $cert;


#region Functions

#Builds a full URI for the given API
function PSafe-BuildUri([string]$api)
{
    "{0}{1}" -f $baseUrl, $api;
}



# Gets a new OAuth 2.0 access token using client credentials (Password Safe style)
function Get-OAuthToken() {
    $Body = "grant_type=client_credentials&client_id=$clientId&client_secret=$clientSecret"
    $tokenResponse = Invoke-RestMethod -Uri ("{0}BeyondTrust/api/public/v3/auth/connect/token" -f $baseUrl) -Method POST -Body $Body -SessionVariable session
    $script:accessToken = $tokenResponse.access_token
}

# Builds and returns the headers for the request
function PSafe-BuildHeaders() {
    if (-not $script:accessToken) { Get-OAuthToken }
    @{ Authorization = "Bearer $($script:accessToken)" }
}

#Calls the SignAppin API

# Calls the SignAppin API (now with OAuth)
function PSafe-SignAppin() {
    $method = "POST"
    $uri = PSafe-BuildUri "Auth/SignAppin"
    $headers = PSafe-BuildHeaders

    try {
        if ($script:authCert -eq $null) {
            $result = Invoke-RestMethod -Uri $uri -Method $method -Headers $headers -SessionVariable script:session
            $result
        } else {
            $result = Invoke-RestMethod -Uri $uri -Method $method -Headers $headers -SessionVariable script:session -Certificate $script:authCert
            $result
        }
    } catch {
        throw
    }
}

#Calls the SignAppin API with an Authentication challenge
#Note: Should only be called after an initial attempt at Auth/SignAppin since it uses the existing Web Session

# 2FA challenge is not supported in OAuth client credentials flow, so this is now a stub
function PSafe-SignAppinChallenge($challengeResponse) {
    throw "2FA challenge is not supported with OAuth client credentials flow."
}

#Calls the given API
function PSafe-RestMethod([string]$method, [string]$api, $body)
{
    $uri = PSafe-BuildUri $api;
    $headers = PSafe-BuildHeaders;

    if ($script:authCert -eq $null)
    {
        $result = Invoke-RestMethod -Uri $uri -Method $method -WebSession $script:session -Headers $headers -Body $body;
        $result;
    }
    else
    {
        $result = Invoke-RestMethod -Uri $uri -Method $method -WebSession $script:session -Headers $headers -Body $body -Certificate $script:authCert;
        $result;
    }
}

#Calls the given API with a custom Content Type
function PSafe-RestMethod([string]$method, [string]$api, $body, $contentType)
{
    $uri = PSafe-BuildUri $api;
    $headers = PSafe-BuildHeaders;

    if ($script:authCert -eq $null)
    {
        $result = Invoke-RestMethod -Uri $uri -Method $method -WebSession $script:session -ContentType $contentType -Headers $headers -Body $body;
        $result;
    }
    else
    {
        $result = Invoke-RestMethod -Uri $uri -Method $method -WebSession $script:session -ContentType $contentType -Headers $headers -Body $body -Certificate $script:authCert;
        $result;
    }
}

#Calls a POST API
function PSafe-Post([string]$api, $body)
{
    PSafe-RestMethod "POST" $api $body;
}

#Calls a POST API with the given ContentType
function PSafe-Post([string]$api, $body, $contentType)
{
    PSafe-RestMethod "POST" $api $body $contentType;
}

#Calls a GET API
function PSafe-Get([string]$api, $body)
{
    PSafe-RestMethod "GET" $api $body;
}

#Calls a PUT API
function PSafe-Put([string]$api, $body)
{
    PSafe-RestMethod "PUT" $api $body "application/json";
}

#Calls a DELETE API
function PSafe-Delete([string]$api, $body)
{
    PSafe-RestMethod "DELETE" $api $body;
}

#Json Wrapper - The Powershell Cmd-lets have an intrinsic maximum json length that cannot be modified
#  Note: This accepts piped input.
function From-Json()
{
    [void][System.Reflection.Assembly]::LoadWithPartialName("System.Web.Extensions"); 
    $jsonserial = New-Object -TypeName System.Web.Script.Serialization.JavaScriptSerializer;
    $jsonserial.MaxJsonLength = [int]::MaxValue;
    $jsonserial.DeserializeObject($input);
}

#Displays the given list of items
function Display-Items($items)
{
    $cnt = $items.Length;
    if ($cnt -eq $null)
    { 
        $cnt = "1"; 
    }

    "..$($cnt) returned:";
    foreach($item in $items) 
    { 
        "$($item)"; 
    }
}

#endregion

#PSafe-SignAppin
#psafe-post "UserGroups" @{"GroupType"="ActiveDirectory";"GroupName"="req_BPM";"description"="req_BPM";"domainName"="packet.farm";"SmartRuleAccess"=@{"SmartRuleID"=10038;"AccessLevelID"=1}}

#Find the BeyondInsight signed client certificate
function PSafe-FindBICertificate()
{
    $certStore = "LocalMachine"; # Alternative: CurrentUser
    $subFieldName = "CN";
    $issuedTo = "eEyeEmsClient";

    $cert = PSafe-FindClientCertificates $certStore | Where-Object { $_.Subject -eq "${subFieldName}=${issuedTo}" };
    $cert;
}

#Finds a client certificate for a User Principal Name, i.e. Smart Card Logon for AD account jdoe@doe-main
function PSafe-FindCertificateForUPN([string]$upnName)
{
    $certStore = "CurrentUser"; # Alternative: LocalMachine
    $nameType = "UpnName";

    $cert = PSafe-FindClientCertificates $certStore | Where-Object  {$_.GetNameInfo("${nameType}", $false) -eq $upnName };
    $cert;
}

#Finds all client certificates in the given certificate store
function PSafe-FindClientCertificates([string]$certStore)
{
    $certs = Get-ChildItem -Path "cert:\${certStore}\My" -EKU "Client Authentication";
    $certs;
}

#endregion