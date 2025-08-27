#requires -version 3.0


####Powershell: Various Generic Samples (see $sampleType below).

####BeyondInsight and Password Safe API: 6.4.4+
####Workflow: Sign in, Execute sample type, Sign out
####Permissions: Dependent on sample type

#### Script Version: 1.2
#### Modified: 29-Jun-2018


cls;


#Secure Connection
$baseUrl = "https://tenantname.ps.beyondtrustcloud.com/BeyondTrust/api/public/v3/";

#The Application API Key generated in BeyondInsight
$apiKey = "your-api-key";

#Username of BeyondInsight user granted permission to the API Key
$runAsUser = "you-api-user";

#Password if required by the API registration
#$runAsUserPassword = "un1qu3";



#Client Certificate Parameters:
#Type of certificate. Possible values:
#None
#BICertificate
#SmartCardLogon
#$clientCertificateType = "None";

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

#$cert= PSafe-FindBICertificate
#Script-level Client Certificate
[System.Security.Cryptography.X509Certificates.X509Certificate2]$script:authCert = $cert;


#region Functions

#Builds a full URI for the given API
function PSafe-BuildUri([string]$api)
{
    "{0}{1}" -f $baseUrl, $api;
}


#Builds and returns the headers for the request
function PSafe-BuildHeaders()
{
    #Build the Authorization header
    if ( $script:runAsUserPassword -eq $null )
    { @{ Authorization="PS-Auth key=${script:apiKey}; runas=${script:runAsUser};"; }; }
    else
    { @{ Authorization="PS-Auth key=${script:apiKey}; runas=${script:runAsUser}; pwd=[${script:runAsUserPassword}];"; }; }
}

#Calls the SignAppin API
function PSafe-SignAppin()
{
    $method = "POST";
    $uri = PSafe-BuildUri "Auth/SignAppin";
    $headers = PSafe-BuildHeaders;

    try
    {
        if ($script:authCert -eq $null)
        {
            $result = Invoke-RestMethod -Uri $uri -Method $method -Headers $headers -SessionVariable script:session;
            $result;
        }
        else
        {
            $result = Invoke-RestMethod -Uri $uri -Method $method -Headers $headers -SessionVariable script:session -Certificate $script:authCert;
            $result;
        }
    }
    catch [System.Net.WebException]
    {
        #401 with WWW-Authenticate-2FA header expected for two-factor authentication challenge
        if($_.Exception.Response.StatusCode -eq 401 -and $_.Exception.Response.Headers.Contains("WWW-Authenticate-2FA") -eq $true)
        {
            $challengeMessage = $_.Exception.Response.Headers["WWW-Authenticate-2FA"];
            $challengeResponse = Read-Host $challengeMessage;
            PSafe-SignAppinChallenge $challengeResponse;
        }
        else
        {
            throw;
        }
    }

}

#Calls the SignAppin API with an Authentication challenge
#Note: Should only be called after an initial attempt at Auth/SignAppin since it uses the existing Web Session
function PSafe-SignAppinChallenge($challengeResponse)
{
    $method = "POST";
    $uri = PSafe-BuildUri "Auth/SignAppin";
    $headers = PSafe-BuildHeaders;

    # add challenge to the Auth header
    $headers["Authorization"] = "$($headers["Authorization"]) challenge=$($challengeResponse);"; 

    if ($script:authCert -eq $null)
    {
        $result = Invoke-RestMethod -Uri $uri -Method $method -Headers $headers -WebSession $script:session;
        $result;
    }
    else
    {
        $result = Invoke-RestMethod -Uri $uri -Method $method -Headers $headers -WebSession $script:session -Certificate $script:authCert;
        $result;
    }
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