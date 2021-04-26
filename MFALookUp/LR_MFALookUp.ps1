###########################################
# Tri Bui
# Ferris State University
# LogRhythm SRP - 04/2021
###########################################


[CmdletBinding()]
Param(
    [string]$Users = "",
    [string]$CredentialsFile = "C:\LogRhythm\SmartResponsePlugins\Cred.xml"
)

# Domain settings
$domain = "example.com"

$isRunAsAdministrator = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

trap [Exception]
{
    Write-Error $("Error: $_")
}

#------------------Credentials---------------------------
if (Test-Path $CredentialsFile) {
    Write-Host ("Credentials file found: " + $CredentialsFile)
    try {
        #$credObject = Import-Clixml -Path $CredentialsFile
        $Credentials = Import-Clixml -Path $CredentialsFile
        $domainHost = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR((($Credentials.domain))))
        $acctName = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR((($Credentials.Account))))
        $password = $Credentials.Pass
        $credObject = New-Object System.Management.Automation.PSCredential -ArgumentList $acctName,$password
    }
    catch {

       Write-Error ("The credentials within the credentials file are corrupt. Please recreate the file: " + $CredentialsFile)
       exit
    }
}
else
{
    Write-Error "Credentials file not found. Please run setup action!"
    Exit 1
}
#--------------------------------------------------------------

$AzureCheck = Get-Module -ListAvailable -Name MSOnline
if (!$AzureCheck) {
    Write-Host "AzureAD module does not exist. Trying to install.."
    if($isRunAsAdministrator) {
        Install-Module -Name MSOnline -RequiredVersion 1.1.183.57 -AllowClobber
        Import-Module -Name MSOnline
    } else { Write-Host "Please run the scripts using Administrator privilege." -ForegroundColor Red; Break}
}

    try 
    { $var = Get-AzureADTenantDetail } 
    catch [Microsoft.Open.Azure.AD.CommonLibrary.AadNeedAuthenticationException] 
    { 
        Write-Host "You're not connected. Trying to connect to AzureAD..";
        try {
            Write-Host "Connecting to MSOL"
            Connect-MsolService -Credential $credObject
        } catch { 
            try { Connect-MsolService }
            catch { Break }
        }
    }

#------------------------------------------------------------------

if($Users -ne "") {
    try{
        
        $Users.Split(",") | % {
            $uName = $_
                    if($uName.IndexOf("@") -eq -1) {
                        $uName += "@$($domain)"
                    
                    }
            $test = Get-MsolUser -userPrincipalName $uName
            $state = $test.StrongAuthenticationRequirements.State
            if($state -ne $null) {
                Write-Host "$($uName) MFA $($state)"
            } else {
                Write-Host "$($uName) NO MFA"
            }
        }

    } catch{
        Write-Host "Error: $err"
    }

}

