###########################################
# Tri Bui
# Ferris State University
# LogRhythm SRP - 04/2021
###########################################


[CmdletBinding()]
Param(
    [string]$users = "",
    [string]$notif = "email@example.com",
    [string]$CredentialsFile = "C:\LogRhythm\SmartResponsePlugins\Cred.xml",
    [string]$policyName = "Block Basic Auth"
)

# Domain settings
$domain = "example.com"
$fromEmail = "alert@email.com"
$smtpServer = "smtp.example.com"


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

$EXOCheck = Get-Module -ListAvailable -Name ExchangeOnlineManagement
if (!$EXOCheck) {
    Write-Host "ExchangeOnlineManagement module does not exist. Trying to install.."
    if($isRunAsAdministrator) {
        Install-Module -Name ExchangeOnlineManagement
        Import-Module -Name ExchangeOnlineManagement
    } else { Write-Host "Please run the scripts using Administrator privilege." -ForegroundColor Red; Break}
}
$basicAuth = (Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\).AllowBasic
Write-Host "Checking BasicAuth:" ($basicAuth -eq 1) `n
whoami
if($basicAuth -eq 0) {
    if($isRunAsAdministrator) {
        Set-ExecutionPolicy RemoteSigned
        #winrm set winrm/config/client/auth @{Basic="true"}
        Set-ItemProperty -Path "HKLM:SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowBasic" -Value 1
        winrm quickconfig -force
    } else { Write-Host "BasicAuth for WimRM is not enabled. Please run as Administrator."`n -ForegroundColor Red; Break }
} 


$hasEXO = Get-PSSession
if(!$hasEXO) { 
    Write-Host "Connecting to EXO"
    Connect-ExchangeOnline -Credential $credObject -ShowBanner:$false
}

#------------------------------------------------------------------

if($users -ne "" -and $policyName -ne "") {
    try{
        
        $users.Split(",") | % {
            $uName = $_
                    if($uName.IndexOf("@") -eq -1) {
                        $uName += "@$($domain)"
                    
                    }
            Set-User -Identity $uName -AuthenticationPolicy $policyName -Confirm:$false
            Write-Host "$($uName) BasicAuth Disabled."
        }

        if($notif -ne '') {
            #----------Notification Email--------
            $Body = "<html><body><div>
            <h2>Disable Basic Auth on $(Get-Date) </h2>
            <p>We have disabled the O365 BasicAuth of the following account(s):</p>
            <div>"
            $Body += "<p>$($users -replace ",","<br>")</p>"
            $Body += "</div></div></body></html>"
            $Subject = "Disable BasicAuth for [$($users)] " + $(Get-Date)    
            [string[]]$To= $notif.Split(',')    

            Send-MailMessage -From $fromEmail -To $To -Subject $Subject -Body $Body -SmtpServer $smtpServer -Port "25" -BodyAsHtml -Priority High
            Write-Host "Email notification was sent successfully!" 
        }

    } catch{
        Write-Host "Error: $err"
    }

    Disconnect-ExchangeOnline -Confirm:$false

}