###########################################
# Tri Bui
# Ferris State University
# LogRhythm SRP - 04/2021
###########################################


[CmdletBinding()]
Param(
    [string]$email = "test@test.com",
    [string]$notif = "email@example.com",
    [string]$CredentialsFile = "C:\LogRhythm\SmartResponsePlugins\InfoSecPS.xml",
    [string]$BlockRuleID = "CHANGE_THIS_TO_YOUR_TRANSPORT_RULE_ID",
    [string]$RedirectID = "CHANGE_THIS_TO_YOUR_TRANSPORT_RULE_ID"
)

# Settings:
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


try{
    $BlockList = (Get-TransportRule -Identity $BlockRuleID).From
    $RedirectList = (Get-TransportRule -Identity $RedirectID).SentTo
    $Updated = $false

    $email.Split(",") | % {

        if($_ -notin $BlockList) {
            $BlockList += $_
            Set-TransportRule -Identity $BlockRuleID -From $BlockList
            Write-Host "Added to Blocked list: " ($_) -ForegroundColor Red
            $Updated = $true
        } else { Write-Host "Blocked list: $($_) is already in the Block list`n" }

        if($_ -notin $RedirectList) {
            $RedirectList += $_
            Set-TransportRule -Identity $RedirectID -SentTo $RedirectList
            Write-Host "Added to Redirect list: " ($_) -ForegroundColor Red
            $Updated = $true
        } else { Write-Host "Redirect list: $($_) is already in the Redirect list`n" }

    }

    if($Updated -and ($notif -ne '')) {
        #----------Notification Email--------
        $Body = "<html><body><div>
        <h2>Email blocking and redirecting on: $(Get-Date) </h2>
        <p>We have identified that the following email have been sending scam/phishing email. We have blocked all of the inbound email(s) from that email and redirect email(s) replying to them to us.</p>
        <div>"
        $Body += "<p>$($email -replace ",","<br>")</p>"
        $Body += "</div></div></body></html>"
        $Subject = "Email blocking and redirecting for $($email) " + $(Get-Date)    
        [string[]]$To= $notif.Split(',')    

        Send-MailMessage -From $fromEmail -To $To -Subject $Subject -Body $Body -SmtpServer $smtpServer -Port "25" -BodyAsHtml -Priority High
        Write-Host "Email notification was sent successfully!" 
    }

} catch{
    Write-Host "Error: $err"
}

Disconnect-ExchangeOnline -Confirm:$false