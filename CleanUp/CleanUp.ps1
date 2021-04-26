###########################################
# Tri Bui
# Ferris State University
# LogRhythm SRP - 04/2021
###########################################


[CmdletBinding()]
Param(
    [string]$emails = "",
    [string]$ruleID = "",
    [string]$searchName = "",
    [string]$CredentialsFile = "C:\LogRhythm\SmartResponsePlugins\InfoSecPS.xml"
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

if($emails -ne "" -or $ruleID -ne "" -or $searchName -ne "") {

    $EXOCheck = Get-Module -ListAvailable -Name ExchangeOnlineManagement
    if (!$EXOCheck) {
        Write-Host "ExchangeOnlineManagement module does not exist. Trying to install.."
        if($isRunAsAdministrator) {
            Install-Module -Name ExchangeOnlineManagement
            Import-Module -Name ExchangeOnlineManagement
        } else { Write-Host "Please run the scripts using Administrator privilege." -ForegroundColor Red; Break}
    }
            winrm quickconfig -force >$null 2>&1
    $basicAuth = (Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\).AllowBasic
    #Write-Host "Checking BasicAuth:" ($basicAuth -eq 1) `n
    #whoami
    if($basicAuth -eq 0) {
        if($isRunAsAdministrator) {
            Set-ExecutionPolicy RemoteSigned
            #winrm set winrm/config/client/auth @{Basic="true"}
            Set-ItemProperty -Path "HKLM:SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowBasic" -Value 1
            winrm quickconfig -force >$null 2>&1
            Write-Host "Checking BasicAuth:" ((Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\).AllowBasic -eq 1)
        } else { Write-Host "BasicAuth for WimRM is not enabled. Please run as Administrator."`n -ForegroundColor Red; Break }
    } 


    $hasEXO = Get-PSSession
    if(!$hasEXO) { 
        Write-Host "Connecting to EXO"
        Connect-ExchangeOnline -Credential $credObject -ShowBanner:$false
    }

    #------------------------------------------------------------------

    if($emails -ne "") {
        $emails.Split(",") | % {

            if($_.IndexOf("@") -eq -1) {
                $_ += "@$($domain)"
            }
            try {
                Get-InboxRule -Mailbox $_ | Remove-InboxRule -Confirm:$false
                Write-Host "$($_) InboxRule removed."
            } catch {
                Write-Host "ERROR: $_"
            }
        }
        Write-host "####################"
        Write-host "Removed ALL Inbox Rules of $($emails)."
    }

    if($ruleID -ne "") {
        $ruleID.Split(",") | % {
            try {
                Remove-InboxRule -Identity $_ -Confirm:$false
                Write-Host "RuleID $($_) removed."
            } catch {
                Write-Host "ERROR: $_"
            }
        }
        Write-host "####################"
        Write-host "Removed ALL Inbox Rules ID $($ruleID)"
    }

    if($searchName -ne "") {
        $getExchange = (Get-PSSessionConfiguration -Name Microsoft.Exchange | Select *)
        if ($getExchange -eq $null)  {
            Register-PSSessionConfiguration -Name Microsoft.Exchange
        }

        try {

            $SccSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://ps.compliance.protection.outlook.com/powershell-liveid/ -Credential $credObject -Authentication "Basic" -AllowRedirection;
            Import-PSSession $SccSession -AllowClobber -ShowBanner:$false

            $sData = (Get-ComplianceSearch $searchName)

            if($sData.Status -eq "Completed") {
                New-ComplianceSearchAction -SearchName $searchName -Purge -PurgeType HardDelete -Confirm:$false
            } else {
                Write-Host "The content search `"$($searchName)`" has not fisnished yet. Current status: $($sData.Status)"
            }

            Write-host "####################"
            Write-Host "Purging the content search `"$($searchName)`". "

            Remove-PSSession $SccSession

        } catch {
            Write-Host "Error Purging Content Search: $_"
        }
    }

    Disconnect-ExchangeOnline -Confirm:$false

}