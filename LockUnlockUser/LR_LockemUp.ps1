###########################################
# Tri Bui
# Ferris State University
# LogRhythm SRP - 04/2021
###########################################


[CmdletBinding()]
Param(
    [string]$bUsers = "",
    [string]$uUsers = "",
    [string]$ULUsers = "",
    [string]$notif = "email@example.com",
    [string]$CredentialsFile = "C:\LogRhythm\SmartResponsePlugins\Cred.xml"
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

$AzureCheck = Get-Module -ListAvailable -Name AzureAD
if (!$AzureCheck) {
    Write-Host "AzureAD module does not exist. Trying to install.."
    if($isRunAsAdministrator) {
        Install-Module -Name AzureAD -RequiredVersion 2.0.2.102 -AllowClobber
        Import-Module -Name AzureAD
    } else { Write-Host "Please run the scripts using Administrator privilege." -ForegroundColor Red; Break}
}

    try 
    { $var = Get-AzureADTenantDetail } 
    catch [Microsoft.Open.Azure.AD.CommonLibrary.AadNeedAuthenticationException] 
    { 
        Write-Host "You're not connected. Trying to connect to AzureAD..";
        try {
            Write-Host "Connecting to AzureAD"
            Connect-AzureAD -Credential $credObject
        } catch { 
            try { Connect-AzureAD }
            catch { Break }
        }
    }

#------------------------------------------------------------------

if($bUsers -ne "") {
    try{
        
        $bUsers.Split(",") | % {
            $uName = $_
                    if($uName.IndexOf("@") -eq -1) {
                        $uName += "@$($domain)"
                    
                    }
            Set-AzureADUser -ObjectID $uName -AccountEnabled $false
        }

    } catch{
        Write-Host "Error: $err"
    }

}

if($uUsers -ne "") {
    try{
        
        $uUsers.Split(",") | % {
            $uName = $_
                    if($uName.IndexOf("@") -eq -1) {
                        $uName += "@$($domain)"
                    
                    }
            Set-AzureADUser -ObjectID $uName -AccountEnabled $true
        }

    } catch{
        Write-Host "Error: $err"
    }

}

if($ULUsers -ne "") {
    try{
        
        $ULUsers.Split(",") | % {
            $uName = $_
                if($uName.IndexOf("@") -ne -1) {
                    $uName = ($uName -split "@")[0]
                }
            Unlock-ADAccount -Identity $uName -Confirm:$false
        }

    } catch{
        Write-Host "Error: $err"
    }

}


if($notif -ne '') {
    #----------Notification Email--------
    $Body = "<html><body><div>
    <h2>Actions on user account(s) on $(Get-Date) </h2>
    <p>We have done following actions(s):</p>
    <div>"
    $Body += "<p><strong>Unlocking:</strong><br>-------<br>$($ULUsers -replace ",","<br>")</p>"
    $Body += "<p><strong>Disabled:</strong><br>-------<br>$($bUsers -replace ",","<br>")</p>"
    $Body += "<p><strong>Enabled:</strong><br>-------<br>$($uUsers -replace ",","<br>")</p>"
    $Body += "</div></div></body></html>"
    $Subject = "Actions on user account(s) - " + $(Get-Date)    
    [string[]]$To= $notif.Split(',')    

    Send-MailMessage -From $fromEmail -To $To -Subject $Subject -Body $Body -SmtpServer $smtpServer -Port "25" -BodyAsHtml -Priority High
    Write-Host "Email notification was sent successfully!" 
}

Disconnect-AzureAD -Confirm:$false