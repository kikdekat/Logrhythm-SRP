###########################################
# Tri Bui
# Ferris State University
# LogRhythm SRP - 04/2021
###########################################


[CmdletBinding()]
Param(
    [string]$bIPs = "",
    [string]$uIPs = "",
    [string]$listID = "",
    [string]$notif = "email@example.com",
    [string]$mutex = "",
    [string]$CredentialsFile = "C:\LogRhythm\SmartResponsePlugins\InfoSecPS.xml"
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

if($listID -ne "") {

if($mutex -eq "") {
    $update = $false
    $rule = Get-AzureADMSNamedLocationPolicy -PolicyId $listID
    Write-Host "Current block list: "
    $rule.IpRanges
    Write-Host "---------------------"

            if($bIPs -ne "") {
                try{
        
                    $bIPs.Split(",") | % {
                        if($_.IndexOf("/") -eq -1) {
                            $_ += "/32"
                        }
                        if(!$rule.IpRanges.Contains($_)) {
                            $rule.IpRanges += $_
                            Write-Host "Adding $($_) to list.."
                            $update = $true
                        } else {
                            Write-Host "$($_) was already in the list."
                        }
                    }
                } catch{
                    Write-Host "Error: $err"
                }

            }

            if($uIPs -ne "") {
                try{
        
                    $uIPs.Split(",") | % {
                        if($_.IndexOf("/") -eq -1) {
                            $_ += "/32"
                        }
                        if($rule.IpRanges.Contains($_)) {
                            $rule.IpRanges.Remove($_)
                            Write-Host "Removing $($_) from list.."
                            $update = $true
                        }
                    }
                    
                } catch{
                    Write-Host "Error: $err"
                }

            }

        if($update) {
            Set-AzureADMSNamedLocationPolicy -PolicyId $listID -OdataType "#microsoft.graph.ipNamedLocation" -IpRanges $rule.IpRanges
            Write-Host "Updated the IPs blacklist."
        }

} else {

    $lock = New-Object System.Threading.Mutex($false, "BlockIPs_Mutex")

    $i = 0;
    while($lock.WaitOne(1000) -eq $false) { Write-Host "Waiting.. $($i=$i+1;$i)"; if($i -ge 30) { exit; } else { Sleep -Seconds 1;} }

    try {
        $update = $false
        $rule = Get-AzureADMSNamedLocationPolicy -PolicyId $listID
        Write-Host "Current block list: "
        $rule.IpRanges
        Write-Host "---------------------"

            if($bIPs -ne "") {
                try{
        
                    $bIPs.Split(",") | % {
                        if($_.IndexOf("/") -eq -1) {
                            $_ += "/32"
                        }
                        if(!$rule.IpRanges.Contains($_)) {
                            $rule.IpRanges += $_
                            Write-Host "Adding $($_) to list.."
                            $update = $true
                        } else {
                            Write-Host "$($_) was already in the list."
                        }
                    }
                } catch{
                    Write-Host "Error: $err"
                }

            }

            if($uIPs -ne "") {
                try{
        
                    $uIPs.Split(",") | % {
                        if($_.IndexOf("/") -eq -1) {
                            $_ += "/32"
                        }
                        if($rule.IpRanges.Contains($_)) {
                            $rule.IpRanges.Remove($_)
                            Write-Host "Removing $($_) from list.."
                            $update = $true
                        }
                    }
                    
                } catch{
                    Write-Host "Error: $err"
                }

            }

            if($update) {
                Set-AzureADMSNamedLocationPolicy -PolicyId $listID -OdataType "#microsoft.graph.ipNamedLocation" -IpRanges $rule.IpRanges
                Write-Host "Updated the IPs blacklist."
            }

            $lock.ReleaseMutex()
            $lock.Dispose()
            Write-Host "Released mutex lock."
    } catch {
        $lock.ReleaseMutex()
        $lock.Dispose()
    }

}


    if($notif -ne '' -and $update) {
        if($mutex) {
            $auto = "[AUTO] "
        }
        #----------Notification Email--------
        $Body = "<html><body><div>
        <h2>Actions on IP(s) on $(Get-Date) </h2>
        <p>We have block/unlock following IP(s) from all AzureAD and O365 services:</p>
        <div>"
        if($bIPs -ne "") {
            $Body += "<p><strong>Block:</strong><br>-------<br>$($bIPs -replace ",","<br>")</p>"
        }
        if($uIPs -ne "") {
            $Body += "<p><strong>Unblock:</strong><br>-------<br>$($uIPs -replace ",","<br>")</p>"
        }

        $Body += "<br><p><strong>List ID:</strong><br>-------<br>$($listID)</p>"

        $Body += "</div></div></body></html>"
        $Subject = "$($auto)Actions on IP(s) - " + $(Get-Date)    
        [string[]]$To= $notif.Split(',')    

        Send-MailMessage -From $fromEmail -To $To -Subject $Subject -Body $Body -SmtpServer $smtpServer -Port "25" -BodyAsHtml -Priority High
        Write-Host "Email notification was sent successfully!" 
    }


}