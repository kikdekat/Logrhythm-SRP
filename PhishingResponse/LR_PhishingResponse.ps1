###########################################
# Tri Bui
# Ferris State University
# LogRhythm SRP - 04/2021
###########################################


[CmdletBinding()]
Param(
    [string]$scammer = "test@test.com",
    [string]$notif = "email@example.com",
    [string]$CredentialsFile = "C:\LogRhythm\SmartResponsePlugins\AIO.xml",
    [string]$BlockRuleID = "CHANGE_THIS_TO_YOUR_TRANSPORT_RULE_ID",
    [string]$RedirectID = "CHANGE_THIS_TO_YOUR_TRANSPORT_RULE_ID",
    [string]$User = "UserOrUserscommSep",
    [string]$ToEmails = "",
    [string]$ccEmail = "",
    [string]$searchName = "",
    [string]$searchKey = "",
    [string]$searchFrom = "",
    [string]$listID,
    [string]$bIPs,
    [string]$alertTittle,
    [string]$imageURL = "",
    [string]$alertTo = "",
    [string]$alertCC = ""
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


#------------------------------------------------------------------
$prepUser = {
    function Get-RandomCharacters {
        Param(
            [int]$length = 16, 
            $characters = 'abcdefghiklmnoprstuvwxyzABCDEFGHKLMNOPRSTUVWXYZ1234567890!"§$%&/()=?}][{@#*+'
        )
        if ($length -ne 0 -and $characters -ne '') {
            $random = 1..$length | ForEach-Object { Get-Random -Maximum $characters.length }
            $private:ofs=""
            return [String]$characters[$random]
        }
    }
    function Scramble-String {
        param(
            [string]$inputString
        )     
        $characterArray = $inputString.ToCharArray()   
        $scrambledStringArray = $characterArray | Get-Random -Count $characterArray.Length    
        $outputString = -join $scrambledStringArray
        return $outputString 
    }
}
#------------------------------------------------------------------
$jobArray = @()



if($scammer -ne "") {
$jobArray += Start-Job -Name "BlockEmail" -ScriptBlock {

        $hasEXO = Get-PSSession
        if(!$hasEXO) { 
            Write-Host "Connecting to EXO"
            Connect-ExchangeOnline -Credential $args[4] -ShowBanner:$false
        }

        try {
            $BlockList = (Get-TransportRule -Identity $args[1]).From
            $RedirectList = (Get-TransportRule -Identity $args[2]).SentTo
            $Updated = $false

            $args[0].Split(",") | % {

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

            if($Updated -and ($args[3] -ne '')) {
                #----------Notification Email--------
                $Body = "<html><body><div>
                <h2>Email blocking and redirecting on: $(Get-Date) </h2>
                <p>We have identified that the following email have been sending scam/phishing email. We have blocked all of the inbound email(s) from that email and redirect email(s) replying to them to us.</p>
                <div>"
                $Body += "<p>$($args[0] -replace ",","<br>")</p>"
                $Body += "</div></div></body></html>"
                $Subject = "Email blocking and redirecting for $($args[0]) " + $(Get-Date)    
                [string[]]$To = $args[3].Split(',')    

                Send-MailMessage -From $fromEmail -To $To -Subject $Subject -Body $Body -SmtpServer $smtpServer -Port "25" -BodyAsHtml -Priority High
                Write-Host "[BLOCK] Email notification was sent successfully!" 
            }

            Disconnect-ExchangeOnline -Confirm:$false

        } catch {
            Write-Host "Error Blocking Email: $_"
        }
        Write-Host "Block email(s): DONE"
        Write-Host "================================================="
    } -ArgumentList ($scammer,$BlockRuleID,$RedirectID,$notif,$credObject)

}


if($searchName -ne "" -and $searchKey -ne "" -and $searchFrom -ne "") {
$jobArray += Start-Job -Name "ContentSearch" -ScriptBlock {

        $hasEXO = Get-PSSession
        if(!$hasEXO) { 
            Write-Host "Connecting to EXO"
            Connect-ExchangeOnline -Credential $args[4] -ShowBanner:$false
        }

        $getExchange = (Get-PSSessionConfiguration -Name Microsoft.Exchange | Select *)
        if ($getExchange -eq $null)  {
            Register-PSSessionConfiguration -Name Microsoft.Exchange
        }

        $searchSenders = ""

        $senders = $args[2].Split(",")

        $senders | % {
            if($_.IndexOf("@") -eq -1) {
                $_ += "@$($domain)"
            }
            $_ = $_.Trim()

            $searchSenders += "(from=$($_))"
        }
        #$dateRange = "$((Get-Date).AddDays(-3).ToString("yyyy-MM-dd"))..$((Get-Date).ToString("yyyy-MM-dd"))"
        $dateRange = "$((Get-Date).AddDays(-3).ToString("yyyy-MM-dd"))"
        $searchQuery = "$($args[1])(c:c)$($searchSenders)(date>$($dateRange))"

        try {

            $SccSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://ps.compliance.protection.outlook.com/powershell-liveid/ -Credential $args[4] -Authentication "Basic" -AllowRedirection;
            Import-PSSession $SccSession -AllowClobber

            $searchTerms = New-ComplianceSearch "$($args[0])" -ExchangeLocation All -ContentMatchQuery "$($searchQuery)" -Description "Automated search for email sending from $($senders)"
            Start-ComplianceSearch $searchTerms.Name

            if(($args[3] -ne '')) {
                #----------Notification Email--------
                $Body = "<html><body><div>
                <h2>Content search started at $(Get-Date) </h2>
                <p>Search name: $($args[0])<br><br>Keywords: $($args[1])<br>Senders: $($args[2])</p>
                <div>"
                $Body += "<p>$($args[0])</p>"
                
                $Subject = "Content search started: $($args[0]) " + $(Get-Date)    
                [string[]]$To = $args[3].Split(',')    

                Send-MailMessage -From $fromEmail -To $To -Subject $Subject -Body $Body -SmtpServer $smtpServer -Port "25" -BodyAsHtml -Priority High
                Write-Host "[SEARCH] Email notification was sent successfully!" 
            }

            Disconnect-ExchangeOnline -Confirm:$false
            Remove-PSSession $SccSession

        } catch {
            Write-Host "Error Creating Content Search: $_"
        }
        Write-Host "Create content search: DONE"
        Write-Host "================================================="
    } -ArgumentList ($searchName,$searchKey,$searchFrom,$notif,$credObject)

    

}


if($User -ne "") {

#    $CredentialsFile = "C:\LogRhythm\SmartResponsePlugins\Cred.xml"
#    #------------------Credentials---------------------------
#    if (Test-Path $CredentialsFile) {
#        Write-Host ("Credentials file (for RESETTING USER) found: " + $CredentialsFile)
#        try {
#            #$credObject = Import-Clixml -Path $CredentialsFile
#            $Credentials = Import-Clixml -Path $CredentialsFile
#            $domainHost = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR((($Credentials.domain))))
#            $acctName = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR((($Credentials.Account))))
#            $password = $Credentials.Pass
#            $credObject = New-Object System.Management.Automation.PSCredential -ArgumentList $acctName,$password
#        }
#        catch {
#
#           Write-Error ("The credentials within the credentials file are corrupt. Please recreate the file: " + $CredentialsFile)
#           exit
#        }
#    }
#    else
#    {
#        Write-Error "Credentials file (for RESETTING USER) not found. Please run setup action!"
#        Exit 1
#    }
    #--------------------------------------------------------------

    $jobArray += Start-Job -Name "ResetUser" -ScriptBlock {

        function Get-RandomCharacters {
            Param(
                [int]$length = 16, 
                $characters = 'abcdefghiklmnoprstuvwxyzABCDEFGHKLMNOPRSTUVWXYZ1234567890!"§$%&/()=?}][{@#*+'
            )
            if ($length -ne 0 -and $characters -ne '') {
                $random = 1..$length | ForEach-Object { Get-Random -Maximum $characters.length }
                $private:ofs=""
                return [String]$characters[$random]
            }
        }
        function Scramble-String {
            param(
                [string]$inputString
            )     
            $characterArray = $inputString.ToCharArray()   
            $scrambledStringArray = $characterArray | Get-Random -Count $characterArray.Length    
            $outputString = -join $scrambledStringArray
            return $outputString 
        }

        #Azure Active Directory
        Connect-AzureAD -Credential $args[4]
        #SharePoint Online
        Connect-SPOService -Url "https://ferrisstateuniversity-admin.sharepoint.com/" -Credential $args[4]

        try{
            $AffiliatesUsers = $AlumniUsers = $CurrentUsers = $EmeritiUsers = $RetireeUsers = $StaffUsers = ""
            $args[0].Split(',') | ForEach-Object {
                $uName = $_
                if($uName.IndexOf("@") -eq -1) {
                    $uName += "@$($domain)"
                    
                }
                $password = Get-RandomCharacters
                Revoke-SPOUserSession -User "$uName" -Confirm:$false
                Get-AzureADUser -SearchString "$uName" | Revoke-AzureADUserAllRefreshToken

                if($uName.IndexOf("@") -ne -1) {
                    $uName = ($uName -split "@")[0]
                }

                $Newpassword = Scramble-String $password
                $SecurePassword = ConvertTo-SecureString -String $Newpassword -AsPlainText -Force
                Set-ADAccountPassword -Identity $uName -NewPassword $SecurePassword -Reset
              
                $UserDN = Get-ADUser -Filter {enabled -eq $true -and SamAccountName -eq $uName} -SearchBase "OU=Ferris,DC=ferris,DC=local" -Properties EmailAddress, DistinguishedName | Select DistinguishedName
                $uGroup = ($UserDN.DistinguishedName -split ",OU=")[1]
                #$GroupList = Get-ADPrincipalGroupMembership $uName 
                #ForEach($Group in $GroupList){
                    if($uGroup -eq "Affiliates") {$AffiliatesUsers +=  "$uName<br/>"}
                    elseif($uGroup -eq "Alumni") {$AlumniUsers += "$uName<br/>"}
                    elseif($uGroup -eq "Current") {$CurrentUsers += "$uName<br/>"}
                    elseif($uGroup -eq "Emeriti") {$EmeritiUsers += "$uName<br/>"}
                    elseif($uGroup -eq "Retiree") {$RetireeUsers += "$uName<br/>"}
                    elseif($uGroup -eq "Users") {$StaffUsers += "$uName<br/>"}            
                #}
                Write-Host "The account of: $email@example.com has been REVOKED from all Office365 Sessions and password have been changed"
            }
            #----------Notification Email--------
            $Body = "<html><body><div>
            <h2>Identified Compromised User Accounts on: $(Get-Date) </h2>
            <p>We have identified that the following user(s) have been compromised. We have reset their passwords and killed their active sessions on Office365. If needed please assist them in resetting their password.</p>
            <div>"
            if($AffiliatesUsers -ne ""){$Body += "<p><b>Affiliates Users</b><br/>==================<br/>$AffiliatesUsers</p>"}
            if($AlumniUsers -ne "") {$Body += "<p><b>Alumni Users</b><br/>==================<br/>$AlumniUsers</p>"}
            if($CurrentUsers -ne ""){$Body += "<p><b>Current Students</b><br/>==================<br/>$CurrentUsers</p>"}
            if($EmeritiUsers -ne ""){$Body += "<p><b>Emirti Users</b><br/>==================<br/>$EmeritiUsers</p>"}
            if($RetireeUsers -ne ""){$Body += "<p><b>Retiree Users</b><br/>==================<br/>$RetireeUsers</p>"}
            if($StaffUsers -ne ""){$Body += "<p><b>Staff Users</b><br/>==================<br/>$StaffUsers</p>"}
            $Body += "</div></div></body></html>"
            $Subject = "Encrypt | Compromised Accounts " + $(Get-Date)    
            [string[]]$To = $args[1].Split(',')    
            #Send-MailMessage -From $fromEmail -To $To -Cc $args[2] -Subject $Subject -Body $Body -SmtpServer $smtpServer -Port "25" -BodyAsHtml -Priority High
            if($args[2] -ne "") {
                Send-MailMessage -From $fromEmail -To $To -Cc $args[2] -Subject $Subject -Body $Body -SmtpServer $smtpServer -Port "25" -BodyAsHtml -Priority High
            } else {
                Send-MailMessage -From $fromEmail -To $To  -Subject $Subject -Body $Body -SmtpServer $smtpServer -Port "25" -BodyAsHtml -Priority High
            }
            Write-Host "[RESET] Email notification was sent successfully!" 
            Disconnect-SPOService
        } catch{
            Write-Host "Error Resetting User: $_"
        }
        Write-Host "Reset user(s): DONE"
        Write-Host "================================================="
    } -ArgumentList ($User,$ToEmails,$ccEmail,$domainHost,$credObject) #-InitializationScript $prepUser

     
}


if($listID -ne "" -and $bIPs -ne "") {
    $jobArray += Start-Job -Name "BlockIPs" -ScriptBlock {

        try 
        { $var = Get-AzureADTenantDetail } 
        catch [Microsoft.Open.Azure.AD.CommonLibrary.AadNeedAuthenticationException] 
        { 
            Write-Host "You're not connected. Trying to connect to AzureAD..";
            try {
                Write-Host "Connecting to AzureAD"
                Connect-AzureAD -Credential $args[3]
            } catch { 
                Write-Host "ERROR connecting AzureAD"
            }
        }

        $update = $false
        $rule = Get-AzureADMSNamedLocationPolicy -PolicyId $args[0]
        Write-Host "Current block list: "
        $rule.IpRanges
        Write-Host "---------------------"

            if($args[1] -ne "") {
                try{
        
                    $args[1].Split(",") | % {
                        if($_.IndexOf("/") -eq -1) {
                            $_ += "/32"
                        }
                        $rule.IpRanges += $_
                        Write-Host "Adding $($_) to list.."
                    }
                    $update = $true
                } catch{
                    Write-Host "Error: $err"
                }

            }


            if($update) {
                Set-AzureADMSNamedLocationPolicy -PolicyId $args[0] -OdataType "#microsoft.graph.ipNamedLocation" -IpRanges $rule.IpRanges
                Write-Host "Updated the IPs blacklist."
            }



            if($args[2] -ne '' -and $update) {
                #----------Notification Email--------
                $Body = "<html><body><div>
                <h2>Actions on IP(s) on $(Get-Date) </h2>
                <p>We have block/unlock following IP(s) from all AzureAD and O365 services:</p>
                <div>"
                $Body += "<p><strong>Block:</strong><br>-------<br>$($args[1] -replace ",","<br>")</p>"
                $Body += "</div></div></body></html>"
                $Subject = "Actions on IP(s) - " + $(Get-Date)    
                [string[]]$To= $args[2].Split(',')    

                Send-MailMessage -From $fromEmail -To $To -Subject $Subject -Body $Body -SmtpServer $smtpServer -Port "25" -BodyAsHtml -Priority High
                Write-Host "Email notification was sent successfully!" 
            }

    } -ArgumentList ($listID,$bIPs,$notif,$credObject)

}



Write-Debug ($jobArray | Out-String)
Write-Host "================================================="
$results = ($jobArray | Wait-Job | Receive-Job)
Write-Host $results

Write-Host "================================================="

if($alertTittle -ne "" -and $imageURL -ne "" -and $alertTo -ne "") {
Write-Host "Sending ALERT.."
    try{
        $comp = $User -split ","
        $comp | % {
        if($_.IndexOf("@") -eq -1) {
            $_ += "@$($domain)"
            }
        }

        $tmp = wget $imageURL -OutFile $env:TEMP/image.tmp
        $imageData = [convert]::ToBase64String((get-content $env:TEMP/image.tmp -Encoding byte))
        Remove-Item $env:TEMP/image.tmp

        $mailSubject = "Encrypt | Mass Phishing Alert $((Get-Date).ToString("MM/dd/yyyy")) - `"$($alertTittle)`""
        $mailBody = @"
CHANGE THIS TO YOUR ALERT CONTENT.
"@
        [string[]]$To = $alertTo.Split(',')
        if($alertCC -ne "") {
            Send-MailMessage -From $fromEmail -To $To -Cc $alertCC -Subject $mailSubject -Body $mailBody -SmtpServer $smtpServer -Port "25" -BodyAsHtml -Priority High
        } else {
            Send-MailMessage -From $fromEmail -To $To -Subject $mailSubject -Body $mailBody -SmtpServer $smtpServer -Port "25" -BodyAsHtml -Priority High
        }
        Write-Host "[ALERT] Email notification was sent successfully!"
    } catch{
         Write-Host "Error sending ALERT: $_"
    }

    Write-Host "Send alert: DONE"
    
}

