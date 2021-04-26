###########################################
# Tri Bui
# Ferris State University
# LogRhythm SRP - 04/2021
###########################################


[CmdletBinding()]
Param(
    [string]$emails = "",
    [string]$CredentialsFile = "C:\LogRhythm\SmartResponsePlugins\InfoSecPS.xml",
    [string]$sourceip,
    [string]$notif = "email@example.com"
)

# Settings
$badKeys = @("@","password","delete","do not open","change","compromise",
                 "phishing","job","payroll","it server","webmaster","web master",
                 "help desk","helpdesk","security","administrator","not me",
                 "not from me","apply","interested","legit","scam","spam")
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

if($emails -ne "") {

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
        Connect-ExchangeOnline -Credential $credObject  -ShowBanner:$false
    }

    #------------------------------------------------------------------



    # Scanning malicious Inbox Rule  without AuditLog
    function scanInboxRules {
    param(
        [Parameter(Mandatory)]
        [PSObject]$emails
        )

        $badAddr = @("@",$domain)

        $users = @()

        Write-Progress -Activity "Scanning Inbox Rules.." -CurrentOperation ("Please wait.. ")
        $emails | % {

            if($_.IndexOf("@") -eq -1) {
                $_ += "@$($domain)"
            }

            $tmp = New-Object -TypeName psobject
            $tmp | Add-Member -MemberType NoteProperty -Name Email -Value $_
            $tmp | Add-Member -MemberType NoteProperty -Name Compromised -Value $false
            $tmp | Add-Member -MemberType NoteProperty -Name CompReason -Value $null

#            $tmp | Add-Member -MemberType NoteProperty -Name MaliciousRules -Value @()
#            $Rules = Get-InboxRule -Mailbox $tmp.Email | WHERE { $_.DeleteMessage -eq $true } |
#                                           SELECT RuleIdentity, Name, SubjectOrBodyContainsWords, SubjectContainsWords, BodyContainsWords,
#                                                  FromAddressContainsWords, RecipientAddressContainsWords, From, SentTo, DeleteMessage

            $Rules = Get-InboxRule -Mailbox $tmp.Email |
                                           SELECT RuleIdentity, Name, SubjectOrBodyContainsWords, SubjectContainsWords, BodyContainsWords,
                                                  FromAddressContainsWords, RecipientAddressContainsWords, From, SentTo, MoveToFolder,
                                                  ForwardAsAttachmentTo, ForwardTo, RedirectTo, DeleteMessage
            $tmp | Add-Member -MemberType NoteProperty -Name Rules -Value $Rules
            $Rules | % {
                if($_.DeleteMessage -eq $true -and
                  (   ($_.SubjectOrBodyContainsWords.Count -eq 0 -and
                       $_.SubjectContainsWords.Count -eq 0 -and
                       $_.BodyContainsWords.Count -eq 0 -and
                       $_.FromAddressContainsWords.Count -eq 0 -and
                       $_.RecipientAddressContainsWords.Count -eq 0 -and
                       $_.From -eq $null -and ($_.SentTo -eq $null -or ($_.SentTo -match ($tmp.email).split("@")[0]))) -or 

                   ( ( ($_.SubjectOrBodyContainsWords | Where { $badKeys -contains $_ }).Count -ge 2) -or
                     ( ($_.SubjectContainsWords | Where { $badKeys -contains $_ }).Count -ge 2) -or
                     ( ($_.BodyContainsWords | Where { $badKeys -contains $_ }).Count -ge 2) -and
                     $_.From -eq $null -and ($_.SentTo -eq $null -or ($_.SentTo -match ($tmp.email).split("@")[0]))
                   ) -or

                   ( ($_.RecipientAddressContainsWords | Where { $badAddr -contains $_ }).Count -ge 1 -or
                     ($_.FromAddressContainsWords | Where { $badAddr -contains $_ }).Count -ge 1)
                   )) {

                        $tmp.Compromised = $true
                        $tmp.CompReason += " # Malicious InboxRules #"
                        #$tmp.MaliciousRules += $_
                        $_ | Add-Member -MemberType NoteProperty -Name MALICIOUS -Value $true
                }

            }

            $users += $tmp
           
        }

        return $users

    }


    $list = $emails.Split(",")
    $results = scanInboxRules $list
    $results = $results | SORT Compromised -Descending

    $results | % {
        Write-Host "`n############################"
        $resbody += "############################`n"
        if($_.Compromised -eq $false) {
            Write-Host "$($_.Email) : GOOD`n"
            $resbody += "$($_.Email) : GOOD`n`n"
        } else {
            Write-Host "$($_.Email) : MALICIOUS RULE(S) FOUND`n"
            $resbody += "$($_.Email) : MALICIOUS RULE(S) FOUND`n`n"
        }

        $_.Rules | SORT MALICIOUS -Descending | % {
            $rule = ""
            if($_.MALICIOUS) { $rule += "### MALICIOUS RULE ###" }
            $rule += ($_.PSObject.Properties | ? {$_.Value -ne $null} | FT Name, Value | Out-String)
            $resbody += $rule.Trim() + "`n`n"
            Write-Host "$($rule.Trim())`n"
        }
        
        #Write-Output "`n"
        #Write-Host "#########################`n"
    }



    if(($notif -ne '' -and $results.Compromised -eq $true)) {
        if($sourceip -ne "") {
            $url = "http://proxycheck.io/v2/$($sourceip)?days=60&vpn=1&asn=1&node=1&time=1&inf=1&risk=2&port=1&seen=1&tag=msg"
            $api = (curl $url) -replace "'", ""
            $proxy = ConvertFrom-Json -InputObject $api
        }

        $iptext = "Source IP: <strong><span style=`"color: rgb(209, 72, 65);`">$($sourceip)</span></strong>
                    <br>$($proxy.$sourceip)<br>---------------"
        
        $badUsers = ($results | ? { $_.Compromised -eq $true } ).Email

        #----------Notification Email--------
        $Body = "<html><body><div>
        <h2>Malicious rule(s) found at $(Get-Date)</h2>
        
        <div>"
        $Body += "<p>$($iptext)</p><br><p><pre>$($resbody -replace "### MALICIOUS RULE ###","<strong><span style='color: rgb(209, 72, 65);'>### MALICIOUS RULE ###</span></strong>")</pre></p></div></div></body></html>"
        
        $Subject = "[ALERT] Malicious rule(s) found [$($badUsers -join ",")] - $(Get-Date)"
        [string[]]$To = $notif.Split(',')    

        Send-MailMessage -From $fromEmail -To $To -Subject $Subject -Body $Body -SmtpServer $smtpServer -Port "25" -BodyAsHtml -Priority High
        Write-Host "`n`nEmail notification was sent successfully!" 
    }

    #$resbody

    Disconnect-ExchangeOnline -Confirm:$false

}