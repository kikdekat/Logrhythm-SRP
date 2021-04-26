# From LogRhythm Support

[CmdletBinding()]
Param(
    [string]$domainHost,
    [string]$acctName,
    [string]$password,
    [string]$CredentialsFilePath = "C:\Program Files\LogRhythm\SmartResponsePlugins"
)

#----------Check Output folder
if(!(Test-Path -Path $CredentialsFilePath)){
    Try{
        New-Item -ItemType Directory -Path $CredentialsFilePath -Force
   }catch{
        Write-Error "Error creating output directory"
        exit 
        }
}

$Credentials = [PSCustomObject]@{
                "domain" = $domainHost | ConvertTo-SecureString -AsPlainText -Force 
                "Account" = $acctName  | ConvertTo-SecureString -AsPlainText -Force 
                "Pass" = $password | ConvertTo-SecureString -AsPlainText -Force 
}

#---------Create Credntials file
$CredentialsFile = $CredentialsFilePath + "\cred.xml"

Try{
    if(!(Test-Path -Path $CredentialsFile)){
        New-Item -ItemType File -Path $CredentialsFile -Force
        }
        $Credentials | Export-Clixml -Path $CredentialsFile -Force
        Write-Host "Creadentials file creted successfully!"
}catch{
    Write-Error "Error creating output file!"
    exit 
}



