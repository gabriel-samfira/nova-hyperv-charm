#
# Copyright 2014 Cloudbase Solutions SRL
#

$ErrorActionPreference = 'Stop'

Import-Module -Force -DisableNameChecking CharmHelpers
Import-Module Carbon

$JUJUD_PASS_FILE = "$env:SystemDrive\Juju\Jujud.pass"
$localAdminUsername = "adminlocal"
$localAdminUnjoinUsername = "adminlocalunjoin"
$WINDOWS_FEATURES = @( 'RSAT-AD-Powershell' )
$nova_compute = "nova-compute"

function Get-ActiveDirectoryUser {
    return "nova-hyperv"
}

function Get-ActiveDirectoryGroups {
    return "CN=Schema Admins,CN=Users"
}

function Get-AdUserAndGroup {
    $user = Get-ActiveDirectoryUser
    $groups = Get-ActiveDirectoryGroups
    return "$user;$groups"
}

function Get-AdComputerGroup {
    return "CN=Nova,OU=OpenStack"
}


function Get-RelationParams($type){
    $ctx = @{
        "ad_host" = $null;
        "ip_address" = $null;
        "ad_hostname" = $null;
        "ad_username" = $null;
        "ad_password" = $null;
        "ad_domain" = $null;
        "my_ad_password"= $null;
        "context" = $True;
    }

    $relations = relation_ids -reltype $type
    foreach($rid in $relations){
        $related_units = related_units -relid $rid
        if($related_units -ne $Null -and $related_units.Count -gt 0){
            foreach($unit in $related_units){
                $ctx["ad_host"] = relation_get -attr "private-address" -rid $rid -unit $unit
                $ctx["ip_address"] = relation_get -attr "address" -rid $rid -unit $unit
                $ctx["ad_hostname"] = relation_get -attr "hostname" -rid $rid -unit $unit
                $ctx["ad_username"] = relation_get -attr "username" -rid $rid -unit $unit
                $ctx["ad_password"] = relation_get -attr "password" -rid $rid -unit $unit
                $ctx["ad_domain"] = relation_get -attr "domainName" -rid $rid -unit $unit
                $ctx["my_ad_password"] = relation_get -attr "myAdPassword" -rid $rid -unit $unit
                $ctxComplete = Check-ContextComplete -ctx $ctx
                if ($ctxComplete){
                    break
                }
            }
        }
        else{
            $ctx["ad_host"] = relation_get -attr "private-address" -rid $rid 
            $ctx["ip_address"] = relation_get -attr "address" -rid $rid
            $ctx["ad_hostname"] = relation_get -attr "hostname" -rid $rid
            $ctx["ad_username"] = relation_get -attr "username" -rid $rid 
            $ctx["ad_password"] = relation_get -attr "password" -rid $rid 
            $ctx["ad_domain"] = relation_get -attr "domainName" -rid $rid
            $ctx["my_ad_password"] = relation_get -attr "myAdPassword" -rid $rid
            $ctxComplete = Check-ContextComplete -ctx $ctx
        }
    }

    $ctxComplete = Check-ContextComplete -ctx $ctx
    if (!$ctxComplete){
        $ctx["context"] = $False
    }

    return $ctx
}

function Get-AdCredential($params){
    $adminusername = $params["ad_username"]
    $adminpassword = $params["ad_password"]
    $domain = Get-DomainName $params["ad_domain"]
    $passwordSecure = $adminpassword | ConvertTo-SecureString -asPlainText -Force
    $adCredential = New-Object System.Management.Automation.PSCredential("$domain\$adminusername", $passwordSecure)
    return $adCredential
}

function Join-AnyDomain($domain, $domainCtrlIp, $localCredential, $adCredential){
    $networkName = (Get-MainNetadapter)
    Set-DnsClientServerAddress -InterfaceAlias $networkName -ServerAddresses $domainCtrlIp
    $domain = Get-DomainName $domain
    Add-Computer -LocalCredential $localCredential -Credential $adCredential -Domain $domain
}

function Get-DomainName($fullDomainName){
    $domainNameParts = $fullDomainName.split(".")
    $domainNamePartsPosition = $domainNameParts.Length - 2
    $domainName = [System.String]::Join(".", $domainNameParts[0..$domainNamePartsPosition])
    return $domainName
}

function Set-NovaUser {
    Param (
        [Parameter(Mandatory=$true)]
        [string]$Username,
        [string]$Password,
        [Parameter(Mandatory=$true)]
        [string]$Domain
    )

    $novaSvc = gwmi Win32_Service | Where-Object {$_.Name -eq $nova_compute}
    if (!$novaSvc){
        Juju-Error "Cound not find $nova_compute. Is nova installed?"
    }

    $unit_name = local_unit
    $charm_name = $unit_name.Split("/")[0]
    $key = "NovaADPass"
    $cachedPass = Get-CharmState $charm_name $key
    $updatePass = $false
    $domUser = "$domain\$Username"

    if ($cachedPass) {
        $passAsString = Decrypt-String $cachedPass
        if ($passAsString -ne $Password) {
            $updatePass = $true
        }
    } elseif ($domUser -ne $novaSvc.StartName) {
        $updatePass = $true
    }

    if ($updatePass){
        if ($Password) {
            $encPass = Encrypt-String $Passwd
            Set-CharmState $charm_name $key $encPass
        }
        Change-ServiceLogon $novaSvc $domUser $Password
        AddTo-LocalGroup -Username $domUser -GroupSID "S-1-5-32-544"
        Grant-Privilege $domUser SeServiceLogonRight
        return $true
    }
    return $false
}

function Join-Domain(){    
    Log "Started Join Domain"

    $localAdminPassword = Generate-StrongPassword
    Create-LocalAdmin $localAdminUsername $localAdminPassword
    
    $params = Get-RelationParams('ad-join')
    if($params["context"]){        
        $passwordSecure = $localAdminPassword | ConvertTo-SecureString -asPlainText -Force
        $localCredential = New-Object System.Management.Automation.PSCredential($localAdminUsername, $passwordSecure)
        $adCredential = Get-AdCredential $params

        Join-AnyDomain $params["ad_domain"] $params["ip_address"] $localCredential $adCredential
        juju-reboot.exe --now
    }
}

function Remove-FromDomain(){
    Log "Remove from domain"
    $localAdminPassword = Generate-StrongPassword
    Create-LocalAdmin $localAdminUnjoinUsername $localAdminPassword   

    $passwordSecure = $localAdminPassword | ConvertTo-SecureString -asPlainText -Force
    $localCredential = New-Object System.Management.Automation.PSCredential($localAdminUnjoinUsername, $passwordSecure)
    $adCredential = Get-AdCredential $params
    
    Remove-Computer -LocalCredential $localCredential -UnJoinDomainCredential $adCredential -Force -Confirm:$False
    juju-reboot.exe --now
}

#MAIN
function Win-AdRemove(){
    $params = Get-RelationParams('ad-join')
    if ($params['context'] -and (Is-In-Domain $params['ad_domain'])){
        Remove-FromDomain
    
        Stop-Service $nova_compute
        Set-NovaUser "LocalSystem" $null "."
        Start-Service $nova_compute
    }
}


function Set-ExtraRelationParams {
    $adUser = Get-AdUserAndGroup
    $adGroup = Get-AdComputerGroup

    $relation_set = @{
        'computerGroup'=$adGroup;
        'computername'=$env:computername;
    }
    $ret = relation_set -relation_settings $relation_set
    if ($ret -eq $false){
       Juju-Error "Failed to set extra relation params" -Fatal $false
    }
}

function Win-AdMain(){
    Install-WindowsFeatures $WINDOWS_FEATURES 
    $params = Get-RelationParams('ad-join')
    if ($params['context'] -and !(Is-InDomain $params['ad_domain'])){
        Join-Domain

        Set-ExtraRelationParams
    
        $username = Get-ActiveDirectoryUser 
        $pass = $params["my_ad_password"]
        Stop-Service $nova_compute
        Set-NovaUser -Username $username -Password $pass -Domain $params['ad_domain']
        Start-Service $nova_compute
    } else {
        Juju-Log "ad-join returned EMPTY"
    }
}

Export-ModuleMember -Function Win-AdMain
Export-ModuleMember -Function Win-AdRemove

