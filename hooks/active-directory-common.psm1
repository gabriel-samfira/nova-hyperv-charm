$ErrorActionPreference = 'Stop'

Import-Module -Force -DisableNameChecking CharmHelpers

$localAdminUsername = "adminlocal"
$localAdminUnjoinUsername = "adminlocalunjoin"


function Create-Local-Admin($localAdminUsername, $localAdminPassword){
    Juju-Log "Creating local administrator"
    $existentUser = Get-WmiObject -Class Win32_Account -Filter "Name = '$localAdminUsername'" 
    if ($existentUser -eq $Null){
        $computer = [ADSI]"WinNT://$env:computername"
        $localAdmin = $Computer.Create("User", $localAdminUsername)
        $localAdmin.SetPassword($localAdminPassword)
        $localAdmin.SetInfo()
    }
    else{
        net user $localAdminUsername $localAdminPassword
    }
    if ((net localgroup administrators | Where {$_ -Match $localAdminUsername}).Length -eq 0){
        ([ADSI]"WinNT://$env:computername/Administrators,group").Add("WinNT://$env:computername/$localAdminUsername")
    }
}

function Get-Relation-Params($type){
    $ctx = @{
        "ad_host" = $null;
        "ip_address" = $null;
        "ad_hostname" = $null;
        "ad_username" = $null;
        "ad_password" = $null;
        "ad_domain" = $null;
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
            $ctxComplete = Check-ContextComplete -ctx $ctx
        }
    }

    $ctxComplete = Check-ContextComplete -ctx $ctx
    if (!$ctxComplete){
        $ctx["context"] = $False
    }

    return $ctx
}

function Get-Ad-Credential($params){
    $adminusername = $params["ad_username"]
    $adminpassword = $params["ad_password"]
    $domain = Get-Domain-Name $params["ad_domain"]
    $passwordSecure = $adminpassword | ConvertTo-SecureString -asPlainText -Force
    $adCredential = New-Object System.Management.Automation.PSCredential("$domain\$adminusername", $passwordSecure)
    return $adCredential
}

function Join-Any-Domain($domain, $domainCtrlIp, $localCredential, $adCredential){
    $networkName = (Get-MainNetadapter)
    Set-DnsClientServerAddress -InterfaceAlias $networkName -ServerAddresses $domainCtrlIp
    $domain = Get-Domain-Name $domain
    Add-Computer -LocalCredential $localCredential -Credential $adCredential -Domain $domain
}

function Get-Domain-Name($fullDomainName){
    $domainNameParts = $fullDomainName.split(".")
    $domainNamePartsPosition = $domainNameParts.Length - 2
    $domainName = [System.String]::Join(".", $domainNameParts[0..$domainNamePartsPosition])
    return $domainName
}

function Join-Domain(){    
    Log "Started Join Domain"

    $localAdminPassword = Generate-Strong-Password
    Create-Local-Admin $localAdminUsername $localAdminPassword
    
    $params = Get-Relation-Params('ad-join')
    if($params["context"]){        
        $passwordSecure = $localAdminPassword | ConvertTo-SecureString -asPlainText -Force
        $localCredential = New-Object System.Management.Automation.PSCredential($localAdminUsername, $passwordSecure)
        $adCredential = Get-Ad-Credential $params

        Join-Any-Domain $params["ad_domain"] $params["ip_address"] $localCredential $adCredential
        juju-reboot.exe --now
    }
}

function Remove-From-Domain(){
    Log "Remove from domain"
    $localAdminPassword = Generate-Strong-Password
    Create-Local-Admin $localAdminUnjoinUsername $localAdminPassword   

    $passwordSecure = $localAdminPassword | ConvertTo-SecureString -asPlainText -Force
    $localCredential = New-Object System.Management.Automation.PSCredential($localAdminUnjoinUsername, $passwordSecure)
    $adCredential = Get-Ad-Credential $params
    
    Remove-Computer -LocalCredential $localCredential -UnJoinDomainCredential $adCredential -Force -Confirm:$False
    juju-reboot.exe --now
}

#MAIN
function Win-Ad-Remove(){
    $params = Get-Relation-Params('ad-join')
    if ($params['context'] -and (Is-In-Domain $params['ad_domain'])){
        Remove-From-Domain
    }
}

function Win-Ad-Main(){
    $params = Get-Relation-Params('ad-join')
    if ($params['context'] -and !(Is-In-Domain $params['ad_domain'])){
        Join-Domain
    }
}

Export-ModuleMember -Function Win-Ad-Main
Export-ModuleMember -Function Win-Ad-Remove

