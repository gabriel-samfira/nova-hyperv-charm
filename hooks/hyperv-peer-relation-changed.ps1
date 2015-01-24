$ErrorActionPreference = "Stop"

Import-Module -DisableNameChecking CharmHelpers
try {
    $adJoinModulePath = "$psscriptroot\active-directory.psm1"
    Import-Module -Force -DisableNameChecking $adJoinModulePath

    $charm_dir = charm_dir

    $unit = relation_get -reltype "hyperv-peer"
    if (!$unit['computername']){
        Juju-Log "Peer $env:JUJU_REMOTE_UNIT did not set computer name"
        exit 0
    }

    $params = Get-RelationParams "ad-join"

    if ($params['context'] -and (Is-InDomain $params['ad_domain'])){
         $charm_dir\hooks\Set-KCD.ps1 $env:COMPUTERNAME $unit['computername'] -ServiceType "Microsoft Virtual System Migration Service"
         $charm_dir\hooks\Set-KCD.ps1 $env:COMPUTERNAME $unit['computername'] -ServiceType cifs
    }
} catch {
        juju-log.exe "Failed to join domain $_.Exception.Message"
        exit 1
}
