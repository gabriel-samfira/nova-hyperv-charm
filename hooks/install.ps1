#
# Copyright 2014 Cloudbase Solutions SRL
#

$ErrorActionPreference = "Stop"

Import-Module -DisableNameChecking CharmHelpers
Import-Module -Force -DisableNameChecking "$psscriptroot\compute-hooks.psm1"

function Juju-RunInstall {
    Import-CloudbaseCert
    $net_type = charm_config -scope "network-type"
    if ($net_type -eq "ovs"){
        $InstallerPath = Get-OVSInstaller
        Install-OVS $InstallerPath
    }
    Juju-ConfigureVMSwitch
    $installerPath = Get-NovaInstaller
    Juju-Log "Running Nova install"
    Install-Nova -InstallerPath $installerPath
    Juju-Log "Running install from local"
    Install-FromLocalCache
    Juju-Log "Install rootwrap"
    Install-RootWrap
    Juju-Log "Running Configure neutron"
    Configure-NeutronAgent
}

try{
    Juju-RunInstall
}catch{
    juju-log.exe "Failed to run install: $_.Exception"
    exit 1
}
