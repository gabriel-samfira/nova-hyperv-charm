#
# Copyright 2014 Cloudbase Solutions SRL
#

# we want to exit on error
$ErrorActionPreference = "Stop"

try {
    Import-Module -DisableNameChecking CharmHelpers
    Import-Module -Force -DisableNameChecking "$psscriptroot\compute-hooks.psm1"
}catch{
    juju-log.exe "Failed to import modules: $_.Exception.Message"
    exit 1
}

function Run-ConfigChanged {
    Juju-ConfigureVMSwitch
    $neutronSvc = Configure-NeutronAgent
	
    $nova_restart = Generate-Config -ServiceName "nova"
    $neutron_restart = Generate-Config -ServiceName "neutron"

     $neutron_ovs_restart = Generate-Config -ServiceName $neutronSvc.MyName
    $JujuCharmServices = Charm-Services

    if ($nova_restart){
        juju-log.exe "Restarting service Nova"
        Restart-Nova
    }

    if ($neutron_restart -or $neutron_ovs_restart){
        juju-log.exe "Restarting service Neutron"
        Restart-Neutron
    }
}

try {
    Run-ConfigChanged
} catch {
    juju-log.exe "Config changed failed: $_.Exception.Message"
    exit 1
}
