#
# Copyright 2014 Cloudbase Solutions SRL
#

# we want to exit on error
# $ErrorActionPreference = "Stop"

try {
    Import-Module -DisableNameChecking CharmHelpers
    Import-Module -Force -DisableNameChecking "$psscriptroot\compute-hooks.psm1"
}catch{
    juju-log.exe "Failed to import modules: $_.Exception.Message"
    exit 1
}

function Run-ConfigChanged {
    Juju-ConfigureVMSwitch
    $nova_restart = Generate-Config -ServiceName "nova"
    $neutron_restart = Generate-Config -ServiceName "neutron"
    $JujuCharmServices = Charm-Services

    if ($nova_restart){
        juju-log.exe "Restarting service Nova"
        Restart-Service $JujuCharmServices["nova"]["service"]
    }

    if ($neutron_restart){
        juju-log.exe "Restarting service Nova"
        Restart-Service $JujuCharmServices["neutron"]["service"]
    }
}

try {
    Run-ConfigChanged
} catch {
    juju-log.exe "Config changed failed: $_.Exception.Message"
    exit 1
}
