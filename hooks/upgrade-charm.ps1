#
# Copyright 2014 Cloudbase Solutions SRL
#

Import-Module -DisableNameChecking CharmHelpers
Import-Module -Force -DisableNameChecking "$psscriptroot\compute-hooks.psm1"

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