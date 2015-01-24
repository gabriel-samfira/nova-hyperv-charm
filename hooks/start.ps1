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

try {
    Restart-Nova
    Restart-Neutron
} catch {
    juju-log.exe "Failed to start services: $_.Exception.Message"
    exit 1
}
