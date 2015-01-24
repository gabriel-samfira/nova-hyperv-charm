#
# Copyright 2014 Cloudbase Solutions SRL
#

# we want to exit on error
$ErrorActionPreference = "Stop"

try {
    $adJoinModulePath = "$psscriptroot\active-directory.psm1"
    Import-Module -Force -DisableNameChecking $adJoinModulePath

    Win-AdMain
} catch {
    juju-log.exe "Failed to join domain $_.Exception.Message"
    exit 1
}
