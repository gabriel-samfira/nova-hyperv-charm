#
# Copyright 2014 Cloudbase Solutions SRL
#

# we want to exit on error
$ErrorActionPreference = "Stop"

$adJoinModulePath = "$psscriptroot\active-directory.psm1"
Import-Module -Force -DisableNameChecking $adJoinModulePath

Win-AdRemove
