#
# Copyright 2014-2016 Cloudbase Solutions SRL
#

$ErrorActionPreference = "Stop"

Import-Module JujuLogging

try {
    Import-Module ComputeHooks
    Import-Module S2DCharmUtils

    Start-S2DRelationChangedHook
    Start-ConfigChangedHook
} catch {
    Write-HookTracebackToLog $_
    exit 1
}