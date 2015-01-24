$ErrorActionPreference = "Stop"

Import-Module -DisableNameChecking CharmHelpers


$relation_set = @{
        'computername'=$env:COMPUTERNAME
}

relation_set -relation_settings $relation_set
