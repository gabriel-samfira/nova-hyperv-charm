# Copyright 2016 Cloudbase Solutions Srl
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#

function Convert-HashtableToDictionary {
    Param(
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
        [hashtable]$Data
    )
    $new = [System.Collections.Generic.Dictionary[string, object]](New-Object 'System.Collections.Generic.Dictionary[string, object]')
    foreach($i in $($data.Keys)) {
        $new[$i] = Convert-PSObjectToGenericObject $Data[$i]
    }
    return $new
}

function Convert-ListToGenericList {
    Param(
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
        [array]$Data
    )
    $new = [System.Collections.Generic.List[object]](New-Object 'System.Collections.Generic.List[object]')
    foreach($i in $Data) {
        $val = Convert-PSObjectToGenericObject $i
        $new.Add($val)
    }
    return ,$new
}

function Convert-PSCustomObjectToDictionary {
    Param(
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
        [PSCustomObject]$Data
    )
    $ret = [System.Collections.Generic.Dictionary[string,object]](New-Object 'System.Collections.Generic.Dictionary[string,object]')
    foreach ($i in $Data.psobject.properties) {
        $ret[$i.Name] = Convert-PSObjectToGenericObject $i.Value
    }
    return $ret
}

function Convert-PSObjectToGenericObject {
    Param(
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
        [System.Object]$Data
    )
    # explicitly cast object to its type. Without this, it gets wrapped inside a powershell object
    # which causes YamlDotNet to fail
    $data = $data -as $data.GetType().FullName
    switch($data.GetType()) {
        ($_.FullName -eq "System.Management.Automation.PSCustomObject") {
            return Convert-PSCustomObjectToDictionary $data
        }
        default {
            if (([System.Collections.IDictionary].IsAssignableFrom($_))){
                return Convert-HashtableToDictionary $data
            } elseif (([System.Collections.IList].IsAssignableFrom($_))) {
                return Convert-ListToGenericList $data
            }
            return $data
        }
    }
}

function Invoke-RenderTemplate {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [hashtable]$Context,
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [DotLiquid.Template]$TemplateData
    )
    PROCESS {
        $norm = Convert-PSObjectToGenericObject $Context
        $hash = [DotLiquid.Hash]::FromDictionary($norm)
        return $TemplateData.Render($hash)
    }
}

function Invoke-RenderTemplateFromFile {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Context,
        [Parameter(Mandatory=$true)]
        [string]$Template,
        [Parameter(Mandatory=$true)]
        [string]$TemplateDir
    )
    PROCESS {
        if (!(Test-Path $TemplateDir)) {
            Throw "TemplateDir not found"
        }
        $TemplateDir = $TemplateDir.Replace("\", "/")
        $Template = $Template.Replace("\", "/")

        $td = [DotLiquid.FileSystems.LocalFileSystem](New-Object "DotLiquid.FileSystems.LocalFileSystem" $TemplateDir)
        [DotLiquid.Template]::FileSystem = $td

        $tplCtx = [DotLiquid.Context]::new([CultureInfo]::InvariantCulture)

        $items = (Get-ChildItem -Recurse $TemplateDir | Where-Object {$_.Name -like "*.liquid"})
        foreach ($tplItem in $items) {
            $dir = $tplItem.DirectoryName.Replace("\", "/")
            $name = $tplItem.Name.TrimStart("_").TrimEnd(".liquid")

            if ($dir.TrimEnd("/") -eq $TemplateDir.TrimEnd("/")) {
                # NOTE: DotLiquid does some regex matching which fails for templates
                # in subfolders, unless the key is a double quoted string...
                $asQuoted = '"{0}"' -f $name
            } else {
                $name = Join-Path $dir.TrimStart($td.Root).TrimStart("/").TrimStart("\") $name
                $asQuoted = '"{0}"' -f $name
            }
            $tplCtx.Scopes[0][$asQuoted] = $name
        }
        $tplAsQuoted = '"{0}"' -f $Template
        if (!$tplCtx.Scopes[0][$tplAsQuoted]) {
            Throw "Template $Template not found in $TemplateDir"
        }

        $tplData = $td.ReadTemplateFile($tplCtx, $tplAsQuoted)
        $parsedTpl = [DotLiquid.Template]::Parse($tplData)
        return Invoke-RenderTemplate -Context $Context -TemplateData $parsedTpl
    }
}

Export-ModuleMember -Function * -Alias *
