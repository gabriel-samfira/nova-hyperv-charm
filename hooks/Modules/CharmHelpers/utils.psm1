# UNTESTABLE METHODS

function Restore-EnvironmentVariable ($variable, $prevValue) {
    if ($prevValue -eq $null -and (Test-Path "Env:$variable")) {
        Remove-Item "Env:$variable"
    } else {
        [Environment]::SetEnvironmentVariable($variable,$prevValue)
    }
}

function Prepare-MockEnvVariable($varName, $value) {
    $prevValue = [Environment]::GetEnvironmentVariable($varName)
    [Environment]::SetEnvironmentVariable($varName,$value)
    return $prevValue
}

function Exit-Basic {
    Param(
        [int]$ExitCode
    )

    exit $ExitCode
}

function Invoke-StaticMethod {
    Param(
        [parameter(Mandatory=$true)]
        [string]$Type,
        [parameter(Mandatory=$true)]
        [string]$Name,
        [array]$Params=$null
    )

    $fullType = "System.Management.Automation." + $Type
    $staticClass = [Type]$fullType

    return $staticClass::$Name.Invoke($Params)
}

function Execute-Process ($DestinationFile, $Arguments) {
    if (($Arguments.Count -eq 0) -or ($Arguments -eq $null)) {
        $p = Start-Process -FilePath $DestinationFile `
                           -PassThru `
                           -Wait
    } else {
        $p = Start-Process -FilePath $DestinationFile `
                           -ArgumentList $Arguments `
                           -PassThru `
                           -Wait
    }

    return $p
}

function Get-UserPath () {
    return [System.Environment]::GetEnvironmentVariable("PATH", "User")
}

function Get-SystemPath {
    return [System.Environment]::GetEnvironmentVariable("PATH", "Machine")
}


# TESTABLE METHODS

function Compare-Objects ($first, $last) {
    (Compare-Object $first $last -SyncWindow 0).Length -eq 0
}

function Compare-ScriptBlocks {
    Param(
        [System.Management.Automation.ScriptBlock]$scrBlock1,
        [System.Management.Automation.ScriptBlock]$scrBlock2
    )

    $sb1 = $scrBlock1.ToString()
    $sb2 = $scrBlock2.ToString()

    return ($sb1.CompareTo($sb2) -eq 0)
}

function Add-FakeObjProperty ([ref]$obj, $name, $value) {
    Add-Member -InputObject $obj.value -MemberType NoteProperty `
        -Name $name -Value $value
}

function Add-FakeObjProperties ([ref]$obj, $fakeProperties, $value) {
    foreach ($prop in $fakeProperties) {
        Add-Member -InputObject $obj.value -MemberType NoteProperty `
            -Name $prop -Value $value
    }
}

function Add-FakeObjMethod ([ref]$obj, $name) {
    Add-Member -InputObject $obj.value -MemberType ScriptMethod `
        -Name $name -Value { return 0 }
}

function Add-FakeObjMethods ([ref]$obj, $fakeMethods) {
    foreach ($method in $fakeMethods) {
        Add-Member -InputObject $obj.value -MemberType ScriptMethod `
            -Name $method -Value { return 0 }
    }
}

function Compare-Arrays ($arr1, $arr2) {
    return (((Compare-Object $arr1 $arr2).InputObject).Length -eq 0)
}

function Compare-HashTables ($tab1, $tab2) {
    if ($tab1.Count -ne $tab2.Count) {
        return $false
    }
    foreach ($i in $tab1.Keys) {
        if (($tab2.ContainsKey($i) -eq $false) -or ($tab1[$i] -ne $tab2[$i])) {
            return $false
        }
    }
    return $true
}

function Execute-ExternalCommand {
    param(
        [ScriptBlock]$Command,
        [array]$ArgumentList=@(),
        [string]$ErrorMessage
    )

    $res = Invoke-Command -ScriptBlock $Command -ArgumentList $ArgumentList
    if ($LASTEXITCODE -ne 0) {
        throw $ErrorMessage
    }
    return $res
}

function ExecuteWith-Retry {
    param(
        [ScriptBlock]$Command,
        [int]$MaxRetryCount=10,
        [int]$RetryInterval=3,
        [array]$ArgumentList=@()
    )

    $currentErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"

    $retryCount = 0
    while ($true) {
        try {
            $res = Invoke-Command -ScriptBlock $Command `
                     -ArgumentList $ArgumentList
            $ErrorActionPreference = $currentErrorActionPreference
            return $res
        } catch [System.Exception] {
            $retryCount++
            if ($retryCount -gt $MaxRetryCount) {
                $ErrorActionPreference = $currentErrorActionPreference
                throw $_.Exception
            } else {
                Write-Error $_.Exception
                Start-Sleep $RetryInterval
            }
        }
    }
}

function Unzip-File ($zipFile, $destination) {
    $shellApp = New-Object -ComObject Shell.Application
    $zipFileNs = $shellApp.NameSpace($zipFile)
    $destinationNs = $shellApp.NameSpace($destination)
    $destinationNs.CopyHere($zipFileNs.Items(), 0x4)
}

function Check-FileIntegrityWithSHA1 {
    param(
        [Parameter(Mandatory=$true)]
        [string]$File,
        [Parameter(Mandatory=$true)]
        [string]$ExpectedSHA1Hash
    )

    $hash = (Get-FileHash -Path $File -Algorithm "SHA1").Hash
    if ($hash -ne $ExpectedSHA1Hash) {
        $errMsg = "SHA1 hash not valid for file: $filename. " +
                  "Expected: $ExpectedSHA1Hash Current: $hash"
        throw $errMsg
    }
}

function Download-File ($DownloadLink, $DestinationFile, $ExpectedSHA1Hash) {
    $webclient = New-Object System.Net.WebClient
    ExecuteWith-Retry -Command {
        $webclient.DownloadFile($DownloadLink, $DestinationFile)
    }
    Check-FileIntegrityWithSHA1 $DestinationFile $ExpectedSHA1Hash
}

function Remove-DuplicatePaths ($Path) {
    $arrayPath = $Path.Split(';')
    $arrayPath = $arrayPath | Select-Object -Unique
    $newPath = $arrayPath -join ';'

    return $newPath
}

function AddTo-UserPath ($Path) {
    $newPath = Remove-DuplicatePaths "$env:Path;$Path"

    Execute-ExternalCommand -Command {
        setx PATH $newPath
    } -ErrorMessage "Failed to set user path"

    Renew-PSSessionPath
}

function Renew-PSSessionPath () {
    $userPath = Get-UserPath
    $systemPath = Get-SystemPath

    $newPath = $env:Path
    if (($userPath -ne $null) -and ($systemPath -ne $null)) {
        $newPath += ";$userPath;$systemPath"
    } else {
        if ($userPath -eq $null) {
            $newPath += ";$systemPath"
        } else {
            $newPath += ";$userPath"
        }
    }

    $env:Path = Remove-DuplicatePaths $newPath
}


# ALIASES

function ExecRetry {
    Param(
        [ScriptBlock]$Command,
        [int]$MaxRetryCount=3,
        [int]$RetryInterval=0
    )

    ExecuteWith-Retry $Command $MaxRetryCount $RetryInterval
}

Export-ModuleMember -Function *
