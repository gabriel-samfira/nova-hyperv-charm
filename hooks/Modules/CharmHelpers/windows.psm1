$utilsModulePath = Join-Path $PSScriptRoot "utils.psm1"
Import-Module -Force -DisableNameChecking $utilsModulePath
$jujuModulePath = Join-Path $PSScriptRoot "juju.psm1"
Import-Module -Force -DisableNameChecking $jujuModulePath

function Import-Certificate()
{
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$true,ValueFromPipeline=$true)]
        [string]$CertificatePath,

        [parameter(Mandatory=$true)]
        [System.Security.Cryptography.X509Certificates.StoreLocation]$StoreLocation,

        [parameter(Mandatory=$true)]
        [System.Security.Cryptography.X509Certificates.StoreName]$StoreName
    )
    PROCESS
    {
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store(
            $StoreName, $StoreLocation)
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)

        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
            $CertificatePath)
        $store.Add($cert)
    }
}

function Start-ProcessRedirect {
    param(
        [Parameter(Mandatory=$true)]
        [array]$Filename,
        [Parameter(Mandatory=$true)]
        [array]$Arguments,
        [Parameter(Mandatory=$false)]
        [array]$Domain,
        [Parameter(Mandatory=$false)]
        [array]$Username,
        [Parameter(Mandatory=$false)]
        $SecPassword
    )

    $pinfo = New-Object System.Diagnostics.ProcessStartInfo
    $pinfo.FileName = $Filename
    if ($Domain -ne $null) {
        $pinfo.Username = $Username
        $pinfo.Password = $secPassword
        $pinfo.Domain = $Domain
    }
    $pinfo.CreateNoWindow = $true
    $pinfo.RedirectStandardError = $true
    $pinfo.RedirectStandardOutput = $true
    $pinfo.UseShellExecute = $false
    $pinfo.LoadUserProfile = $true
    $pinfo.Arguments = $Arguments
    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $pinfo
    $p.Start() | Out-Null
    $p.WaitForExit()

    $stdout = $p.StandardOutput.ReadToEnd()
    $stderr = $p.StandardError.ReadToEnd()
    Write-JujuLog "stdout: $stdout"
    Write-JujuLog "stderr: $stderr"

    return $p
}

function Is-ComponentInstalled {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name
    )

    $component = Get-WmiObject -Class Win32_Product | `
                     Where-Object { $_.Name -Match $Name}

    return ($component -ne $null)
}

function Rename-Hostname {
    $jujuUnitName = ${env:JUJU_UNIT_NAME}.split('/')
    if ($jujuUnitName[0].Length -ge 15) {
        $jujuName = $jujuUnitName[0].substring(0, 12)
    } else {
        $jujuName = $jujuUnitName[0]
    }
    $newHostname = $jujuName + $jujuUnitName[1]

    if ($env:computername -ne $newHostname) {
        Rename-Computer -NewName $newHostname
        ExitFrom-JujuHook -WithReboot
    }
}

function Create-ADUsers {
    param(
        [Parameter(Mandatory=$true)]
        $UsersToAdd,
        [Parameter(Mandatory=$true)]
        [string]$AdminUsername,
        [Parameter(Mandatory=$true)]
        $AdminPassword,
        [Parameter(Mandatory=$true)]
        [string]$Domain,
        [Parameter(Mandatory=$true)]
        [string]$DCName,
        [Parameter(Mandatory=$true)]
        [string]$MachineName
    )

    $dcsecpassword = ConvertTo-SecureString $AdminPassword -AsPlainText -Force
    $dccreds = New-Object System.Management.Automation.PSCredential("$Domain\$AdminUsername", $dcsecpassword)
    $session = New-PSSession -ComputerName $DCName -Credential $dccreds
    Import-PSSession -Session $session -CommandName New-ADUser, Get-ADUser, Set-ADAccountPassword

    foreach($user in $UsersToAdd){
        $username = $user['Name']
        $password = $user['Password']
        $alreadyUser = $False
        try{
            $alreadyUser = (Get-ADUser $username) -ne $Null
        }
        catch{
            $alreadyUser = $False
        }

        $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
        if($alreadyUser -eq $False){
            $Description = "AD user"
            New-ADUser -Name $username -AccountPassword $securePassword -Description $Description -Enabled $True

            $User = [ADSI]("WinNT://$Domain/$username")
            $Group = [ADSI]("WinNT://$MachineName/Administrators")
            $Group.PSBase.Invoke("Add",$User.PSBase.Path)
        }
        else{
            Write-JujuLog "User already addded"
            Set-ADAccountPassword -NewPassword $securePassword -Identity $username
        }
    }

    $session | Remove-PSSession
}

function Create-Service {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name,
        [Parameter(Mandatory=$true)]
        [string]$Path,
        [Parameter(Mandatory=$true)]
        [string]$Description,
        [Parameter(Mandatory=$false)]
        [string]$User,
        [Parameter(Mandatory=$false)]
        [string]$Pass
    )

    if($user -and $Pass){
        $secpasswd = ConvertTo-SecureString $Pass -AsPlainText -Force
        $cred = New-Object System.Management.Automation.PSCredential ($User, $secpasswd)
    }

    if ($cred){
        New-Service -Name $Name -BinaryPathName $Path -DisplayName $Name -Description $Description  -Credential $cred -Confirm:$false
    }else{
        New-Service -Name $Name -BinaryPathName $Path -DisplayName $Name -Description $Description -Confirm:$false
    }

}

function Change-ServiceLogon {
    param(
        [Parameter(Mandatory=$true)]
        $Services,
        [Parameter(Mandatory=$true)]
        [string]$UserName,
        [Parameter(Mandatory=$false)]
        $Password
    )

    if($Services.GetType() -eq [System.Array]){
        $Services | ForEach-Object { $_.Change($null,$null,$null,$null,$null,$null,$UserName,$Password) }
    } else {
        $Services.Change($null,$null,$null,$null,$null,$null,$UserName,$Password)
    }
}

function Get-Subnet {
    param(
        [Parameter(Mandatory=$true)]
        $IP,
        [Parameter(Mandatory=$true)]
        $Netmask
    )

    $class = 32
    $netmaskClassDelimiter = "255"
    $netmaskSplit = $Netmask -split "[.]"
    $ipSplit = $IP -split "[.]"
    for ($i = 0; $i -lt 4; $i++) {
        if ($netmaskSplit[$i] -ne $netmaskClassDelimiter) {
            $class -= 8
            $ipSplit[$i] = "0"
        }
    }

    $fullSubnet = ($ipSplit -join ".") + "/" + $class
    return $fullSubnet
}

function Install-WindowsFeatures {
    param(
        [Parameter(Mandatory=$true)]
        [array]$Features
    )

    $rebootNeeded = $false
    foreach ($feature in $Features) {
        $state = ExecuteWith-Retry -Command {
            Install-WindowsFeature -Name $feature -ErrorAction Stop
        }
        if ($state.Success -eq $true) {
            if ($state.RestartNeeded -eq 'Yes') {
                $rebootNeeded = $true
            }
        } else {
            throw "Install failed for feature $feature"
        }
    }

    if ($rebootNeeded -eq $true) {
        ExitFrom-JujuHook -WithReboot
    }
}

function Get-CharmStateKeyPath () {
    return "HKLM:\SOFTWARE\Wow6432Node\Cloudbase Solutions"
}

function Set-CharmState {
    param(
        [Parameter(Mandatory=$true)]
        [string]$CharmName,
        [Parameter(Mandatory=$true)]
        [string]$Key,
        [Parameter(Mandatory=$true)]
        [string]$Val
    )

    $keyPath = Get-CharmStateKeyPath
    $fullKey = ($CharmName + $Key)
    $property = New-ItemProperty -Path $keyPath `
                                 -Name $fullKey `
                                 -Value $Val `
                                 -PropertyType String `
                                 -ErrorAction SilentlyContinue

    if ($property -eq $null) {
        Set-ItemProperty -Path $keyPath -Name $fullKey -Value $Val
    }
}

function Get-CharmState {
    param(
        [Parameter(Mandatory=$true)]
        [string]$CharmName,
        [Parameter(Mandatory=$true)]
        [string]$Key
    )

    $keyPath = Get-CharmStateKeyPath
    $fullKey = ($CharmName + $Key)
    $property = Get-ItemProperty -Path $keyPath `
                                 -Name $fullKey `
                                 -ErrorAction SilentlyContinue

    if ($property -ne $null) {
        $state = Select-Object -InputObject $property -ExpandProperty $fullKey
        return $state
    } else {
        return $null
    }
}

function Check-Membership {
    Param (
        [Parameter(Mandatory=$true)]
        [string]$User,
        [Parameter(Mandatory=$true)]
        [string]$GroupSID
    )
	Juju-Log ">>>>>>>>>>>> $GroupSID"
    $group = Get-CimInstance -ClassName Win32_Group  -Filter "SID = '$GroupSID'"
	Juju-Log "Checking for $User"
    $ret = Get-CimAssociatedInstance -InputObject $group -ResultClassName Win32_UserAccount | Where-Object {$_.Caption -eq $User }
	Juju-Log ">>>>>Found $ret"
    return $ret
}

function Convert-SIDToFriendlyName {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$SID
    )
    $objSID = New-Object System.Security.Principal.SecurityIdentifier($SID)
    $objUser = $objSID.Translate( [System.Security.Principal.NTAccount])
    $name = $objUser.Value
	$n = $name.Split("\")
	if ($n.length -gt 1){
		return $n[1]
	}
    return $n[0]
}


function Normalize-User {
   Param(
    [Parameter(Mandatory=$true)]
    [string]$User
   )

   $splitUser = $User.Split("\")
    if ($splitUser.length -eq 2){
        if ($splitUser[0] -eq "."){
            $domain = $env:COMPUTERNAME
        } else {
            $domain = $splitUser[0]
        }
        $u = $splitUser[1]
    }else{
        $domain = $env:COMPUTERNAME
        $u = $User
    }
    return @($domain, $u)
}

function AddTo-LocalGroup {
    Param (
        [Parameter(Mandatory=$true)]
        [string]$Username,
        [Parameter(Mandatory=$true)]
        [string]$GroupSID
    )

    $usrSplit = Normalize-User -User $Username
    $domain = $usrSplit[0]
    $user = $usrSplit[1]
    $domuser = "$domain\$user"
	Juju-Log "><><><>>>!!!11111 $domuser"
    $isMember = Check-Membership -User $domuser -Group $GroupSID
	Juju-Log "><><><>>>!!!22222222"
    $grpName = Convert-SIDToFriendlyName -SID $GroupSID
	Juju-Log ">>>>>>Got Group $grpName"
    if (!$isMember){
        $ObjUser = [ADSI]("WinNT://$domain/$user")
        $objGroup = [ADSI]("WinNT://$env:COMPUTERNAME/$grpName")
		try {
			$objGroup.PSBase.Invoke("Add",$objUser.PSBase.Path)
		} catch {
			Juju-Log "Ignoring error"
		}
    }

    return $true
}

function Create-LocalAdmin {
    param(
        [Parameter(Mandatory=$true)]
        [string]$LocalAdminUsername,
        [Parameter(Mandatory=$true)]
        [string]$LocalAdminPassword
    )

    $existentUser = Get-WmiObject -Class Win32_Account `
                                  -Filter "Name = '$LocalAdminUsername'"
    if ($existentUser -eq $null) {
        $computer = [ADSI]"WinNT://$env:computername"
        $localAdmin = $computer.Create("User", $LocalAdminUsername)
        $localAdmin.SetPassword($LocalAdminPassword)
        $localAdmin.SetInfo()
        $LocalAdmin.FullName = $LocalAdminUsername
        $LocalAdmin.SetInfo()
        # UserFlags = Logon script | Normal user | No pass expiration
        $LocalAdmin.UserFlags = 1 + 512 + 65536
        $LocalAdmin.SetInfo()
    } else {
        Execute-ExternalCommand -Command {
            net.exe user $LocalAdminUsername $LocalAdminPassword
        } -ErrorMessage "Failed to create new user"
    }

    AddTo-LocalGroup -Username $LocalAdminUsername -GroupSID "S-1-5-32-544"
}

function Get-DomainName {
    param(
        [Parameter(Mandatory=$true)]
        [string]$FQDN
    )

    $fqdnParts = $FQDN.split(".")
    $domainNameParts = $fqdnParts[0..($fqdnParts.Length - 2)]
    $domainName = $domainNameParts -join '.'

    return $domainName
}

function Get-ADCredential {
    param(
        [Parameter(Mandatory=$true)]
        $ADParams
    )

    $adminUsername = $ADParams["ad_username"]
    $adminPassword = $ADParams["ad_password"]
    $domain = Get-DomainName $ADParams["ad_domain"]
    $passwordSecure = ConvertTo-SecureString $adminPassword -AsPlainText -Force
    $adCredential = New-Object PSCredential("$domain\$adminUsername",
                                             $passwordSecure)

    return $adCredential
}

function Set-DNS {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Interface,
        [Parameter(Mandatory=$true)]
        [array]$DNSIPs
    )

    Set-DnsClientServerAddress -InterfaceAlias $Interface `
                               -ServerAddresses $DNSIPs
}

function Get-NetAdapterName {
    param(
        [switch]$Primary
    )

    $primaryEthernetNames = @(
        "Management0",
        "Ethernet0"
    )

    $netAdapters = Get-NetAdapter
    foreach ($adapter in $netAdapters) {
        if ($Primary -eq $true) {
            if ($primaryEthernetNames -match $adapter.Name) {
                return $adapter.Name
            }
        } else {
            if ($primaryEthernetNames -notmatch $adapter.Name) {
                return $adapter.Name
            }
        }
    }

    return $null
}

function Get-PrimaryNetAdapterName {
    return (Get-NetAdapterName)
}

function Get-SecondaryNetAdapterName {
    return (Get-NetAdapterName -Primary)
}

function Join-Domain {
    param(
        [Parameter(Mandatory=$true)]
        [string]$FQDN,
        [Parameter(Mandatory=$true)]
        [string]$DomainCtrlIP,
        [Parameter(Mandatory=$true)]
        $LocalCredential,
        [Parameter(Mandatory=$true)]
        $ADCredential
    )

    $netAdapterName = Get-PrimaryNetAdapterName
    if ($netAdapterName -eq $null) {
        $netAdapterName = Get-SecondaryNetAdapterName
    }
    Set-DNS $netAdapterName $DomainCtrlIP

    $domainName = Get-DomainName $FQDN
    Add-Computer -LocalCredential $LocalCredential `
                 -Credential $ADCredential `
                 -Domain $domainName
}

function Is-InDomain {
    param(
        [Parameter(Mandatory=$true)]
        [string]$WantedDomain
    )

    $currentDomain = (Get-WmiObject -Class `
                          Win32_ComputerSystem).Domain.ToLower()
    $comparedDomain = ($WantedDomain).ToLower()
    $inDomain = $currentDomain.Equals($comparedDomain)

    return $inDomain
}

function New-NetstatObject {
    param(
        [Parameter(Mandatory=$True)]
        $Properties
    )

    $process = Get-Process | Where-Object { $_.Id -eq $Properties.PID }
    $processName = $process.ProcessName

    $processObject = New-Object psobject -property @{
        Protocol      = $Properties.Protocol
        LocalAddress  = $Properties.LAddress
        LocalPort     = $Properties.LPort
        RemoteAddress = $Properties.RAddress
        RemotePort    = $Properties.RPort
        State         = $Properties.State
        ID            = [int]$Properties.PID
        ProcessName   = $processName
    }

    return $processObject
}

# It works only for command: netstat -ano
function Get-NetstatObjects {
    $null, $null, $null, $null,
    $netstatOutput = Execute-ExternalCommand -Command {
        netstat -ano
    } -ErrorMessage "Failed to execute netstat"

    [regex]$regexTCP = '(?<Protocol>\S+)\s+(?<LAddress>\S+):(?<LPort>\S+)' +
            '\s+(?<RAddress>\S+):(?<RPort>\S+)\s+(?<State>\S+)\s+(?<PID>\S+)'
    [regex]$regexUDP = '(?<Protocol>\S+)\s+(?<LAddress>\S+):(?<LPort>\S+)' +
                       '\s+(?<RAddress>\S+):(?<RPort>\S+)\s+(?<PID>\S+)'
    $objects = @()

    foreach ($line in $netstatOutput) {
        switch -regex ($line.Trim()) {
            $regexTCP {
                $process = New-NetstatObject -Properties $matches
                $objects = $objects + $process
                continue
            }
            $regexUDP {
                $process = New-NetstatObject -Properties $matches
                $objects = $objects + $process
                continue
            }
        }
    }

    return $objects
}

function Add-WindowsUser {
    param(
        [parameter(Mandatory=$true)]
        [string]$Username,
        [parameter(Mandatory=$true)]
        [string]$Password
    )

    Execute-ExternalCommand -Command {
        NET.EXE USER $Username $Password '/ADD'
    } -ErrorMessage "Failed to create new user"
}

function Delete-WindowsUser {
    param(
        [parameter(Mandatory=$true)]
        [string]$Username
    )

    Execute-ExternalCommand -Command {
        NET.EXE USER $Username '/DELETE'
    } -ErrorMessage "Failed to create new user"
}


# ALIASES

function Get-Domain-Name {
    param(
        [Parameter(Mandatory=$true)]
        [string]$FullDomainName
    )

    return (Get-DomainName $FullDomainName)
}

function Create-Local-Admin {
    param(
        [Parameter(Mandatory=$true)]
        [string]$LocalAdminUsername,
        [Parameter(Mandatory=$true)]
        [string]$LocalAdminPassword
    )

    Create-LocalAdmin $LocalAdminUsername $LocalAdminPassword
}

function Get-Ad-Credential {
    param(
        [Parameter(Mandatory=$true)]
        $params
    )

    return (Get-ADCredential $params)
}

function Join-Any-Domain {
    param(
        [Parameter(Mandatory=$true)]
        [string]$domain,
        [Parameter(Mandatory=$true)]
        [string]$domainCtrlIp,
        [Parameter(Mandatory=$true)]
        $localCredential,
        [Parameter(Mandatory=$true)]
        $adCredential
    )

    Join-Domain $domain $domainCtrlIp $localCredential $adCredential
}

function Is-Component-Installed {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name
    )

    return (Is-ComponentInstalled $Name)
}

function Start-Process-Redirect {
    param(
        [Parameter(Mandatory=$true)]
        [array]$Filename,
        [Parameter(Mandatory=$true)]
        [array]$Arguments,
        [Parameter(Mandatory=$false)]
        [array]$Domain,
        [Parameter(Mandatory=$false)]
        [array]$Username,
        [Parameter(Mandatory=$false)]
        $SecPassword
    )

    return (Start-ProcessRedirect $FileName `
                                   $Arguments `
                                   $Domain `
                                   $Username `
                                   $SecPassword)
}

function Create-AD-Users {
    param(
        [Parameter(Mandatory=$true)]
        $UsersToAdd,
        [Parameter(Mandatory=$true)]
        [string]$AdminUsername,
        [Parameter(Mandatory=$true)]
        $AdminPassword,
        [Parameter(Mandatory=$true)]
        [string]$Domain,
        [Parameter(Mandatory=$true)]
        [string]$DCName,
        [Parameter(Mandatory=$true)]
        [string]$MachineName
    )

    Create-ADUsers $UsersToAdd `
                   $AdminUsername `
                   $AdminPassword `
                   $Domain `
                   $DCName `
                   $MachineName
}

function Encrypt-String {
    Param (
        [Parameter(Mandatory=$true)]
        [string]$content
    )
    $ret = ConvertTo-SecureString -AsPlainText -Force $content | ConvertFrom-SecureString
    return $ret
}

function Decrypt-String {
    Param (
        [Parameter(Mandatory=$true)]
        [string]$content
    )
    $c = ConvertTo-SecureString $content
    $dec = [System.Runtime.InteropServices.Marshal]::SecureStringToCoTaskMemUnicode($c)
    $ret = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($dec)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeCoTaskMemUnicode($dec)
    return $ret
}

Export-ModuleMember -Function *
