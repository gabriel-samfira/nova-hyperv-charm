#
# Copyright 2014 Cloudbase Solutions SRL
#
$ErrorActionPreference = "Stop"

$name = Split-Path -Path $MyInvocation.MyCommand.Path -Parent
$fullPath = Join-Path $name "Modules\CharmHelpers"
Import-Module -Force -DisableNameChecking $fullPath


$ovs_vsctl = "${env:ProgramFiles(x86)}\Cloudbase Solutions\Open vSwitch\bin\ovs-vsctl.exe"
$ovsExtName = "Open vSwitch Extension"

function Is-ValidIPV4 {
    Param (
        [Parameter(Mandatory=$true)]
        [string]$ip
    )

    $arr = $ip.Split(".")
    foreach($i in $arr){
        $asInt = $i -as [int]
        if ($asInt -eq $null){
            return $false
        }
        if ($asInt -lt 0 -or $asInt -gt 255){
            return $false
        }
    }
    return $true
}

function Parse-CIDR {
    Param (
        [Parameter(Mandatory=$true)]
        [string]$range
    )

    $split_cidr = $range.Split("/")
    if ($split_cidr.length -eq 1) {
        $ip = $split_cidr[0]
        $prefix = 24
    }elseif ($split_cidr.length -eq 2) {
        $a = $split_cidr[1]
        $prefix = $split_cidr[1] -as [int]
        if ($prefix -eq $null){
            Juju-Error "CIDR mask is not valid: $split_cidr[1]"
        }
        $ip = $split_cidr[0]
    }else{
        Juju-Error "CIDR mask is nonsense: $local_ip_pool"
    }
    $ipIsValid = Is-ValidIPV4 $ip
    if(!$ipIsValid){
        Throw "IP is invalid. Must have IPv4"
    }
    return @($ip, $prefix)
}

function Get-LocalIP {
    $private_ip = unit_private_ip
    $local_ip_pool =  charm_config -scope "local-ip-pool"
    Juju-Log "Local IP pool is: $local_ip_pool"
    if ($local_ip_pool -eq $null) {
        $local_ip = $private_ip
        return @($local_ip, "32")
    }
    $asCidr = Parse-CIDR $local_ip_pool
    $prefixClass = $asCidr[1]/8
    $isInt = $prefixClass -is [int]

    if(!$isInt){
        Juju-Error "CIDR prefix must be /8, /16 or /24. Got: /$prefix"
    }
    $pool_split = $asCidr[0].Split(".")
    if ($prefixClass -eq 1){
        $base = $pool_split[0]
    }else{
        $base = $pool_split[0..($prefixClass-1)]
    }
    if ($prefixClass -eq 3){
        $privateBits = $private_ip.split(".")[$prefixClass]
    }else {
        $private_split = $private_ip.split(".")
        $privateBits = $private_split[$prefixClass..($private_split.length-1)]
    }
    $base += $privateBits
    $joined = $base -join "."
    return @($joined, $asCidr[1])
}


function Juju-GetVMSwitch {
    $VMswitchName = charm_config -scope "vmswitch-name"
    if (!$VMswitchName){
        return "br100"
    }
    return $VMswitchName
}

function Do-Reboot {
	$hasRebooted = Test-Path C:\has_rebooted.txt
        if ($hasRebooted -eq $false){
            Set-Content C:\has_rebooted.txt "meh"
            juju-reboot.exe --now
        }
		Juju-Error "Failed to create bonding interface: $_.Exception.Message"
}

function Setup-BondInterface {
    $bondExists = Get-NetLbfoTeam
    if ($bondExists -ne $null){ return }
    $bondPorts = Get-InterfaceFromConfig -ConfigOption "bond-ports"
    if ($bondPorts.Length -eq 0) {
        return
    }
    try {
        New-NetLbfoTeam -Name "bond0" -TeamMembers $bondPorts.Name -TeamNicName "bond0" -TeamingMode LACP -Confirm:$false
		if ($? -eq $false){
			Do-Reboot
		}
    }catch{
        Do-Reboot
    }
    #$bond = Get-NetLbfoTeam -Name "bond0"
    #if ($bond.Status -eq "Down"){
    #    Juju-Error "Failed to bring up bond0 interface. Bond state is $bond.Status"
    #}
}

function Get-TemplatesDir {
    $templates =  Join-Path "$env:CHARM_DIR" "templates"
    return $templates
}

function Get-PackageDir {
    $packages =  Join-Path "$env:CHARM_DIR" "packages"
    return $packages
}

function Get-FilesDir {
    $packages =  Join-Path "$env:CHARM_DIR" "files"
    return $packages
}


function Install-RootWrap {
    $template = Get-TemplatesDir
    $rootWrap = Join-Path $template "ovs\rootwrap.cmd"

    if(!(Test-Path $rootWrap)){
        return $true
    }

    $dst = "C:\Program Files (x86)\Cloudbase Solutions\OpenStack\Nova\bin\rootwrap.cmd"
    $parent = Split-Path -Path $dst -Parent
    $exists = Test-Path $parent
    if (!$exists){
        mkdir $parent
    }
    cp $rootWrap $dst
    return $?
}

function Charm-Services {
    $template_dir = Get-TemplatesDir
    $distro = charm_config -scope "openstack-origin"
    $nova_config = "${env:programfiles(x86)}\Cloudbase Solutions\Openstack\Nova\etc\nova.conf"
    $neutron_config = "${env:programfiles(x86)}\Cloudbase Solutions\Openstack\Nova\etc\neutron_hyperv_agent.conf"
    $neutron_ml2 = "${env:programfiles(x86)}\Cloudbase Solutions\Openstack\Nova\etc\ml2_conf.ini"

    $serviceWrapper = "${env:programfiles(x86)}\Cloudbase Solutions\Openstack\Nova\bin\OpenStackServiceNeutron.exe"
    $novaExe = "${env:programfiles(x86)}\Cloudbase Solutions\Openstack\Nova\Python27\Scripts\nova-compute.exe"
    $neutronHypervAgentExe = "${env:programfiles(x86)}\Cloudbase Solutions\Openstack\Nova\Python27\Scripts\neutron-hyperv-agent.exe"
    $neutronOpenvswitchExe = "${env:programfiles(x86)}\Cloudbase Solutions\Openstack\Nova\Python27\Scripts\neutron-openvswitch-agent.exe"

    $JujuCharmServices = @{
        "nova"=@{
            "myname"="nova";
            "template"="$template_dir\$distro\nova.conf";
            "service"="nova-compute";
            "binpath"="$novaExe";
            "serviceBinPath"="`"$serviceWrapper`" nova-compute `"$novaExe`" --config-file `"$nova_config`"";
            "config"="$nova_config";
            "context_generators"=@(
                "Get-RabbitMQContext",
                "Get-NeutronContext",
                "Get-GlanceContext",
                "Get-CharmConfigContext"
                );
        };
        "neutron"=@{
            "myname"="neutron";
            "template"="$template_dir\$distro\neutron_hyperv_agent.conf"
            "service"="neutron-hyperv-agent";
            "binpath"="$neutronHypervAgentExe";
            "serviceBinPath"="`"$serviceWrapper`" neutron-hyperv-agent `"$neutronHypervAgentExe`" --config-file `"$neutron_config`"";
            "config"="$neutron_config";
            "context_generators"=@(
                "Get-RabbitMQContext",
                "Get-NeutronContext",
                "Get-CharmConfigContext"
                );
        }
        "neutron-ovs"=@{
            "myname"="neutron-ovs";
            "template"="$template_dir\$distro\ml2_conf.ini"
            "service"="neutron-openvswitch-agent";
            "binpath"="$neutronOpenvswitchExe";
            "serviceBinPath"="`"$serviceWrapper`" neutron-openvswitch-agent `"$neutronOpenvswitchExe`" --config-file `"$neutron_ml2`" --config-file `"$neutron_config`"";
            "config"="$neutron_ml2";
            "context_generators"=@(
                "Get-NeutronContext",
                "Get-CharmConfigContext"
                );
        }
    }
    return $JujuCharmServices
}

function Get-RabbitMQContext {
    Juju-Log "Generating context for RabbitMQ"
    $username = charm_config -scope 'rabbit-user'
    $vhost = charm_config -scope 'rabbit-vhost'
    if (!$username -or !$vhost){
        Juju-Error "Missing required charm config options: rabbit-user or rabbit-vhost"
    }

    $ctx = @{
        "rabbit_host"=$null;
        "rabbit_userid"=$username;
        "rabbit_password"=$null;
        "rabbit_virtual_host"=$vhost
    }

    $relations = relation_ids -reltype 'amqp'
    foreach($rid in $relations){
        $related_units = related_units -relid $rid
        foreach($unit in $related_units){
            $ctx["rabbit_host"] = relation_get -attr "private-address" -rid $rid -unit $unit
            $ctx["rabbit_password"] = relation_get -attr "password" -rid $rid -unit $unit
            $ctx_complete = Check-ContextComplete -ctx $ctx
            if ($ctx_complete){
                break
            }
        }
    }
    $ctx_complete = Check-ContextComplete -ctx $ctx
    if ($ctx_complete){
        return $ctx
    }
    Juju-Log "RabbitMQ context not yet complete. Peer not ready?"
    return @{}
}

function Get-NeutronUrl {
    Param (
        [Parameter(Mandatory=$true)]
        [string]$rid,
        [Parameter(Mandatory=$true)]
        [string]$unit
    )

    $url = relation_get -attr 'neutron_url' -rid $rid -unit $unit
    if ($url){
        return $url
    }
    $url = relation_get -attr 'quantum_url' -rid $rid -unit $unit
    return $url
}


function Get-NeutronContext {
    Juju-Log "Generating context for Neutron"

    $logdir = charm_config -scope 'log-dir'
    $instancesDir = charm_config -scope 'instances-dir'
    $data_port_vlan = charm_config -scope 'data-port-vlan'
    $logdirExists = Test-Path $logdir
    $instancesExist = Test-Path $instancesDir

    if (!$logdirExists){
        mkdir $logdir
    }

    if (!$instancesExist){
        mkdir $instancesDir
    }

    $ctx = @{
        "neutron_url"=$null;
        "keystone_host"=$null;
        "data_port_vlan"=$data_port_vlan;
        "auth_port"=$null;
        "auth_protocol"=$null;
        "neutron_auth_strategy"="keystone";
        "neutron_admin_tenant_name"=$null;
        "neutron_admin_username"=$null;
        "neutron_admin_password"=$null;
        "log_dir"=$logdir;
        "instances_dir"=$instancesDir
    }

    $rids = relation_ids -reltype 'cloud-compute'
    foreach ($rid in $rids){
        $units = related_units -relid $rid
        foreach ($unit in $units){
            $url = Get-NeutronUrl -rid $rid -unit $unit
            if (!$url){
                continue
            }
            $ctx["neutron_url"] = $url
            $ctx["keystone_host"] = relation_get -attr 'auth_host' -rid $rid -unit $unit
            $ctx["auth_port"] = relation_get -attr 'auth_port' -rid $rid -unit $unit
            $ctx["auth_protocol"] = relation_get -attr 'auth_protocol' -rid $rid -unit $unit
            $ctx["neutron_admin_tenant_name"] = relation_get -attr 'service_tenant_name' -rid $rid -unit $unit
            $ctx["neutron_admin_username"] = relation_get -attr 'service_username' -rid $rid -unit $unit
            $ctx["neutron_admin_password"] = relation_get -attr 'service_password' -rid $rid -unit $unit
            $ctx_complete = Check-ContextComplete -ctx $ctx
            if ($ctx_complete){
                break
            }
        }
    }
    $ctx_complete = Check-ContextComplete -ctx $ctx
    if (!$ctx_complete){
        Juju-Log "Missing required relation settings for Neutron. Peer not ready?"
        return @{}
    }
    $ctx["neutron_admin_auth_url"] = $ctx["auth_protocol"] + "://" + $ctx['keystone_host'] + ":" + $ctx['auth_port']+ "/v2.0"
    $ip = Get-LocalIP
    $ctx["local_ip"] = $ip[0]
    return $ctx
}

function Get-GlanceContext {
    Juju-Log "Getting glance context"
    $rids = relation_ids -reltype 'image-service'
    if(!$rids){
        return @{}
    }
    foreach ($i in $rids){
        $units = related_units -relid $i
        foreach ($j in $units){
            $api_server = relation_get -attr 'glance-api-server' -rid $i -unit $j
            if($api_server){
                return @{"glance_api_servers"=$api_server}
            }
        }
    }
    Juju-Log "Glance context not yet complete. Peer not ready?"
    return @{}
}


function Get-CharmConfigContext {
    $config = charm_config
    $noteProp = $config | Get-Member -MemberType NoteProperty
    $asHash = @{}
    foreach ($i in $noteProp){
        $name = $i.Name
        $asHash[$name] = $config.$name
    }
    return $asHash
}

function Generate-Config {
    param (
        [Parameter(Mandatory=$true)]
        [string]$ServiceName
    )
    $JujuCharmServices = Charm-Services
    $should_restart = $true
    $service = $JujuCharmServices[$ServiceName]
    if (!$service){
        Juju-Error -Msg "No such service $ServiceName" -Fatal $false
        return $false
    }
    $config = gc $service["template"]
    # populate config with variables from context
    foreach ($context in $service['context_generators']){
        Juju-Log "Getting context for $context"
        $ctx = & $context
        Juju-Log "Got $context context $ctx"
        if ($ctx.Count -eq 0){
            # Context is empty. Probably peer not ready
            Juju-Log "Context for $context is EMPTY"
            $should_restart = $false
            continue
        }
        foreach ($val in $ctx.GetEnumerator()) {
            $regex = "{{[\s]{0,}" + $val.Name + "[\s]{0,}}}"
            $config = $config -Replace $regex,$val.Value
        }
    }
    # Any variables not available in context we remove
    $config = $config -Replace "{{[\s]{0,}[a-zA-Z0-9_-]{0,}[\s]{0,}}}",""
    Set-Content $service["config"] $config
    # Restart-Service $service["service"]
    return $should_restart
}

function Get-InterfaceFromConfig {
    Param (
        [string]$ConfigOption="data-port"
    )

    $nic = $null
    $DataInterfaceFromConfig = charm_config -scope $ConfigOption
    Juju-Log "Looking for $DataInterfaceFromConfig"
    if ($DataInterfaceFromConfig -eq $null){
        return $null
    }
    $byMac = @()
    $byName = @()
    $macregex = "^([a-f-A-F0-9]{2}:){5}([a-fA-F0-9]{2})$"
    foreach ($i in $DataInterfaceFromConfig.Split()){
        if ($i -match $macregex){
            $byMac += $i.Replace(":", "-")
        }else{
            $byName += $i
        }
    }
    Juju-Log "We have MAC: $byMac  Name: $byName"
    if ($byMac.Length -ne 0){
        $nicByMac = Get-NetAdapter | Where-Object { $_.MacAddress -in $byMac }
    }
    Juju-Log ">>>> $nicByMac"
    if ($byName.Length -ne 0){
        $nicByName = Get-NetAdapter | Where-Object { $_.Name -in $byName }
    }
    Juju-Log ">>>> $nicByName"
    if ($nicByMac -ne $null -and $nicByMac.GetType() -ne [System.Array]){
        $nicByMac = @($nicByMac)
    }
    if ($nicByName -ne $null -and $nicByName.GetType() -ne [System.Array]){
        $nicByName = @($nicByName)
    }
    $ret = $nicByMac + $nicByName
    if ($ret -ne $null){
        Juju-Log "got VmSWITCH $ret  $nicByMac + $nicByName"
    }
    return $ret
}

function Juju-ConfigureVMSwitch {
    Setup-BondInterface
    $unit_ip = unit_private_ip
    $local_ip = Get-LocalIP
    $net_type = charm_config -scope "network-type"
    $managementOS = $false
    if ($net_type -eq "ovs"){
        $managementOS = $true
    }

    $VMswitchName = Juju-GetVMSwitch
    try {
        $isConfigured = Get-VMSwitch -SwitchType External -Name $VMswitchName
    } catch {
        $isConfigured = $false
    }
    if ($isConfigured){
        return $true
    }
    $VMswitches = Get-VMSwitch -SwitchType External
    if ($VMswitches.Count -gt 0){
        Rename-VMSwitch $VMswitches[0] -NewName $VMswitchName
        return $true
    }

    $interfaces = Get-NetAdapter -Physical

    if ($interfaces.GetType().BaseType -ne [System.Array]){
        # we have ony one ethernet adapter. Going to use it for
        # vmswitch
        New-VMSwitch -Name $VMswitchName -NetAdapterName $interfaces.Name -AllowManagementOS $true
        if ($? -eq $false){
            Juju-Error "Failed to create vmswitch"
        }
    }else{
        Juju-Log "Trying to fetch data port from config"
        $nic = Get-InterfaceFromConfig
        Juju-Log "Got NetAdapterName $nic"
        if (!$nic) {
            Juju-Log "Data port not found. Not configuring switch"
            return $true
        }
        New-VMSwitch -Name $VMswitchName -NetAdapterName $nic[0].Name -AllowManagementOS $managementOS
        if ($? -eq $false){
            Juju-Error "Failed to create vmswitch"
        }
        if ($net_type -eq "ovs"){
            if ($local_ip[0] -eq $unit_ip){
                return $true
            }
            $curIP = Get-NetIPAddress -InterfaceAlias "vEthernet ($VMswitchName)" -AddressFamily IPv4
            if ($curIP.IPAddress -ne $local_ip[0]){
                New-NetIPAddress -IPAddress $local_ip[0] -InterfaceAlias "vEthernet ($VMswitchName)" -PrefixLength $local_ip[1] -Confirm:$false
            }
        } else {
            Remove-NetIPAddress -InterfaceAlias "vEthernet ($VMswitchName)" -Confirm:$false -ErrorAction SilentlyContinue
            Set-VMSwitch -Name $VMswitchName -AllowManagementOS $false
        }
        return $true
    }
    return $true
}


function Get-NovaPythonBinaries {
    $python = "${env:ProgramFiles(x86)}\Cloudbase Solutions\OpenStack\Nova\Python27\python.exe"
    $pip = "${env:ProgramFiles(x86)}\Cloudbase Solutions\OpenStack\Nova\Python27\Scripts\pip.exe"
    if (!(Test-Path $python)){
        Throw "Python was not found in $python"
    }

    if (!(Test-Path $pip)){
        Throw "pip was not found in $pip"
    }
    return @{"python"=$python; "pip"=$pip}
}

function Install-LocalPythonPackage {
    param(
        [Parameter(Mandatory=$true)]
        [string]$package
    )

    $bins = Get-NovaPythonBinaries

    $packageDir = Get-PackageDir
    # At this point we expect packages to be a tar.gz
    $pkg = Join-Path $packageDir ($package + ".tar.gz")
    if(!(Test-Path $pkg)){
        Throw "Package $pkg not found on this system"
    }
    $tmpDestination = Get-NewTempDir
    try {
        Start-Extract $pkg  $tmpDestination.ToString()
    } catch {
        Juju-Error "Failed extracting archive: $_.Exception.Message"
    }
    # There should be only one folder
    set-location $tmpDestination\*\
    & $bins["python"] setup.py install | out-null
    if ($lastexitcode){
        Juju-Error "Failed to install package $package"
    }
    set-location $env:TEMP
    # cleanup
    try {
        rm -Recurse -Force $tmpDestination
    } catch {
        # not the end of the world, but worth mentioning
        Juju-Log "Failed to clean temporary directory: $_.Exception.Message"
    }
    return $true
}

$distro_urls = @{
    'icehouse' = 'https://www.cloudbase.it/downloads/HyperVNovaCompute_Icehouse_2014_1_3.msi';
    'juno' = 'https://www.cloudbase.it/downloads/HyperVNovaCompute_Juno_2014_2.msi';
}

function Download-File {
     param(
        [Parameter(Mandatory=$true)]
        [string]$url
    )

    $msi = $url.split('/')[-1]
    $download_location = "$env:TEMP\" + $msi
    $installerExists = Test-Path $download_location

    if ($installerExists){
        return $download_location
    }
    Juju-Log "Downloading file from $url to $download_location"
    try {
        ExecuteWith-Retry { (new-object System.Net.WebClient).DownloadFile($url, $download_location) }
    } catch {
        Juju-Error "Could not download $url to destination $download_location"
    }

    return $download_location
}

function Get-NovaInstaller {
    $distro = charm_config -scope "openstack-origin"
    $installer_url = charm_config -scope "installer-url"
    if ($distro -eq $false){
        $distro = "juno"
    }
    if ($installer_url -eq $false) {
        if (!$distro_urls[$distro]){
            Juju-Error "Could not find a download URL for $distro"
        }
        $url = $distro_urls[$distro]
    }else {
        $url = $installer_url
    }
    $location = Download-File $url
    return $location
}

function Get-OVSInstaller {
    $installer_url = charm_config -scope "ovs-installer-url"
    if ($installer_url -eq $false) {
        Throw "Could not find a download URL for $distro"
    }else {
        $url = $installer_url
    }
    $location = Download-File $url
    return $location
}

function Install-Nova {
    param(
        [Parameter(Mandatory=$true)]
        [string]$InstallerPath
    )
    Juju-Log "Running Nova install"
    $hasInstaller = Test-Path $InstallerPath
    if($hasInstaller -eq $false){
        $InstallerPath = Get-NovaInstaller
    }
    Juju-Log "Installing from $InstallerPath"
    cmd.exe /C call msiexec.exe /i $InstallerPath /qn /l*v $env:APPDATA\log.txt SKIPNOVACONF=1

    if ($lastexitcode){
        Juju-Error "Nova failed to install"
    }
    return $true
}

function Install-OVS {
    param(
        [Parameter(Mandatory=$true)]
        [string]$InstallerPath
    )

    Juju-Log "Running OVS install"
    $hasInstaller = Test-Path $InstallerPath
    if($hasInstaller -eq $false){
        $InstallerPath = Get-OVSInstaller
    }
    Juju-Log "Installing from $InstallerPath"
    cmd.exe /C call msiexec.exe /i $InstallerPath ADDLOCAL="VC120Redist,OpenvSwitchCLI,OpenvSwitchDriver" /qn /l*v $env:APPDATA\ovs-log.txt

    if ($lastexitcode){
        Juju-Error "OVs FAILED to install"
    }
    juju-reboot.exe --now
    return $true
}

function Disable-Service {
    param(
        [Parameter(Mandatory=$true)]
        [string]$ServiceName
    )

    $svc = Get-Service $ServiceName -ErrorAction SilentlyContinue
    if ($svc -eq $null) {
        return $true
    }
    Get-Service $ServiceName | Set-Service -StartupType Disabled 
}

function Enable-Service {
     param(
        [Parameter(Mandatory=$true)]
        [string]$ServiceName
    )

    Get-Service $ServiceName | Set-Service -StartupType Automatic
}

function Check-OVSPrerequisites {
    $services = Charm-Services
    try {
        $ovsdbSvc = Get-Service "ovsdb-server"
        $ovsSwitchSvc = Get-Service "ovs-vswitchd"
    } catch {
        $InstallerPath = Get-OVSInstaller
        Install-OVS $InstallerPath
    }
    if(!(Test-Path $ovs_vsctl)){
        Juju-Error "Could not find ovs_vsctl.exe in location: $ovs_vsctl"
    }

    try {
        $ovsAgent = Get-Service $services["neutron-ovs"]["service"] 
    } catch {
        $name = $services["neutron-ovs"].service
        $svcPath = $services["neutron-ovs"].serviceBinPath
        Create-Service -Name $name -Path $svcPath -Description "Neutron Open vSwitch Agent"
        Disable-Service $name
    }
}

function Get-OVSExtStatus {
    $br = Juju-GetVMSwitch
	Juju-Log "Switch name is $br"
    $ext = Get-VMSwitchExtension -VMSwitchName $br -Name $ovsExtName

    if ($ext -eq $null){
        Juju-Log "Open vSwitch extension not installe"
        return $null
    }

    return $ext
}

function Enable-OVSExtension {
    $ext = Get-OVSExtStatus
    if ($ext -eq $null){
       Juju-Error "Cannot enable OVS extension. Not installed"
    }
    if ($ext.Enabled -eq $false) {
        Enable-VMSwitchExtension $ovsExtName $ext.SwitchName
    }
    return $true
}

function Disable-OVSExtension {
    $ext = Get-OVSExtStatus
    if ($ext -ne $null -and $ext.Enabled -eq $true) {
        Disable-VMSwitchExtension $ovsExtName $ext.SwitchName
    }
    return $true
}

function Disable-OVS {
    Stop-Service "ovs-vswitchd" -ErrorAction SilentlyContinue
    Stop-Service "ovsdb-server" -ErrorAction SilentlyContinue

    Disable-Service "ovs-vswitchd"
    Disable-Service "ovsdb-server"

    Disable-OVSExtension
}

function Enable-OVS {
    Enable-OVSExtension

    Enable-Service "ovsdb-server"
    Enable-Service "ovs-vswitchd"

    Start-Service "ovsdb-server"
    Start-Service "ovs-vswitchd"
}

function Configure-NeutronAgent {
    $services = Charm-Services
    $vmswitch = Juju-GetVMSwitch
    $net_type = charm_config -scope "network-type"
    if ($net_type -eq $null){
        Juju-Error "Could not get network type"
    }
    if ($net_type -eq "hyperv"){
        Disable-Service $services["neutron-ovs"]["service"]
        Stop-Service $services["neutron-ovs"]["service"] -ErrorAction SilentlyContinue

        Disable-OVS

        Enable-Service $services["neutron"]["service"]

        return $services["neutron"]
    }

    Check-OVSPrerequisites

    Disable-Service $services["neutron"]["service"]
    Stop-Service $services["neutron"]["service"]

    Enable-OVS
    Enable-Service $services["neutron-ovs"]["service"]

	$x = $services["neutron-ovs"]
    return $services["neutron-ovs"]
}

function Restart-Neutron {
    $svc = Configure-NeutronAgent
    Stop-Service $svc.service
    Start-Service $svc.service
}

function Restart-Nova {
    $services = Charm-Services
    Stop-Service $services.nova.service
    Start-Service $services.nova.service
}

function Stop-Neutron {
    $svc = Configure-NeutronAgent
    Stop-Service $svc.service
}

function Install-FromLocalCache {
    $shouldUseUglyHack = charm_config -scope "install-local-packages"

    if ($shouldUseUglyHack){
        Install-LocalPythonPackage "nova"
        Install-LocalPythonPackage "neutron"
    }
}

function Import-CloudbaseCert {
    $filesDir = Get-FilesDir
    $crt = Join-Path $filesDir "Cloudbase_signing.cer" 
    if (!(Test-Path $crt)){
        return $false
    }
    Import-Certificate $crt -StoreLocation LocalMachine -StoreName TrustedPublisher
}

Export-ModuleMember -Function * -Variable JujuCharmServices
