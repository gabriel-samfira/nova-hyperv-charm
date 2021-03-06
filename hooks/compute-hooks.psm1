#
# Copyright 2014 Cloudbase Solutions SRL
#
$ErrorActionPreference = "Stop"

$name = Split-Path -Path $MyInvocation.MyCommand.Path -Parent
$fullPath = Join-Path $name "Modules\CharmHelpers"
Import-Module -Force -DisableNameChecking $fullPath


function Juju-GetVMSwitch {
    $VMswitchName = charm_config -scope "vmswitch-name"
    if (!$VMswitchName){
        return "br100"
    }
    return $VMswitchName
}


function Charm-Services {
    $template_dir = "$env:CHARM_DIR"
    $distro = charm_config -scope "openstack-origin"
    $nova_config = "C:\Program Files (x86)\Cloudbase Solutions\Openstack\Nova\etc\nova.conf"
    $neutron_config = "C:\Program Files (x86)\Cloudbase Solutions\Openstack\Nova\etc\neutron_hyperv_agent.conf"

    $JujuCharmServices = @{
        "nova"=@{
            "template"="$template_dir\templates\$distro\nova.conf";
            "service"="nova-compute";
            "config"="$nova_config";
            "context_generators"=@(
                "Get-RabbitMQContext",
                "Get-NeutronContext",
                "Get-GlanceContext",
                "Get-CharmConfigContext"
                );
        };
        "neutron"=@{
            "template"="$template_dir\templates\$distro\neutron_hyperv_agent.conf"
            "service"="neutron-hyperv-agent";
            "config"="$neutron_config";
            "context_generators"=@(
                "Get-RabbitMQContext",
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
    $nic = $null
    $DataInterfaceFromConfig = charm_config -scope "data-port"
    if ($DataInterfaceFromConfig -eq $false){
        return $null
    }
    foreach ($i in $DataInterfaceFromConfig.Split()){
        $nic = Get-NetAdapter -Physical | Where-Object { $_.MacAddress -match $i.Replace(':', '-') }
        if ($nic) {
            return $nic
        }
    }
    return $nic
}

function Juju-ConfigureVMSwitch {
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
        if (!$nic) {
            Juju-Log "Data port not found. Not configuring switch"
            return $true
        }
        New-VMSwitch -Name $VMswitchName -NetAdapterName $nic.Name -AllowManagementOS $false
        if ($? -eq $false){
            Juju-Error "Failed to create vmswitch"
        }
        return $true
    }
    return $true
}

Export-ModuleMember -Function * -Variable JujuCharmServices
