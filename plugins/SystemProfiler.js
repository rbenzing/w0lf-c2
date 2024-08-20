// Register a plugin
module.exports = {
    name: 'SytemProfiler',
    type: 'client',
    description: 'A client plugin to profile the system.',
    commands: {
        whoami: {
            name: 'whoami',
            method: 'payload-ps',
            description: `Returns the current logged in user information of the client.`,
            handler: (props) => {
                return Buffer.from(`@{Username=$env:USERNAME; HomeDir=$env:USERPROFILE; FullName=(Get-WmiObject -Class Win32_ComputerSystem).UserName; SID=(New-Object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())).Identity.User.Value; Domain=$env:USERDOMAIN; IsAdmin=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)} | Format-Table -AutoSize`).toString('base64');
            }
        },
        sysinfo: {
            name: 'sysinfo',
            method: 'payload-ps',
            description: `Returns a list of system details of the client.`,
            handler: (props) => {
                return Buffer.from(`Get-ComputerInfo`).toString('base64');
            }
        },
        dnsinfo: {
            name: 'dnsinfo',
            method: 'payload-ps',
            description: `Returns the dns info of all inferfaces on the client.`,
            handler: (props) => {
                return Buffer.from(`Get-DnsClientServerAddress`).toString('base64');
            }
        },
        routeinfo: {
            name: 'routeinfo',
            method: 'payload-ps',
            description: `Returns the routes info of the client.`,
            handler: (props) => {
                return Buffer.from(`Get-NetRoute | Select-Object DestinationPrefix, NextHop, RouteMetric, InterfaceAlias, AddressFamily, State | ConvertTo-Json`).toString('base64');
            }
        },
        checkps: {
            name: 'checkps',
            method: 'payload-ps',
            description: `Checks if powershell is enabled on the client.`,
            handler: (props) => {
                return Buffer.from(`Get-ChildItem -Path HKLM:\\Software\\Microsoft\\PowerShell`).toString('base64');
            }
        },
        network: {
            name: 'network',
            method: 'payload-ps',
            description: `Returns system network information of the client.`,
            handler: (props) => {
                return Buffer.from(`Get-NetAdapter | ForEach-Object { $adapter = $_; (Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -ErrorAction SilentlyContinue) | ForEach-Object { [PSCustomObject]@{ Interface=$adapter.Name; IPAddress=$_.IPAddress; AddressFamily=$_.AddressFamily; PrefixLength=$_.PrefixLength; MacAddress=$adapter.MacAddress; LinkSpeed=$adapter.LinkSpeed; Status=$adapter.Status }}} | ConvertTo-Json`).toString('base64');
            }
        },
        drives: {
            name: 'drives',
            method: 'payload-ps',
            description: `Get the list of drives mounted on the client.`,
            handler: (props) => {
                return Buffer.from(`Get-PSDrive -PSProvider FileSystem | Select-Object Name, @{Name='Path'; Expression={$_.Root}}`).toString('base64');
            }
        },
    }
};