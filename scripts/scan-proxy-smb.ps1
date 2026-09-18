[CmdletBinding()]
param(
    [ValidateSet('Resolve', 'Setup', 'Status')]
    [string]$Mode = 'Resolve',

    [string]$FilePath,
    [string]$RelativePath,
    [string]$UserName = 'scanner-service',
    [int]$LookbackMinutes = 10,
    [string]$ReferenceTimeUtc,
    [int]$AmbiguitySeconds = 8,
    [string]$IgnoredNetworks = ''
)

$Version = '2.11.0-english-repository'
$ErrorActionPreference = 'Stop'
$DetailedFileShareGuid = '{0CCE9244-69AE-11D9-BED3-505054503030}'
$IgnoredNetworkList = @(
    $IgnoredNetworks -split '[,;]' |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_ }
)

function Normalize-UserName {
    param([string]$Value)

    if (-not $Value) {
        return ''
    }

    return (($Value.Trim() -split '\\')[-1] -split '@')[0].ToLowerInvariant()
}

function Test-SameUser {
    param(
        [string]$Actual,
        [string]$Expected
    )

    return (-not $Expected) -or ((Normalize-UserName $Actual) -eq (Normalize-UserName $Expected))
}

function Normalize-RelativePath {
    param([string]$Value)

    if (-not $Value) {
        return ''
    }

    return $Value.Trim().Replace('/', '\').Trim('\').ToLowerInvariant()
}

function Normalize-FilePath {
    param([string]$Value)

    if (-not $Value) {
        return ''
    }

    $Normalized = $Value.Trim().Replace('/', '\')
    if ($Normalized.StartsWith('\??\')) {
        $Normalized = $Normalized.Substring(4)
    }
    elseif ($Normalized.StartsWith('\\?\')) {
        $Normalized = $Normalized.Substring(4)
    }

    return $Normalized.TrimEnd('\').ToLowerInvariant()
}

function Normalize-ClientAddress {
    param([string]$Value)

    if (-not $Value) {
        return ''
    }

    $Text = $Value.Trim().Trim('[', ']')
    if ($Text.StartsWith('::ffff:')) {
        $Text = $Text.Substring(7)
    }

    $Address = $null
    if (-not [Net.IPAddress]::TryParse(($Text -split '%')[0], [ref]$Address)) {
        return ''
    }

    if ($Address.IsIPv4MappedToIPv6) {
        $Address = $Address.MapToIPv4()
    }

    $Normalized = $Address.ToString()
    if ($Normalized -in @('127.0.0.1', '::1', '0.0.0.0', '::')) {
        return ''
    }

    return $Normalized
}

function Convert-IPv4ToNumber {
    param([string]$Value)

    try {
        $Address = [Net.IPAddress]::Parse($Value)
        if ($Address.IsIPv4MappedToIPv6) {
            $Address = $Address.MapToIPv4()
        }

        $Bytes = $Address.GetAddressBytes()
        if ($Bytes.Length -ne 4) {
            return $null
        }

        return (
            [uint64]$Bytes[0] * 16777216 +
            [uint64]$Bytes[1] * 65536 +
            [uint64]$Bytes[2] * 256 +
            [uint64]$Bytes[3]
        )
    }
    catch {
        return $null
    }
}

function Test-IpInCidr {
    param(
        [string]$IpAddress,
        [string]$Cidr
    )

    try {
        $Parts = $Cidr -split '/', 2
        if ($Parts.Count -ne 2) {
            return $false
        }

        $AddressNumber = Convert-IPv4ToNumber $IpAddress
        $NetworkNumber = Convert-IPv4ToNumber $Parts[0]
        if ($null -eq $AddressNumber -or $null -eq $NetworkNumber) {
            return $false
        }

        $Prefix = 0
        if (
            -not [int]::TryParse($Parts[1], [ref]$Prefix) -or
            $Prefix -lt 0 -or
            $Prefix -gt 32
        ) {
            return $false
        }

        $BlockSize = [uint64][Math]::Pow(2, 32 - $Prefix)
        return (
            [uint64][Math]::Floor($AddressNumber / $BlockSize) -eq
            [uint64][Math]::Floor($NetworkNumber / $BlockSize)
        )
    }
    catch {
        return $false
    }
}

function Get-ScannerClient {
    param([string]$Value)

    $Client = Normalize-ClientAddress $Value
    if (-not $Client) {
        return ''
    }

    foreach ($Cidr in $IgnoredNetworkList) {
        if (Test-IpInCidr $Client $Cidr) {
            return ''
        }
    }

    return $Client
}

function Convert-EventDataToMap {
    param($Event)

    $Xml = [xml]$Event.ToXml()
    $Map = @{}
    foreach ($Data in $Xml.Event.EventData.Data) {
        $Map[[string]$Data.Name] = [string]$Data.'#text'
    }
    return $Map
}

function Write-ResolutionResult {
    param(
        [string]$Client,
        [string]$Source,
        [string]$Reason,
        [long]$RecordId = 0,
        [bool]$Open = $false,
        [string]$Confidence = 'None'
    )

    [pscustomobject]@{
        Client = $Client
        Source = $Source
        Reason = $Reason
        RecordId = $RecordId
        Open = $Open
        Confidence = $Confidence
    } | ConvertTo-Json -Compress
}

function Test-WriteAccessMask {
    param([string]$Mask)

    try {
        $Value = if ($Mask.StartsWith('0x')) {
            [Convert]::ToUInt32($Mask.Substring(2), 16)
        }
        else {
            [Convert]::ToUInt32($Mask, 10)
        }

        return ($Value -band [uint32]0x400D0156) -ne 0
    }
    catch {
        return $false
    }
}

if ($Mode -eq 'Setup') {
    & auditpol.exe /set /subcategory:$DetailedFileShareGuid /success:enable | Out-Host
    if ($LASTEXITCODE) {
        exit $LASTEXITCODE
    }

    & auditpol.exe /get /subcategory:$DetailedFileShareGuid
    exit 0
}

if ($Mode -eq 'Status') {
    Write-Host "scan-proxy-smb $Version"
    Write-Host "Lookback=$LookbackMinutes min | Ignored networks=$($IgnoredNetworkList -join ',')"
    & auditpol.exe /get /subcategory:$DetailedFileShareGuid

    Get-SmbOpenFile -ErrorAction SilentlyContinue |
        Where-Object { Test-SameUser $_.ClientUserName $UserName } |
        Where-Object { Get-ScannerClient $_.ClientComputerName } |
        Select-Object Path, ShareRelativePath, ClientComputerName, ClientUserName |
        Format-Table -AutoSize
    exit 0
}

if (-not $FilePath) {
    Write-ResolutionResult '' 'None' 'FilePath is missing'
    exit 0
}

$NormalizedFilePath = Normalize-FilePath $FilePath
$NormalizedRelativePath = Normalize-RelativePath $RelativePath

try {
    $OpenFileMatches = @(
        Get-SmbOpenFile -ErrorAction Stop |
            Where-Object { Test-SameUser $_.ClientUserName $UserName } |
            ForEach-Object {
                $Client = Get-ScannerClient $_.ClientComputerName
                $Strength = if ((Normalize-FilePath $_.Path) -eq $NormalizedFilePath) {
                    3
                }
                elseif (
                    $NormalizedRelativePath -and
                    (Normalize-RelativePath $_.ShareRelativePath) -eq $NormalizedRelativePath
                ) {
                    2
                }
                else {
                    0
                }

                if ($Client -and $Strength) {
                    [pscustomobject]@{
                        Client = $Client
                        Strength = $Strength
                    }
                }
            }
    )

    if ($OpenFileMatches.Count) {
        $MaximumStrength = ($OpenFileMatches | Measure-Object Strength -Maximum).Maximum
        $Clients = @(
            $OpenFileMatches |
                Where-Object Strength -eq $MaximumStrength |
                Select-Object -ExpandProperty Client -Unique
        )

        if ($Clients.Count -eq 1) {
            Write-ResolutionResult $Clients[0] 'Get-SmbOpenFile' 'Exact currently open SMB file' 0 $true 'ExactOpenFile'
            exit 0
        }
        if ($Clients.Count -gt 1) {
            Write-ResolutionResult '' 'None' 'Ambiguous open SMB file' 0 $false 'Ambiguous'
            exit 0
        }
    }
}
catch {
}

try {
    $ReferenceTime = if ($ReferenceTimeUtc) {
        [DateTime]::Parse($ReferenceTimeUtc).ToUniversalTime()
    }
    else {
        (Get-Date).ToUniversalTime()
    }
}
catch {
    $ReferenceTime = (Get-Date).ToUniversalTime()
}

try {
    $StartTime = $ReferenceTime.AddMinutes(-[Math]::Abs($LookbackMinutes)).ToLocalTime()
    $EndTime = $ReferenceTime.AddSeconds(2).ToLocalTime()
    $Events = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        Id = 5145
        StartTime = $StartTime
        EndTime = $EndTime
    } -ErrorAction Stop

    $Matches = @(
        foreach ($Event in $Events) {
            $Data = Convert-EventDataToMap $Event
            if (-not (Test-SameUser $Data.SubjectUserName $UserName)) {
                continue
            }

            $Client = Get-ScannerClient $Data.IpAddress
            if (-not $Client) {
                continue
            }

            $LocalPath = ''
            try {
                $LocalPath = Normalize-FilePath (
                    [IO.Path]::Combine(
                        (Normalize-FilePath $Data.ShareLocalPath),
                        ([string]$Data.RelativeTargetName).TrimStart('\')
                    )
                )
            }
            catch {
            }

            $Strength = if ($LocalPath -and $LocalPath -eq $NormalizedFilePath) {
                3
            }
            elseif (
                $NormalizedRelativePath -and
                (Normalize-RelativePath $Data.RelativeTargetName) -eq $NormalizedRelativePath
            ) {
                2
            }
            else {
                0
            }

            if ($Strength) {
                [pscustomobject]@{
                    Client = $Client
                    Strength = $Strength
                    Time = $Event.TimeCreated.ToUniversalTime()
                    Record = $Event.RecordId
                    Write = Test-WriteAccessMask $Data.AccessMask
                }
            }
        }
    )

    if ($Matches.Count) {
        $MaximumStrength = ($Matches | Measure-Object Strength -Maximum).Maximum
        $StrongMatches = @(
            $Matches |
                Where-Object Strength -eq $MaximumStrength |
                Sort-Object Time -Descending
        )
        $NewestTime = $StrongMatches[0].Time
        $RecentMatches = @(
            $StrongMatches |
                Where-Object {
                    ($NewestTime - $_.Time).TotalSeconds -le [Math]::Max(1, $AmbiguitySeconds)
                }
        )

        $Clients = @($RecentMatches | Select-Object -ExpandProperty Client -Unique)
        $WritingClients = @(
            $RecentMatches |
                Where-Object Write |
                Select-Object -ExpandProperty Client -Unique
        )

        if ($Clients.Count -eq 1) {
            $BestMatch = $RecentMatches |
                Where-Object Client -eq $Clients[0] |
                Sort-Object Write, Time -Descending |
                Select-Object -First 1

            Write-ResolutionResult $BestMatch.Client 'Security-5145' 'Unique file event 5145' $BestMatch.Record $false 'ExactPathRecent'
            exit 0
        }

        if ($WritingClients.Count -eq 1) {
            $BestMatch = $RecentMatches |
                Where-Object { $_.Client -eq $WritingClients[0] -and $_.Write } |
                Sort-Object Time -Descending |
                Select-Object -First 1

            Write-ResolutionResult $BestMatch.Client 'Security-5145' 'Exactly one writing client in the time window' $BestMatch.Record $false 'ExactPathWrite'
            exit 0
        }

        Write-ResolutionResult '' 'None' 'Ambiguous 5145 file events' 0 $false 'Ambiguous'
        exit 0
    }
}
catch {
}

try {
    $Clients = @(
        Get-SmbSession -ErrorAction Stop |
            Where-Object { Test-SameUser $_.ClientUserName $UserName } |
            ForEach-Object { Get-ScannerClient $_.ClientComputerName } |
            Where-Object { $_ } |
            Sort-Object -Unique
    )

    if ($Clients.Count -eq 1) {
        Write-ResolutionResult $Clients[0] 'Get-SmbSession' 'Exactly one SMB session for the configured user' 0 $false 'UniqueSession'
        exit 0
    }
    if ($Clients.Count -gt 1) {
        Write-ResolutionResult '' 'None' 'Multiple SMB sessions; no safe attribution' 0 $false 'Ambiguous'
        exit 0
    }
}
catch {
}

Write-ResolutionResult '' 'None' "No unambiguous SMB IP attribution; ignored networks: $($IgnoredNetworkList -join ',')"
exit 0
