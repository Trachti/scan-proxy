[CmdletBinding()]
param(
    [ValidateSet('Resolve','ResolveBatch','OpenSnapshot','Setup','Status')][string]$Mode='Resolve',
    [string]$FilePath,
    [string]$RelativePath,
    [string]$UserName='',
    [int]$LookbackMinutes=10,
    [string]$ReferenceTimeUtc,
    [int]$AmbiguitySeconds=8,
    [int]$SessionFallbackMaxAgeSeconds=30,
    [string]$IgnoredNetworks=''
)

$Version = '2.13.0'
# Maintainer: Trachti. Deployment-specific accounts and network ranges are not bundled.

$ErrorActionPreference='Stop'
$DetailedFileShareGuid='{0CCE9244-69AE-11D9-BED3-505054503030}'
$IgnoredNetworkList=@(
    $IgnoredNetworks -split '[,;]' |
        ForEach-Object {$_.Trim()} |
        Where-Object {$_}
)

function Normalize-UserName($value) {
    if ([string]::IsNullOrWhiteSpace($value)) { return '' }
    return (($value.Trim() -split '\\')[-1] -split '@')[0].ToLowerInvariant()
}

function Test-SameUser($actualUserName, $expectedUserName) {
    if ([string]::IsNullOrWhiteSpace($expectedUserName)) { return $false }
    return (Normalize-UserName $actualUserName) -eq (Normalize-UserName $expectedUserName)
}

function Normalize-RelativePath($value) {
    if ([string]::IsNullOrWhiteSpace($value)) { return '' }
    return $value.Trim().Replace('/', '\').Trim('\').ToLowerInvariant()
}

function Normalize-FullPath($value) {
    if ([string]::IsNullOrWhiteSpace($value)) { return '' }
    $normalizedPath = $value.Trim().Replace('/', '\')
    if ($normalizedPath.StartsWith('\??\')) {
        $normalizedPath = $normalizedPath.Substring(4)
    } elseif ($normalizedPath.StartsWith('\\?\')) {
        $normalizedPath = $normalizedPath.Substring(4)
    }
    return $normalizedPath.TrimEnd('\').ToLowerInvariant()
}

function Get-RelativePathFromUnc($value) {
    if ([string]::IsNullOrWhiteSpace($value)) { return '' }
    $normalizedPath = $value.Trim().Replace('/', '\')
    if ($normalizedPath -match '^\\\\[^\\]+\\[^\\]+\\(.+)$') {
        return Normalize-RelativePath $Matches[1]
    }
    return ''
}

function Normalize-ClientIp($value) {
    if ([string]::IsNullOrWhiteSpace($value)) { return '' }
    $candidate = $value.Trim().Trim('[', ']')
    if ($candidate.StartsWith('::ffff:')) { $candidate = $candidate.Substring(7) }
    $parsedAddress = $null
    if (-not [Net.IPAddress]::TryParse(($candidate -split '%')[0], [ref]$parsedAddress)) {
        return ''
    }
    if ($parsedAddress.IsIPv4MappedToIPv6) { $parsedAddress = $parsedAddress.MapToIPv4() }
    $normalizedIp = $parsedAddress.ToString()
    if ($normalizedIp -in @('127.0.0.1', '::1', '0.0.0.0', '::')) { return '' }
    return $normalizedIp
}

# Compare IPv4 and IPv6 CIDRs without assuming a particular server network.
function Test-InCidr($address, $cidr) {
    try {
        $parts = $cidr -split '/', 2
        if ($parts.Count -ne 2) { return $false }
        $clientAddress = [Net.IPAddress]::Parse($address)
        $networkAddress = [Net.IPAddress]::Parse($parts[0])
        if ($clientAddress.IsIPv4MappedToIPv6) { $clientAddress = $clientAddress.MapToIPv4() }
        if ($networkAddress.IsIPv4MappedToIPv6) { $networkAddress = $networkAddress.MapToIPv4() }
        if ($clientAddress.AddressFamily -ne $networkAddress.AddressFamily) { return $false }
        $clientBytes = $clientAddress.GetAddressBytes()
        $networkBytes = $networkAddress.GetAddressBytes()
        $prefix = 0
        if (-not [int]::TryParse($parts[1], [ref]$prefix)) { return $false }
        if ($prefix -lt 0 -or $prefix -gt $clientBytes.Length * 8) { return $false }
        $fullBytes = [int][Math]::Floor($prefix / 8)
        for ($index = 0; $index -lt $fullBytes; $index++) {
            if ($clientBytes[$index] -ne $networkBytes[$index]) { return $false }
        }
        $remainingBits = $prefix % 8
        if ($remainingBits -gt 0) {
            $mask = [int](256 - [Math]::Pow(2, 8 - $remainingBits))
            if (($clientBytes[$fullBytes] -band $mask) -ne ($networkBytes[$fullBytes] -band $mask)) {
                return $false
            }
        }
        return $true
    } catch {
        return $false
    }
}
function Get-ScannerClientIp($value) {
    $clientIp = Normalize-ClientIp $value
    if (-not $clientIp) { return '' }
    foreach ($ignoredNetwork in $IgnoredNetworkList) {
        if (Test-InCidr $clientIp $ignoredNetwork) { return '' }
    }
    return $clientIp
}

function Convert-EventData($record) {
    $eventXml = [xml]$record.ToXml()
    $values = @{}
    foreach ($element in $eventXml.Event.EventData.Data) {
        $values[[string]$element.Name] = [string]$element.'#text'
    }
    return $values
}

function New-ResolutionResult($clientIp, $source, $reason, $recordId=0, $isOpen=$false, $confidence='None', $id=$null) {
    $result = [ordered]@{
        Client = $clientIp
        Source = $source
        Reason = $reason
        RecordId = [long]$recordId
        Open = [bool]$isOpen
        Confidence = $confidence
    }
    if ($null -ne $id) { $result.Id = [string]$id }
    return [pscustomobject]$result
}

function Write-ResolutionResult($clientIp, $source, $reason, $recordId=0, $isOpen=$false, $confidence='None') {
    New-ResolutionResult $clientIp $source $reason $recordId $isOpen $confidence | ConvertTo-Json -Compress
}

function Test-WriteAccess($accessMask) {
    try {
        if ($accessMask.StartsWith('0x')) {
            $value = [Convert]::ToUInt32($accessMask.Substring(2), 16)
        } else {
            $value = [Convert]::ToUInt32($accessMask, 10)
        }
        return ($value -band [uint32]0x400D0156) -ne 0
    } catch {
        return $false
    }
}

# Enable detailed file share auditing (requires elevation).
if($Mode -eq 'Setup'){
    & auditpol.exe /set /subcategory:$DetailedFileShareGuid /success:enable | Out-Host
    if($LASTEXITCODE){exit $LASTEXITCODE}
    & auditpol.exe /get /subcategory:$DetailedFileShareGuid
    exit 0
}


if ([string]::IsNullOrWhiteSpace($UserName)) {
    if ($Mode -eq 'Status') {
        Write-Host 'SMB attribution is disabled: configure -UserName explicitly.'
    } elseif ($Mode -eq 'ResolveBatch') {
        ConvertTo-Json -InputObject @() -Compress
    } elseif ($Mode -eq 'OpenSnapshot') {
        ConvertTo-Json -InputObject @() -Compress
    } else {
        Write-ResolutionResult '' 'None' 'SMB attribution requires a configured user account'
    }
    exit 0
}

if($Mode -eq 'Status'){
    Write-Host "scan-proxy-smb $Version"
    Write-Host "Lookback=$LookbackMinutes min | SessionFallbackMaxAge=$SessionFallbackMaxAgeSeconds s | Ignored networks=$($IgnoredNetworkList -join ',')"
    & auditpol.exe /get /subcategory:$DetailedFileShareGuid
    Write-Host "`nCurrently open SMB files:"
    Get-SmbOpenFile -ErrorAction SilentlyContinue |
        Where-Object {Test-SameUser $_.ClientUserName $UserName} |
        Where-Object {Get-ScannerClientIp $_.ClientComputerName} |
        Select-Object Path,ShareRelativePath,ClientComputerName,ClientUserName |
        Format-Table -AutoSize

    Write-Host "`nCurrent SMB sessions:"
    Get-SmbSession -ErrorAction SilentlyContinue |
        Where-Object {Test-SameUser $_.ClientUserName $UserName} |
        Where-Object {Get-ScannerClientIp $_.ClientComputerName} |
        Select-Object ClientComputerName,ClientUserName,NumOpens |
        Format-Table -AutoSize

    Write-Host "`nRecent event 5145 matches for user ${UserName}:"
    try{
        $statusStart=(Get-Date).AddMinutes(-[Math]::Abs($LookbackMinutes))
        $statusEvents=@(
            Get-WinEvent -FilterHashtable @{LogName='Security';Id=5145;StartTime=$statusStart} -ErrorAction Stop |
                ForEach-Object {
                    $d=Convert-EventData $_
                    if(Test-SameUser $d.SubjectUserName $UserName){
                        [pscustomobject]@{
                            TimeCreated=$_.TimeCreated
                            Client=(Get-ScannerClientIp $d.IpAddress)
                            RelativeTargetName=$d.RelativeTargetName
                            AccessMask=$d.AccessMask
                            RecordId=$_.RecordId
                        }
                    }
                } |
                Where-Object {$_.Client}
        )
        Write-Host "5145 events in lookback window: $($statusEvents.Count)"
        $statusEvents |
            Sort-Object TimeCreated -Descending |
            Select-Object -First 15 |
            Format-Table -AutoSize
    }catch{
        Write-Warning "Could not read Windows Security event 5145: $($_.Exception.Message)"
    }
    exit 0
}

# Return a single, low-cost snapshot of open SMB files.
if($Mode -eq 'OpenSnapshot'){
    $rows=@(
        Get-SmbOpenFile -ErrorAction SilentlyContinue |
            Where-Object {Test-SameUser $_.ClientUserName $UserName} |
            ForEach-Object {
                $c=Get-ScannerClientIp $_.ClientComputerName
                if($c){
                    [pscustomobject]@{
                        Client=$c
                        Path=(Normalize-FullPath $_.Path)
                        RelativePath=(Normalize-RelativePath $_.ShareRelativePath)
                    }
                }
            }
    )
    ConvertTo-Json -InputObject $rows -Compress -Depth 3
    exit 0
}

# Resolve historical pending entries in one PowerShell process.
if($Mode -eq 'ResolveBatch'){
    try{
        $raw=[Console]::In.ReadToEnd()
        if([string]::IsNullOrWhiteSpace($raw)){
            ConvertTo-Json -InputObject @() -Compress
            exit 0
        }
        $inputItems=@($raw | ConvertFrom-Json -ErrorAction Stop)
    }catch{
        Write-Error "ResolveBatch: invalid JSON: $($_.Exception.Message)"
        exit 2
    }

    $items=@(
        foreach($item in $inputItems){
            $id=[string]$item.Id
            if([string]::IsNullOrWhiteSpace($id)){continue}
            $fp=[string]$item.FilePath
            $rel=Get-RelativePathFromUnc $fp
            if(!$rel){$rel=Normalize-RelativePath ([string]$item.RelativePath)}
            $ref=[DateTime]::UtcNow
            try{
                if($item.ReferenceTimeUtc){
                    $ref=[DateTime]::Parse([string]$item.ReferenceTimeUtc).ToUniversalTime()
                }
            }catch{}
            [pscustomobject]@{
                Id=$id
                File=(Normalize-FullPath $fp)
                Relative=$rel
                Ref=$ref
                Bucket=[long][Math]::Floor(
                    $ref.Ticks / [double]([TimeSpan]::TicksPerMinute * 15)
                )
            }
        }
    )

    $results=@{}

    $openRows=@()
    try{
        $openRows=@(
            Get-SmbOpenFile -ErrorAction Stop |
                Where-Object {Test-SameUser $_.ClientUserName $UserName} |
                ForEach-Object {
                    $c=Get-ScannerClientIp $_.ClientComputerName
                    if($c){
                        [pscustomobject]@{
                            Client=$c
                            File=(Normalize-FullPath $_.Path)
                            Relative=(Normalize-RelativePath $_.ShareRelativePath)
                        }
                    }
                }
        )
    }catch{}

    $unresolved=@()
    foreach($item in $items){
        $hits=@(
            foreach($open in $openRows){
                $strength=if($open.File -and $open.File -eq $item.File){
                    3
                }elseif($item.Relative -and $open.Relative -eq $item.Relative){
                    2
                }else{0}
                if($strength){
                    [pscustomobject]@{Client=$open.Client;Strength=$strength}
                }
            }
        )
        if($hits.Count){
            $max=($hits | Measure-Object Strength -Maximum).Maximum
            $clients=@(
                $hits | Where-Object Strength -eq $max |
                    Select-Object -ExpandProperty Client -Unique
            )
            if($clients.Count -eq 1){
                $results[[string]$item.Id]=New-ResolutionResult $clients[0] 'Get-SmbOpenFile' 'Batch: exact currently open SMB file' 0 $true 'ExactOpenFile' $item.Id
                continue
            }
            if($clients.Count -gt 1){
                $results[[string]$item.Id]=New-ResolutionResult '' 'None' 'Batch: ambiguous open SMB file' 0 $false 'Ambiguous' $item.Id
                continue
            }
        }
        $unresolved += $item
    }

    foreach($group in @($unresolved | Group-Object Bucket)){
        $members=@($group.Group)
        if(!$members.Count){continue}
        $ordered=@($members | Sort-Object Ref)
        $start=$ordered[0].Ref.AddMinutes(-[Math]::Abs($LookbackMinutes)).ToLocalTime()
        $end=$ordered[-1].Ref.AddSeconds(2).ToLocalTime()
        $eventRows=@()
        try{
            $eventRows=@(
                Get-WinEvent -FilterHashtable @{
                    LogName='Security'
                    Id=5145
                    StartTime=$start
                    EndTime=$end
                } -ErrorAction Stop |
                    ForEach-Object {
                        $event=$_
                        $d=Convert-EventData $event
                        if(Test-SameUser $d.SubjectUserName $UserName){
                            $c=Get-ScannerClientIp $d.IpAddress
                            if($c){
                                $local=''
                                try{
                                    $local=Normalize-FullPath ([IO.Path]::Combine(
                                        (Normalize-FullPath $d.ShareLocalPath),
                                        ([string]$d.RelativeTargetName).TrimStart('\')
                                    ))
                                }catch{}
                                [pscustomobject]@{
                                    Client=$c
                                    File=$local
                                    Relative=(Normalize-RelativePath $d.RelativeTargetName)
                                    Time=$event.TimeCreated.ToUniversalTime()
                                    Record=$event.RecordId
                                    Write=(Test-WriteAccess $d.AccessMask)
                                }
                            }
                        }
                    }
            )
        }catch{
            $eventRows=@()
        }

        foreach($item in $members){
            $lower=$item.Ref.AddMinutes(-[Math]::Abs($LookbackMinutes))
            $upper=$item.Ref.AddSeconds(2)
            $matches=@(
                foreach($event in $eventRows){
                    if($event.Time -lt $lower -or $event.Time -gt $upper){continue}
                    $strength=if($event.File -and $event.File -eq $item.File){
                        3
                    }elseif($item.Relative -and $event.Relative -eq $item.Relative){
                        2
                    }else{0}
                    if($strength){
                        [pscustomobject]@{
                            Client=$event.Client
                            Strength=$strength
                            Time=$event.Time
                            Record=$event.Record
                            Write=$event.Write
                        }
                    }
                }
            )
            if($matches.Count){
                $max=($matches | Measure-Object Strength -Maximum).Maximum
                $strong=@($matches | Where-Object Strength -eq $max | Sort-Object Time -Descending)
                $newest=$strong[0].Time
                $recent=@(
                    $strong | Where-Object {
                        ($newest-$_.Time).TotalSeconds -le [Math]::Max(1,$AmbiguitySeconds)
                    }
                )
                $clients=@($recent | Select-Object -ExpandProperty Client -Unique)
                $writes=@($recent | Where-Object Write | Select-Object -ExpandProperty Client -Unique)
                if($clients.Count -eq 1){
                    $best=$recent | Where-Object Client -eq $clients[0] |
                        Sort-Object Write,Time -Descending | Select-Object -First 1
                    $results[[string]$item.Id]=New-ResolutionResult $best.Client 'Security-5145' 'Batch: unambiguous file event 5145' $best.Record $false 'ExactPathRecent' $item.Id
                    continue
                }
                if($writes.Count -eq 1){
                    $best=$recent | Where-Object {$_.Client -eq $writes[0] -and $_.Write} |
                        Sort-Object Time -Descending | Select-Object -First 1
                    $results[[string]$item.Id]=New-ResolutionResult $best.Client 'Security-5145' 'Batch: one unambiguous writing client' $best.Record $false 'ExactPathWrite' $item.Id
                    continue
                }
                $results[[string]$item.Id]=New-ResolutionResult '' 'None' 'Batch: ambiguous file events 5145' 0 $false 'Ambiguous' $item.Id
            }else{
                $results[[string]$item.Id]=New-ResolutionResult '' 'None' 'Batch: no matching file event 5145' 0 $false 'None' $item.Id
            }
        }
    }

    $orderedResults=@(
        foreach($item in $items){
            $key=[string]$item.Id
            if($results.ContainsKey($key)){
                $results[$key]
            }else{
                New-ResolutionResult '' 'None' 'Batch: no unambiguous SMB client IP' 0 $false 'None' $item.Id
            }
        }
    )
    ConvertTo-Json -InputObject $orderedResults -Compress -Depth 4
    exit 0
}

if(!$FilePath){
    Write-ResolutionResult '' 'None' 'FilePath is required'
    exit 0
}

$file=Normalize-FullPath $FilePath
$relative=Get-RelativePathFromUnc $FilePath
if(!$relative){$relative=Normalize-RelativePath $RelativePath}

try{
    $hits=@(
        Get-SmbOpenFile -ErrorAction Stop |
            Where-Object {Test-SameUser $_.ClientUserName $UserName} |
            ForEach-Object {
                $c=Get-ScannerClientIp $_.ClientComputerName
                $strength=if((Normalize-FullPath $_.Path)-eq $file){
                    3
                }elseif($relative -and (Normalize-RelativePath $_.ShareRelativePath)-eq $relative){
                    2
                }else{
                    0
                }
                if($c -and $strength){
                    [pscustomobject]@{Client=$c;Strength=$strength}
                }
            }
    )
    if($hits.Count){
        $max=($hits | Measure-Object Strength -Maximum).Maximum
        $clients=@(
            $hits |
                Where-Object Strength -eq $max |
                Select-Object -Expand Client -Unique
        )
        if($clients.Count -eq 1){
            Write-ResolutionResult $clients[0] 'Get-SmbOpenFile' 'Exact currently open SMB file' 0 $true 'ExactOpenFile'
            exit 0
        }
        if($clients.Count -gt 1){
            Write-ResolutionResult '' 'None' 'Ambiguous open SMB file' 0 $false 'Ambiguous'
            exit 0
        }
    }
}catch{}

try{
    $ref=if($ReferenceTimeUtc){
        [DateTime]::Parse($ReferenceTimeUtc).ToUniversalTime()
    }else{
        (Get-Date).ToUniversalTime()
    }
}catch{
    $ref=(Get-Date).ToUniversalTime()
}
$referenceAgeSeconds=[Math]::Abs(((Get-Date).ToUniversalTime()-$ref).TotalSeconds)
try{
    $start=$ref.AddMinutes(-[Math]::Abs($LookbackMinutes)).ToLocalTime()
    $end=$ref.AddSeconds(2).ToLocalTime()
    $events=Get-WinEvent -FilterHashtable @{
        LogName='Security'
        Id=5145
        StartTime=$start
        EndTime=$end
    } -ErrorAction Stop
    $matches=@(
        foreach($e in $events){
            $d=Convert-EventData $e
            if(!(Test-SameUser $d.SubjectUserName $UserName)){continue}
            $c=Get-ScannerClientIp $d.IpAddress
            if(!$c){continue}
            $local=''
            try{
                $local=Normalize-FullPath ([IO.Path]::Combine(
                    (Normalize-FullPath $d.ShareLocalPath),
                    ([string]$d.RelativeTargetName).TrimStart('\')
                ))
            }catch{}
            $strength=if($local -and $local -eq $file){
                3
            }elseif($relative -and (Normalize-RelativePath $d.RelativeTargetName)-eq $relative){
                2
            }else{
                0
            }
            if($strength){
                [pscustomobject]@{
                    Client=$c
                    Strength=$strength
                    Time=$e.TimeCreated.ToUniversalTime()
                    Record=$e.RecordId
                    Write=(Test-WriteAccess $d.AccessMask)
                }
            }
        }
    )
    if($matches.Count){
        $max=($matches | Measure-Object Strength -Maximum).Maximum
        $strong=@($matches | Where-Object Strength -eq $max | Sort-Object Time -Descending)
        $newest=$strong[0].Time
        $recent=@(
            $strong |
                Where-Object {($newest-$_.Time).TotalSeconds -le [Math]::Max(1,$AmbiguitySeconds)}
        )
        $clients=@($recent | Select-Object -Expand Client -Unique)
        $writes=@($recent | Where-Object Write | Select-Object -Expand Client -Unique)
        if($clients.Count -eq 1){
            $best=$recent |
                Where-Object Client -eq $clients[0] |
                Sort-Object Write,Time -Descending |
                Select-Object -First 1
            Write-ResolutionResult $best.Client 'Security-5145' 'Unambiguous file event 5145' $best.Record $false 'ExactPathRecent'
            exit 0
        }
        if($writes.Count -eq 1){
            $best=$recent |
                Where-Object {$_.Client -eq $writes[0] -and $_.Write} |
                Sort-Object Time -Descending |
                Select-Object -First 1
            Write-ResolutionResult $best.Client 'Security-5145' 'One writing client in the selected time window' $best.Record $false 'ExactPathWrite'
            exit 0
        }
        Write-ResolutionResult '' 'None' 'Ambiguous file events 5145' 0 $false 'Ambiguous'
        exit 0
    }
}catch{}

if($referenceAgeSeconds -le [Math]::Max(0,$SessionFallbackMaxAgeSeconds)){
    try{
        $clients=@(
            Get-SmbSession -ErrorAction Stop |
                Where-Object {Test-SameUser $_.ClientUserName $UserName} |
                ForEach-Object {Get-ScannerClientIp $_.ClientComputerName} |
                Where-Object {$_} |
                Sort-Object -Unique
        )
        if($clients.Count -eq 1){
            Write-ResolutionResult $clients[0] 'Get-SmbSession' 'One recent SMB session for the configured user' 0 $false 'UniqueSessionRecent'
            exit 0
        }
        if($clients.Count -gt 1){
            Write-ResolutionResult '' 'None' 'Multiple SMB sessions; attribution is ambiguous' 0 $false 'Ambiguous'
            exit 0
        }
    }catch{}
}

Write-ResolutionResult '' 'None' "No unambiguous SMB client IP; ignored networks: $($IgnoredNetworkList -join ',')"
exit 0
