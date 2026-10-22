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

$Version = '2.13.1'
# Changes:
# 2026-09-18 | Trachti | Batched low-CPU OpenSnapshot and historical SMB resolution.
# 2026-09-18 | Trachti | Added cautious Event 5140 share-level fallback after Event 5145.
# 2026-10-22 | Trachti | Removed deployment-specific defaults and translated all messages.

$ErrorActionPreference='Stop'
if ($Mode -ne 'Setup' -and [string]::IsNullOrWhiteSpace($UserName)) {
    if ($Mode -eq 'OpenSnapshot' -or $Mode -eq 'ResolveBatch') {
        ConvertTo-Json -InputObject @() -Compress
        exit 0
    }
    Write-Error 'UserName is required. Set SCAN_PROXY_SMB_USER in your local environment.'
    exit 2
}
$DetailedFileShareGuid='{0CCE9244-69AE-11D9-BED3-505054503030}'
$FileShareGuid='{0CCE9224-69AE-11D9-BED3-505054503030}'
$IgnoredNetworkList=@(
    $IgnoredNetworks -split '[,;]' |
        ForEach-Object {$_.Trim()} |
        Where-Object {$_}
)

# Compare account names independently of DOMAIN\user or user@domain notation.
function User($v){
    if(!$v){return ''}
    (($v.Trim() -split '\\')[-1] -split '@')[0].ToLowerInvariant()
}
function SameUser($a,$b){ [bool]$b -and [bool]$a -and (User $a) -eq (User $b) }

# Normalize file and share-relative paths without modifying real filesystem paths.
function Rel($v){
    if(!$v){return ''}
    $v.Trim().Replace('/','\').Trim('\').ToLowerInvariant()
}
function PathNorm($v){
    if(!$v){return ''}
    $p=$v.Trim().Replace('/','\')
    if($p.StartsWith('\??\')){$p=$p.Substring(4)}
    elseif($p.StartsWith('\\?\')){$p=$p.Substring(4)}
    $p.TrimEnd('\').ToLowerInvariant()
}

function RelativeFromUnc($v){
    if(!$v){return ''}
    $p=$v.Trim().Replace('/','\')
    if($p -match '^\\\\[^\\]+\\[^\\]+\\(.+)$'){
        return Rel $Matches[1]
    }
    return ''
}

# Extract the share name from a UNC path for Event 5140 attribution.
function ShareFromUnc($v){
    if(!$v){return ''}
    $p=$v.Trim().Replace('/','\')
    if($p -match '^\\\\[^\\]+\\([^\\]+)(?:\\|$)'){
        return $Matches[1].ToLowerInvariant()
    }
    return ''
}
function ShareNameNorm($v){
    if(!$v){return ''}
    $p=$v.Trim().Replace('/','\').TrimEnd('\')
    if($p -match '^\\\\(?:\*|[^\\]+)\\([^\\]+)$'){
        return $Matches[1].ToLowerInvariant()
    }
    return (($p -split '\\')[-1]).ToLowerInvariant()
}
# A UNC share must refer to this Windows host (or a locally configured alias).
# Do not correlate an unrelated remote server that happens to use the same share name.
function LocalUncServer($v){
    if(!$v){return $false}
    $path=$v.Trim().Replace('/','\')
    if($path -notmatch '^\\\\([^\\]+)\\[^\\]+(?:\\|$)'){return $false}
    $hostName=($Matches[1] -split '\.')[0].ToLowerInvariant()
    $known=@([string]$env:COMPUTERNAME, [Environment]::MachineName) +
        @($env:SCAN_PROXY_LOCAL_SERVER_ALIASES -split '[,;]')
    foreach($candidate in $known){
        if([string]::IsNullOrWhiteSpace($candidate)){continue}
        $shortName=($candidate.Trim() -split '\.')[0]
        if($shortName.ToLowerInvariant() -eq $hostName){return $true}
    }
    return $false
}
function ShareMatches($file,$shareName,$shareLocal){
    $f=PathNorm $file
    $local=PathNorm $shareLocal
    if($f -and $local -and ($f -eq $local -or $f.StartsWith($local + '\'))){
        return $true
    }
    $wanted=ShareFromUnc $file
    $actual=ShareNameNorm $shareName
    return [bool]($wanted -and $actual -and $wanted -eq $actual -and (LocalUncServer $file))
}

# Reject local, invalid, mapped and explicitly ignored client addresses.
function Client($v){
    if(!$v){return ''}
    $s=$v.Trim().Trim('[',']')
    if($s.StartsWith('::ffff:')){$s=$s.Substring(7)}
    $ip=$null
    if(![Net.IPAddress]::TryParse(($s -split '%')[0],[ref]$ip)){return ''}
    if($ip.IsIPv4MappedToIPv6){$ip=$ip.MapToIPv4()}
    $n=$ip.ToString()
    if($n -in @('127.0.0.1','::1','0.0.0.0','::')){return ''}
    $n
}
function IPv4Number($v){
    try{
        $ip=[Net.IPAddress]::Parse($v)
        if($ip.IsIPv4MappedToIPv6){$ip=$ip.MapToIPv4()}
        $b=$ip.GetAddressBytes()
        if($b.Length -ne 4){return $null}
        [uint64]$b[0]*16777216 + [uint64]$b[1]*65536 + [uint64]$b[2]*256 + [uint64]$b[3]
    }catch{return $null}
}
function InCidr($ip,$cidr){
    try{
        $parts=$cidr -split '/',2
        if($parts.Count -ne 2){return $false}
        $a=IPv4Number $ip
        $n=IPv4Number $parts[0]
        if($null -eq $a -or $null -eq $n){return $false}
        $prefix=0
        if(![int]::TryParse($parts[1],[ref]$prefix) -or $prefix -lt 0 -or $prefix -gt 32){return $false}
        $block=[uint64][Math]::Pow(2,32-$prefix)
        ([uint64][Math]::Floor($a/$block)) -eq ([uint64][Math]::Floor($n/$block))
    }catch{return $false}
}
function ScannerClient($v){
    $c=Client $v
    if(!$c){return ''}
    foreach($cidr in $IgnoredNetworkList){if(InCidr $c $cidr){return ''}}
    $c
}

# Read Windows Security EventData XML into a case-sensitive key/value map.
function Map($e){
    $x=[xml]$e.ToXml()
    $h=@{}
    foreach($d in $x.Event.EventData.Data){
        $h[[string]$d.Name]=[string]$d.'#text'
    }
    $h
}
function ResultObject($client,$source,$reason,$record=0,$open=$false,$confidence='None',$id=$null){
    $o=[ordered]@{
        Client=$client
        Source=$source
        Reason=$reason
        RecordId=[long]$record
        Open=[bool]$open
        Confidence=$confidence
    }
    if($null -ne $id){$o.Id=[string]$id}
    [pscustomobject]$o
}
function Result($client,$source,$reason,$record=0,$open=$false,$confidence='None'){
    ResultObject $client $source $reason $record $open $confidence | ConvertTo-Json -Compress
}
function WriteLike($mask){
    try{
        $v=if($mask.StartsWith('0x')){
            [Convert]::ToUInt32($mask.Substring(2),16)
        }else{
            [Convert]::ToUInt32($mask,10)
        }
        ($v -band [uint32]0x400D0156)-ne 0
    }catch{$false}
}

# Audit policy setup requires an elevated, authorized administrator.
if($Mode -eq 'Setup'){
    & auditpol.exe /set /subcategory:$DetailedFileShareGuid /success:enable | Out-Host
    if($LASTEXITCODE){exit $LASTEXITCODE}
    & auditpol.exe /set /subcategory:$FileShareGuid /success:enable | Out-Host
    if($LASTEXITCODE){exit $LASTEXITCODE}
    & auditpol.exe /get /subcategory:$DetailedFileShareGuid
    & auditpol.exe /get /subcategory:$FileShareGuid
    exit 0
}

# Show current SMB activity and recent Security event evidence for one account.
if($Mode -eq 'Status'){
    Write-Host "scanproxy-smb $Version"
    Write-Host "Lookback=$LookbackMinutes min | SessionFallbackMaxAge=$SessionFallbackMaxAgeSeconds s | Ignored networks=$($IgnoredNetworkList -join ',')"
    & auditpol.exe /get /subcategory:$DetailedFileShareGuid
    & auditpol.exe /get /subcategory:$FileShareGuid
    Write-Host "`nCurrently open SMB files:"
    Get-SmbOpenFile -ErrorAction SilentlyContinue |
        Where-Object {SameUser $_.ClientUserName $UserName} |
        Where-Object {ScannerClient $_.ClientComputerName} |
        Select-Object Path,ShareRelativePath,ClientComputerName,ClientUserName |
        Format-Table -AutoSize

    Write-Host "`nCurrent SMB sessions:"
    Get-SmbSession -ErrorAction SilentlyContinue |
        Where-Object {SameUser $_.ClientUserName $UserName} |
        Where-Object {ScannerClient $_.ClientComputerName} |
        Select-Object ClientComputerName,ClientUserName,NumOpens |
        Format-Table -AutoSize

    $statusStart=(Get-Date).AddMinutes(-[Math]::Abs($LookbackMinutes))

    Write-Host "`nRecent Event 5145 matches for user ${UserName}:"
    $status5145=@(
        Get-WinEvent -FilterHashtable @{LogName='Security';Id=5145;StartTime=$statusStart} -ErrorAction SilentlyContinue |
            ForEach-Object {
                $d=Map $_
                if(SameUser $d.SubjectUserName $UserName){
                    $c=ScannerClient $d.IpAddress
                    if($c){
                        [pscustomobject]@{
                            TimeCreated=$_.TimeCreated
                            Client=$c
                            RelativeTargetName=$d.RelativeTargetName
                            AccessMask=$d.AccessMask
                            RecordId=$_.RecordId
                        }
                    }
                }
            }
    )
    Write-Host "5145 events in lookback: $($status5145.Count)"
    $status5145 |
        Sort-Object TimeCreated -Descending |
        Select-Object -First 15 |
        Format-Table -AutoSize

    Write-Host "`nRecent Event 5140 matches for user ${UserName}:"
    $status5140=@(
        Get-WinEvent -FilterHashtable @{LogName='Security';Id=5140;StartTime=$statusStart} -ErrorAction SilentlyContinue |
            ForEach-Object {
                $d=Map $_
                if(SameUser $d.SubjectUserName $UserName){
                    $c=ScannerClient $d.IpAddress
                    if($c){
                        [pscustomobject]@{
                            TimeCreated=$_.TimeCreated
                            Client=$c
                            ShareName=$d.ShareName
                            ShareLocalPath=$d.ShareLocalPath
                            LogonId=$d.SubjectLogonId
                            RecordId=$_.RecordId
                        }
                    }
                }
            }
    )
    Write-Host "5140 events in lookback: $($status5140.Count)"
    $status5140 |
        Sort-Object TimeCreated -Descending |
        Select-Object -First 15 |
        Format-Table -AutoSize
    exit 0
}

# One shared open-file snapshot per file scan cycle.
if($Mode -eq 'OpenSnapshot'){
    $rows=@(
        Get-SmbOpenFile -ErrorAction SilentlyContinue |
            Where-Object {SameUser $_.ClientUserName $UserName} |
            ForEach-Object {
                $c=ScannerClient $_.ClientComputerName
                if($c){
                    [pscustomobject]@{
                        Client=$c
                        Path=(PathNorm $_.Path)
                        RelativePath=(Rel $_.ShareRelativePath)
                    }
                }
            }
    )
    ConvertTo-Json -InputObject $rows -Compress -Depth 3
    exit 0
}

# Resolve pending records in batches, preferring exact Event 5145 evidence.
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
            $rel=RelativeFromUnc $fp
            if(!$rel){$rel=Rel ([string]$item.RelativePath)}
            $ref=[DateTime]::UtcNow
            try{
                if($item.ReferenceTimeUtc){
                    $ref=[DateTime]::Parse([string]$item.ReferenceTimeUtc).ToUniversalTime()
                }
            }catch{}
            [pscustomobject]@{
                Id=$id
                File=(PathNorm $fp)
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
                Where-Object {SameUser $_.ClientUserName $UserName} |
                ForEach-Object {
                    $c=ScannerClient $_.ClientComputerName
                    if($c){
                        [pscustomobject]@{
                            Client=$c
                            File=(PathNorm $_.Path)
                            Relative=(Rel $_.ShareRelativePath)
                        }
                    }
                }
        )
    }catch{}

    # Prefer a unique exact open-file path match over weaker relative-path evidence.
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
                $results[[string]$item.Id]=ResultObject $clients[0] 'Get-SmbOpenFile' 'Batch: exact currently open SMB file' 0 $true 'ExactOpenFile' $item.Id
                continue
            }
            if($clients.Count -gt 1){
                $results[[string]$item.Id]=ResultObject '' 'None' 'Batch: ambiguous open SMB file' 0 $false 'Ambiguous' $item.Id
                continue
            }
        }
        $unresolved += $item
    }

    # Group historical queries into 15-minute buckets to minimize event-log I/O.
    foreach($group in @($unresolved | Group-Object Bucket)){
        $members=@($group.Group)
        if(!$members.Count){continue}
        $ordered=@($members | Sort-Object Ref)
        $start=$ordered[0].Ref.AddMinutes(-[Math]::Abs($LookbackMinutes)).ToLocalTime()
        $end=$ordered[-1].Ref.AddSeconds([Math]::Max(2,$SessionFallbackMaxAgeSeconds)).ToLocalTime()
        $eventRows=@()
        $shareRows=@()
        try{
            $events=Get-WinEvent -FilterHashtable @{
                LogName='Security'
                Id=@(5145,5140)
                StartTime=$start
                EndTime=$end
            } -ErrorAction SilentlyContinue
            foreach($event in $events){
                $d=Map $event
                if(!(SameUser $d.SubjectUserName $UserName)){continue}
                $c=ScannerClient $d.IpAddress
                if(!$c){continue}
                if($event.Id -eq 5145){
                    $local=''
                    try{
                        $local=PathNorm ([IO.Path]::Combine(
                            (PathNorm $d.ShareLocalPath),
                            ([string]$d.RelativeTargetName).TrimStart('\')
                        ))
                    }catch{}
                    $eventRows += [pscustomobject]@{
                        Client=$c
                        File=$local
                        Relative=(Rel $d.RelativeTargetName)
                        Time=$event.TimeCreated.ToUniversalTime()
                        Record=$event.RecordId
                        Write=(WriteLike $d.AccessMask)
                    }
                }elseif($event.Id -eq 5140){
                    $shareRows += [pscustomobject]@{
                        Client=$c
                        ShareName=[string]$d.ShareName
                        ShareLocal=(PathNorm $d.ShareLocalPath)
                        Time=$event.TimeCreated.ToUniversalTime()
                        Record=$event.RecordId
                    }
                }
            }
        }catch{
            $eventRows=@()
            $shareRows=@()
        }

        foreach($item in $members){
            $lower=$item.Ref.AddMinutes(-[Math]::Abs($LookbackMinutes))
            $upper=$item.Ref.AddSeconds(2)
            # Event 5145 identifies a file; choose a unique recent writer if possible.
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
                    $results[[string]$item.Id]=ResultObject $best.Client 'Security-5145' 'Batch: unique file Event 5145' $best.Record $false 'ExactPathRecent' $item.Id
                    continue
                }
                if($writes.Count -eq 1){
                    $best=$recent | Where-Object {$_.Client -eq $writes[0] -and $_.Write} |
                        Sort-Object Time -Descending | Select-Object -First 1
                    $results[[string]$item.Id]=ResultObject $best.Client 'Security-5145' 'Batch: exactly one writing client' $best.Record $false 'ExactPathWrite' $item.Id
                    continue
                }
                $results[[string]$item.Id]=ResultObject '' 'None' 'Batch: ambiguous file Event 5145' 0 $false 'Ambiguous' $item.Id
                continue
            }

            # Event 5140 has only a share name: accept exactly one client within a narrow window.
            $shareHits=@(
                foreach($event in $shareRows){
                    $delta=[Math]::Abs(($event.Time-$item.Ref).TotalSeconds)
                    if($delta -gt [Math]::Max(0,$SessionFallbackMaxAgeSeconds)){continue}
                    if(!(ShareMatches $item.File $event.ShareName $event.ShareLocal)){continue}
                    [pscustomobject]@{
                        Client=$event.Client
                        Time=$event.Time
                        Record=$event.Record
                        Delta=$delta
                    }
                }
            )
            if($shareHits.Count){
                $clients=@($shareHits | Select-Object -ExpandProperty Client -Unique)
                if($clients.Count -eq 1){
                    $best=$shareHits | Where-Object Client -eq $clients[0] |
                        Sort-Object Delta,Time | Select-Object -First 1
                    $results[[string]$item.Id]=ResultObject $best.Client 'Security-5140' 'Batch: unique Event 5140 share access within narrow time window' $best.Record $false 'UniqueShareRecent' $item.Id
                    continue
                }
                $results[[string]$item.Id]=ResultObject '' 'None' 'Batch: multiple Event 5140 clients on share; attribution unsafe' 0 $false 'Ambiguous' $item.Id
                continue
            }

            $results[[string]$item.Id]=ResultObject '' 'None' 'Batch: no matching file Event 5145 or unique share Event 5140' 0 $false 'None' $item.Id
        }
    }

    $orderedResults=@(
        foreach($item in $items){
            $key=[string]$item.Id
            if($results.ContainsKey($key)){
                $results[$key]
            }else{
                ResultObject '' 'None' 'Batch: no unambiguous SMB client IP attribution' 0 $false 'None' $item.Id
            }
        }
    )
    ConvertTo-Json -InputObject $orderedResults -Compress -Depth 4
    exit 0
}

if(!$FilePath){
    Result '' 'None' 'FilePath missing'
    exit 0
}

$file=PathNorm $FilePath
$relative=RelativeFromUnc $FilePath
if(!$relative){$relative=Rel $RelativePath}

try{
    $hits=@(
        Get-SmbOpenFile -ErrorAction Stop |
            Where-Object {SameUser $_.ClientUserName $UserName} |
            ForEach-Object {
                $c=ScannerClient $_.ClientComputerName
                $strength=if((PathNorm $_.Path)-eq $file){
                    3
                }elseif($relative -and (Rel $_.ShareRelativePath)-eq $relative){
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
            Result $clients[0] 'Get-SmbOpenFile' 'Exact currently open SMB file' 0 $true 'ExactOpenFile'
            exit 0
        }
        if($clients.Count -gt 1){
            Result '' 'None' 'Ambiguous open SMB file' 0 $false 'Ambiguous'
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
# A current session must never be used as historical evidence outside the time window.
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
            $d=Map $e
            if(!(SameUser $d.SubjectUserName $UserName)){continue}
            $c=ScannerClient $d.IpAddress
            if(!$c){continue}
            $local=''
            try{
                $local=PathNorm ([IO.Path]::Combine(
                    (PathNorm $d.ShareLocalPath),
                    ([string]$d.RelativeTargetName).TrimStart('\')
                ))
            }catch{}
            $strength=if($local -and $local -eq $file){
                3
            }elseif($relative -and (Rel $d.RelativeTargetName)-eq $relative){
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
                    Write=(WriteLike $d.AccessMask)
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
            Result $best.Client 'Security-5145' 'Unambiguous file Event 5145' $best.Record $false 'ExactPathRecent'
            exit 0
        }
        if($writes.Count -eq 1){
            $best=$recent |
                Where-Object {$_.Client -eq $writes[0] -and $_.Write} |
                Sort-Object Time -Descending |
                Select-Object -First 1
            Result $best.Client 'Security-5145' 'Exactly one writing client in time window' $best.Record $false 'ExactPathWrite'
            exit 0
        }
        Result '' 'None' 'Ambiguous file Event 5145' 0 $false 'Ambiguous'
        exit 0
    }
}catch{}

try{
    $shareAge=[Math]::Max(0,$SessionFallbackMaxAgeSeconds)
    $shareStart=$ref.AddSeconds(-$shareAge).ToLocalTime()
    $shareEnd=$ref.AddSeconds($shareAge).ToLocalTime()
    $shareHits=@(
        Get-WinEvent -FilterHashtable @{
            LogName='Security'
            Id=5140
            StartTime=$shareStart
            EndTime=$shareEnd
        } -ErrorAction SilentlyContinue |
            ForEach-Object {
                $event=$_
                $d=Map $event
                if(SameUser $d.SubjectUserName $UserName){
                    $c=ScannerClient $d.IpAddress
                    if($c -and (ShareMatches $file $d.ShareName $d.ShareLocalPath)){
                        [pscustomobject]@{
                            Client=$c
                            Time=$event.TimeCreated.ToUniversalTime()
                            Record=$event.RecordId
                            Delta=[Math]::Abs(($event.TimeCreated.ToUniversalTime()-$ref).TotalSeconds)
                        }
                    }
                }
            }
    )
    if($shareHits.Count){
        $clients=@($shareHits | Select-Object -ExpandProperty Client -Unique)
        if($clients.Count -eq 1){
            $best=$shareHits | Where-Object Client -eq $clients[0] |
                Sort-Object Delta,Time | Select-Object -First 1
            Result $best.Client 'Security-5140' 'Unique share Event 5140 in narrow time window' $best.Record $false 'UniqueShareRecent'
            exit 0
        }
        Result '' 'None' 'Multiple Event 5140 clients on same share; attribution unsafe' 0 $false 'Ambiguous'
        exit 0
    }
}catch{}

if($referenceAgeSeconds -le [Math]::Max(0,$SessionFallbackMaxAgeSeconds)){
    try{
        $clients=@(
            Get-SmbSession -ErrorAction Stop |
                Where-Object {SameUser $_.ClientUserName $UserName} |
                ForEach-Object {ScannerClient $_.ClientComputerName} |
                Where-Object {$_} |
                Sort-Object -Unique
        )
        if($clients.Count -eq 1){
            Result $clients[0] 'Get-SmbSession' 'Exactly one recent SMB session for user' 0 $false 'UniqueSessionRecent'
            exit 0
        }
        if($clients.Count -gt 1){
            Result '' 'None' 'Multiple SMB sessions; attribution unsafe' 0 $false 'Ambiguous'
            exit 0
        }
    }catch{}
}

Result '' 'None' "No unambiguous SMB IP attribution (OpenFile/5145/5140/Session); ignored networks: $($IgnoredNetworkList -join ',')"
exit 0
