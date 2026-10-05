[CmdletBinding()]
param(
    [ValidateSet('Resolve','ResolveBatch','Setup','Status')][string]$Mode='Resolve',
    [string]$FilePath,
    [string]$RelativePath,
    [string]$UserName='scanner-service',
    [int]$LookbackMinutes=10,
    [string]$ReferenceTimeUtc,
    [int]$AmbiguitySeconds=8,
    [int]$SessionFallbackMaxAgeSeconds=30,
    [string]$IgnoredNetworks=''
)

$Version = '2.12.0'
# 2026-09-18 | Trachti | Added batched low-CPU SMB attribution and grouped Event 5145 queries.
# 2026-09-18 | Trachti | Added direct UNC-to-share-relative path matching.

$ErrorActionPreference='Stop'
$DetailedFileShareGuid='{0CCE9244-69AE-11D9-BED3-505054503030}'
$IgnoredNetworkList=@(
    $IgnoredNetworks -split '[,;]' |
        ForEach-Object {$_.Trim()} |
        Where-Object {$_}
)
function User($v){
    if(!$v){return ''}
    (($v.Trim() -split '\\')[-1] -split '@')[0].ToLowerInvariant()
}
function SameUser($a,$b){ !$b -or (User $a) -eq (User $b) }
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

if($Mode -eq 'Setup'){
    & auditpol.exe /set /subcategory:$DetailedFileShareGuid /success:enable | Out-Host
    if($LASTEXITCODE){exit $LASTEXITCODE}
    & auditpol.exe /get /subcategory:$DetailedFileShareGuid
    exit 0
}

if($Mode -eq 'Status'){
    Write-Host "scanproxy-smb $Version"
    Write-Host "Lookback=$LookbackMinutes min | SessionFallbackMaxAge=$SessionFallbackMaxAgeSeconds s | Ignored networks=$($IgnoredNetworkList -join ',')"
    & auditpol.exe /get /subcategory:$DetailedFileShareGuid
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

    Write-Host "`nRecent Event 5145 matches for user ${UserName}:"
    try{
        $statusStart=(Get-Date).AddMinutes(-[Math]::Abs($LookbackMinutes))
        $statusEvents=@(
            Get-WinEvent -FilterHashtable @{LogName='Security';Id=5145;StartTime=$statusStart} -ErrorAction Stop |
                ForEach-Object {
                    $d=Map $_
                    if(SameUser $d.SubjectUserName $UserName){
                        [pscustomobject]@{
                            TimeCreated=$_.TimeCreated
                            Client=(ScannerClient $d.IpAddress)
                            RelativeTargetName=$d.RelativeTargetName
                            AccessMask=$d.AccessMask
                            RecordId=$_.RecordId
                        }
                    }
                } |
                Where-Object {$_.Client}
        )
        Write-Host "5145 events in lookback: $($statusEvents.Count)"
        $statusEvents |
            Sort-Object TimeCreated -Descending |
            Select-Object -First 15 |
            Format-Table -AutoSize
    }catch{
        Write-Warning "Security Event 5145 could not be read: $($_.Exception.Message)"
    }
    exit 0
}
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
                        $d=Map $event
                        if(SameUser $d.SubjectUserName $UserName){
                            $c=ScannerClient $d.IpAddress
                            if($c){
                                $local=''
                                try{
                                    $local=PathNorm ([IO.Path]::Combine(
                                        (PathNorm $d.ShareLocalPath),
                                        ([string]$d.RelativeTargetName).TrimStart('\')
                                    ))
                                }catch{}
                                [pscustomobject]@{
                                    Client=$c
                                    File=$local
                                    Relative=(Rel $d.RelativeTargetName)
                                    Time=$event.TimeCreated.ToUniversalTime()
                                    Record=$event.RecordId
                                    Write=(WriteLike $d.AccessMask)
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
                    $results[[string]$item.Id]=ResultObject $best.Client 'Security-5145' 'Batch: unambiguous file Event 5145' $best.Record $false 'ExactPathRecent' $item.Id
                    continue
                }
                if($writes.Count -eq 1){
                    $best=$recent | Where-Object {$_.Client -eq $writes[0] -and $_.Write} |
                        Sort-Object Time -Descending | Select-Object -First 1
                    $results[[string]$item.Id]=ResultObject $best.Client 'Security-5145' 'Batch: exactly one writing client' $best.Record $false 'ExactPathWrite' $item.Id
                    continue
                }
                $results[[string]$item.Id]=ResultObject '' 'None' 'Batch: ambiguous 5145 file events' 0 $false 'Ambiguous' $item.Id
            }else{
                $results[[string]$item.Id]=ResultObject '' 'None' 'Batch: no matching 5145 file event' 0 $false 'None' $item.Id
            }
        }
    }

    $orderedResults=@(
        foreach($item in $items){
            $key=[string]$item.Id
            if($results.ContainsKey($key)){
                $results[$key]
            }else{
                ResultObject '' 'None' 'Batch: no unambiguous SMB client IP mapping' 0 $false 'None' $item.Id
            }
        }
    )
    ConvertTo-Json -InputObject $orderedResults -Compress -Depth 4
    exit 0
}

if(!$FilePath){
    Result '' 'None' 'FilePath is missing'
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
            Result $best.Client 'Security-5145' 'Exactly one writing client in the time window' $best.Record $false 'ExactPathWrite'
            exit 0
        }
        Result '' 'None' 'Ambiguous 5145 file events' 0 $false 'Ambiguous'
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
            Result '' 'None' 'Multiple SMB sessions; no reliable mapping' 0 $false 'Ambiguous'
            exit 0
        }
    }catch{}
}

Result '' 'None' "No unambiguous SMB client IP mapping; ignored: $($IgnoredNetworkList -join ',')"
exit 0
