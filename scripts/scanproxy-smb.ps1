[CmdletBinding()]
param(
    [ValidateSet('Resolve','Setup','Status')][string]$Mode='Resolve',
    [string]$FilePath,
    [string]$RelativePath,
    [string]$UserName='scan-service',
    [int]$LookbackMinutes=10,
    [string]$ReferenceTimeUtc,
    [int]$AmbiguitySeconds=8,
    [string]$IgnoredNetworks=''
)

$Version = '2.11.0-public'
# +------------+---------+-------------------------------------------------------------------------+
# | Date       | Author  | Change                                                                  |
# +------------+---------+-------------------------------------------------------------------------+
# | 01.10.2026 | Trachti | Public release: translated comments and output to English; removed     |
# |            |         | organization-specific account and network defaults.                    |
# +------------+---------+-------------------------------------------------------------------------+
# | 14.08.2026 | Trachti | Made ignored networks and the lookback window configurable.            |
# +------------+---------+-------------------------------------------------------------------------+
# | 14.08.2026 | Trachti | Removed collector logic and set the SMB query window to 10 minutes.    |
# +------------+---------+-------------------------------------------------------------------------+

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

function SameUser($a,$b){
    !$b -or (User $a) -eq (User $b)
}

function Rel($v){
    if(!$v){return ''}
    $v.Trim().Replace('/','\').Trim('\').ToLowerInvariant()
}

function PathNorm($v){
    if(!$v){return ''}
    $p=$v.Trim().Replace('/','\')
    if($p.StartsWith('\??\')){
        $p=$p.Substring(4)
    } elseif($p.StartsWith('\\?\')){
        $p=$p.Substring(4)
    }
    $p.TrimEnd('\').ToLowerInvariant()
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
    }catch{
        return $null
    }
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
    }catch{
        return $false
    }
}

function ScannerClient($v){
    $c=Client $v
    if(!$c){return ''}
    foreach($cidr in $IgnoredNetworkList){
        if(InCidr $c $cidr){return ''}
    }
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

function Result($client,$source,$reason,$record=0,$open=$false,$confidence='None'){
    [pscustomobject]@{
        Client=$client
        Source=$source
        Reason=$reason
        RecordId=[long]$record
        Open=[bool]$open
        Confidence=$confidence
    } | ConvertTo-Json -Compress
}

function WriteLike($mask){
    try{
        $v=if($mask.StartsWith('0x')){
            [Convert]::ToUInt32($mask.Substring(2),16)
        }else{
            [Convert]::ToUInt32($mask,10)
        }
        ($v -band [uint32]0x400D0156)-ne 0
    }catch{
        $false
    }
}

if($Mode -eq 'Setup'){
    & auditpol.exe /set /subcategory:$DetailedFileShareGuid /success:enable | Out-Host
    if($LASTEXITCODE){exit $LASTEXITCODE}
    & auditpol.exe /get /subcategory:$DetailedFileShareGuid
    exit 0
}

if($Mode -eq 'Status'){
    Write-Host "scanproxy-smb $Version"
    Write-Host "Lookback=$LookbackMinutes min | Ignored networks=$($IgnoredNetworkList -join ',')"
    & auditpol.exe /get /subcategory:$DetailedFileShareGuid
    Get-SmbOpenFile -ErrorAction SilentlyContinue |
        Where-Object {SameUser $_.ClientUserName $UserName} |
        Where-Object {ScannerClient $_.ClientComputerName} |
        Select-Object Path,ShareRelativePath,ClientComputerName,ClientUserName |
        Format-Table -AutoSize
    exit 0
}

if(!$FilePath){
    Result '' 'None' 'FilePath is required'
    exit 0
}

$file=PathNorm $FilePath
$relative=Rel $RelativePath

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
        $strong=@(
            $matches |
                Where-Object Strength -eq $max |
                Sort-Object Time -Descending
        )
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
            Result $best.Client 'Security-5145' 'Unambiguous file event 5145' $best.Record $false 'ExactPathRecent'
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

try{
    $clients=@(
        Get-SmbSession -ErrorAction Stop |
            Where-Object {SameUser $_.ClientUserName $UserName} |
            ForEach-Object {ScannerClient $_.ClientComputerName} |
            Where-Object {$_} |
            Sort-Object -Unique
    )
    if($clients.Count -eq 1){
        Result $clients[0] 'Get-SmbSession' 'Exactly one SMB session for the user' 0 $false 'UniqueSession'
        exit 0
    }
    if($clients.Count -gt 1){
        Result '' 'None' 'Multiple SMB sessions; no reliable mapping' 0 $false 'Ambiguous'
        exit 0
    }
}catch{}

Result '' 'None' "No unambiguous SMB client IP mapping; ignored networks: $($IgnoredNetworkList -join ',')"
exit 0
