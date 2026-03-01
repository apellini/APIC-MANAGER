# ── Cisco APIC Manager v1.4 ───────────────────────────────────────────────────

$script:ExitRequested = $false
$script:AppVersion    = '1.4'      # used for GitHub update check

# ── Global config ─────────────────────────────────────────────────────────────
$script:Config = @{
    ApicHost               = $null
    Username               = $null
    Password               = $null
    SSLVerify              = $true
    InputFolder            = $null
    AutoUpdate             = $true    # check GitHub for new version on startup
    BulkValidatePortPolicy = $true    # validate DPC/VPC policy groups on APIC
    BulkValidateTenant     = $true    # validate tenants on APIC
    BulkLookupEpg          = $true    # look up AP/EPG on APIC
}

# ── Session state ─────────────────────────────────────────────────────────────
$script:Session = @{
    LoggedIn  = $false
    Token     = $null
    Host      = $null
    Username  = $null
    SSLVerify = $true
}

# ── DB paths ──────────────────────────────────────────────────────────────────
$script:PointerDir  = Join-Path $env:APPDATA "APICManager"
$script:PointerFile = Join-Path $script:PointerDir ".dbpath"
$script:DbFile      = "apic_manager.db"
$script:DbFolder    = $script:PointerDir
$script:DbPath      = Join-Path $script:DbFolder $script:DbFile

# ════════════════════════════════════════════════════════════════════════════════
#  POINTER FILE
# ════════════════════════════════════════════════════════════════════════════════

function Read-DbPointer {
    if (Test-Path $script:PointerFile) {
        $p = (Get-Content $script:PointerFile -Raw).Trim()
        if ($p -and (Test-Path (Split-Path $p -Parent))) { return $p }
    }
    return $null
}

function Write-DbPointer {
    param([string]$Path)
    if (-not (Test-Path $script:PointerDir)) {
        New-Item -ItemType Directory -Path $script:PointerDir -Force | Out-Null
    }
    $Path | Set-Content -Path $script:PointerFile -Encoding UTF8 -Force
}

# ════════════════════════════════════════════════════════════════════════════════
#  ENCRYPTION  (DPAPI — Windows current-user/machine scope)
# ════════════════════════════════════════════════════════════════════════════════

function Protect-String {
    param([string]$Plain)
    if ([string]::IsNullOrEmpty($Plain)) { return $null }
    try   { return ($Plain | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString) }
    catch { return [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Plain)) }
}

function Unprotect-String {
    param([string]$Cipher)
    if ([string]::IsNullOrEmpty($Cipher)) { return $null }
    try {
        $ss    = $Cipher | ConvertTo-SecureString -ErrorAction Stop
        $bstr  = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($ss)
        $plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        return $plain
    } catch {
        try   { return [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Cipher)) }
        catch { return $null }
    }
}

# ════════════════════════════════════════════════════════════════════════════════
#  SQLITE LAYER
# ════════════════════════════════════════════════════════════════════════════════

function Install-PSSQLite {
    if (-not (Get-Module -ListAvailable -Name PSSQLite)) {
        Write-Host "  📦  PSSQLite not found. Installing..." -ForegroundColor Yellow
        try {
            Install-Module -Name PSSQLite -Scope CurrentUser -Force -ErrorAction Stop
            Write-Host "  ✔  PSSQLite installed." -ForegroundColor Green
        } catch {
            Write-Host "  ✘  Install failed: $_" -ForegroundColor Red
            Write-Host "     Run: Install-Module -Name PSSQLite -Scope CurrentUser -Force" -ForegroundColor DarkYellow
            Wait-AnyKey; return $false
        }
    }
    try   { Import-Module PSSQLite -ErrorAction Stop; return $true }
    catch { Write-Host "  ✘  Import failed: $_" -ForegroundColor Red; Wait-AnyKey; return $false }
}

function Initialize-Database {
    if (-not (Test-Path $script:DbFolder)) {
        New-Item -ItemType Directory -Path $script:DbFolder -Force | Out-Null
    }
    $sql = @"
CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT
);
CREATE TABLE IF NOT EXISTS db_meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);
CREATE TABLE IF NOT EXISTS apic_hosts (
    ip            TEXT PRIMARY KEY,
    source        TEXT DEFAULT 'discovered',
    is_preferred  INTEGER DEFAULT 0,
    discovered_at TEXT DEFAULT (datetime('now')),
    last_used_at  TEXT,
    last_status   TEXT DEFAULT 'unknown',
    node_id       TEXT,
    pod_id        TEXT,
    node_name     TEXT,
    fabric_state  TEXT,
    model         TEXT,
    firmware      TEXT,
    uptime        TEXT,
    health_score  INTEGER,
    last_enriched TEXT
);
INSERT OR IGNORE INTO db_meta (key,value) VALUES ('created_at', datetime('now'));
INSERT OR IGNORE INTO db_meta (key,value) VALUES ('version',    '1.3');
CREATE TABLE IF NOT EXISTS bulk_imports (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    file_name   TEXT,
    file_path   TEXT,
    imported_at TEXT DEFAULT (datetime('now')),
    row_count   INTEGER,
    status      TEXT DEFAULT 'pending'
);
CREATE TABLE IF NOT EXISTS bulk_import_rows (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    import_id   INTEGER REFERENCES bulk_imports(id),
    src_line    INTEGER,
    tenant      TEXT,
    type        TEXT,
    pod         TEXT,
    leaf        TEXT,
    port        TEXT,
    vlan        INTEGER,
    mode        TEXT,
    native_vlan INTEGER,
    ap          TEXT,
    epg         TEXT,
    valid       INTEGER DEFAULT 1,
    errors      TEXT,
    created_at  TEXT DEFAULT (datetime('now'))
);
"@
    try { Invoke-SqliteQuery -DataSource $script:DbPath -Query $sql | Out-Null }
    catch { Write-Host "  ✘  DB init error: $_" -ForegroundColor Red; return $false }

    # ── Schema migration: only add columns that don't exist yet ──────────────
    try {
        $existing = Invoke-SqliteQuery -DataSource $script:DbPath `
            -Query "PRAGMA table_info(apic_hosts)"
        $cols = @($existing | ForEach-Object { $_.name })
    } catch { $cols = @() }

    $migrations = @(
        @{ col="is_preferred";  sql="ALTER TABLE apic_hosts ADD COLUMN is_preferred  INTEGER DEFAULT 0" }
        @{ col="node_id";       sql="ALTER TABLE apic_hosts ADD COLUMN node_id       TEXT" }
        @{ col="pod_id";        sql="ALTER TABLE apic_hosts ADD COLUMN pod_id        TEXT" }
        @{ col="node_name";     sql="ALTER TABLE apic_hosts ADD COLUMN node_name     TEXT" }
        @{ col="fabric_state";  sql="ALTER TABLE apic_hosts ADD COLUMN fabric_state  TEXT" }
        @{ col="model";         sql="ALTER TABLE apic_hosts ADD COLUMN model         TEXT" }
        @{ col="firmware";      sql="ALTER TABLE apic_hosts ADD COLUMN firmware      TEXT" }
        @{ col="uptime";        sql="ALTER TABLE apic_hosts ADD COLUMN uptime        TEXT" }
        @{ col="health_score";  sql="ALTER TABLE apic_hosts ADD COLUMN health_score  INTEGER" }
        @{ col="serial";        sql="ALTER TABLE apic_hosts ADD COLUMN serial        TEXT" }
        @{ col="last_enriched"; sql="ALTER TABLE apic_hosts ADD COLUMN last_enriched TEXT" }
    )
    foreach ($m in $migrations) {
        if ($cols -notcontains $m.col) {
            try { Invoke-SqliteQuery -DataSource $script:DbPath -Query $m.sql | Out-Null } catch {}
        }
    }
    return $true
}

function Save-Config {
    if (-not (Initialize-Database)) { return }
    $pairs = @{
        apic_host  = Protect-String $script:Config.ApicHost
        username   = Protect-String $script:Config.Username
        password   = Protect-String $script:Config.Password
        ssl_verify = [string]($script:Config.SSLVerify)
        db_folder  = $script:DbFolder
        input_folder               = if ($script:Config.InputFolder) { $script:Config.InputFolder } else { $null }
        auto_update                = [string]($script:Config.AutoUpdate)
        bulk_validate_port_policy  = [string]($script:Config.BulkValidatePortPolicy)
        bulk_validate_tenant       = [string]($script:Config.BulkValidateTenant)
        bulk_lookup_epg            = [string]($script:Config.BulkLookupEpg)
    }
    foreach ($k in $pairs.Keys) {
        $v = $pairs[$k]
        if ($null -ne $v) {
            Invoke-SqliteQuery -DataSource $script:DbPath `
                -Query "INSERT OR REPLACE INTO settings (key,value) VALUES (@k,@v)" `
                -SqlParameters @{k=$k;v=$v} | Out-Null
        }
    }
}

function Load-Config {
    if (-not (Test-Path $script:DbPath)) { return }
    if (-not (Initialize-Database))      { return }
    try {
        $rows = Invoke-SqliteQuery -DataSource $script:DbPath -Query "SELECT key,value FROM settings"
        $map  = @{}
        foreach ($r in $rows) { $map[$r.key] = $r.value }

        if ($map['apic_host'])  { $script:Config.ApicHost  = Unprotect-String $map['apic_host'] }
        if ($map['username'])   { $script:Config.Username  = Unprotect-String $map['username']  }
        if ($map['password'])   { $script:Config.Password  = Unprotect-String $map['password']  }
        if ($map['ssl_verify']) { $script:Config.SSLVerify = ($map['ssl_verify'] -eq 'True')    }
        if ($map['input_folder'])              { $script:Config.InputFolder              = $map['input_folder'] }
        if ($map['auto_update'])               { $script:Config.AutoUpdate               = ($map['auto_update'] -eq 'True') }
        if ($map['bulk_validate_port_policy']) { $script:Config.BulkValidatePortPolicy   = ($map['bulk_validate_port_policy'] -eq 'True') }
        if ($map['bulk_validate_tenant'])      { $script:Config.BulkValidateTenant       = ($map['bulk_validate_tenant'] -eq 'True') }
        if ($map['bulk_lookup_epg'])           { $script:Config.BulkLookupEpg            = ($map['bulk_lookup_epg'] -eq 'True') }
        if ($map['db_folder'] -and (Test-Path $map['db_folder'])) {
            $script:DbFolder = $map['db_folder']
            $script:DbPath   = Join-Path $script:DbFolder $script:DbFile
        }
    } catch { Write-Host "  ⚠  Load config error: $_" -ForegroundColor DarkYellow }
}

# ── Host pool helpers ─────────────────────────────────────────────────────────

function Get-ApicHostPool {
    # Preferred host first, then the rest in random order
    $preferred = @()
    $others    = @()

    # Pull hosts and their fabric_state so we can filter by 'in-service'
    if (Test-Path $script:DbPath) {
        try {
            $rows = Invoke-SqliteQuery -DataSource $script:DbPath -Query "SELECT ip, is_preferred, fabric_state FROM apic_hosts"
            foreach ($r in $rows) {
                if ($r.is_preferred -eq 1) { $preferred += @{ip=$r.ip;state=$r.fabric_state} }
                else                        { $others    += @{ip=$r.ip;state=$r.fabric_state} }
            }
        } catch {}
    }

    # If preferred exists but not in 'in-service', ignore it (don't prefer)
    $usablePreferred = @()
    foreach ($p in $preferred) {
        if (-not $p.state -or $p.state.ToLower() -eq 'in-service') { $usablePreferred += $p.ip }
    }

    # Bootstrap host not in DB yet → put it first if no usable preferred defined
    if ($script:Config.ApicHost) {
        $allKnownIps = ($usablePreferred + ($others | ForEach-Object { $_.ip }))
        if ($allKnownIps -notcontains $script:Config.ApicHost) {
            # Only add bootstrap if we have no usable preferreds
            if ($usablePreferred.Count -eq 0) { $usablePreferred = @($script:Config.ApicHost) + $usablePreferred }
        }
    }

    # For random/round-robin others, prefer only 'in-service' controllers
    $inServiceOthers = @($others | Where-Object { -not $_.state -or $_.state.ToLower() -eq 'in-service' } | ForEach-Object { $_.ip })
    $otherPool = if ($inServiceOthers.Count -gt 0) { $inServiceOthers } else { $others | ForEach-Object { $_.ip } }

    # Preferred come first (if any), then randomized others
    return $usablePreferred + ($otherPool | Sort-Object { Get-Random })
}

function Get-ApicHostCount {
    if (-not (Test-Path $script:DbPath)) { return 0 }
    try {
        $r = Invoke-SqliteQuery -DataSource $script:DbPath -Query "SELECT COUNT(*) AS cnt FROM apic_hosts"
        return $r.cnt
    } catch { return 0 }
}

function Get-PreferredHost {
    if (-not (Test-Path $script:DbPath)) { return $null }
    try {
        $r = Invoke-SqliteQuery -DataSource $script:DbPath `
            -Query "SELECT ip FROM apic_hosts WHERE is_preferred=1 LIMIT 1"
        return $r.ip
    } catch { return $null }
}

function Save-ApicHosts {
    param([string[]]$IPs, [string]$Source = 'discovered')
    if (-not (Initialize-Database)) { return }
    foreach ($ip in $IPs) {
        if ([string]::IsNullOrWhiteSpace($ip) -or $ip -eq '0.0.0.0') { continue }
        Invoke-SqliteQuery -DataSource $script:DbPath `
            -Query "INSERT OR IGNORE INTO apic_hosts (ip,source,discovered_at,last_status) VALUES (@ip,@src,datetime('now'),'unknown')" `
            -SqlParameters @{ip=$ip;src=$Source} | Out-Null
    }
}

function Update-ApicHostStatus {
    param([string]$IP, [string]$Status)
    if (-not (Test-Path $script:DbPath)) { return }
    try {
        Invoke-SqliteQuery -DataSource $script:DbPath `
            -Query "UPDATE apic_hosts SET last_status=@s, last_used_at=CASE WHEN @s='ok' THEN datetime('now') ELSE last_used_at END WHERE ip=@ip" `
            -SqlParameters @{s=$Status;ip=$IP} | Out-Null
    } catch {}
}

function Update-ApicHostFabricData {
    param(
        [string]$IP,
        [string]$NodeId,
        [string]$PodId,
        [string]$NodeName,
        [string]$FabricState,
        [string]$Model,
        [string]$Firmware,
        [string]$Uptime,
        [int]   $HealthScore,
        [string]$Serial
    )
    if (-not (Test-Path $script:DbPath)) { return }
    try {
        Invoke-SqliteQuery -DataSource $script:DbPath -Query @"
UPDATE apic_hosts SET
    node_id       = @nid,
    pod_id        = @pid,
    node_name     = @nn,
    fabric_state  = @fs,
    model         = @mdl,
    firmware      = @fw,
    uptime        = @up,
    health_score  = @hs,
    serial        = @sn,
    last_enriched = datetime('now')
WHERE ip = @ip
"@ -SqlParameters @{
            nid=$NodeId; pid=$PodId; nn=$NodeName; fs=$FabricState
            mdl=$Model;  fw=$Firmware; up=$Uptime; hs=$HealthScore; sn=$Serial; ip=$IP
        } | Out-Null
    } catch {}
}

function Set-PreferredHost {
    param([string]$IP)
    if (-not (Test-Path $script:DbPath)) { return $false }
    try {
        # Clear all preferred flags first
        Invoke-SqliteQuery -DataSource $script:DbPath `
            -Query "UPDATE apic_hosts SET is_preferred = 0" | Out-Null
        
        # Set the new preferred host if IP is provided
        if ($IP) {
            Invoke-SqliteQuery -DataSource $script:DbPath `
                -Query "UPDATE apic_hosts SET is_preferred = 1 WHERE ip = @ip" `
                -SqlParameters @{ip=$IP} | Out-Null
        }
        return $true
    } catch {
        Write-Host "ERROR setting preferred host: $_" -ForegroundColor Red
        return $false
    }
}

# ── Format APIC uptime string "dd:hh:mm:ss.mmm" → human readable ──────────────
function Format-ApicUptime {
    param([string]$Raw)
    if ([string]::IsNullOrEmpty($Raw)) { return "N/A" }
    try {
        $parts = $Raw -split ':'
        $d = [int]$parts[0]; $h = [int]$parts[1]; $m = [int]$parts[2]
        if     ($d -gt 0) { return "${d}d ${h}h" }
        elseif ($h -gt 0) { return "${h}h ${m}m" }
        else              { return "${m}m" }
    } catch { return $Raw }
}

function Get-DbInfo {
    if (-not (Test-Path $script:DbPath)) {
        return @{Exists=$false;Size=0;Created="N/A";Version="N/A";Rows=0;Hosts=0;Path=$script:DbPath}
    }
    try {
        $meta    = Invoke-SqliteQuery -DataSource $script:DbPath -Query "SELECT key,value FROM db_meta"
        $rows    = Invoke-SqliteQuery -DataSource $script:DbPath -Query "SELECT COUNT(*) AS cnt FROM settings"
        $hosts   = Invoke-SqliteQuery -DataSource $script:DbPath -Query "SELECT COUNT(*) AS cnt FROM apic_hosts"
        $fi      = Get-Item $script:DbPath
        $mm      = @{}; foreach ($r in $meta) { $mm[$r.key]=$r.value }
        return @{
            Exists  = $true
            Size    = [math]::Round($fi.Length/1KB,2)
            Created = $mm['created_at']
            Version = $mm['version']
            Rows    = $rows.cnt
            Hosts   = $hosts.cnt
            Path    = $script:DbPath
        }
    } catch { return @{Exists=$true;Size=0;Created="Error";Version="Error";Rows=0;Hosts=0;Path=$script:DbPath} }
}

# ════════════════════════════════════════════════════════════════════════════════
#  UI HELPERS
# ════════════════════════════════════════════════════════════════════════════════

function Read-MenuKey { return [Console]::ReadKey($true) }

function Write-Header {
    param([string]$Title,[string]$Color)
    Write-Host ""
    Write-Host "  ╔══════════════════════════════════╗" -ForegroundColor $Color
    Write-Host "  ║  $Title  ║" -ForegroundColor $Color
    Write-Host "  ╚══════════════════════════════════╝" -ForegroundColor $Color
    Write-Host ""
}

function Invoke-Menu {
    param(
        [string]   $Title,
        [string]   $Color,
        [string[]] $Items,
        [bool]     $IsMain          = $false,
        [int[]]    $DisabledIndices = @(),
        [bool]     $NoAutoFooter    = $false
    )
    $numbered = @(); for ($n=0;$n -lt $Items.Count;$n++) { $numbered += "[$($n+1)]  $($Items[$n])" }
    if ($IsMain -or $NoAutoFooter) { $allItems = $numbered }
    else                            { $allItems = $numbered + @("[B]  ← Back","[M]  ← Back to Main Menu","[Q]  ✕  Quit") }
    $digitMap = @{"D1"=0;"D2"=1;"D3"=2;"D4"=3;"D5"=4;"D6"=5;"D7"=6;"D8"=7;"D9"=8}
    $selected = 0
    foreach ($i in 0..($allItems.Count-1)) { if ($DisabledIndices -notcontains $i) { $selected=$i; break } }
    [Console]::CursorVisible = $false
    try {
        while ($true) {
            Clear-Host; Write-Header -Title $Title -Color $Color
            Write-Host "  ↑↓ Navigate   Enter/[n] Select   B Back   Q Quit" -ForegroundColor DarkGray
            Write-Host ""
            for ($i=0;$i -lt $allItems.Count;$i++) {
                # print divider before footer items
                if ($i -eq $numbered.Count -and -not $IsMain -and -not $NoAutoFooter) {
                    Write-Host "  ────────────────────────────────────" -ForegroundColor DarkGray
                }
                $isDis = $DisabledIndices -contains $i
                if ($isDis)            { Write-Host "    $($allItems[$i])  ⊘" -ForegroundColor DarkGray }
                elseif ($i -eq $selected) { Write-Host "  ► $($allItems[$i])  " -BackgroundColor DarkCyan -ForegroundColor White }
                else                   { Write-Host "    $($allItems[$i])" -ForegroundColor Gray }
            }
            Write-Host ""; $key = Read-MenuKey
            switch ($key.Key) {
                "UpArrow"   { $p=$selected; do{$p--;if($p -lt 0){$p=$allItems.Count-1}}while($DisabledIndices -contains $p); $selected=$p }
                "DownArrow" { $n=$selected; do{$n++;if($n -ge $allItems.Count){$n=0}}while($DisabledIndices -contains $n); $selected=$n }
                "Enter"     { if ($DisabledIndices -notcontains $selected) { return $selected } }
                "B"         { if (-not $IsMain -and -not $NoAutoFooter) { return ($allItems.Count-3) } }
                "M"         { if (-not $NoAutoFooter) { return ($allItems.Count-2) } }
                "Q"         { if (-not $NoAutoFooter) { return ($allItems.Count-1) } }
            }
            if ($digitMap.ContainsKey($key.Key.ToString())) {
                $idx = $digitMap[$key.Key.ToString()]
                if ($idx -lt $Items.Count -and $DisabledIndices -notcontains $idx) { return $idx }
            }
        }
    } finally { [Console]::CursorVisible = $true }
}

function Invoke-ChoiceMenu {
    param([string]$Title,[string]$Color,[string[]]$Choices,[int]$CurrentIndex=0)
    $selected=$CurrentIndex; [Console]::CursorVisible=$false
    try {
        while ($true) {
            Clear-Host; Write-Header -Title $Title -Color $Color
            Write-Host "  ↑↓ Navigate   Enter Confirm   Esc Cancel" -ForegroundColor DarkGray
            Write-Host ""
            for ($i=0;$i -lt $Choices.Count;$i++) {
                $b = if ($i -eq $selected) { "◉" } else { "○" }
                if ($i -eq $selected) { Write-Host "  ► $b  $($Choices[$i])  " -BackgroundColor DarkCyan -ForegroundColor White }
                else                  { Write-Host "    $b  $($Choices[$i])" -ForegroundColor Gray }
            }
            Write-Host ""; $key = Read-MenuKey
            switch ($key.Key) {
                "UpArrow"   { if($selected -gt 0){$selected--}else{$selected=$Choices.Count-1} }
                "DownArrow" { if($selected -lt $Choices.Count-1){$selected++}else{$selected=0} }
                "Enter"     { return $selected }
                "Escape"    { return -1 }
            }
            $dm=@{"D1"=0;"D2"=1;"D3"=2;"D4"=3;"D5"=4}
            if ($dm.ContainsKey($key.Key.ToString())) { $idx=$dm[$key.Key.ToString()]; if($idx -lt $Choices.Count){return $idx} }
        }
    } finally { [Console]::CursorVisible = $true }
}

function Wait-AnyKey {
    Write-Host "  Press any key to continue..." -ForegroundColor DarkGray
    [Console]::ReadKey($true) | Out-Null
}

function Write-ConfigSummary {
    $hv  = if ($script:Config.ApicHost)  { $script:Config.ApicHost } else { "(not set)" }
    $uv  = if ($script:Config.Username)  { $script:Config.Username } else { "(not set)" }
    $pv  = if ($script:Config.Password)  { "••••••••" }              else { "(not set)" }
    $sv  = if ($script:Config.SSLVerify) { "Enabled ✔" }             else { "Disabled ✘" }
    $sc  = if ($script:Config.SSLVerify) { "Green" }                 else { "Red" }
    $ssv = if ($script:Session.LoggedIn) { "Active ✔  ($($script:Session.Username)@$($script:Session.Host))" } else { "Not logged in" }
    $ssc = if ($script:Session.LoggedIn) { "Green" } else { "DarkGray" }
    $db  = if ($script:DbPath.Length -gt 31) { "..."+$script:DbPath.Substring($script:DbPath.Length-28) } else { $script:DbPath }
    $cnt = Get-ApicHostCount
    $pref = Get-PreferredHost
    $pv2 = if ($cnt -gt 0) { "$cnt controller(s) — preferred: $(if($pref){$pref}else{'none (random)'})" } else { "none yet" }

    Write-Host "  ┌──────────────────────────────────────────────┐" -ForegroundColor DarkGray
    foreach ($row in @(
        @{L="Bootstrap ";V=$hv;C="Cyan"}
        @{L="Host Pool ";V=$pv2;C="DarkYellow"}
        @{L="Username  ";V=$uv;C="Cyan"}
        @{L="Password  ";V=$pv;C="Cyan"}
        @{L="SSL Verify";V=$sv;C=$sc}
        @{L="Session   ";V=$ssv;C=$ssc}
        @{L="DB Path   ";V=$db;C="DarkYellow"}
    )) {
        Write-Host "  │  $($row.L): " -NoNewline -ForegroundColor DarkGray
        Write-Host $row.V.PadRight(31) -NoNewline -ForegroundColor $row.C
        Write-Host "│" -ForegroundColor DarkGray
    }
    Write-Host "  └──────────────────────────────────────────────┘" -ForegroundColor DarkGray
    Write-Host ""
}

# ════════════════════════════════════════════════════════════════════════════════
#  CONTROLLER DISCOVERY + ENRICHMENT
# ════════════════════════════════════════════════════════════════════════════════

function Invoke-DiscoverControllers {
    $url       = "https://$($script:Session.Host)/api/node/class/topSystem.json?query-target-filter=eq(topSystem.role,`"controller`")"
    $token     = $script:Session.Token
    $sslVerify = $script:Session.SSLVerify

    $job = Start-Job -ScriptBlock {
        param($url,$token,$sslVerify)
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        try {
            $h = @{Cookie="APIC-cookie=$token"}
            if ($PSVersionTable.PSVersion.Major -ge 7) {
                $p = @{Uri=$url;Method='GET';Headers=$h;TimeoutSec=15}
                if (-not $sslVerify) { $p['SkipCertificateCheck']=$true }
                $r = Invoke-RestMethod @p
            } else {
                if (-not $sslVerify) {
                    if (-not ([System.Management.Automation.PSTypeName]'TrustAllDiscover').Type) {
                        Add-Type @"
using System.Net; using System.Security.Cryptography.X509Certificates;
public class TrustAllDiscover : ICertificatePolicy {
    public bool CheckValidationResult(ServicePoint sp,X509Certificate c,WebRequest req,int p){return true;} }
"@
                    }
                    [Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllDiscover
                }
                $r = Invoke-RestMethod -Uri $url -Method GET -Headers $h -TimeoutSec 15
            }
            $ips = @()
            foreach ($item in $r.imdata) {
                $a   = $item.topSystem.attributes
                $oob = $a.oobMgmtAddr; $inb = $a.inbMgmtAddr
                $ip  = if ($oob -and $oob -ne '0.0.0.0') { $oob } else { $inb }
                if ($ip -and $ip -ne '0.0.0.0') { $ips += $ip }
            }
            return @{Success=$true;IPs=$ips}
        } catch { return @{Success=$false;Error=$_.Exception.Message} }
    } -ArgumentList $url,$token,$sslVerify

    $res = $job | Wait-Job | Receive-Job -ErrorAction SilentlyContinue
    Remove-Job $job
    if ($res -and $res.Success -and $res.IPs.Count -gt 0) {
        Save-ApicHosts -IPs $res.IPs -Source 'discovered'
        return $res.IPs
    }
    return @()
}

function Invoke-EnrichControllers {
    # Queries fabricNode and topSystem to enrich apic_hosts with live fabric data.
    # Runs after login. Returns enriched count.
    if (-not $script:Session.LoggedIn) { return 0 }

    $sessionHost = $script:Session.Host
    $token       = $script:Session.Token
    $sslVerify   = $script:Session.SSLVerify

    $job = Start-Job -ScriptBlock {
        param($sessionHost,$token,$sslVerify)
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

        function ApicGet($path,$token,$sessionHost,$sslVerify) {
            if ($path -like 'topology/*' -or $path -match '/sys.json$') {
                $url = "https://$sessionHost/api/mo/$path"
            } else {
                $url = "https://$sessionHost/api/node/class/$path"
            }
            $h   = @{Cookie="APIC-cookie=$token"}
            if ($PSVersionTable.PSVersion.Major -ge 7) {
                $p = @{Uri=$url;Method='GET';Headers=$h;TimeoutSec=15}
                if (-not $sslVerify) { $p['SkipCertificateCheck']=$true }
                return Invoke-RestMethod @p
            } else {
                if (-not $sslVerify) {
                    if (-not ([System.Management.Automation.PSTypeName]'TrustAllEnrich').Type) {
                        Add-Type @"
using System.Net; using System.Security.Cryptography.X509Certificates;
public class TrustAllEnrich : ICertificatePolicy {
    public bool CheckValidationResult(ServicePoint sp,X509Certificate c,WebRequest req,int p){return true;} }
"@
                    }
                    [Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllEnrich
                }
                return Invoke-RestMethod -Uri $url -Method GET -Headers $h -TimeoutSec 15
            }
        }

        try {
            # ── topSystem: OOB IP, uptime, nodeId, serial ────────────────────
            $ts = ApicGet 'topSystem.json?query-target-filter=eq(topSystem.role,"controller")&rsp-subtree=children&rsp-subtree-class=healthInst' $token $sessionHost $sslVerify
            
            # Build result map with node info
            $results = @()
            foreach ($item in $ts.imdata) {
                $a   = $item.topSystem.attributes
                $ip  = if ($a.oobMgmtAddr -and $a.oobMgmtAddr -ne '0.0.0.0') { $a.oobMgmtAddr } else { $a.inbMgmtAddr }
                if (-not $ip -or $ip -eq '0.0.0.0') { continue }

                # Parse pod/node from DN
                $podId = if ($a.dn -match 'pod-([^/]+)') { $matches[1] } else { "unknown" }
                $nodeId = $a.id
                
                # Health from child healthInst
                $health = 100
                if ($item.topSystem.children) {
                    foreach ($child in $item.topSystem.children) {
                        if ($child.healthInst) {
                            $hv = $child.healthInst.attributes.cur
                            if ($hv) { $health = [int]$hv }
                        }
                    }
                }

                $results += @{
                    IP       = $ip
                    NodeId   = $nodeId
                    PodId    = $podId
                    NodeName = $a.name
                    Model    = $a.model
                    Firmware = $a.version
                    Serial   = $a.serial
                    Uptime   = $a.systemUpTime
                    Health   = $health
                }
            }
            
            # ── Enrich with fabric state from topology/pod-X/node-Y/sys ─────
            foreach ($result in $results) {
                $sysPath = "topology/pod-$($result.PodId)/node-$($result.NodeId)/sys.json"
                try {
                    $sys = ApicGet $sysPath $token $sessionHost $sslVerify
                    if ($sys -and $sys.imdata -and $sys.imdata.Count -gt 0) {
                        $entry = $sys.imdata[0]
                        # Determine the child property name (e.g. topSystem / nodeSys / fabricNode)
                        $childProp = ($entry | Get-Member -MemberType NoteProperty | Select-Object -First 1 -ExpandProperty Name)
                        if ($childProp -and $entry.$childProp -and $entry.$childProp.attributes) {
                            $sysAttr = $entry.$childProp.attributes
                            # Try common attribute names for state
                            $stateVal = $null
                            if ($sysAttr.PSObject.Properties.Name -contains 'state') { $stateVal = $sysAttr.state }
                            elseif ($sysAttr.PSObject.Properties.Name -contains 'fabricSt') { $stateVal = $sysAttr.fabricSt }
                            elseif ($sysAttr.PSObject.Properties.Name -contains 'operSt') { $stateVal = $sysAttr.operSt }
                            else {
                                # Fallback: pick any property named like *state*
                                foreach ($pn in $sysAttr.PSObject.Properties.Name) { if ($pn -match 'state') { $stateVal = $sysAttr.$pn; break } }
                            }
                            $result['FabricState'] = if ($stateVal) { $stateVal } else { 'unknown' }
                        } else {
                            $result['FabricState'] = 'unknown'
                        }
                    } else {
                        $result['FabricState'] = 'unknown'
                    }
                } catch {
                    $result['FabricState'] = 'unknown'
                }
            }
            
            return @{Success=$true;Results=$results}
        } catch { return @{Success=$false;Error=$_.Exception.Message} }

    } -ArgumentList $sessionHost,$token,$sslVerify

    $res = $job | Wait-Job | Receive-Job -ErrorAction SilentlyContinue
    Remove-Job $job

    if ($res -and $res.Success) {
        foreach ($r in $res.Results) {
            # Ensure host row exists
            Save-ApicHosts -IPs @($r.IP) -Source 'discovered'
            Update-ApicHostFabricData `
                -IP          $r.IP `
                -NodeId      $r.NodeId `
                -PodId       $r.PodId `
                -NodeName    $r.NodeName `
                -FabricState $r.FabricState `
                -Model       $r.Model `
                -Firmware    $r.Firmware `
                -Uptime      $r.Uptime `
                -HealthScore $r.Health `
                -Serial      $r.Serial
        }
        return $res.Results.Count
    }
    return 0
}

# ════════════════════════════════════════════════════════════════════════════════
#  APIC LOGIN  —  random/preferred pool with automatic failover
# ════════════════════════════════════════════════════════════════════════════════

function Test-ApicLogin {
    Clear-Host; Write-Header "🔌  Test Login" "DarkYellow"
    Write-ConfigSummary

    $hostPool  = Get-ApicHostPool
    $username  = $script:Config.Username
    $password  = $script:Config.Password
    $sslVerify = $script:Config.SSLVerify

    if ($hostPool.Count -eq 0) {
        Write-Host "  ✘  No hosts configured. Set a bootstrap host first." -ForegroundColor Red
        Write-Host ""; Wait-AnyKey; return
    }

    $pref = Get-PreferredHost
    Write-Host "  🎲  Host pool   : " -NoNewline -ForegroundColor DarkGray
    Write-Host "$($hostPool.Count) host(s)" -NoNewline -ForegroundColor Cyan
    if ($pref) { Write-Host "  —  preferred: " -NoNewline -ForegroundColor DarkGray; Write-Host "$pref ⭐" -NoNewline -ForegroundColor Yellow }
    Write-Host ""
    if (-not $sslVerify) { Write-Host "  ⚠  SSL verification disabled." -ForegroundColor DarkYellow }
    Write-Host ""

    $frames = @('-','\','|','/')
    $frame  = 0

    $job = Start-Job -ScriptBlock {
        param($hostPool,$username,$password,$sslVerify)
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        if (-not $sslVerify -and $PSVersionTable.PSVersion.Major -lt 7) {
            if (-not ([System.Management.Automation.PSTypeName]'TrustAllLogin').Type) {
                Add-Type @"
using System.Net; using System.Security.Cryptography.X509Certificates;
public class TrustAllLogin : ICertificatePolicy {
    public bool CheckValidationResult(ServicePoint sp,X509Certificate c,WebRequest req,int p){return true;} }
"@
            }
            [Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllLogin
        }
        $body = @{aaaUser=@{attributes=@{name=$username;pwd=$password}}} | ConvertTo-Json -Depth 5
        $attempted = @(); $lastError = "No hosts"

        foreach ($h in $hostPool) {
            $attempted += $h
            try {
                $url = "https://$h/api/aaaLogin.json"
                if ($PSVersionTable.PSVersion.Major -ge 7) {
                    $p = @{Uri=$url;Method='POST';Body=$body;ContentType='application/json';TimeoutSec=10}
                    if (-not $sslVerify) { $p['SkipCertificateCheck']=$true }
                    $r = Invoke-RestMethod @p
                } else {
                    $r = Invoke-RestMethod -Uri $url -Method POST -Body $body -ContentType 'application/json' -TimeoutSec 10
                }
                return @{Success=$true;Host=$h;Token=$r.imdata[0].aaaLogin.attributes.token;Attempted=$attempted}
            } catch {
                $msg = $_.Exception.Message
                try { $d=$_.ErrorDetails.Message|ConvertFrom-Json; $e=$d.imdata[0].error.attributes.text; if($e){$msg=$e} } catch {}
                $lastError = "[$h] $msg"
            }
        }
        return @{Success=$false;Attempted=$attempted;Error=$lastError}
    } -ArgumentList $hostPool,$username,$password,$sslVerify

    [Console]::CursorVisible = $false
    while ($job.State -eq 'Running') {
        Write-Host "`r  [$($frames[$frame%$frames.Count])]  Trying $($hostPool.Count) host(s)..." -NoNewline -ForegroundColor Cyan
        $frame++; Start-Sleep -Milliseconds 120
    }
    $result = Receive-Job $job -ErrorAction SilentlyContinue
    Remove-Job $job
    Write-Host ("`r" + (" " * 60) + "`r") -NoNewline

    if ($result -and $result.Success) {
        $script:Session.LoggedIn  = $true
        $script:Session.Token     = $result.Token
        $script:Session.Host      = $result.Host
        $script:Session.Username  = $username
        $script:Session.SSLVerify = $sslVerify

        Update-ApicHostStatus -IP $result.Host -Status 'ok'
        foreach ($h in $result.Attempted | Where-Object {$_ -ne $result.Host}) {
            Update-ApicHostStatus -IP $h -Status 'failed'
        }

        Write-Host "  ╔══════════════════════════════════╗" -ForegroundColor Green
        Write-Host "  ║   ✔  Login Successful!           ║" -ForegroundColor Green
        Write-Host "  ╚══════════════════════════════════╝" -ForegroundColor Green
        Write-Host ""
        Write-Host "  Connected : " -NoNewline -ForegroundColor DarkGray; Write-Host $result.Host -ForegroundColor Cyan
        if ($result.Attempted.Count -gt 1) {
            Write-Host "  Tried     : " -NoNewline -ForegroundColor DarkGray
            Write-Host "$($result.Attempted.Count) host(s) before success" -ForegroundColor DarkYellow
        }
        Write-Host "  User      : " -NoNewline -ForegroundColor DarkGray; Write-Host $username -ForegroundColor Cyan
        Write-Host "  Token     : " -NoNewline -ForegroundColor DarkGray
        Write-Host "$($result.Token.Substring(0,[Math]::Min(32,$result.Token.Length)))..." -ForegroundColor Green
        Write-Host "  SSL       : " -NoNewline -ForegroundColor DarkGray
        if ($sslVerify) { Write-Host "Verified ✔" -ForegroundColor Green }
        else            { Write-Host "Skipped ⚠ (self-signed)" -ForegroundColor DarkYellow }

        # ── Discover + Enrich ─────────────────────────────────────────────────
        Write-Host ""
        Write-Host "  🔍  Discovering controllers..." -NoNewline -ForegroundColor DarkGray
        $disc = Invoke-DiscoverControllers
        if ($disc.Count -gt 0) { Write-Host " ✔  Found $($disc.Count)" -ForegroundColor Green }
        else                   { Write-Host " ⚠  Not found" -ForegroundColor DarkYellow }

        Write-Host "  📊  Enriching fabric data..." -NoNewline -ForegroundColor DarkGray
        $enriched = Invoke-EnrichControllers
        if ($enriched -gt 0) { Write-Host " ✔  $enriched controller(s) enriched" -ForegroundColor Green }
        else                  { Write-Host " ⚠  Enrichment failed (check permissions)" -ForegroundColor DarkYellow }

    } else {
        $script:Session.LoggedIn = $false; $script:Session.Token = $null
        foreach ($h in $result.Attempted) { Update-ApicHostStatus -IP $h -Status 'failed' }

        $errMsg = if ($result -and $result.Error) { $result.Error } else { "No response." }
        Write-Host "  ╔══════════════════════════════════╗" -ForegroundColor Red
        Write-Host "  ║   ✘  Login Failed!               ║" -ForegroundColor Red
        Write-Host "  ╚══════════════════════════════════╝" -ForegroundColor Red
        Write-Host ""
        Write-Host "  Tried $($result.Attempted.Count) host(s) — all failed." -ForegroundColor DarkYellow
        Write-Host "  Last Error : " -NoNewline -ForegroundColor DarkGray; Write-Host $errMsg -ForegroundColor Red
        Write-Host "  SSL        : " -NoNewline -ForegroundColor DarkGray
        if ($sslVerify) { Write-Host "Verify ON  ⚠ (try disabling for self-signed)" -ForegroundColor DarkYellow }
        else            { Write-Host "Verify OFF ⚠ (check credentials/reachability)" -ForegroundColor DarkYellow }
    }
    Write-Host ""; Wait-AnyKey
}

# ════════════════════════════════════════════════════════════════════════════════
#  APIC LOGOUT
# ════════════════════════════════════════════════════════════════════════════════

function Invoke-ApicLogout {
    param([bool]$Silent = $false)
    if (-not $script:Session.LoggedIn -or -not $script:Session.Token) {
        if (-not $Silent) { Write-Host "  ℹ  No active APIC session." -ForegroundColor DarkGray; Write-Host ""; Wait-AnyKey }
        return
    }
    $url=$script:Session.Host; $tok=$script:Session.Token; $ssl=$script:Session.SSLVerify
    $body=@{aaaUser=@{attributes=@{name=$script:Session.Username}}}|ConvertTo-Json -Depth 5
    if (-not $Silent) {
        Clear-Host; Write-Header "🔌  APIC Logout" "DarkYellow"
        Write-Host "  Host : " -NoNewline -ForegroundColor DarkGray; Write-Host $script:Session.Host -ForegroundColor Cyan
        Write-Host "  User : " -NoNewline -ForegroundColor DarkGray; Write-Host $script:Session.Username -ForegroundColor Cyan
        Write-Host ""
    }
    $frames=@('-','\','|','/'); $frame=0
    $job = Start-Job -ScriptBlock {
        param($h,$body,$tok,$ssl)
        [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
        try {
            $url="https://$h/api/aaaLogout.json"; $hdr=@{Cookie="APIC-cookie=$tok"}
            if ($PSVersionTable.PSVersion.Major -ge 7) {
                $p=@{Uri=$url;Method='POST';Body=$body;ContentType='application/json';Headers=$hdr;TimeoutSec=10}
                if (-not $ssl){$p['SkipCertificateCheck']=$true}
                Invoke-RestMethod @p|Out-Null
            } else {
                if (-not $ssl) {
                    if (-not ([System.Management.Automation.PSTypeName]'TrustAllLogout').Type) {
                        Add-Type @"
using System.Net; using System.Security.Cryptography.X509Certificates;
public class TrustAllLogout : ICertificatePolicy {
    public bool CheckValidationResult(ServicePoint sp,X509Certificate c,WebRequest req,int p){return true;} }
"@
                    }
                    [Net.ServicePointManager]::CertificatePolicy=New-Object TrustAllLogout
                }
                Invoke-RestMethod -Uri $url -Method POST -Body $body -ContentType 'application/json' -Headers $hdr -TimeoutSec 10|Out-Null
            }
            return @{Success=$true}
        } catch { return @{Success=$false;Error=$_.Exception.Message} }
    } -ArgumentList $url,$body,$tok,$ssl

    if (-not $Silent) { [Console]::CursorVisible=$false }
    while ($job.State -eq 'Running') {
        if (-not $Silent) { Write-Host "`r  [$($frames[$frame%$frames.Count])]  Logging out..." -NoNewline -ForegroundColor Cyan }
        $frame++; Start-Sleep -Milliseconds 120
    }
    $res=Receive-Job $job -ErrorAction SilentlyContinue; Remove-Job $job

    $script:Session.LoggedIn=$false; $script:Session.Token=$null
    $script:Session.Host=$null;       $script:Session.Username=$null

    if (-not $Silent) {
        Write-Host ("`r" + (" " * 60) + "`r") -NoNewline
        if ($res -and $res.Success) {
            Write-Host "  ╔══════════════════════════════════╗" -ForegroundColor Green
            Write-Host "  ║   ✔  Logout Successful!          ║" -ForegroundColor Green
            Write-Host "  ╚══════════════════════════════════╝" -ForegroundColor Green
        } else {
            Write-Host "  ╔══════════════════════════════════╗" -ForegroundColor DarkYellow
            Write-Host "  ║   ⚠  Logout response error       ║" -ForegroundColor DarkYellow
            Write-Host "  ╚══════════════════════════════════╝" -ForegroundColor DarkYellow
            Write-Host "  Session cleared locally." -ForegroundColor DarkGray
            if ($res -and $res.Error) { Write-Host "  Error : $($res.Error)" -ForegroundColor DarkYellow }
        }
        Write-Host ""; Wait-AnyKey
    }
}

function Invoke-Quit {
    Clear-Host; Write-Host ""
    if ($script:Session.LoggedIn) {
        Write-Host "  ╔══════════════════════════════════╗" -ForegroundColor DarkYellow
        Write-Host "  ║   🔌  Logging out from APIC...   ║" -ForegroundColor DarkYellow
        Write-Host "  ╚══════════════════════════════════╝" -ForegroundColor DarkYellow
        Write-Host ""
        Write-Host "  Host : " -NoNewline -ForegroundColor DarkGray; Write-Host $script:Session.Host     -ForegroundColor Cyan
        Write-Host "  User : " -NoNewline -ForegroundColor DarkGray; Write-Host $script:Session.Username -ForegroundColor Cyan
        Write-Host ""
        Invoke-ApicLogout -Silent $true
        Write-Host "  ✔  Session closed." -ForegroundColor Green; Write-Host ""
    }
    Write-Host "  ╔══════════════════════════════════╗" -ForegroundColor DarkRed
    Write-Host "  ║      👋  Goodbye! Exiting...     ║" -ForegroundColor DarkRed
    Write-Host "  ╚══════════════════════════════════╝" -ForegroundColor DarkRed
    Write-Host ""; $script:ExitRequested = $true
}

# ════════════════════════════════════════════════════════════════════════════════
#  INTERACTIVE HOST POOL TABLE
# ════════════════════════════════════════════════════════════════════════════════

function Show-DiscoveredHosts {
    [Console]::CursorVisible = $false
    $selected = 0   # initialise here — safe for all loop iterations

    function Draw-HostTable {
        param($rows, $selected, $canEnrich)

        Clear-Host
        Write-Header "🎲  APIC Controller Pool" "DarkYellow"
        
        $helpMsg = "  ↑↓ Navigate   P/Enter Set preferred   B/Esc Back"
        if ($canEnrich) { $helpMsg = "  ↑↓ Navigate   P/Enter Set preferred   R Refresh fabric data   B/Esc Back" }
        Write-Host $helpMsg -ForegroundColor DarkGray
        Write-Host ""

        if ($rows.Count -eq 0) {
            Write-Host "  ℹ  No controllers discovered yet." -ForegroundColor DarkGray
            Write-Host "  💡  Perform a login to auto-discover all APIC controllers." -ForegroundColor DarkGray
            Write-Host ""
            return
        }

        # Header (adjusted widths for readability)
        Write-Host ("  {0,-3} {1,-18} {2,-10} {3,-14} {4,-18} {5,-7} {6,-6} {7,-14} {8,-18} {9}" `
            -f "","IP","Pod/Node","Fabric State","Name","Health","Src","Serial","Firmware","Uptime") -ForegroundColor DarkGray
        Write-Host "  ─────────────────────────────────────────────────────────────────────────────────────────────────────────────" -ForegroundColor DarkGray

        for ($i = 0; $i -lt $rows.Count; $i++) {
            $r = $rows[$i]

            # Fabric state icon + color (include 'in-service')
            $fs = if ($r.fabric_state) { $r.fabric_state.ToLower() } else { 'unknown' }
            $stateIcon  = switch ($fs) {
                'in-service'  { '✔' }; 'active'      { '✔' }; 'inactive'    { '✘' }; 'maintenance' { '⚠' }; default { '?' }
            }
            $stateColor = switch ($fs) {
                'in-service'  { 'Green' }; 'active'      { 'Green' }; 'inactive' { 'Red' }; 'maintenance' { 'DarkYellow' }; default { 'DarkGray' }
            }

            # Health score color
            $hs = if ($r.health_score) { $r.health_score } else { $null }
            $healthStr  = if ($hs -ne $null) { "$hs%" } else { "N/A" }
            $healthColor= if ($hs -ge 90) { 'Green' } elseif ($hs -ge 70) { 'Yellow' } elseif ($hs -ne $null) { 'Red' } else { 'DarkGray' }

            $prefIcon   = if ($r.is_preferred -eq 1) { "⭐" } else { "  " }
            $pn         = if ($r.pod_id -and $r.node_id) { "P$($r.pod_id)/N$($r.node_id)" } else { "N/A" }
            $nm         = if ($r.node_name)   { $r.node_name }  else { "N/A" }
            $sn         = if ($r.serial)      { $r.serial } else { "N/A" }
            $fw         = if ($r.firmware)    { $r.firmware.Substring(0,[Math]::Min(18,$r.firmware.Length)) } else { "N/A" }
            $up         = if ($r.uptime)      { Format-ApicUptime $r.uptime } else { "N/A" }
            $src        = if ($r.source -eq 'manual') { "manual" } else { "disc." }

            if ($i -eq $selected) {
                Write-Host "  ► " -NoNewline -ForegroundColor White
            } else {
                Write-Host "    " -NoNewline
            }
            Write-Host "$prefIcon " -NoNewline -ForegroundColor Yellow
            
            $ipColor = if ($i -eq $selected) { 'White' } else { 'Cyan' }
            Write-Host ("{0,-18}" -f $r.ip) -NoNewline -ForegroundColor $ipColor
            Write-Host ("{0,-10}" -f $pn) -NoNewline -ForegroundColor DarkGray

            # State cell — display fabric_state
            $stateName = if ($r.fabric_state) { $r.fabric_state } else { "unknown" }
            $stateCell = "{0,-14}" -f "$stateIcon $stateName"
            Write-Host $stateCell -NoNewline -ForegroundColor $stateColor

            Write-Host ("{0,-18}" -f $nm) -NoNewline -ForegroundColor Gray
            Write-Host ("{0,-7}" -f $healthStr) -NoNewline -ForegroundColor $healthColor
            Write-Host ("{0,-6}" -f $src) -NoNewline -ForegroundColor DarkGray
            Write-Host ("{0,-14}" -f $sn) -NoNewline -ForegroundColor Cyan
            Write-Host ("{0,-18}" -f $fw) -NoNewline -ForegroundColor DarkGray
            Write-Host ("{0}" -f $up) -ForegroundColor DarkGray
        }

        Write-Host ""
        # Footer: last enriched
        $enriched = $rows | Where-Object { $_.last_enriched } | Sort-Object last_enriched -Descending | Select-Object -First 1
        if ($enriched) {
            Write-Host "  📊  Last enriched : " -NoNewline -ForegroundColor DarkGray
            Write-Host $enriched.last_enriched -ForegroundColor DarkGray
        }
        $pref = $rows | Where-Object { $_.is_preferred -eq 1 } | Select-Object -First 1
        if ($pref) {
            Write-Host "  ⭐  Preferred host: " -NoNewline -ForegroundColor DarkGray
            Write-Host $pref.ip -ForegroundColor Yellow
            Write-Host "     (tried first on next login)" -ForegroundColor DarkGray
        } else {
            Write-Host "  🎲  No preferred host — pool used in random order" -ForegroundColor DarkGray
        }
        Write-Host ""
        Write-Host "  [B]  ← Back        [Q]  ✕ Quit" -ForegroundColor DarkGray
    }

    try {
        while ($true) {
            # Fresh read each loop iteration
            $rows = @()
            if (Test-Path $script:DbPath) {
                try {
                    $raw = Invoke-SqliteQuery -DataSource $script:DbPath -Query @"
SELECT ip, source, is_preferred, node_id, pod_id, node_name,
       fabric_state, model, firmware, serial, uptime, health_score,
       last_enriched, last_status, last_used_at
FROM apic_hosts
ORDER BY is_preferred DESC, pod_id, CAST(node_id AS INTEGER)
"@
                    $rows = @($raw)
                } catch {
                    Write-Host "DB Query Error: $_" -ForegroundColor Red
                    Start-Sleep -Seconds 2
                    return
                }
            } else {
                # Database doesn't exist yet - just show empty pool message
                $rows = @()
            }

            $canEnrich = $script:Session.LoggedIn
            if ($rows.Count -gt 0) {
                $selected = [Math]::Max(0, [Math]::Min($selected, $rows.Count - 1))
            } else {
                $selected = 0
            }

            Draw-HostTable -rows $rows -selected $selected -canEnrich $canEnrich

            if ($rows.Count -eq 0) { Wait-AnyKey; return }

            $key = Read-MenuKey

            switch ($key.Key) {
                "UpArrow"   { if ($selected -gt 0) { $selected-- } else { $selected = $rows.Count-1 } }
                "DownArrow" { if ($selected -lt $rows.Count-1) { $selected++ } else { $selected = 0 } }
                "P"         {
                    $ip = $rows[$selected].ip
                    if ($rows[$selected].is_preferred -eq 1) {
                        Set-PreferredHost -IP $null
                    } else {
                        Set-PreferredHost -IP $ip
                    }
                }
                "Enter" {
                    $ip = $rows[$selected].ip
                    if ($rows[$selected].is_preferred -eq 1) {
                        Set-PreferredHost -IP $null
                    } else {
                        Set-PreferredHost -IP $ip
                    }
                }
                "R" {
                    if ($canEnrich) {
                        Clear-Host; Write-Header "📊  Refreshing Fabric Data" "DarkYellow"
                        Write-Host "  🔄  Querying APIC fabric state..." -ForegroundColor DarkGray
                        $n = Invoke-EnrichControllers
                        if ($n -gt 0) { Write-Host "  ✔  $n controller(s) updated." -ForegroundColor Green }
                        else          { Write-Host "  ⚠  Refresh failed (check session)." -ForegroundColor DarkYellow }
                        Start-Sleep -Milliseconds 800
                    }
                }
                "B"      { return }
                "Escape" { return }
                "Q"      { 
                    Invoke-Quit
                    return
                }
            }
        }
    } catch {
        Clear-Host
        Write-Host "ERROR in Host Pool function:" -ForegroundColor Red
        Write-Host "$_" -ForegroundColor Yellow
        Write-Host ""
        Wait-AnyKey
    } finally {
        [Console]::CursorVisible = $true
    }
}

# ════════════════════════════════════════════════════════════════════════════════
#  SETTINGS ACTIONS
# ════════════════════════════════════════════════════════════════════════════════

function Set-ApicHost {
    Clear-Host; Write-Header "🔩  Set APIC Bootstrap Host" "DarkYellow"
    [Console]::CursorVisible = $true

    if ($script:Config.ApicHost) {
        Write-Host "  Current bootstrap : " -NoNewline -ForegroundColor DarkGray
        Write-Host $script:Config.ApicHost -ForegroundColor Cyan
    }
    $cnt = Get-ApicHostCount
    if ($cnt -gt 0) {
        Write-Host "  Discovered hosts  : " -NoNewline -ForegroundColor DarkGray
        Write-Host "$cnt controller(s) in pool (used automatically)" -ForegroundColor DarkYellow
    }
    $pref = Get-PreferredHost
    if ($pref) {
        Write-Host "  Preferred host    : " -NoNewline -ForegroundColor DarkGray
        Write-Host "$pref ⭐" -ForegroundColor Yellow
    }
    Write-Host ""
    Write-Host "  Bootstrap host is used for first login." -ForegroundColor DarkGray
    Write-Host "  After login all discovered controllers are used with failover." -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Enter IP or hostname (Enter to cancel): " -ForegroundColor Gray
    Write-Host "  > " -NoNewline -ForegroundColor DarkYellow
    $inp = Read-Host; Write-Host ""

    if ([string]::IsNullOrWhiteSpace($inp)) {
        if ($script:Config.ApicHost) { Write-Host "  ⚠  No changes made." -ForegroundColor DarkGray }
        else { Write-Host "  ⚠  Bootstrap host not set." -ForegroundColor DarkYellow }
    } else {
        $script:Config.ApicHost = $inp.Trim()
        Save-ApicHosts -IPs @($script:Config.ApicHost) -Source 'manual'
        Save-Config
        Write-Host "  ✔  Bootstrap host: " -NoNewline -ForegroundColor Green; Write-Host $script:Config.ApicHost -ForegroundColor Cyan
        Write-Host "  💾  Saved (encrypted)." -ForegroundColor DarkGray
    }
    Write-Host ""; [Console]::CursorVisible = $false; Wait-AnyKey
}

function Set-Credentials {
    Clear-Host; Write-Header "🔩  Set Credentials" "DarkYellow"
    [Console]::CursorVisible = $true

    $usernameOk = $false
    while (-not $usernameOk) {
        $cur = if ($script:Config.Username) { " (current: $($script:Config.Username))" } else { "" }
        Write-Host "  Username$cur : " -NoNewline -ForegroundColor Gray
        $user = Read-Host
        if ([string]::IsNullOrWhiteSpace($user)) {
            if ($script:Config.Username) { $user=$script:Config.Username; $usernameOk=$true }
            else { Write-Host "  ✘  Username cannot be empty." -ForegroundColor Red }
        } else { $usernameOk=$true }
    }
    $passwordOk = $false
    while (-not $passwordOk) {
        $cur = if ($script:Config.Password) { " (current: ••••••••)" } else { "" }
        Write-Host "  Password$cur : " -NoNewline -ForegroundColor Gray
        $pc = @()
        while ($true) {
            $k = [Console]::ReadKey($true)
            if ($k.Key -eq "Enter")     { break }
            if ($k.Key -eq "Backspace") { if ($pc.Count -gt 0) { $pc=$pc[0..($pc.Count-2)]; Write-Host "`b `b" -NoNewline } }
            else { $pc += $k.KeyChar; Write-Host "•" -NoNewline }
        }
        Write-Host ""
        $pass = -join $pc
        if ([string]::IsNullOrWhiteSpace($pass)) {
            if ($script:Config.Password) { $pass=$script:Config.Password; $passwordOk=$true }
            else { Write-Host "  ✘  Password cannot be empty." -ForegroundColor Red }
        } else { $passwordOk=$true }
    }
    Write-Host ""
    Write-Host "  Confirm save? [Y/N] : " -NoNewline -ForegroundColor DarkGray
    $confirm=[Console]::ReadKey($true); Write-Host $confirm.KeyChar
    if ($confirm.Key -eq "Y") {
        $script:Config.Username=$user; $script:Config.Password=$pass
        Save-Config
        Write-Host ""; Write-Host "  ✔  Credentials saved." -ForegroundColor Green
        Write-Host "  💾  Saved (encrypted)." -ForegroundColor DarkGray
    } else { Write-Host ""; Write-Host "  ⚠  No changes made." -ForegroundColor DarkGray }
    Write-Host ""; [Console]::CursorVisible=$false; Wait-AnyKey
}

function Set-SSLVerify {
    $ci = if ($script:Config.SSLVerify) { 0 } else { 1 }
    $ch = Invoke-ChoiceMenu -Title "🔩  Toggle SSL Verify       " -Color "DarkYellow" `
        -Choices @(
            "True  — Verify SSL certificates (recommended)"
            "False — Skip SSL verification (lab/self-signed)"
        ) -CurrentIndex $ci
    Clear-Host; Write-Header "🔩  Toggle SSL Verify" "DarkYellow"
    if ($ch -ge 0) {
        $script:Config.SSLVerify = ($ch -eq 0)
        $label = if ($script:Config.SSLVerify) { "Enabled ✔" } else { "Disabled ✘" }
        $color = if ($script:Config.SSLVerify) { "Green" }     else { "Red" }
        Save-Config
        Write-Host "  SSL Verify: " -NoNewline -ForegroundColor Gray; Write-Host $label -ForegroundColor $color
        Write-Host "  💾  Saved." -ForegroundColor DarkGray
    } else { Write-Host "  ⚠  No changes made." -ForegroundColor DarkGray }
    Write-Host ""; Wait-AnyKey
}

function Show-CurrentConfig {
    Clear-Host; Write-Header "🔩  Current Configuration" "DarkYellow"
    Write-ConfigSummary
    $info = Get-DbInfo
    Write-Host "  ┌──────────────────────────────────────────────┐" -ForegroundColor DarkGray
    Write-Host "  │  🗄  Database Info                           │" -ForegroundColor DarkGray
    Write-Host "  ├──────────────────────────────────────────────┤" -ForegroundColor DarkGray
    if ($info.Exists) {
        @(
            @{L="Status   ";V="Connected ✔";                  C="Green"     }
            @{L="Size     ";V="$($info.Size) KB";              C="Cyan"      }
            @{L="Settings ";V="$($info.Rows) records";         C="Cyan"      }
            @{L="Hosts    ";V="$($info.Hosts) controller(s)";  C="DarkYellow"}
            @{L="Created  ";V="$($info.Created)";              C="Cyan"      }
            @{L="Version  ";V="$($info.Version)";              C="Cyan"      }
            @{L="Encrypt  ";V="DPAPI — host/user/pass 🔒";    C="DarkGreen" }
        ) | ForEach-Object {
            Write-Host "  │  $($_.L): " -NoNewline -ForegroundColor DarkGray
            Write-Host ($_.V.PadRight(35)) -NoNewline -ForegroundColor $_.C
            Write-Host "│" -ForegroundColor DarkGray
        }
    } else {
        Write-Host "  │  Status   : Not created yet ✘                  │" -ForegroundColor DarkGray
    }
    Write-Host "  └──────────────────────────────────────────────┘" -ForegroundColor DarkGray
    Write-Host ""; Wait-AnyKey
}

function Set-DbFolder {
    Clear-Host; Write-Header "🗄  Change Database Folder" "DarkYellow"
    [Console]::CursorVisible = $true
    Write-Host "  Current folder : " -NoNewline -ForegroundColor DarkGray; Write-Host $script:DbFolder -ForegroundColor Cyan
    Write-Host "  Pointer file   : " -NoNewline -ForegroundColor DarkGray; Write-Host $script:PointerFile -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Enter new folder path (Enter to cancel):" -ForegroundColor Gray
    Write-Host "  > " -NoNewline -ForegroundColor DarkYellow
    $nf = Read-Host
    if ([string]::IsNullOrWhiteSpace($nf)) {
        Write-Host ""; Write-Host "  ⚠  No changes made." -ForegroundColor DarkGray
        Write-Host ""; [Console]::CursorVisible=$false; Wait-AnyKey; return
    }
    $nf = [System.Environment]::ExpandEnvironmentVariables($nf)
    $nf = [System.IO.Path]::GetFullPath($nf)
    Write-Host ""
    if (-not (Test-Path $nf)) {
        Write-Host "  Create folder? [Y/N] : " -NoNewline -ForegroundColor DarkGray
        $yn=[Console]::ReadKey($true); Write-Host $yn.KeyChar
        if ($yn.Key -ne "Y") { Write-Host "  ⚠  Cancelled." -ForegroundColor DarkGray; Write-Host ""; [Console]::CursorVisible=$false; Wait-AnyKey; return }
        New-Item -ItemType Directory -Path $nf -Force | Out-Null
        Write-Host "  ✔  Folder created." -ForegroundColor Green
    }
    $newDb = Join-Path $nf $script:DbFile
    if (Test-Path $script:DbPath) {
        Write-Host "  Move existing database? [Y/N] : " -NoNewline -ForegroundColor DarkGray
        $mv=[Console]::ReadKey($true); Write-Host $mv.KeyChar
        if ($mv.Key -eq "Y") {
            try {
                Copy-Item -Path $script:DbPath -Destination $newDb -Force
                Remove-Item -Path $script:DbPath -Force
                Write-Host "  ✔  Moved to: $newDb" -ForegroundColor Green
            } catch { Write-Host "  ✘  Move failed: $_" -ForegroundColor Red; Write-Host ""; [Console]::CursorVisible=$false; Wait-AnyKey; return }
        } else { Write-Host "  ℹ  New empty database at new location." -ForegroundColor DarkGray }
    }
    $script:DbFolder=$nf; $script:DbPath=$newDb
    Write-DbPointer -Path $script:DbPath
    Save-Config
    Write-Host ""; Write-Host "  ✔  DB folder: $script:DbFolder" -ForegroundColor Green
    Write-Host "  📌  Pointer updated: $script:PointerFile" -ForegroundColor DarkGreen
    Write-Host "  💾  Config saved to new DB." -ForegroundColor DarkGray
    Write-Host ""; [Console]::CursorVisible=$false; Wait-AnyKey
}

function Set-InputFolder {
    Clear-Host; Write-Header "📂  Input Folder for bulk ops" "DarkYellow"
    [Console]::CursorVisible = $true
    $scriptLocation = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    $default = if ($script:Config.InputFolder) { $script:Config.InputFolder } else { $scriptLocation }

    Write-Host "  Current (default): $default" -ForegroundColor DarkGray
    Write-Host "  Enter folder path (Enter = use default, Esc to cancel): " -NoNewline -ForegroundColor DarkYellow
    $inp = Read-Host

    if ([string]::IsNullOrWhiteSpace($inp)) { $nf = $default } else { $nf = [System.Environment]::ExpandEnvironmentVariables($inp); $nf = [System.IO.Path]::GetFullPath($nf) }

    # Create folder if missing
    if (-not (Test-Path $nf)) {
        Write-Host ""; Write-Host "  Folder does not exist: $nf" -ForegroundColor DarkYellow
        Write-Host "  Create folder? [Y/N] : " -NoNewline -ForegroundColor DarkGray
        $yn=[Console]::ReadKey($true); Write-Host $yn.KeyChar
        if ($yn.Key -ne "Y") { Write-Host ""; Write-Host "  ⚠  Cancelled." -ForegroundColor DarkGray; [Console]::CursorVisible=$false; Wait-AnyKey; return }
        try { New-Item -ItemType Directory -Path $nf -Force | Out-Null } catch { Write-Host "  ✘  Could not create: $_" -ForegroundColor Red; [Console]::CursorVisible=$false; Wait-AnyKey; return }
    }

    # Check read permission by attempting to enumerate
    try {
        Get-ChildItem -Path $nf -ErrorAction Stop | Out-Null
    } catch {
        Write-Host ""; Write-Host "  ✘  Cannot read folder (permission denied): $nf" -ForegroundColor Red
        Write-Host "  Press any key to cancel." -ForegroundColor DarkGray; [Console]::ReadKey($true) | Out-Null
        [Console]::CursorVisible=$false; return
    }

    $script:Config.InputFolder = $nf
    Save-Config
    Write-Host ""; Write-Host "  ✔  Input folder set: $nf" -ForegroundColor Green
    Write-Host ""; [Console]::CursorVisible=$false; Wait-AnyKey
}

function Select-BulkFile {
    # Interactive file picker — no nested functions (scope-safe).
    # Layout  : Header → Folder → Filter textbox → File table → Footer (Cancel)
    # Focus   : 'filter' (typing) ↔ 'table' (navigating rows)
    param()

    $scriptLocation = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    $folder = if ($script:Config.InputFolder -and (Test-Path $script:Config.InputFolder)) {
                  $script:Config.InputFolder
              } else {
                  $scriptLocation
              }
    if (-not $folder -or -not (Test-Path $folder)) { return $null }

    # ── Column widths ────────────────────────────────────────────────────────
    $colN    = 4
    $colName = 42
    $colSize = 10
    $colDate = 12
    $tableW  = $colN + 1 + $colName + 1 + $colSize + 1 + $colDate
    $borderL   = "  ┌" + ('─' * $tableW) + "┐"
    $borderM   = "  ├" + ('─' * $tableW) + "┤"
    $borderB   = "  └" + ('─' * $tableW) + "┘"
    $h0 = "#".PadRight($colN)
    $h1 = "Filename".PadRight($colName)
    $h2 = "Size".PadRight($colSize)
    $h3 = "Modified".PadRight($colDate)
    $headerRow = "  │ $h0 $h1 $h2 $h3│"

    $filter   = ''
    $selected = 0
    $focus    = 'filter'

    # Drain any keys buffered by prior menus
    while ([Console]::KeyAvailable) { [Console]::ReadKey($true) | Out-Null }

    [Console]::CursorVisible = $false
    try {
        while ($true) {

            # ── Build file list ───────────────────────────────────────────────
            $files = @(Get-ChildItem -Path $folder -File -ErrorAction SilentlyContinue |
                       Where-Object { $filter -eq '' -or $_.Name -like "*$filter*" } |
                       Sort-Object Name)

            if ($files.Count -eq 0)             { $selected = 0 }
            elseif ($selected -ge $files.Count) { $selected = $files.Count - 1 }

            # ── Draw header ───────────────────────────────────────────────────
            Clear-Host
            Write-Host ""
            Write-Host "  ╔══════════════════════════════════╗" -ForegroundColor DarkYellow
            Write-Host "  ║  📂  Select Input File            ║" -ForegroundColor DarkYellow
            Write-Host "  ╚══════════════════════════════════╝" -ForegroundColor DarkYellow
            Write-Host ""

            if ($folder.Length -gt 60) { $folderDisp = "..."+$folder.Substring($folder.Length-57) }
            else                        { $folderDisp = $folder }
            Write-Host "  Folder : " -NoNewline -ForegroundColor DarkGray
            Write-Host $folderDisp -ForegroundColor Cyan
            Write-Host ""

            # ── Filter box ────────────────────────────────────────────────────
            if ($filter -eq '') { $filterDisplay = '(type to filter)' }
            else                { $filterDisplay = $filter }

            if ($focus -eq 'filter') { $focusMark = '►' } else { $focusMark = ' ' }

            if ($focus -eq 'filter') {
                $hint     = '  Printable=filter  Backspace=erase  Tab/Enter/↓=list  O=change folder  Esc=cancel'
                $lblColor = 'White'
            } else {
                $hint     = '  ↑↓=navigate  Enter=select  Tab/↑top=filter  O=change folder  Esc=cancel'
                $lblColor = 'DarkGray'
            }

            Write-Host "  $focusMark Filter : " -NoNewline -ForegroundColor $lblColor
            if ($focus -eq 'filter') {
                Write-Host "[ $filterDisplay ]" -NoNewline -BackgroundColor DarkBlue -ForegroundColor White
            } else {
                if ($filter -eq '') { $boxColor = 'DarkGray' } else { $boxColor = 'White' }
                Write-Host "[ $filterDisplay ]" -NoNewline -ForegroundColor $boxColor
            }
            Write-Host ""
            Write-Host $hint -ForegroundColor DarkGray
            Write-Host ""

            # ── Table ─────────────────────────────────────────────────────────
            Write-Host $borderL -ForegroundColor DarkGray
            Write-Host $headerRow -ForegroundColor DarkGray
            Write-Host $borderM -ForegroundColor DarkGray

            if ($files.Count -eq 0) {
                if ($filter) { $emptyMsg = "  No files match '$filter'" }
                else         { $emptyMsg = "  Folder is empty" }
                $padded = $emptyMsg.PadRight($tableW)
                Write-Host "  │$padded│" -ForegroundColor DarkYellow
            } else {
                for ($i = 0; $i -lt $files.Count; $i++) {
                    $f   = $files[$i]
                    $num = ($i + 1).ToString().PadRight($colN)

                    if ($f.Name.Length -gt $colName) {
                        $name = $f.Name.Substring(0, $colName - 1) + [char]0x2026
                    } else {
                        $name = $f.Name.PadRight($colName)
                    }

                    $sizeKB  = ("" + [math]::Round($f.Length / 1KB, 1) + " KB").PadRight($colSize)
                    $dateStr = $f.LastWriteTime.ToString("yyyy-MM-dd").PadRight($colDate)

                    if ($focus -eq 'table' -and $i -eq $selected) {
                        Write-Host "  │ $num $name $sizeKB $dateStr│" -BackgroundColor DarkCyan -ForegroundColor White
                    } else {
                        if ($f.Extension -in @('.csv','.txt','.xlsx','.xls','.json')) { $nc = 'Cyan' }
                        else { $nc = 'Gray' }
                        Write-Host "  │ " -NoNewline -ForegroundColor DarkGray
                        Write-Host $num -NoNewline -ForegroundColor DarkGray
                        Write-Host " $name " -NoNewline -ForegroundColor $nc
                        Write-Host "$sizeKB " -NoNewline -ForegroundColor DarkGray
                        Write-Host "$dateStr│" -ForegroundColor DarkGray
                    }
                }
            }

            Write-Host $borderB -ForegroundColor DarkGray
            Write-Host ""
            if ($filter) { $matchStr = "$($files.Count) file(s) matching '$filter'" }
            else         { $matchStr = "$($files.Count) file(s) in folder" }
            Write-Host "  $matchStr" -ForegroundColor DarkGray
            Write-Host ""
            Write-Host "  ────────────────────────────────────" -ForegroundColor DarkGray
            Write-Host "  [Esc]  Cancel" -ForegroundColor DarkGray

            # ── Read key ─────────────────────────────────────────────────────
            $key = [Console]::ReadKey($true)

            if ($key.Key -eq 'Escape') { return $null }

            # O = change input folder (available in both focus modes)
            if ($key.KeyChar -eq 'o' -or $key.KeyChar -eq 'O') {
                [Console]::CursorVisible = $true
                Set-InputFolder
                [Console]::CursorVisible = $false
                # Reload folder from config
                if ($script:Config.InputFolder -and (Test-Path $script:Config.InputFolder)) {
                    $folder = $script:Config.InputFolder
                } else {
                    $folder = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
                }
                $filter = ''; $selected = 0; $focus = 'filter'
                continue
            }

            if ($focus -eq 'filter') {
                switch ($key.Key) {
                    'Tab'       { if ($files.Count -gt 0) { $focus = 'table'; $selected = 0 } }
                    'DownArrow' { if ($files.Count -gt 0) { $focus = 'table'; $selected = 0 } }
                    'Enter'     { if ($files.Count -gt 0) { $focus = 'table'; $selected = 0 } }
                    'Backspace' {
                        if ($filter.Length -gt 0) {
                            $filter   = $filter.Substring(0, $filter.Length - 1)
                            $selected = 0
                        }
                    }
                    default {
                        $ch = $key.KeyChar
                        if ($ch -ge [char]32 -and $ch -ne [char]0) {
                            $filter  += $ch
                            $selected = 0
                        }
                    }
                }
            } else {
                switch ($key.Key) {
                    'DownArrow' {
                        if ($files.Count -gt 0) {
                            if ($selected -lt $files.Count - 1) { $selected++ } else { $selected = 0 }
                        }
                    }
                    'UpArrow' {
                        if ($selected -gt 0) { $selected-- }
                        else                 { $focus = 'filter' }
                    }
                    'Tab'   { $focus = 'filter' }
                    'Enter' {
                        if ($files.Count -gt 0) {
                            return (Join-Path $folder $files[$selected].Name)
                        }
                    }
                }
            }
        }
    } catch {
        [Console]::CursorVisible = $true
        Clear-Host
        Write-Host ""
        Write-Host "  ✘  File picker error: $_" -ForegroundColor Red
        Write-Host ""
        Wait-AnyKey
        return $null
    } finally {
        [Console]::CursorVisible = $true
    }
}

function Clear-Database {
    Clear-Host; Write-Header "🗄  Clean Database" "DarkRed"
    if (-not (Test-Path $script:DbPath)) {
        Write-Host "  ⚠  No database at: $script:DbPath" -ForegroundColor DarkYellow; Write-Host ""; Wait-AnyKey; return
    }
    $info = Get-DbInfo
    Write-Host "  Database : " -NoNewline -ForegroundColor DarkGray; Write-Host $script:DbPath -ForegroundColor Cyan
    Write-Host "  Size     : $($info.Size) KB   Settings: $($info.Rows)   Hosts: $($info.Hosts)" -ForegroundColor DarkGray
    Write-Host ""
    $action = Invoke-ChoiceMenu -Title "🗄  Clean Database — Choose Action" -Color "DarkRed" `
        -Choices @(
            "Clear all settings  (keeps DB file, removes all saved values)"
            "Clear host pool     (removes discovered controllers only)"
            "Delete DB file      (removes the file entirely)"
            "Cancel"
        ) -CurrentIndex 3
    Clear-Host; Write-Header "🗄  Clean Database" "DarkRed"
    switch ($action) {
        0 {
            [Console]::CursorVisible=$true
            Write-Host "  ⚠  Type YES to confirm: " -NoNewline -ForegroundColor DarkYellow
            $c=Read-Host; [Console]::CursorVisible=$false
            if ($c -eq "YES") {
                try {
                    Invoke-SqliteQuery -DataSource $script:DbPath -Query "DELETE FROM settings"   | Out-Null
                    Invoke-SqliteQuery -DataSource $script:DbPath -Query "DELETE FROM apic_hosts" | Out-Null
                    $script:Config=@{ApicHost=$null;Username=$null;Password=$null;SSLVerify=$true}
                    Write-Host ""; Write-Host "  ✔  All settings and host pool cleared." -ForegroundColor Green
                } catch { Write-Host "  ✘  Error: $_" -ForegroundColor Red }
            } else { Write-Host ""; Write-Host "  ⚠  Cancelled." -ForegroundColor DarkYellow }
        }
        1 {
            [Console]::CursorVisible=$true
            Write-Host "  ⚠  Type YES to confirm: " -NoNewline -ForegroundColor DarkYellow
            $c=Read-Host; [Console]::CursorVisible=$false
            if ($c -eq "YES") {
                try {
                    Invoke-SqliteQuery -DataSource $script:DbPath -Query "DELETE FROM apic_hosts" | Out-Null
                    Write-Host ""; Write-Host "  ✔  Host pool cleared. Login again to rediscover." -ForegroundColor Green
                } catch { Write-Host "  ✘  Error: $_" -ForegroundColor Red }
            } else { Write-Host ""; Write-Host "  ⚠  Cancelled." -ForegroundColor DarkYellow }
        }
        2 {
            [Console]::CursorVisible=$true
            Write-Host "  ⚠  Type YES to confirm: " -NoNewline -ForegroundColor DarkYellow
            $c=Read-Host; [Console]::CursorVisible=$false
            if ($c -eq "YES") {
                try {
                    Remove-Item -Path $script:DbPath -Force
                    $script:Config=@{ApicHost=$null;Username=$null;Password=$null;SSLVerify=$true}
                    Write-Host ""; Write-Host "  ✔  Database deleted." -ForegroundColor Green
                } catch { Write-Host "  ✘  Error: $_" -ForegroundColor Red }
            } else { Write-Host ""; Write-Host "  ⚠  Cancelled." -ForegroundColor DarkYellow }
        }
        default { Write-Host "  ⚠  Cancelled." -ForegroundColor DarkGray }
    }
    Write-Host ""; Wait-AnyKey
}


# ════════════════════════════════════════════════════════════════════════════════
#  GITHUB AUTO-UPDATE
# ════════════════════════════════════════════════════════════════════════════════

function Invoke-AutoUpdate {
    # Checks GitHub releases API for a newer version. Downloads and restarts if found.
    if (-not $script:Config.AutoUpdate) { return }
    if (-not $PSCommandPath)            { return }   # can't restart if path unknown

    Write-Host "  🔄  Checking for updates..." -NoNewline -ForegroundColor DarkGray
    try {
        $apiUrl   = 'https://api.github.com/repos/apellini/APIC-MANAGER/releases/latest'
        $headers  = @{ 'User-Agent' = 'APIC-Manager-Updater' }
        if ($PSVersionTable.PSVersion.Major -ge 7) {
            $rel = Invoke-RestMethod -Uri $apiUrl -Headers $headers -TimeoutSec 10 -ErrorAction Stop
        } else {
            $rel = Invoke-RestMethod -Uri $apiUrl -Headers $headers -TimeoutSec 10 -ErrorAction Stop
        }
        $remoteTag  = $rel.tag_name -replace '^v',''
        $localVer   = $script:AppVersion

        if ($remoteTag -eq $localVer) {
            Write-Host " ✔  up to date (v$localVer)" -ForegroundColor Green
            return
        }

        Write-Host " ℹ  new version v$remoteTag available (current v$localVer)" -ForegroundColor Cyan

        # Find .ps1 asset in release
        $asset = $rel.assets | Where-Object { $_.name -like '*.ps1' } | Select-Object -First 1
        if (-not $asset) {
            # Fallback: raw main branch
            $downloadUrl = "https://raw.githubusercontent.com/apellini/APIC-MANAGER/main/APIC_manager.ps1"
        } else {
            $downloadUrl = $asset.browser_download_url
        }

        Write-Host "  📥  Downloading v$remoteTag..." -NoNewline -ForegroundColor DarkGray
        $tmpFile = [System.IO.Path]::GetTempFileName() + '.ps1'
        if ($PSVersionTable.PSVersion.Major -ge 7) {
            Invoke-WebRequest -Uri $downloadUrl -OutFile $tmpFile -TimeoutSec 30 -ErrorAction Stop
        } else {
            $wc = New-Object System.Net.WebClient
            $wc.Headers['User-Agent'] = 'APIC-Manager-Updater'
            $wc.DownloadFile($downloadUrl, $tmpFile)
        }
        Write-Host " ✔" -ForegroundColor Green

        # Verify download looks like a PowerShell script
        $firstLine = Get-Content $tmpFile -TotalCount 1 -ErrorAction Stop
        if ($firstLine -notlike '*APIC*' -and $firstLine -notlike '#*') {
            Write-Host "  ✘  Downloaded file looks invalid — update aborted." -ForegroundColor Red
            Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue
            return
        }

        # Replace current script and restart
        Copy-Item -Path $tmpFile -Destination $PSCommandPath -Force
        Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue
        Write-Host "  ✔  Script updated. Restarting..." -ForegroundColor Green
        Start-Sleep -Milliseconds 800
        & powershell.exe -NoLogo -NoProfile -File $PSCommandPath
        exit
    } catch {
        Write-Host " ⚠  Update check failed: $($_.Exception.Message)" -ForegroundColor DarkYellow
    }
}

# ════════════════════════════════════════════════════════════════════════════════
#  APIC PORT POLICY VALIDATION  (DPC / VPC)
# ════════════════════════════════════════════════════════════════════════════════

function Invoke-ApicPortPolicyValidation {
    # For each row with type=dpc or type=vpc:
    #  1. Check interface policy group exists (infraAccBndlGrp with lagT=link for dpc, lagT=node for vpc)
    #  2. If found, check that attached AEP has a VLAN domain starting with the tenant name
    # Returns hashtable: "leaf|port|vlan|tenant" → @{Valid=$bool; Message=string}
    param([object[]]$Rows)

    if (-not $script:Session.LoggedIn) { return @{} }
    $token = $script:Session.Token
    $host_ = $script:Session.Host
    $ssl   = $script:Session.SSLVerify

    # Collect unique (port, type, tenant) combos that need checking
    $checks = @{}
    foreach ($r in $Rows) {
        if ($r.type -eq 'dpc' -or $r.type -eq 'vpc') {
            $ck = "$($r.port)|$($r.type)|$($r.tenant)"
            if (-not $checks.ContainsKey($ck)) {
                $checks[$ck] = @{ port=$r.port; type=$r.type; tenant=$r.tenant }
            }
        }
    }
    if ($checks.Count -eq 0) { return @{} }

    $job = Start-Job -ScriptBlock {
        param($host_, $token, $ssl, $checksJson)
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $checks = $checksJson | ConvertFrom-Json

        function ApicGet($url, $tok, $h, $ssl) {
            $hdr = @{ Cookie = "APIC-cookie=$tok" }
            if ($PSVersionTable.PSVersion.Major -ge 7) {
                $p = @{Uri=$url;Method='GET';Headers=$hdr;TimeoutSec=20}
                if (-not $ssl) { $p['SkipCertificateCheck']=$true }
                return Invoke-RestMethod @p
            } else {
                if (-not $ssl) {
                    if (-not ([System.Management.Automation.PSTypeName]'TrustAllPPV').Type) {
                        Add-Type @"
using System.Net; using System.Security.Cryptography.X509Certificates;
public class TrustAllPPV : ICertificatePolicy {
    public bool CheckValidationResult(ServicePoint sp,X509Certificate c,WebRequest req,int p){return true;} }
"@
                    }
                    [Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllPPV
                }
                return Invoke-RestMethod -Uri $url -Method GET -Headers $hdr -TimeoutSec 20
            }
        }

        $results = @{}
        try {
            # Fetch all infraAccBndlGrp (DPC=link, VPC=node)
            $base = "https://$h"
            $grpUrl = "$base/api/node/class/infraAccBndlGrp.json?rsp-subtree=full&rsp-subtree-class=infraRsAttEntP"
            $grpResp = ApicGet $grpUrl $tok $h $ssl
            $grpMap  = @{}   # name → @{lagT; aepDns=[]}
            foreach ($item in $grpResp.imdata) {
                $a    = $item.infraAccBndlGrp.attributes
                $aeps = @()
                if ($item.infraAccBndlGrp.children) {
                    foreach ($ch in $item.infraAccBndlGrp.children) {
                        if ($ch.infraRsAttEntP) {
                            $aepDn = $ch.infraRsAttEntP.attributes.tDn
                            if ($aepDn) { $aeps += $aepDn }
                        }
                    }
                }
                $grpMap[$a.name] = @{ lagT=$a.lagT; aeps=$aeps }
            }

            # Fetch all VLAN domains (fvnsVlanInstP)
            $vdUrl  = "$base/api/node/class/fvnsVlanInstP.json?rsp-prop-include=naming-only"
            $vdResp = ApicGet $vdUrl $tok $h $ssl
            $vlanDomains = @()
            foreach ($item in $vdResp.imdata) {
                $vlanDomains += $item.fvnsVlanInstP.attributes.name
            }

            # Fetch AEP → vlan domain associations
            $aepUrl  = "$base/api/node/class/infraRsDomP.json"
            $aepResp = ApicGet $aepUrl $tok $h $ssl
            $aepDomMap = @{}   # aepDn → [domain names]
            foreach ($item in $aepResp.imdata) {
                $dn    = $item.infraRsDomP.attributes.dn
                $tDn   = $item.infraRsDomP.attributes.tDn
                # dn like: uni/infra/attentp-<AEP>/rsdomP-[uni/...]
                if ($dn -match 'attentp-([^/]+)/rsdomP') {
                    $aepName = $Matches[1]
                    $aepDn   = "uni/infra/attentp-$aepName"
                    if (-not $aepDomMap.ContainsKey($aepDn)) { $aepDomMap[$aepDn] = @() }
                    # domain name from tDn: uni/phys-<name> or uni/vmmp-.../dom-<name> or uni/l2dom-<name>
                    if ($tDn -match '-([^-/]+)$') { $aepDomMap[$aepDn] += $Matches[1] }
                }
            }

            foreach ($ckKey in $checks.PSObject.Properties.Name) {
                $ck     = $checks.$ckKey
                $port   = $ck.port
                $type   = $ck.type
                $tenant = $ck.tenant
                $lagT   = if ($type -eq 'dpc') { 'link' } else { 'node' }

                if (-not $grpMap.ContainsKey($port)) {
                    $results[$ckKey] = @{ Valid=$false; Message="policy group '$port' not found on APIC" }
                    continue
                }
                $grp = $grpMap[$port]
                if ($grp.lagT -ne $lagT) {
                    $results[$ckKey] = @{ Valid=$false; Message="policy group '$port' is type '$($grp.lagT)' not '$lagT'" }
                    continue
                }

                # Check AEP has vlan domain starting with tenant name
                $domainOk = $false
                $foundDomains = @()
                foreach ($aepDn in $grp.aeps) {
                    if ($aepDomMap.ContainsKey($aepDn)) {
                        foreach ($dom in $aepDomMap[$aepDn]) {
                            $foundDomains += $dom
                            if ($dom -like "$tenant*") { $domainOk = $true }
                        }
                    }
                }
                if (-not $domainOk) {
                    $domList = if ($foundDomains.Count -gt 0) { $foundDomains -join ',' } else { 'none' }
                    $results[$ckKey] = @{ Valid=$false; Message="AEP has no VLAN domain starting with '$tenant' (found: $domList)" }
                } else {
                    $results[$ckKey] = @{ Valid=$true; Message="OK" }
                }
            }
        } catch {
            $results['_error'] = @{ Valid=$false; Message=$_.Exception.Message }
        }
        return $results
    } -ArgumentList $host_, $token, $ssl, ($checks | ConvertTo-Json -Depth 5)

    $res = $job | Wait-Job | Receive-Job -ErrorAction SilentlyContinue
    Remove-Job $job
    if ($res) { return $res }
    return @{}
}

# ════════════════════════════════════════════════════════════════════════════════
#  BULK ADVANCED SETTINGS MENU
# ════════════════════════════════════════════════════════════════════════════════

function Show-BulkAdvancedSettings {
    while (-not $script:ExitRequested) {
        $vpLbl  = if ($script:Config.BulkValidatePortPolicy) { "enabled ✔" } else { "disabled ✘" }
        $tvLbl  = if ($script:Config.BulkValidateTenant -ne $false) { "enabled ✔" } else { "disabled ✘" }
        $epLbl  = if ($script:Config.BulkLookupEpg -ne $false)      { "enabled ✔" } else { "disabled ✘" }

        $items = @(
            "Validate port policy (DPC/VPC)  — $vpLbl"
            "Validate tenant on APIC         — $tvLbl"
            "Lookup AP/EPG on APIC           — $epLbl"
        )
        $sel = Invoke-Menu -Title "⚙  Bulk Advanced Settings  " -Color "Green" -Items $items
        $backIdx = $items.Count; $backMainIdx = $items.Count + 1; $quitIdx = $items.Count + 2
        switch ($sel) {
            0 {
                $script:Config.BulkValidatePortPolicy = -not $script:Config.BulkValidatePortPolicy
                Save-Config
            }
            1 {
                if ($script:Config.BulkValidateTenant -ne $false) { $script:Config.BulkValidateTenant = $false }
                else { $script:Config.BulkValidateTenant = $true }
                Save-Config
            }
            2 {
                if ($script:Config.BulkLookupEpg -ne $false) { $script:Config.BulkLookupEpg = $false }
                else { $script:Config.BulkLookupEpg = $true }
                Save-Config
            }
            $backIdx     { return }
            $backMainIdx { $script:ReturnToMain = $true; return }
            $quitIdx     { Invoke-Quit; return }
        }
    }
}

# ════════════════════════════════════════════════════════════════════════════════
#  SUBMENUS
# ════════════════════════════════════════════════════════════════════════════════

function Show-ConfigureMenu {
    $items=@("Tenants","Fabric")
    while (-not $script:ExitRequested) {
        $sel = Invoke-Menu -Title "⚙  Configure              " -Color "Green" -Items $items
        $backIdx = $items.Count
        $backMainIdx = $items.Count + 1
        $quitIdx = $items.Count + 2
        switch ($sel) {
            0 { Show-TenantsMenu; if ($script:ReturnToMain) { return } }
            1 { Clear-Host; Write-Header "⚙  Fabric" "Green"; Write-Host "  → Fabric configuration (placeholder)" -ForegroundColor Yellow; Wait-AnyKey }
            $backIdx     { return }
            $backMainIdx { $script:ReturnToMain = $true; return }
            $quitIdx     { Invoke-Quit; return }
        }
    }
}

function Show-TenantsMenu {
    $items = @("Tenant","Application Profiles","Networking")
    while (-not $script:ExitRequested) {
        $sel = Invoke-Menu -Title "🏷️  Tenants               " -Color "Green" -Items $items
        $backIdx = $items.Count; $backMainIdx = $items.Count + 1; $quitIdx = $items.Count + 2
        switch ($sel) {
            0 { Clear-Host; Write-Header "🏷️  Tenant" "Green"; Write-Host "  → Tenant actions (placeholder)" -ForegroundColor Yellow; Wait-AnyKey }
            1 { Show-ApplicationProfilesMenu; if ($script:ReturnToMain) { return } }
            2 { Clear-Host; Write-Header "🌐  Networking" "Green"; Write-Host "  → Networking actions (placeholder)" -ForegroundColor Yellow; Wait-AnyKey }
            $backIdx     { return }
            $backMainIdx { $script:ReturnToMain = $true; return }
            $quitIdx     { Invoke-Quit; return }
        }
    }
}

function Show-ApplicationProfilesMenu {
    $items = @("Application Profile","Endpoint Groups")
    while (-not $script:ExitRequested) {
        $sel = Invoke-Menu -Title "📦  Application Profiles  " -Color "Green" -Items $items
        $backIdx = $items.Count; $backMainIdx = $items.Count + 1; $quitIdx = $items.Count + 2
        switch ($sel) {
            0 { Clear-Host; Write-Header "📦  Application Profile" "Green"; Write-Host "  → Application Profile actions (placeholder)" -ForegroundColor Yellow; Wait-AnyKey }
            1 { Show-EndpointGroupsMenu; if ($script:ReturnToMain) { return } }
            $backIdx     { return }
            $backMainIdx { $script:ReturnToMain = $true; return }
            $quitIdx     { Invoke-Quit; return }
        }
    }
}


# ════════════════════════════════════════════════════════════════════════════════
#  BULK CSV IMPORT — HELPERS
# ════════════════════════════════════════════════════════════════════════════════

function Expand-VlanList {
    param([string]$Raw)
    # Parses "2,360,2070-2072" → @(2,360,2070,2071,2072)
    $vlans = [System.Collections.Generic.List[int]]::new()
    foreach ($token in ($Raw -split ',')) {
        $token = $token.Trim()
        if ($token -match '^(\d+)-(\d+)$') {
            $from = [int]$Matches[1]; $to = [int]$Matches[2]
            if ($from -gt $to) { $tmp=$from; $from=$to; $to=$tmp }
            for ($v=$from; $v -le $to; $v++) { $vlans.Add($v) }
        } elseif ($token -match '^\d+$') {
            $vlans.Add([int]$token)
        }
    }
    return ($vlans | Select-Object -Unique | Sort-Object)
}

function ConvertTo-NativeBool {
    param([string]$Val)
    # Returns $true, $false, or $null (invalid)
    $Val = $Val.Trim()
    $trueVals  = @('true','TRUE','True','vero','VERO','Vero')
    $falseVals = @('false','FALSE','False','falso','FALSO','Falso')
    if ($trueVals  -contains $Val) { return $true  }
    if ($falseVals -contains $Val) { return $false }
    return $null
}

function Invoke-ApicTenantValidation {
    # Validates a list of tenant names against APIC.
    # Returns hashtable: tenant name → $true/$false
    param([string[]]$Tenants)
    if (-not $script:Session.LoggedIn) { return @{} }

    $token     = $script:Session.Token
    $host_     = $script:Session.Host
    $ssl       = $script:Session.SSLVerify
    $uniq      = @($Tenants | Sort-Object -Unique)

    $job = Start-Job -ScriptBlock {
        param($h,$tok,$ssl,$tenants)
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        try {
            $headers = @{ Cookie = "APIC-cookie=$tok" }
            $url     = "https://$h/api/node/class/fvTenant.json?rsp-prop-include=naming-only"
            if ($PSVersionTable.PSVersion.Major -ge 7) {
                $p = @{ Uri=$url; Method='GET'; Headers=$headers; TimeoutSec=20 }
                if (-not $ssl) { $p['SkipCertificateCheck'] = $true }
                $r = Invoke-RestMethod @p
            } else {
                if (-not $ssl) {
                    if (-not ([System.Management.Automation.PSTypeName]'TrustAllTenant').Type) {
                        Add-Type @"
using System.Net; using System.Security.Cryptography.X509Certificates;
public class TrustAllTenant : ICertificatePolicy {
    public bool CheckValidationResult(ServicePoint sp,X509Certificate c,WebRequest req,int p){return true;} }
"@
                    }
                    [Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllTenant
                }
                $r = Invoke-RestMethod -Uri $url -Method GET -Headers $headers -TimeoutSec 20
            }
            $valid = @{}
            foreach ($item in $r.imdata) {
                $name = $item.fvTenant.attributes.name
                if ($name) { $valid[$name] = $true }
            }
            return @{ Success=$true; Valid=$valid }
        } catch { return @{ Success=$false; Error=$_.Exception.Message } }
    } -ArgumentList $host_, $token, $ssl, $uniq

    $res = $job | Wait-Job | Receive-Job -ErrorAction SilentlyContinue
    Remove-Job $job

    $result = @{}
    foreach ($t in $uniq) { $result[$t] = $false }
    if ($res -and $res.Success) {
        foreach ($t in $uniq) {
            if ($res.Valid.ContainsKey($t)) { $result[$t] = $true }
        }
    }
    return $result
}

function Invoke-ApicEpgLookup {
    # For each tenant, fetches all EPGs and returns hashtable:
    # tenant -> list of @{Vlan=int; AP=string; EPG=string}
    param([string[]]$Tenants)
    if (-not $script:Session.LoggedIn) { return @{} }

    $token = $script:Session.Token
    $host_ = $script:Session.Host
    $ssl   = $script:Session.SSLVerify
    $uniq  = @($Tenants | Sort-Object -Unique)

    $job = Start-Job -ScriptBlock {
        param($h,$tok,$ssl,$tenants)
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $allResults = @{}
        foreach ($tenant in $tenants) {
            try {
                $headers = @{ Cookie = "APIC-cookie=$tok" }
                $url     = "https://$h/api/node/mo/uni/tn-$tenant.json?query-target=subtree&target-subtree-class=fvAEPg&rsp-prop-include=naming-only"
                if ($PSVersionTable.PSVersion.Major -ge 7) {
                    $p = @{ Uri=$url; Method='GET'; Headers=$headers; TimeoutSec=20 }
                    if (-not $ssl) { $p['SkipCertificateCheck'] = $true }
                    $r = Invoke-RestMethod @p
                } else {
                    if (-not $ssl) {
                        if (-not ([System.Management.Automation.PSTypeName]'TrustAllEpg').Type) {
                            Add-Type @"
using System.Net; using System.Security.Cryptography.X509Certificates;
public class TrustAllEpg : ICertificatePolicy {
    public bool CheckValidationResult(ServicePoint sp,X509Certificate c,WebRequest req,int p){return true;} }
"@
                        }
                        [Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllEpg
                    }
                    $r = Invoke-RestMethod -Uri $url -Method GET -Headers $headers -TimeoutSec 20
                }
                $epgList = [System.Collections.Generic.List[object]]::new()
                foreach ($item in $r.imdata) {
                    $dn  = $item.fvAEPg.attributes.dn
                    $epg = $item.fvAEPg.attributes.name
                    # DN: uni/tn-<T>/ap-<AP>/epg-<EPG>
                    if ($dn -match '/ap-([^/]+)/epg-') {
                        $ap = $Matches[1]
                    } else { $ap = '' }
                    # EPG name starts with VLAN id: "2_Server_Farm" → vlan 2
                    if ($epg -match '^(\d+)') {
                        $vlan = [int]$Matches[1]
                        $epgList.Add(@{ Vlan=$vlan; AP=$ap; EPG=$epg })
                    }
                }
                $allResults[$tenant] = $epgList
            } catch {
                $allResults[$tenant] = @()
            }
        }
        return @{ Success=$true; Results=$allResults }
    } -ArgumentList $host_, $token, $ssl, $uniq

    $res = $job | Wait-Job | Receive-Job -ErrorAction SilentlyContinue
    Remove-Job $job

    $out = @{}
    foreach ($t in $uniq) { $out[$t] = @() }
    if ($res -and $res.Success) {
        foreach ($t in $uniq) {
            if ($res.Results.ContainsKey($t)) { $out[$t] = $res.Results[$t] }
        }
    }
    return $out
}

# ════════════════════════════════════════════════════════════════════════════════
#  BULK CSV IMPORT — MAIN ORCHESTRATOR
# ════════════════════════════════════════════════════════════════════════════════

function Import-BulkCsv {
    param([string]$FilePath)

    Clear-Host; Write-Header "📋  Import bulk CSV" "Green"
    Write-Host "  File : " -NoNewline -ForegroundColor DarkGray
    Write-Host $FilePath -ForegroundColor Cyan
    Write-Host ""

    # ── 1. Read CSV ───────────────────────────────────────────────────────────
    Write-Host "  📖  Reading CSV..." -NoNewline -ForegroundColor DarkGray
    try {
        $rawLines = Get-Content -Path $FilePath -Encoding UTF8 -ErrorAction Stop
    } catch {
        Write-Host " ✘  $_" -ForegroundColor Red; Write-Host ""; Wait-AnyKey; return
    }
    if ($rawLines.Count -lt 2) {
        Write-Host " ✘  File is empty or has no data rows." -ForegroundColor Red; Write-Host ""; Wait-AnyKey; return
    }
    Write-Host " ✔  $($rawLines.Count - 1) data row(s)" -ForegroundColor Green

    $header = $rawLines[0] -split ';' | ForEach-Object { $_.Trim().ToLower() }
    $expected = @('tenant','type','pod','leaf','port','vlan','mode','native')
    foreach ($col in $expected) {
        if ($header -notcontains $col) {
            Write-Host "  ✘  Missing column: $col" -ForegroundColor Red; Write-Host ""; Wait-AnyKey; return
        }
    }

    # Parse raw rows into objects
    $rawRows = [System.Collections.Generic.List[hashtable]]::new()
    for ($li = 1; $li -lt $rawLines.Count; $li++) {
        $line = $rawLines[$li]
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $cells = $line -split ';'
        $row   = @{}
        for ($ci = 0; $ci -lt $header.Count; $ci++) {
            $row[$header[$ci]] = if ($ci -lt $cells.Count) { $cells[$ci].Trim() } else { '' }
        }
        $row['_line'] = $li + 1
        $rawRows.Add($row)
    }
    Write-Host "  ✔  Parsed $($rawRows.Count) row(s)" -ForegroundColor Green

    # ── 2. Ensure APIC session — auto-login if needed ────────────────────────
    if (-not $script:Session.LoggedIn) {
        Write-Host "  🔌  Not logged in — attempting auto-login..." -NoNewline -ForegroundColor DarkYellow
        $hostPool  = Get-ApicHostPool
        $loginOk   = $false
        foreach ($tryHost in $hostPool) {
            Write-Host "." -NoNewline -ForegroundColor DarkGray
            $loginJob = Start-Job -ScriptBlock {
                param($h,$u,$p,$ssl)
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                $body = '{"aaaUser":{"attributes":{"name":"' + $u + '","pwd":"' + $p + '"}}}'
                try {
                    if ($PSVersionTable.PSVersion.Major -ge 7) {
                        $r = Invoke-RestMethod -Uri "https://$h/api/aaaLogin.json" -Method POST -Body $body -ContentType 'application/json' -TimeoutSec 15 -SkipCertificateCheck:(-not $ssl)
                    } else {
                        if (-not $ssl) {
                            if (-not ([System.Management.Automation.PSTypeName]'TrustAllBulkLogin').Type) {
                                Add-Type @"
using System.Net; using System.Security.Cryptography.X509Certificates;
public class TrustAllBulkLogin : ICertificatePolicy {
    public bool CheckValidationResult(ServicePoint sp,X509Certificate c,WebRequest req,int p){return true;} }
"@
                            }
                            [Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllBulkLogin
                        }
                        $r = Invoke-RestMethod -Uri "https://$h/api/aaaLogin.json" -Method POST -Body $body -ContentType 'application/json' -TimeoutSec 15
                    }
                    $tok = $r.imdata[0].aaaLogin.attributes.token
                    if ($tok) { return @{Success=$true;Token=$tok;Host=$h} }
                    return @{Success=$false}
                } catch { return @{Success=$false;Error=$_.Exception.Message} }
            } -ArgumentList $tryHost, $script:Config.Username, $script:Config.Password, $script:Config.SSLVerify

            $res = $loginJob | Wait-Job | Receive-Job -ErrorAction SilentlyContinue
            Remove-Job $loginJob
            if ($res -and $res.Success) {
                $script:Session.LoggedIn  = $true
                $script:Session.Token     = $res.Token
                $script:Session.Host      = $res.Host
                $script:Session.Username  = $script:Config.Username
                $script:Session.SSLVerify = $script:Config.SSLVerify
                $loginOk = $true
                break
            }
        }
        if ($loginOk) {
            Write-Host " ✔  Connected to $($script:Session.Host)" -ForegroundColor Green
        } else {
            Write-Host " ✘" -ForegroundColor Red
            Write-Host "  ⚠  Auto-login failed. Continue without APIC validation? [Y/N] : " -NoNewline -ForegroundColor DarkYellow
            $yn = [Console]::ReadKey($true); Write-Host $yn.KeyChar
            if ($yn.Key -ne 'Y') { Write-Host ""; Wait-AnyKey; return }
        }
    } else {
        Write-Host "  🔌  Using active session: $($script:Session.Username)@$($script:Session.Host)" -ForegroundColor DarkGreen
    }

    # ── 3. Validate tenants on APIC ──────────────────────────────────────────
    Write-Host "  🔍  Validating tenants on APIC..." -NoNewline -ForegroundColor DarkGray
    $tenantNames = @($rawRows | ForEach-Object { $_['tenant'] } | Where-Object { $_ } | Sort-Object -Unique)
    if ($script:Session.LoggedIn -and $script:Config.BulkValidateTenant -ne $false) {
        $tenantValid = Invoke-ApicTenantValidation -Tenants $tenantNames
        Write-Host " ✔" -ForegroundColor Green
    } else {
        $tenantValid = @{}
        foreach ($t in $tenantNames) { $tenantValid[$t] = $null }
        if (-not $script:Session.LoggedIn) { Write-Host " ⚠  Skipped (no session)" -ForegroundColor DarkYellow }
        else                               { Write-Host " ⊘  Disabled in advanced settings" -ForegroundColor DarkGray }
    }

    # ── 4. Serialize rows (expand VLANs) ─────────────────────────────────────
    Write-Host "  🔄  Serializing VLAN lists..." -NoNewline -ForegroundColor DarkGray
    $serialized = [System.Collections.Generic.List[hashtable]]::new()
    $validTypes = @('port','dpc','vpc')
    $validModes = @('access','native','regular','trunk')

    foreach ($row in $rawRows) {
        $errs  = [System.Collections.Generic.List[string]]::new()
        $srcLine = $row['_line']

        # --- Tenant ----------------------------------------------------------
        $tenant = $row['tenant']
        if ([string]::IsNullOrWhiteSpace($tenant)) {
            $errs.Add("tenant is empty")
        } elseif ($tenantValid.ContainsKey($tenant) -and $tenantValid[$tenant] -eq $false) {
            $errs.Add("tenant '$tenant' not found on APIC")
        }

        # --- Type ------------------------------------------------------------
        $type = $row['type'].ToLower()
        if ($validTypes -notcontains $type) { $errs.Add("invalid type '$($row['type'])' (port/dpc/vpc)") }

        # --- Pod -------------------------------------------------------------
        $podRaw = $row['pod']
        if ($podRaw -match '^\d+$')          { $pod = "pod-$podRaw" }
        elseif ($podRaw -match '^pod-\d+$')  { $pod = $podRaw }
        else { $pod = $podRaw; $errs.Add("invalid pod '$podRaw'") }

        # --- Leaf / Port (pass-through) ──────────────────────────────────────
        $leaf = $row['leaf']
        $port = $row['port']

        # --- Native ----------------------------------------------------------
        $nativeRaw = $row['native'].Trim()
        $nativeBool = $null
        $nativeVlan = $null   # integer override
        if ($nativeRaw -match '^\d+$') {
            $nativeVlan = [int]$nativeRaw
        } else {
            $nb = ConvertTo-NativeBool $nativeRaw
            if ($nb -eq $null -and $nativeRaw -ne '') {
                $errs.Add("invalid native value '$nativeRaw'")
            }
            $nativeBool = $nb
        }

        # --- VLAN list -------------------------------------------------------
        $vlanRaw = $row['vlan']
        $vlanList = @(Expand-VlanList $vlanRaw)
        if ($vlanList.Count -eq 0) { $errs.Add("no valid vlan in '$vlanRaw'") }

        # native bool=true forces single vlan
        if ($nativeBool -eq $true -and $vlanList.Count -gt 1) {
            $errs.Add("native=TRUE but multiple VLANs — only one allowed")
        }

        # --- Mode validation ─────────────────────────────────────────────────
        $modeRaw = $row['mode'].ToLower().Trim()
        if ($validModes -notcontains $modeRaw) { $errs.Add("invalid mode '$($row['mode'])'") }

        # ranges disallow native/access
        $isRange = ($vlanList.Count -gt 1)
        if ($isRange -and ($modeRaw -eq 'native' -or $modeRaw -eq 'access')) {
            $errs.Add("mode '$modeRaw' not allowed for VLAN range — use regular or trunk")
        }

        $rowValid = ($errs.Count -eq 0)
        $errStr   = if ($errs.Count -gt 0) { $errs -join ' | ' } else { '' }

        # --- Expand one row per VLAN ─────────────────────────────────────────
        foreach ($vlan in $vlanList) {
            # native=TRUE  → all rows are native
            # native=<int> → matching VLAN = native, others = regular
            # native=FALSE/empty → use declared mode
            if ($nativeBool -eq $true) {
                $finalMode = 'native'
            } elseif ($nativeVlan -ne $null) {
                if ($vlan -eq $nativeVlan) { $finalMode = 'native' }
                else                       { $finalMode = 'regular' }
            } else {
                $finalMode = $modeRaw
            }

            if ($nativeVlan -ne $null) { $nvOut = $nativeVlan } else { $nvOut = 0 }
            if ($rowValid)             { $vOut  = 1 }           else { $vOut  = 0 }

            $serialized.Add(@{
                src_line    = $srcLine
                tenant      = $tenant
                type        = $type
                pod         = $pod
                leaf        = $leaf
                port        = $port
                vlan        = $vlan
                mode        = $finalMode
                native_vlan = $nvOut
                ap          = ''
                epg         = ''
                valid       = $vOut
                errors      = $errStr
            })
        }
    }
    Write-Host " ✔  $($serialized.Count) serialized row(s)" -ForegroundColor Green

    # ── 4b. Duplicate port validation ────────────────────────────────────────
    Write-Host "  🔍  Checking duplicate ports..." -NoNewline -ForegroundColor DarkGray
    $portSeen = @{}
    foreach ($srow in $serialized) {
        $pk = "$($srow.leaf)|$($srow.port)"
        if (-not $portSeen.ContainsKey($pk)) {
            $portSeen[$pk] = $srow.src_line
        } elseif ($srow.src_line -ne $portSeen[$pk]) {
            $srow.valid = 0
            $first = $portSeen[$pk]
            $dupErr = "duplicate port (first used on src line $first)"
            if ($srow.errors) { $srow.errors += " | $dupErr" }
            else              { $srow.errors  = $dupErr }
        }
    }
    $dupCount = ($serialized | Where-Object { $_.errors -like '*duplicate port*' }).Count
    if ($dupCount -gt 0) { Write-Host " ⚠  $dupCount row(s) invalidated" -ForegroundColor DarkYellow }
    else                 { Write-Host " ✔  no duplicates" -ForegroundColor Green }

    # ── 5. Enrich with AP/EPG from APIC ─────────────────────────────────────
    Write-Host "  🔗  Looking up AP/EPG on APIC..." -NoNewline -ForegroundColor DarkGray
    $validTenants = @($serialized | Where-Object { $_.valid -eq 1 } |
                      ForEach-Object { $_.tenant } | Sort-Object -Unique)
    if ($script:Session.LoggedIn -and $validTenants.Count -gt 0 -and $script:Config.BulkLookupEpg -ne $false) {
        $epgMap = Invoke-ApicEpgLookup -Tenants $validTenants
        foreach ($srow in $serialized) {
            if ($srow.valid -ne 1) { continue }
            $t = $srow.tenant
            if ($epgMap.ContainsKey($t)) {
                foreach ($epgEntry in $epgMap[$t]) {
                    if ($epgEntry.Vlan -eq $srow.vlan) {
                        $srow.ap  = $epgEntry.AP
                        $srow.epg = $epgEntry.EPG
                        break
                    }
                }
            }
        }
        Write-Host " ✔" -ForegroundColor Green
    } else {
        Write-Host " ⚠  Skipped (not logged in or no valid rows)" -ForegroundColor DarkYellow
    }

    # ── 5b. Validate DPC/VPC port policy groups ─────────────────────────────
    $dpcVpcRows = @($serialized | Where-Object { $_.valid -eq 1 -and ($_.type -eq 'dpc' -or $_.type -eq 'vpc') })
    if ($script:Session.LoggedIn -and $dpcVpcRows.Count -gt 0 -and $script:Config.BulkValidatePortPolicy) {
        Write-Host "  🔌  Validating DPC/VPC port policies..." -NoNewline -ForegroundColor DarkGray
        $ppResults = Invoke-ApicPortPolicyValidation -Rows $dpcVpcRows
        $ppFail = 0
        foreach ($srow in $serialized) {
            if ($srow.type -ne 'dpc' -and $srow.type -ne 'vpc') { continue }
            if ($srow.valid -ne 1) { continue }
            $ckKey = "$($srow.port)|$($srow.type)|$($srow.tenant)"
            if ($ppResults.ContainsKey($ckKey) -and $ppResults[$ckKey].Valid -eq $false) {
                $srow.valid = 0
                $ppErr = "port policy: $($ppResults[$ckKey].Message)"
                if ($srow.errors) { $srow.errors += " | $ppErr" }
                else              { $srow.errors  = $ppErr }
                $ppFail++
            }
        }
        if ($ppFail -gt 0) { Write-Host " ⚠  $ppFail row(s) failed" -ForegroundColor DarkYellow }
        else               { Write-Host " ✔" -ForegroundColor Green }
    } elseif ($dpcVpcRows.Count -gt 0 -and -not $script:Config.BulkValidatePortPolicy) {
        Write-Host "  🔌  Port policy validation — ⊘ disabled in advanced settings" -ForegroundColor DarkGray
    }

    # ── 6. Save to DB ────────────────────────────────────────────────────────
    Write-Host "  💾  Saving to database..." -NoNewline -ForegroundColor DarkGray
    Initialize-Database | Out-Null
    $fileName   = Split-Path $FilePath -Leaf
    $validCount = ($serialized | Where-Object { $_.valid -eq 1 }).Count

    Invoke-SqliteQuery -DataSource $script:DbPath -Query @"
INSERT INTO bulk_imports (file_name, file_path, row_count, status)
VALUES (@fn, @fp, @rc, @st)
"@ -SqlParameters @{ fn=$fileName; fp=$FilePath; rc=$serialized.Count; st='imported' } | Out-Null

    $importId = (Invoke-SqliteQuery -DataSource $script:DbPath -Query "SELECT last_insert_rowid() AS id").id

    foreach ($srow in $serialized) {
        Invoke-SqliteQuery -DataSource $script:DbPath -Query @"
INSERT INTO bulk_import_rows
    (import_id,src_line,tenant,type,pod,leaf,port,vlan,mode,native_vlan,ap,epg,valid,errors)
VALUES
    (@iid,@sl,@te,@ty,@po,@le,@pr,@vl,@mo,@nv,@ap,@ep,@va,@er)
"@ -SqlParameters @{
            iid=$importId; sl=$srow.src_line; te=$srow.tenant; ty=$srow.type
            po=$srow.pod;  le=$srow.leaf;    pr=$srow.port;   vl=$srow.vlan
            mo=$srow.mode; nv=$srow.native_vlan; ap=$srow.ap; ep=$srow.epg
            va=$srow.valid; er=$srow.errors
        } | Out-Null
    }
    Write-Host " ✔  Import #$importId saved" -ForegroundColor Green

    Write-Host ""
    Write-Host "  ┌────────────────────────────────────┐" -ForegroundColor DarkGray
    Write-Host "  │  Import Summary                    │" -ForegroundColor DarkGray
    Write-Host "  ├────────────────────────────────────┤" -ForegroundColor DarkGray
    $sumRows = @(
        @{ L="File       "; V=$fileName }
        @{ L="Source rows"; V="$($rawRows.Count)" }
        @{ L="After expand"; V="$($serialized.Count) rows" }
        @{ L="Valid rows "; V="$validCount" }
        @{ L="Invalid    "; V="$($serialized.Count - $validCount)" }
        @{ L="Import ID  "; V="#$importId" }
    )
    foreach ($sr in $sumRows) {
        Write-Host "  │  $($sr.L): " -NoNewline -ForegroundColor DarkGray
        Write-Host ($sr.V.PadRight(22)) -NoNewline -ForegroundColor Cyan
        Write-Host "│" -ForegroundColor DarkGray
    }
    Write-Host "  └────────────────────────────────────┘" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Press any key to view results table..." -ForegroundColor DarkGray
    [Console]::ReadKey($true) | Out-Null

    Show-BulkImportResults -ImportId $importId
}

# ════════════════════════════════════════════════════════════════════════════════
#  BULK IMPORT RESULTS TABLE
# ════════════════════════════════════════════════════════════════════════════════

function Show-BulkImportResults {
    param([int]$ImportId)

    # Load rows from DB
    try {
        $allRows = @(Invoke-SqliteQuery -DataSource $script:DbPath -Query @"
SELECT id,src_line,tenant,type,pod,leaf,port,vlan,mode,native_vlan,ap,epg,valid,errors
FROM bulk_import_rows WHERE import_id=@iid ORDER BY src_line,vlan
"@ -SqlParameters @{iid=$ImportId})
    } catch {
        Clear-Host; Write-Header "📋  Import Results" "Green"
        Write-Host "  ✘  DB query error: $_" -ForegroundColor Red
        Write-Host ""; Wait-AnyKey; return
    }

    if ($allRows.Count -eq 0) {
        Clear-Host; Write-Header "📋  Import Results" "Green"
        Write-Host "  ⚠  No rows found for import #$ImportId" -ForegroundColor DarkYellow
        Write-Host ""; Wait-AnyKey; return
    }

    # Column widths
    $wTenant = 14; $wType = 5; $wPod = 7; $wLeaf = 6
    $wPort   = 8;  $wVlan = 6; $wMode = 8; $wAp = 14; $wEpg = 20
    $tableInner = $wTenant+$wType+$wPod+$wLeaf+$wPort+$wVlan+$wMode+$wAp+$wEpg + 9

    $bL = "  ┌" + ('─' * $tableInner) + "┐"
    $bM = "  ├" + ('─' * $tableInner) + "┤"
    $bB = "  └" + ('─' * $tableInner) + "┘"
    $hdr = "  │ " +
           "Tenant".PadRight($wTenant) + " " +
           "Type".PadRight($wType)   + " " +
           "Pod".PadRight($wPod)     + " " +
           "Leaf".PadRight($wLeaf)   + " " +
           "Port".PadRight($wPort)   + " " +
           "VLAN".PadRight($wVlan)   + " " +
           "Mode".PadRight($wMode)   + " " +
           "AP".PadRight($wAp)       + " " +
           "EPG".PadRight($wEpg)     + "│"

    $pageSize = 18   # rows visible at once
    $offset   = 0
    $showInvalid = $false   # invalid rows hidden by default

    [Console]::CursorVisible = $false
    try {
        while ($true) {
            # Filter
            if ($showInvalid) { $viewRows = $allRows }
            else              { $viewRows = @($allRows | Where-Object { $_.valid -eq 1 }) }

            $total = $viewRows.Count
            $page  = $viewRows | Select-Object -Skip $offset -First $pageSize

            # ── Draw ─────────────────────────────────────────────────────────
            Clear-Host
            Write-Host ""
            Write-Host "  ╔══════════════════════════════════╗" -ForegroundColor Green
            Write-Host "  ║  📋  Import Results  #$($ImportId.ToString().PadRight(9))║" -ForegroundColor Green
            Write-Host "  ╚══════════════════════════════════╝" -ForegroundColor Green
            Write-Host ""

            $validCnt   = ($allRows | Where-Object { $_.valid -eq 1 }).Count
            $invalidCnt = $allRows.Count - $validCnt
            $filterLbl  = if ($showInvalid) { "all ($total)" } else { "valid only ($total)" }

            Write-Host "  Rows: " -NoNewline -ForegroundColor DarkGray
            Write-Host "$($allRows.Count) total" -NoNewline -ForegroundColor Cyan
            Write-Host "   ✔ $validCnt valid" -NoNewline -ForegroundColor Green
            if ($invalidCnt -gt 0) { Write-Host "   ✘ $invalidCnt invalid" -NoNewline -ForegroundColor Red }
            Write-Host "   Filter: $filterLbl" -ForegroundColor DarkGray
            Write-Host "  ↑↓/PgUp/PgDn scroll   F toggle invalid rows   Esc back" -ForegroundColor DarkGray
            Write-Host ""

            Write-Host $bL -ForegroundColor DarkGray
            Write-Host $hdr -ForegroundColor DarkGray
            Write-Host $bM -ForegroundColor DarkGray

            foreach ($r in $page) {
                $isValid = ($r.valid -eq 1)

                $tenantC = if ($isValid) { 'Cyan'  } else { 'DarkYellow' }
                $rowColor = if ($isValid) { 'Gray'  } else { 'DarkYellow' }

                $tTenant = if ($r.tenant.Length -gt $wTenant) { $r.tenant.Substring(0,$wTenant-1)+'…' } else { $r.tenant.PadRight($wTenant) }
                $tType   = $r.type.PadRight($wType)
                $tPod    = $r.pod.PadRight($wPod)
                $tLeaf   = $r.leaf.PadRight($wLeaf)
                $tPort   = $r.port.PadRight($wPort)
                $tVlan   = $r.vlan.ToString().PadRight($wVlan)
                $tMode   = $r.mode.PadRight($wMode)
                $tAp     = if ($r.ap.Length  -gt $wAp)  { $r.ap.Substring(0,$wAp-1)+'…'  } else { $r.ap.PadRight($wAp)   }
                $tEpg    = if ($r.epg.Length -gt $wEpg) { $r.epg.Substring(0,$wEpg-1)+'…' } else { $r.epg.PadRight($wEpg) }

                $modeColor = switch ($r.mode) {
                    'native'  { 'DarkYellow' }
                    'trunk'   { 'Cyan' }
                    'access'  { 'Green' }
                    'regular' { 'Gray' }
                    default   { 'Gray' }
                }

                if ($isValid) { $vlanColor = 'Yellow' } else { $vlanColor = 'DarkYellow' }
                if ($r.ap)    { $apColor   = 'DarkCyan' } else { $apColor   = 'DarkGray' }
                if ($r.epg)   { $epgColor  = 'DarkCyan' } else { $epgColor  = 'DarkGray' }

                Write-Host "  │ " -NoNewline -ForegroundColor DarkGray
                Write-Host $tTenant -NoNewline -ForegroundColor $tenantC
                Write-Host " $tType "  -NoNewline -ForegroundColor $rowColor
                Write-Host "$tPod "    -NoNewline -ForegroundColor $rowColor
                Write-Host "$tLeaf "   -NoNewline -ForegroundColor $rowColor
                Write-Host "$tPort "   -NoNewline -ForegroundColor $rowColor
                Write-Host "$tVlan "   -NoNewline -ForegroundColor $vlanColor
                Write-Host "$tMode "   -NoNewline -ForegroundColor $modeColor
                Write-Host "$tAp "     -NoNewline -ForegroundColor $apColor
                Write-Host "$tEpg"     -NoNewline -ForegroundColor $epgColor
                Write-Host "│" -ForegroundColor DarkGray

                # Show error note if invalid
                if (-not $isValid -and $r.errors) {
                    if ($r.errors.Length -gt $tableInner - 4) {
                        $errShort = $r.errors.Substring(0, $tableInner - 7) + '...'
                    } else {
                        $errShort = $r.errors
                    }
                    Write-Host "  │  ✘ $($errShort.PadRight($tableInner - 4))│" -ForegroundColor Red
                }
            }

            Write-Host $bB -ForegroundColor DarkGray
            Write-Host ""
            $pageNum  = [math]::Floor($offset / $pageSize) + 1
            $pageTot  = [math]::Max(1, [math]::Ceiling($total / $pageSize))
            Write-Host "  Page $pageNum / $pageTot   (rows $($offset+1)–$([math]::Min($offset+$pageSize,$total)) of $total)" -ForegroundColor DarkGray
            Write-Host ""
            Write-Host "  ────────────────────────────────────" -ForegroundColor DarkGray
            Write-Host "  [Esc] Back" -ForegroundColor DarkGray

            $key = [Console]::ReadKey($true)
            switch ($key.Key) {
                'Escape'   { return }
                'UpArrow'  { if ($offset -gt 0) { $offset -= 1 } }
                'DownArrow'{ if ($offset + $pageSize -lt $total) { $offset += 1 } }
                'PageUp'   { $offset = [math]::Max(0, $offset - $pageSize) }
                'PageDown' {
                    if ($offset + $pageSize -lt $total) {
                        $offset = [math]::Min($total - 1, $offset + $pageSize)
                    }
                }
                'F' {
                    $showInvalid = -not $showInvalid
                    $offset = 0
                }
            }
        }
    } finally {
        [Console]::CursorVisible = $true
    }
}

function Invoke-BulkStaticPort {
    # Ensure input folder is configured before entering the TUI
    if (-not $script:Config.InputFolder -or -not (Test-Path $script:Config.InputFolder)) {
        Clear-Host; Write-Header "🔗  Bulk add static ports" "Green"
        Write-Host "  ⚠  Input folder not configured or not found." -ForegroundColor DarkYellow
        Write-Host ""
        Write-Host "  Set it now? [Y/N] : " -NoNewline -ForegroundColor DarkGray
        $yn = [Console]::ReadKey($true); Write-Host $yn.KeyChar
        if ($yn.Key -eq 'Y') {
            Set-InputFolder
        } else {
            Write-Host ""; Wait-AnyKey; return
        }
        # After Set-InputFolder, re-check — user may have cancelled inside it
        if (-not $script:Config.InputFolder -or -not (Test-Path $script:Config.InputFolder)) {
            Write-Host "  ⚠  Input folder still not set. Returning." -ForegroundColor DarkYellow
            Write-Host ""; Wait-AnyKey; return
        }
    }

    $file = Select-BulkFile
    if ($file) {
        Import-BulkCsv -FilePath $file
    }
}

function Show-EndpointGroupsMenu {
    $items = @(
        "Add static port to EPG"
        "Add bulk static port to EPG via input file"
        "Bulk import — Advanced settings"
    )
    while (-not $script:ExitRequested) {
        $sel = Invoke-Menu -Title "🔗  Endpoint Groups       " -Color "Green" -Items $items
        $backIdx = $items.Count; $backMainIdx = $items.Count + 1; $quitIdx = $items.Count + 2
        switch ($sel) {
            0 { Clear-Host; Write-Header "🔗  Add static port to EPG" "Green"; Write-Host "  → Add single static port (placeholder)" -ForegroundColor Yellow; Wait-AnyKey }
            1 { Invoke-BulkStaticPort }
            2 { Show-BulkAdvancedSettings; if ($script:ReturnToMain) { return } }
            $backIdx     { return }
            $backMainIdx { $script:ReturnToMain = $true; return }
            $quitIdx     { Invoke-Quit; return }
        }
    }
}

function Show-ShowMenu {
    $items=@("Show Tenants","Show VRFs","Show BDs","Show EPGs")
    while (-not $script:ExitRequested) {
        $sel = Invoke-Menu -Title "👁  Show                   " -Color "Cyan" -Items $items
        $backIdx = $items.Count; $backMainIdx = $items.Count + 1; $quitIdx = $items.Count + 2
        switch ($sel) {
            0{Clear-Host;Write-Header "👁  Show Tenants" "Cyan";Write-Host "  → Logic here" -ForegroundColor Yellow;Wait-AnyKey}
            1{Clear-Host;Write-Header "👁  Show VRFs"   "Cyan";Write-Host "  → Logic here" -ForegroundColor Yellow;Wait-AnyKey}
            2{Clear-Host;Write-Header "👁  Show BDs"    "Cyan";Write-Host "  → Logic here" -ForegroundColor Yellow;Wait-AnyKey}
            3{Clear-Host;Write-Header "👁  Show EPGs"   "Cyan";Write-Host "  → Logic here" -ForegroundColor Yellow;Wait-AnyKey}
            $backIdx     { return }
            $backMainIdx { $script:ReturnToMain = $true; return }
            $quitIdx     { Invoke-Quit; return }
        }
    }
}

function Show-TroubleshootMenu {
    $items=@("Check Faults","Check Connectivity","Ping Endpoint","Show Logs")
    while (-not $script:ExitRequested) {
        $sel = Invoke-Menu -Title "🔧  Troubleshoot           " -Color "Magenta" -Items $items
        $backIdx = $items.Count; $backMainIdx = $items.Count + 1; $quitIdx = $items.Count + 2
        switch ($sel) {
            0{Clear-Host;Write-Header "🔧  Check Faults"       "Magenta";Write-Host "  → Logic here" -ForegroundColor Yellow;Wait-AnyKey}
            1{Clear-Host;Write-Header "🔧  Check Connectivity" "Magenta";Write-Host "  → Logic here" -ForegroundColor Yellow;Wait-AnyKey}
            2{Clear-Host;Write-Header "🔧  Ping Endpoint"      "Magenta";Write-Host "  → Logic here" -ForegroundColor Yellow;Wait-AnyKey}
            3{Clear-Host;Write-Header "🔧  Show Logs"          "Magenta";Write-Host "  → Logic here" -ForegroundColor Yellow;Wait-AnyKey}
            $backIdx     { return }
            $backMainIdx { $script:ReturnToMain = $true; return }
            $quitIdx     { Invoke-Quit; return }
        }
    }
}

function Show-SettingsMenu {
    while (-not $script:ExitRequested) {
        $hLbl  = if ($script:Config.ApicHost)  { $script:Config.ApicHost } else { "not set" }
        $uLbl  = if ($script:Config.Username)  { $script:Config.Username } else { "not set" }
        $sLbl  = if ($script:Config.SSLVerify) { "true ✔" }               else { "false ✘" }
        $dbS   = if ($script:DbFolder.Length -gt 28) { "..."+$script:DbFolder.Substring($script:DbFolder.Length-25) } else { $script:DbFolder }
        $cnt   = Get-ApicHostCount
        $pref  = Get-PreferredHost
        $pLbl  = if ($cnt -gt 0) { "$cnt ctrl — pref: $(if($pref){$pref}else{'random 🎲'})" } else { "none — login to discover" }

        $loginReady = $script:Config.ApicHost -and $script:Config.Username -and $script:Config.Password
        $loginLbl   = if ($loginReady) { "Test Login          ─ pool: $cnt host(s) + failover" }
                      else             { "Test Login          ─ ⚠ configure host & credentials first" }
        $logoutLbl  = if ($script:Session.LoggedIn) { "APIC Logout         ─ 🔌 $($script:Session.Username)@$($script:Session.Host)" }
                      else                          { "APIC Logout         ─ ⊘ no active session" }

        $inputLbl  = if ($script:Config.InputFolder) { $script:Config.InputFolder } else { "(not set)" }
        $auLbl     = if ($script:Config.AutoUpdate) { "enabled ✔" } else { "disabled ✘" }
        $items = @(
            "Bootstrap Host      ─ $hLbl"
            "Set Credentials     ─ $uLbl"
            "Toggle SSL Verify   ─ $sLbl"
            "Show Current Config"
            $loginLbl
            $logoutLbl
            "Host Pool           ─ $pLbl"
            "Change DB Folder    ─ $dbS"
            "Input Folder for bulk operation ─ $inputLbl"
            "Auto-update from GitHub ─ $auLbl"
            "Clean Database      ─ 🗄 clear or delete DB"
        )
        $dis = @()
        if (-not $loginReady)              { $dis += 4 }
        if (-not $script:Session.LoggedIn) { $dis += 5 }

        switch (Invoke-Menu -Title "🔩  Settings               " -Color "DarkYellow" -Items $items -DisabledIndices $dis) {
            default {
                $sel = $_
            }
        }
        # Map selection using indices because footer items are appended
        $backIdx = $items.Count; $backMainIdx = $items.Count + 1; $quitIdx = $items.Count + 2
        switch ($sel) {
            0  { Set-ApicHost }
            1  { Set-Credentials }
            2  { Set-SSLVerify }
            3  { Show-CurrentConfig }
            4  { Test-ApicLogin }
            5  { Invoke-ApicLogout -Silent $false }
            6  { Show-DiscoveredHosts; if ($script:ReturnToMain) { return } }
            7  { Set-DbFolder }
            8  { Set-InputFolder }
            9  { $script:Config.AutoUpdate = -not $script:Config.AutoUpdate; Save-Config }
            10 { Clear-Database }
            $backIdx     { return }
            $backMainIdx { $script:ReturnToMain = $true; return }
            $quitIdx     { Invoke-Quit; return }
        }
    }
}

# ════════════════════════════════════════════════════════════════════════════════
#  MAIN MENU
# ════════════════════════════════════════════════════════════════════════════════

function Show-MainMenu {
    $items = @("Configure","Show","Troubleshoot","Settings","Quit")
    while (-not $script:ExitRequested) {
        $script:ReturnToMain = $false
        switch (Invoke-Menu -Title "🌐  APIC Manager v1.4      " -Color "Cyan" -Items $items -IsMain $true) {
            0 { Show-ConfigureMenu }; 1 { Show-ShowMenu }
            2 { Show-TroubleshootMenu }; 3 { Show-SettingsMenu }; 4 { Invoke-Quit }
        }
    }
}

# ════════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ════════════════════════════════════════════════════════════════════════════════

Clear-Host
Write-Host ""
Write-Host "  ╔══════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "  ║   🌐  APIC Manager v1.4          ║" -ForegroundColor Cyan
Write-Host "  ║   🚀  Starting up...             ║" -ForegroundColor Cyan
Write-Host "  ╚══════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

Write-Host "  📦  Checking PSSQLite..." -NoNewline -ForegroundColor DarkGray
$dbReady = Install-PSSQLite
if ($dbReady) { Write-Host " ✔" -ForegroundColor Green }
else          { Write-Host " ✘  Settings will not be persisted." -ForegroundColor DarkYellow }

if ($dbReady) {
    $saved = Read-DbPointer
    if ($saved) {
        $script:DbPath=$saved; $script:DbFolder=Split-Path $saved -Parent
        Write-Host "  📌  DB from pointer: " -NoNewline -ForegroundColor DarkGray; Write-Host $script:DbPath -ForegroundColor Cyan
    } else {
        Write-DbPointer -Path $script:DbPath
        Write-Host "  📌  First run — DB: " -NoNewline -ForegroundColor DarkGray; Write-Host $script:DbPath -ForegroundColor Cyan
    }

    Load-Config

    if ($script:Config.ApicHost -or $script:Config.Username) {
        Write-Host "  ✔  Config restored:" -ForegroundColor Green
        if ($script:Config.ApicHost) { Write-Host "     Bootstrap : $($script:Config.ApicHost)" -ForegroundColor Gray }
        if ($script:Config.Username) { Write-Host "     Username  : $($script:Config.Username)" -ForegroundColor Gray }
        $pc   = Get-ApicHostCount
        $pref = Get-PreferredHost
        if ($pc -gt 0) {
            Write-Host "     Host pool : $pc controller(s)" -NoNewline -ForegroundColor Gray
            if ($pref) { Write-Host "  —  preferred: $pref ⭐" -ForegroundColor Yellow }
            else       { Write-Host "  (random 🎲)" -ForegroundColor DarkGray }
        }
        Write-Host "  🔒  Sensitive fields encrypted (DPAPI)." -ForegroundColor DarkGreen
    } else {
        Write-Host "  ℹ  No saved config — starting fresh." -ForegroundColor DarkGray
    }
}

Write-Host ""

# ── GitHub auto-update check ──────────────────────────────────────────────────
if ($dbReady) { Invoke-AutoUpdate }

Start-Sleep -Milliseconds 600
Show-MainMenu
