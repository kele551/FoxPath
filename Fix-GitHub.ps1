#requires -Version 5.1
<#
    GitHubDirectFix - GitHub 直连 IP 自动维护工具

    干什么:
      电信宽带到 GitHub 的路径质量一直在漂, 某个 IP 今天 0.8s 明天就彻底不通。
      手工往 hosts 里钉 IP 只能管两三天。这个脚本定时重测一批 GitHub 官方 IP,
      挑当前真正能握手的两个写进 hosts, 死掉的自动换掉。

    怎么判断 IP 是真 GitHub:
      不是 ping(很多机器禁 ICMP, 而且 ping 通不代表能开网页),
      而是真连 443 做 TLS 握手, 并且校验证书 Subject 里必须有 github.com。

    用法:
      powershell -NoProfile -ExecutionPolicy Bypass -File Fix-GitHub.ps1 -Status
      powershell -NoProfile -ExecutionPolicy Bypass -File Fix-GitHub.ps1 -Fix
      powershell -NoProfile -ExecutionPolicy Bypass -File Fix-GitHub.ps1 -Gui
      powershell -NoProfile -ExecutionPolicy Bypass -File Fix-GitHub.ps1 -Install
      powershell -NoProfile -ExecutionPolicy Bypass -File Fix-GitHub.ps1 -Uninstall

    -Install 会建一个每 15 分钟跑一次的计划任务, 后台静默维护, 不需要再管。
    改 hosts 需要管理员权限, 所以请用 Run-GitHubFix.bat 启动(会自动申请提权)。
#>

[CmdletBinding()]
param(
    [switch]$Status,
    [switch]$Fix,
    [switch]$Gui,
    [switch]$Install,
    [switch]$Uninstall,
    [switch]$Silent
)

$ErrorActionPreference = 'Stop'

$AppName   = 'GitHubDirectFix'
$AppDir    = Split-Path -Parent $MyInvocation.MyCommand.Path
$HostsPath = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
$BackupDir = Join-Path $AppDir 'backups'
$LogDir    = Join-Path $AppDir 'logs'
$LogFile   = Join-Path $LogDir 'fix.log'
$TaskName  = 'GitHubDirectFix'

# hosts 里的标记段。本段内容全部用 ASCII, 避免中文注释被写坏成 ??
$BlockBegin = '# >>> GitHubDirectFix BEGIN >>>'
$BlockEnd   = '# <<< GitHubDirectFix END <<<'

# 需要加速的域名
$Domains = @('github.com', 'www.github.com')

# 候选 IP 池: 全部来自 GitHub 官方公布的段 (https://api.github.com/meta)
# 140.82.112.0/20 是 GitHub 主站段; 20.x 那几个是官方单独列出的 web 地址
$Candidates = @(
    '140.82.112.3', '140.82.112.4',
    '140.82.113.3', '140.82.113.4',
    '140.82.114.3', '140.82.114.4',
    '140.82.115.3', '140.82.115.4',
    '140.82.116.3', '140.82.116.4',
    '20.27.177.113', '20.27.177.114',
    '20.200.245.247', '20.205.243.166',
    '20.201.28.151'
)

# ---------------------------------------------------------------- 基础工具

function Write-AppLog {
    param([string]$Message)
    $line = '{0}  {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message
    if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
    Add-Content -Path $LogFile -Value $line -Encoding UTF8
    if (-not $Silent) { Write-Host $line }
}

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Backup-HostsFile {
    if (-not (Test-Path $BackupDir)) { New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null }
    $dest = Join-Path $BackupDir ('hosts.backup-{0}.txt' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
    Copy-Item -Path $HostsPath -Destination $dest -Force
    return $dest
}

# ---------------------------------------------------------------- 探测

# 真连 443 + TLS 握手 + 校验证书。不通或证书不是 GitHub 的一律判死。
$ProbeScript = {
    param([string]$Ip, [int]$TimeoutMs)

    $tcp = New-Object System.Net.Sockets.TcpClient
    try {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $ar = $tcp.BeginConnect($Ip, 443, $null, $null)
        if (-not $ar.AsyncWaitHandle.WaitOne($TimeoutMs)) { return $null }
        if (-not $tcp.Connected) { return $null }

        $check = [System.Net.Security.RemoteCertificateValidationCallback]{
            param($sender, $cert, $chain, $errors)
            return ($cert.Subject -like '*github.com*')
        }
        $ssl = New-Object System.Net.Security.SslStream($tcp.GetStream(), $true, $check)
        $ssl.AuthenticateAsClient('github.com')
        $sw.Stop()
        $ms = [int]$sw.Elapsed.TotalMilliseconds
        $ssl.Dispose()

        return [pscustomobject]@{ IP = $Ip; Ms = $ms }
    }
    catch {
        return $null
    }
    finally {
        try { $tcp.Close() } catch { }
    }
}

function Measure-GitHubIps {
    param(
        [string[]]$Ips,
        [int]$TimeoutMs = 3000,
        [int]$MaxParallel = 16
    )

    $pool = [RunspaceFactory]::CreateRunspacePool(1, $MaxParallel)
    $pool.Open()
    $running = @()

    foreach ($ip in $Ips) {
        $ps = [PowerShell]::Create()
        $ps.RunspacePool = $pool
        $null = $ps.AddScript($ProbeScript).AddArgument($ip).AddArgument($TimeoutMs)
        $running += [pscustomobject]@{
            PS     = $ps
            Handle = $ps.BeginInvoke()
            IP     = $ip
        }
    }

    $alive = @()
    $dead  = @()
    foreach ($r in $running) {
        try {
            $res = $r.PS.EndInvoke($r.Handle)
            if ($res) { $alive += $res } else { $dead += $r.IP }
        }
        catch { $dead += $r.IP }
        finally { $r.PS.Dispose() }
    }
    $pool.Close()
    $pool.Dispose()

    $alive = $alive | Sort-Object Ms
    return [pscustomobject]@{
        Alive = $alive
        Dead  = $dead
    }
}

# ---------------------------------------------------------------- hosts 读写

function Get-CurrentPins {
    $pins = @()
    if (-not (Test-Path $HostsPath)) { return $pins }
    foreach ($l in (Get-Content -Path $HostsPath -Encoding UTF8 -ErrorAction SilentlyContinue)) {
        if ($l -match '^\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3})\s+(.+?)\s*$') {
            $names = $Matches[2] -split '\s+' | Where-Object { $_ }
            if ($names -contains 'github.com') {
                $pins += [pscustomobject]@{ IP = $Matches[1]; Line = $l.Trim() }
            }
        }
    }
    return $pins
}

function Update-HostsFile {
    param([string[]]$Ips)

    $lines = Get-Content -Path $HostsPath -Encoding UTF8 -ErrorAction SilentlyContinue
    $out   = New-Object System.Collections.Generic.List[string]
    $inBlock  = $false
    $tookOver = 0

    foreach ($l in $lines) {
        if ($l.Trim() -eq $BlockBegin) { $inBlock = $true; continue }
        if ($l.Trim() -eq $BlockEnd)   { $inBlock = $false; continue }
        if ($inBlock) { continue }

        # 块外遗留的手写 github.com 绑定一律接管, 免得和自动段打架
        if ($l -match '^\s*([0-9a-fA-F:.]+)\s+(.+?)\s*$') {
            $names = $Matches[2] -split '\s+' | Where-Object { $_ }
            if (($names | Where-Object { $Domains -contains $_ }) -and ($l -notmatch '^\s*#')) {
                $out.Add(('# [taken over by GitHubDirectFix] {0}' -f $l))
                $tookOver++
                continue
            }
        }
        $out.Add($l)
    }

    $out.Add('')
    $out.Add($BlockBegin)
    $out.Add('# Managed by GitHubDirectFix - do not edit this block by hand')
    $out.Add('# Updated: ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
    foreach ($ip in $Ips) {
        foreach ($d in $Domains) { $out.Add('{0}    {1}' -f $ip, $d) }
    }
    $out.Add($BlockEnd)

    $bak = Backup-HostsFile
    # hosts 用 ASCII 写, 防止中文注释被其他工具写成乱码
    [System.IO.File]::WriteAllLines($HostsPath, $out, (New-Object System.Text.UTF8Encoding($false)))

    try { Clear-DnsClientCache -ErrorAction Stop } catch { }
    try { & "$env:SystemRoot\System32\ipconfig.exe" /flushdns | Out-Null } catch { }

    return [pscustomobject]@{ Backup = $bak; TookOver = $tookOver }
}

# ---------------------------------------------------------------- 计划任务

function Install-Schedule {
    $ps1  = Join-Path $AppDir 'Fix-GitHub.ps1'
    $tr   = 'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File "{0}" -Fix -Silent' -f $ps1
    $args = @('/Create', '/TN', $TaskName, '/TR', $tr, '/SC', 'MINUTE', '/MO', '15', '/RL', 'HIGHEST', '/F')
    & "$env:SystemRoot\System32\schtasks.exe" $args 2>&1 | ForEach-Object { Write-AppLog "schtasks: $_" }
    if ($LASTEXITCODE -eq 0) {
        Write-AppLog "计划任务已安装: 每 15 分钟自动维护一次"
        return $true
    }
    Write-AppLog "计划任务安装失败, 退出码 $LASTEXITCODE (需要管理员权限)"
    return $false
}

function Uninstall-Schedule {
    & "$env:SystemRoot\System32\schtasks.exe" /Delete /TN $TaskName /F 2>&1 | ForEach-Object { Write-AppLog "schtasks: $_" }
    if ($LASTEXITCODE -eq 0) {
        Write-AppLog '计划任务已移除'
        return $true
    }
    Write-AppLog "移除失败, 退出码 $LASTEXITCODE"
    return $false
}

# ---------------------------------------------------------------- 主流程

function Invoke-Fix {
    if (-not (Test-IsAdmin)) {
        Write-AppLog '没有管理员权限, 改不了 hosts。请用 Run-GitHubFix.bat 启动。'
        return $null
    }

    $before = Get-CurrentPins
    Write-AppLog ('检测前 hosts 里的 github.com: {0}' -f (($before.IP -join ', ') -or '(无)'))

    $r = Measure-GitHubIps -Ips $Candidates
    Write-AppLog ('可用 {0} 个 / 超时 {1} 个' -f $r.Alive.Count, $r.Dead.Count)
    foreach ($a in $r.Alive) { Write-AppLog ('  OK   {0}  {1} ms' -f $a.IP, $a.Ms) }

    if ($r.Alive.Count -eq 0) {
        Write-AppLog '所有候选都不通, 本次不改 hosts (保留原样, 避免钉上死 IP)'
        return $null
    }

    # 只取最快的两个: Windows 会按顺序试, 记录太多会在 21 秒 SYN 超时里耗尽
    $pick = @($r.Alive | Select-Object -First 2 | ForEach-Object { $_.IP })
    Write-AppLog ('本次选中: {0}' -f ($pick -join ', '))

    $u = Update-HostsFile -Ips $pick
    Write-AppLog ('hosts 已更新, 备份: {0}, 接管旧绑定 {1} 条' -f $u.Backup, $u.TookOver)
    return $pick
}

function Get-StatusText {
    $pins = Get-CurrentPins
    $sb = New-Object System.Text.StringBuilder
    $null = $sb.AppendLine('=== 当前 hosts 里 github.com 的绑定 ===')
    if ($pins.Count -eq 0) {
        $null = $sb.AppendLine('(无, 走 DNS 自动解析)')
    }
    else {
        foreach ($p in $pins) { $null = $sb.AppendLine('  ' + $p.Line) }
    }
    $null = $sb.AppendLine('')
    $null = $sb.AppendLine('=== 逐个实测 (TCP443 + TLS 握手 + 证书校验) ===')
    $r = Measure-GitHubIps -Ips $Candidates
    foreach ($a in $r.Alive) { $null = $sb.AppendLine(('  可用  {0,-16} {1,5} ms' -f $a.IP, $a.Ms)) }
    foreach ($d in $r.Dead) { $null = $sb.AppendLine(('  不通  {0,-16}' -f $d)) }
    return $sb.ToString()
}

# ---------------------------------------------------------------- 图形界面

function Show-Gui {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'GitHub 直连助手'
    $form.Size = New-Object System.Drawing.Size(680, 520)
    $form.StartPosition = 'CenterScreen'
    $form.FormBorderStyle = 'FixedDialog'
    $form.MaximizeBox = $false
    $form.Font = New-Object System.Drawing.Font('Microsoft YaHei UI', 9)

    $lblTop = New-Object System.Windows.Forms.Label
    $lblTop.Location = New-Object System.Drawing.Point(15, 15)
    $lblTop.Size = New-Object System.Drawing.Size(640, 40)
    $lblTop.Text = '定时重测 GitHub 官方 IP, 把当前真正能连通的写进 hosts。改 hosts 需要管理员权限。'
    $form.Controls.Add($lblTop)

    $txt = New-Object System.Windows.Forms.TextBox
    $txt.Location = New-Object System.Drawing.Point(15, 60)
    $txt.Size = New-Object System.Drawing.Size(640, 300)
    $txt.Multiline = $true
    $txt.ScrollBars = 'Vertical'
    $txt.ReadOnly = $true
    $txt.Font = New-Object System.Drawing.Font('Consolas', 9)
    $txt.BackColor = [System.Drawing.Color]::White
    $form.Controls.Add($txt)

    $btnFix = New-Object System.Windows.Forms.Button
    $btnFix.Location = New-Object System.Drawing.Point(15, 375)
    $btnFix.Size = New-Object System.Drawing.Size(150, 34)
    $btnFix.Text = '立即检测并修复'
    $form.Controls.Add($btnFix)

    $btnCheck = New-Object System.Windows.Forms.Button
    $btnCheck.Location = New-Object System.Drawing.Point(175, 375)
    $btnCheck.Size = New-Object System.Drawing.Size(150, 34)
    $btnCheck.Text = '只看不修'
    $form.Controls.Add($btnCheck)

    $btnTask = New-Object System.Windows.Forms.Button
    $btnTask.Location = New-Object System.Drawing.Point(335, 375)
    $btnTask.Size = New-Object System.Drawing.Size(150, 34)
    $btnTask.Text = '装自动维护(15分钟)'
    $form.Controls.Add($btnTask)

    $btnUntask = New-Object System.Windows.Forms.Button
    $btnUntask.Location = New-Object System.Drawing.Point(495, 375)
    $btnUntask.Size = New-Object System.Drawing.Size(160, 34)
    $btnUntask.Text = '撤掉自动维护'
    $form.Controls.Add($btnUntask)

    $lblAdmin = New-Object System.Windows.Forms.Label
    $lblAdmin.Location = New-Object System.Drawing.Point(15, 420)
    $lblAdmin.Size = New-Object System.Drawing.Size(640, 24)
    if (Test-IsAdmin) {
        $lblAdmin.Text = '当前: 已管理员运行, 可以改 hosts'
        $lblAdmin.ForeColor = [System.Drawing.Color]::FromArgb(0, 120, 60)
    }
    else {
        $lblAdmin.Text = '当前: 没有管理员权限, 只能看不能改。请退出后用 Run-GitHubFix.bat 启动。'
        $lblAdmin.ForeColor = [System.Drawing.Color]::FromArgb(180, 40, 40)
    }
    $form.Controls.Add($lblAdmin)

    $btnFix.Add_Click({
        $btnFix.Enabled = $false
        $txt.Text = '正在测 15 个 IP, 大概 10 秒...'
        $form.Refresh()
        try {
            $pick = Invoke-Fix
            if ($pick) { $txt.Text = "已更新 hosts -> $($pick -join ', ')`r`n`r`n" + (Get-StatusText) }
            else { $txt.Text = "没改成(可能没权限, 或全部不通)。`r`n`r`n" + (Get-StatusText) }
        }
        catch { $txt.Text = "出错: $($_.Exception.Message)" }
        $btnFix.Enabled = $true
    })

    $btnCheck.Add_Click({
        $btnCheck.Enabled = $false
        $txt.Text = '正在测...'
        $form.Refresh()
        try { $txt.Text = Get-StatusText } catch { $txt.Text = "出错: $($_.Exception.Message)" }
        $btnCheck.Enabled = $true
    })

    $btnTask.Add_Click({
        if (Install-Schedule) { [System.Windows.Forms.MessageBox]::Show('自动维护已装好, 每 15 分钟跑一次。', 'GitHub 直连助手') }
        else { [System.Windows.Forms.MessageBox]::Show('安装失败, 需要用管理员身份运行。', 'GitHub 直连助手') }
    })

    $btnUntask.Add_Click({
        if (Uninstall-Schedule) { [System.Windows.Forms.MessageBox]::Show('自动维护已撤掉。', 'GitHub 直连助手') }
        else { [System.Windows.Forms.MessageBox]::Show('撤掉失败, 可能本来就没装。', 'GitHub 直连助手') }
    })

    $txt.Text = Get-StatusText
    $form.ShowDialog() | Out-Null
}

# ---------------------------------------------------------------- 入口

if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

if ($Uninstall) { Uninstall-Schedule; exit 0 }
if ($Install)   { Install-Schedule;   exit 0 }
if ($Fix)       { $null = Invoke-Fix;  exit 0 }
if ($Status)    { Get-StatusText | Write-Host; exit 0 }

Show-Gui
