<#
.SYNOPSIS
    MaintenanceSuprema v6.1 – Script modular PowerShell para manutenção avançada de Windows
.AUTOR
    Regnon Molina
.DESCRIPTION
    Agrupa em funções:
      • Logging
      • Limpeza (temporários, WinUpdate, DNS, Storage Sense)
      • Otimização de volumes e registro
      • Reparo de sistema (DISM/SFC)
      • Remoção de bloatware
      • Desativação de serviços/tarefas/telemetria
      • Atualizações (Windows, Store, Drivers)
      • Reinício opcional
.PARAMETER NoReboot
    Se presente, pula o prompt de reinício.
#>

param(
    [switch]$NoReboot
)

# ——————————————————————————————————————————————————————————
# Configurações e utilitários
# ——————————————————————————————————————————————————————————
$ErrorActionPreference = 'Continue'
$LogFile = Join-Path $env:TEMP "MaintSuprema_$(Get-Date -Format yyyyMMdd_HHmmss).log"

function Write-Log {
    param(
        [string]$Message,
        [ConsoleColor]$Color = 'White'
    )
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    "$ts  $Message" | Tee-Object -FilePath $LogFile -Append | Write-Host -ForegroundColor $Color
}

function Require-Admin {
    if (-not ([Security.Principal.WindowsPrincipal] `
        [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
        [Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Log "Execute como Administrador!" Red
        exit 1
    }
}

# ——————————————————————————————————————————————————————————
# Limpeza
# ——————————————————————————————————————————————————————————
function Clean-Temporary {
    Write-Log "🔸 Limpando arquivos temporários..." Yellow
    $paths = @(
        "$env:TEMP\*",
        "$env:SystemRoot\Temp\*",
        "$env:LOCALAPPDATA\Temp\*"
    )
    foreach ($p in $paths) {
        Remove-Item $p -Recurse -Force -ErrorAction SilentlyContinue
    }
    Write-Log "→ OK" Green
}

function Clean-WinUpdateCache {
    Write-Log "🔸 Limpando cache do Windows Update..." Yellow
    Stop-Service wuauserv -Force -ErrorAction SilentlyContinue
    Remove-Item "$env:SystemRoot\SoftwareDistribution\Download\*" `
        -Recurse -Force -ErrorAction SilentlyContinue
    Start-Service wuauserv -ErrorAction SilentlyContinue
    Write-Log "→ OK" Green
}

function Flush-DNS {
    Write-Log "🔸 Flush DNS..." Yellow
    ipconfig /flushdns | Out-Null
    Write-Log "→ OK" Green
}

function Clean-StorageSense {
    Write-Log "🔸 Ativando Storage Sense para limpar cache do Store..." Yellow
    $key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy'
    New-ItemProperty -Path $key -Name '01' -PropertyType DWord -Value 1 -Force | Out-Null
    Write-Log "→ OK" Green
}

# ——————————————————————————————————————————————————————————
# Otimização
# ——————————————————————————————————————————————————————————
function Optimize-Volumes {
    Write-Log "🔸 Otimizando volumes..." Yellow
    Get-Volume -DriveType Fixed | ForEach-Object {
        $dl = $_.DriveLetter + ':'
        if ($_.FileSystem -in 'NTFS','ReFS') {
            if ($_.PhysicalSectorSize -le 4096) {
                Write-Log "   • TRIM em $dl" Cyan
                Optimize-Volume -DriveLetter $_.DriveLetter -ReTrim | Out-Null
            } else {
                Write-Log "   • Defrag em $dl" Cyan
                Optimize-Volume -DriveLetter $_.DriveLetter -Defrag | Out-Null
            }
        }
    }
    Write-Log "→ OK" Green
}

function Optimize-Registry {
    Write-Log "🔸 Otimizando registro básico..." Yellow
    # Ajusta prioridade de perfil como exemplo
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" `
        /v ProcessPriorityClass /t REG_DWORD /d 8 /f | Out-Null
    Write-Log "→ OK" Green
}

# ——————————————————————————————————————————————————————————
# Reparo de Sistema
# ——————————————————————————————————————————————————————————
function Repair-System {
    Write-Log "🔸 Reparando sistema (DISM + SFC)..." Yellow
    dism /online /cleanup-image /restorehealth | Out-Null
    sfc /scannow | Out-Null
    Write-Log "→ OK" Green
}

function Cleanup-OldUpdates {
    Write-Log "🔸 Limpando atualizações antigas..." Yellow
    dism /online /cleanup-image /startcomponentcleanup | Out-Null
    Write-Log "→ OK" Green
}

# ——————————————————————————————————————————————————————————
# Bloatware / Telemetria / Serviços / Tarefas
# ——————————————————————————————————————————————————————————
function Remove-Bloatware {
    Write-Log "🔸 Removendo bloatware (preserva Fotos/Câmera/Notepad)..." Yellow
    $bloat = @(
        "Microsoft.BingNews","Microsoft.BingWeather","Microsoft.GetHelp",
        "Microsoft.Getstarted","Microsoft.MicrosoftOfficeHub",
        "Microsoft.MicrosoftSolitaireCollection","Microsoft.People",
        "Microsoft.SkypeApp","Microsoft.WindowsAlarms",
        "microsoft.windowscommunicationsapps","Microsoft.WindowsFeedbackHub",
        "Microsoft.WindowsMaps","Microsoft.WindowsSoundRecorder",
        "Microsoft.Xbox*","Microsoft.Zune*","Microsoft.YourPhone",
        "Microsoft.MixedReality.Portal"
    )
    foreach ($app in $bloat) {
        Get-AppxPackage -Name $app -AllUsers |
            Remove-AppxPackage -ErrorAction SilentlyContinue
        Get-AppxProvisionedPackage -Online |
            Where-Object DisplayName -Like $app |
            Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
    }
    Write-Log "→ OK" Green
}

function Disable-UnneededTasks {
    Write-Log "🔸 Desativando tarefas agendadas inúteis..." Yellow
    $paths = @(
        '\Microsoft\Windows\Application Experience\*',
        '\Microsoft\Windows\Customer Experience Improvement Program\*',
        '\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem'
    )
    foreach ($p in $paths) {
        Get-ScheduledTask -TaskPath $p -ErrorAction SilentlyContinue |
            Disable-ScheduledTask -ErrorAction SilentlyContinue
    }
    Write-Log "→ OK" Green
}

function Disable-UnneededServices {
    Write-Log "🔸 Desativando serviços inúteis (Telemetria/Xbox)..." Yellow
    $svcs = @(
        'DiagTrack','dmwappushservice','lfsvc','MapsBroker',
        'WMPNetworkSvc','XblAuthManager','XblGameSave','XboxNetApiSvc'
    )
    foreach ($s in $svcs) {
        Stop-Service $s -Force -ErrorAction SilentlyContinue
        Set-Service $s -StartupType Disabled -ErrorAction SilentlyContinue
    }
    Write-Log "→ OK" Green
}

function Configure-Privacy {
    Write-Log "🔸 Aplicando políticas de privacidade..." Yellow
    $policies = @{
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' = @{AllowTelemetry=0}
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' = @{AllowCortana=0}
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' = @{
            ContentDeliveryAllowed=0; 'SubscribedContent-338388Enabled'=0
        }
    }
    foreach ($path in $policies.Keys) {
        foreach ($name in $policies[$path].Keys) {
            New-ItemProperty -Path $path -Name $name -PropertyType DWORD `
                -Value $policies[$path][$name] -Force | Out-Null
        }
    }
    Write-Log "→ OK" Green
}

# ——————————————————————————————————————————————————————————
# Atualizações
# ——————————————————————————————————————————————————————————
function Update-WindowsAndStore {
    Write-Log "🔸 Instalando atualizações do Windows..." Yellow
    $session = New-Object -ComObject Microsoft.Update.Session
    $searcher = $session.CreateUpdateSearcher()
    $soft = $searcher.Search("IsInstalled=0 and Type='Software'")
    if ($soft.Updates.Count) {
        $col = New-Object -ComObject Microsoft.Update.UpdateColl
        $soft.Updates | ForEach-Object { $col.Add($_)|Out-Null }
        $installer = $session.CreateUpdateInstaller(); $installer.Updates = $col
        $installer.Install() | Out-Null
    }

    Write-Log "🔸 Atualizando apps da Microsoft Store..." Yellow
    Get-AppxPackage -AllUsers |
      Where-Object { -not $_.IsFramework -and -not $_.NonRemovable } |
      ForEach-Object {
        Try {
          Add-AppxPackage -Register -DisableDevelopmentMode `
            "$($_.InstallLocation)\AppXManifest.xml" -ErrorAction Stop
        } Catch {}
      }
    Write-Log "→ OK" Green
}

function Update-Drivers {
    Write-Log "🔸 Instalando atualizações de drivers..." Yellow
    $session = New-Object -ComObject Microsoft.Update.Session
    $searcher = $session.CreateUpdateSearcher()
    $drivers = $searcher.Search("IsInstalled=0 and Type='Driver'").Updates
    if ($drivers.Count) {
        $colD = New-Object -ComObject Microsoft.Update.UpdateColl
        $drivers | ForEach-Object { $colD.Add($_)|Out-Null }
        $installer = $session.CreateUpdateInstaller(); $installer.Updates = $colD
        $installer.Install() | Out-Null
    }
    pnputil /scan-devices | Out-Null
    pnputil /update-drivers | Out-Null
    Write-Log "→ OK" Green
}

# ——————————————————————————————————————————————————————————
# Orquestração Principal
# ——————————————————————————————————————————————————————————
function Main {
    Require-Admin
    Write-Log "=== Iniciando Manutenção Suprema v6.1 ===" Cyan

    # Limpeza
    Clean-Temporary
    Clean-WinUpdateCache
    Flush-DNS
    Clean-StorageSense

    # Otimização
    Optimize-Volumes
    Optimize-Registry

    # Reparo
    Repair-System
    Cleanup-OldUpdates

    # Bloatware & Privacidade
    Remove-Bloatware
    Disable-UnneededTasks
    Disable-UnneededServices
    Configure-Privacy

    # Atualizações
    Update-WindowsAndStore
    Update-Drivers

    Write-Log "=== Manutenção concluída! Log em: $LogFile ===" Cyan

    if (-not $NoReboot) {
        if (Read-Host "Reiniciar agora? [S/N]" -match '^[Ss]') {
            Write-Log "Reiniciando..." Yellow
            Restart-Computer
        }
    }
}

# Executa
Main
