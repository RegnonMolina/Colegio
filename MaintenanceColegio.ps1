<#
.SYNOPSIS
    Script Supremo de Manutenção Windows – Limpeza, Otimização, Reparo, Bloatware, Privacidade, Atualizações e Otimizações de Laptop
.DESCRIPTION
    • Modularizado em funções  
    • Remove bloatware (exceto Notepad, Camera, Photos)  
    • Limpeza de arquivos temporários, Windows Update, DNS, Storage Sense  
    • Otimização de volumes (TRIM/HDD) e registro  
    • Reparo de sistema (DISM + SFC) e limpeza de componentes antigos  
    • Desativação de tarefas, serviços de telemetria/Xbox e configurações de privacidade  
    • Atualizações: Windows Update, Microsoft Store, Drivers  
    • Otimizações avançadas para laptops (GPU híbrida, touchpad, brilho, USB)  
.PARAMETER NoReboot
    Se presente, não pergunta por reinício ao final.  
.PARAMETER ForceDriverUpdate
    Se presente, força atualização de drivers mesmo sem novas detecções.
.NOTES
    Autor: Regnon Molina 
    Versão: 1.0 – Script Supremo  
    Requisitos: PowerShell 5.1+ (executar como Administrador)
#>

param(
    [switch]$NoReboot,
    [switch]$ForceDriverUpdate
)

#————————————————————————————————————————————————————————————————————
# Verificar permissão de Administrador
#————————————————————————————————————————————————————————————————————
if (-not ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
    [Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "🔴 Execute este script como Administrador!" -ForegroundColor Red
    exit 1
}

#————————————————————————————————————————————————————————————————————
# Configurações e Log
#————————————————————————————————————————————————————————————————————
$ErrorActionPreference = 'Continue'
$LogFile = Join-Path $env:TEMP "ScriptSupremo_$(Get-Date -Format yyyyMMdd_HHmmss).log"

function Write-Log {
    param([string]$Msg, [ConsoleColor]$Color = 'White')
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    "$ts  $Msg" | Tee-Object -FilePath $LogFile -Append |
        Write-Host -ForegroundColor $Color
}

Write-Log "=== INICIANDO SCRIPT SUPREMO DE MANUTENÇÃO ===" Cyan

#————————————————————————————————————————————————————————————————————
# BLOCO 1 – LIMPEZA
#————————————————————————————————————————————————————————————————————
function Clean-Temps {
    Write-Log "🔸 Limpando arquivos temporários..." Yellow
    $paths = @("$env:TEMP\*", "$env:SystemRoot\Temp\*", "$env:LOCALAPPDATA\Temp\*")
    foreach ($p in $paths) {
        Remove-Item $p -Recurse -Force -ErrorAction SilentlyContinue
    }
    Write-Log "→ Tempos limpos" Green
}

function Clean-WUCache {
    Write-Log "🔸 Limpando cache do Windows Update..." Yellow
    Stop-Service wuauserv -Force -ErrorAction SilentlyContinue
    Remove-Item "$env:SystemRoot\SoftwareDistribution\Download\*" -Recurse -Force -ErrorAction SilentlyContinue
    Start-Service wuauserv -ErrorAction SilentlyContinue
    Write-Log "→ Cache Windows Update limpo" Green
}

function Clean-DNS {
    Write-Log "🔸 Limpando cache DNS..." Yellow
    ipconfig /flushdns | Out-Null
    Write-Log "→ Cache DNS limpo" Green
}

function Clean-StorageSense {
    Write-Log "🔸 Ativando Storage Sense para limpar cache da Store..." Yellow
    $key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy'
    New-ItemProperty -Path $key -Name '01' -PropertyType DWord -Value 1 -Force | Out-Null
    Write-Log "→ Storage Sense ativado" Green
}

#————————————————————————————————————————————————————————————————————
# BLOCO 2 – OTIMIZAÇÃO
#————————————————————————————————————————————————————————————————————
function Optimize-Volumes {
    Write-Log "🔸 Otimizando volumes (SSD/TRIM – HDD/Defrag)..." Yellow
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
    Write-Log "→ Volumes otimizados" Green
}

function Optimize-Registry {
    Write-Log "🔸 Otimizando registro (prioridade de perfil)..." Yellow
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" `
        /v ProcessPriorityClass /t REG_DWORD /d 8 /f | Out-Null
    Write-Log "→ Registro otimizado" Green
}

#————————————————————————————————————————————————————————————————————
# BLOCO 3 – REPARO
#————————————————————————————————————————————————————————————————————
function Repair-System {
    Write-Log "🔸 Executando DISM /restorehealth..." Yellow
    dism /online /cleanup-image /restorehealth | Out-Null
    Write-Log "🔸 Executando SFC /scannow..." Yellow
    sfc /scannow | Out-Null
    Write-Log "→ Sistema reparado" Green
}

function Cleanup-OldWU {
    Write-Log "🔸 Limpando componentes antigos do Windows Update..." Yellow
    dism /online /cleanup-image /startcomponentcleanup | Out-Null
    Write-Log "→ Componentes limpos" Green
}

#————————————————————————————————————————————————————————————————————
# BLOCO 4 – BLOATWARE
#————————————————————————————————————————————————————————————————————
function Remove-Bloatware {
    Write-Log "🔸 Removendo bloatware (exceto Notepad/Camera/Photos)..." Yellow
    $exceptions = @('Microsoft.WindowsNotepad','Microsoft.WindowsCamera','Microsoft.Windows.Photos')
    $apps = Get-AppxPackage -AllUsers | Where-Object {
        ($_.Name -like 'Microsoft.*') -and ($exceptions -notcontains $_.Name)
    }
    foreach ($app in $apps) {
        Remove-AppxPackage -Package $app.PackageFullName -AllUsers -ErrorAction SilentlyContinue
        Remove-AppxProvisionedPackage -Online -PackageName $app.PackageFullName -ErrorAction SilentlyContinue
    }
    Write-Log "→ Bloatware removido" Green
}

#————————————————————————————————————————————————————————————————————
# BLOCO 5 – TAREFAS, SERVIÇOS E PRIVACIDADE
#————————————————————————————————————————————————————————————————————
function Disable-Tasks {
    Write-Log "🔸 Desativando tarefas desnecessárias..." Yellow
    $paths = @(
        '\Microsoft\Windows\Application Experience\*',
        '\Microsoft\Windows\Customer Experience Improvement Program\*',
        '\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem'
    )
    foreach ($p in $paths) {
        Get-ScheduledTask -TaskPath $p -ErrorAction SilentlyContinue |
            Disable-ScheduledTask -ErrorAction SilentlyContinue
    }
    Write-Log "→ Tarefas desativadas" Green
}

function Disable-Services {
    Write-Log "🔸 Desativando serviços de telemetria/Xbox..." Yellow
    $svcs = @(
        'DiagTrack','dmwappushservice','lfsvc','MapsBroker',
        'WMPNetworkSvc','XblAuthManager','XblGameSave','XboxNetApiSvc'
    )
    foreach ($s in $svcs) {
        Stop-Service $s -Force -ErrorAction SilentlyContinue
        Set-Service  $s -StartupType Disabled -ErrorAction SilentlyContinue
    }
    Write-Log "→ Serviços desativados" Green
}

function Configure-Privacy {
    Write-Log "🔸 Configurando políticas de privacidade..." Yellow
    $pols = @{
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'                = @{AllowTelemetry=0}
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'                 = @{AllowCortana   =0}
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'    = @{
            ContentDeliveryAllowed    =0
            SubscribedContent-338388Enabled =0
        }
    }
    foreach ($path in $pols.Keys) {
        foreach ($name in $pols[$path].Keys) {
            New-ItemProperty -Path $path -Name $name `
                -PropertyType DWORD -Value $pols[$path][$name] -Force | Out-Null
        }
    }
    Write-Log "→ Privacidade ajustada" Green
}

#————————————————————————————————————————————————————————————————————
# BLOCO 6 – OTIMIZAÇÕES PARA LAPTOP
#————————————————————————————————————————————————————————————————————
function Optimize-Laptop {
    $isLaptop = (Get-CimInstance Win32_ComputerSystem).PCSystemType -eq 2
    if (-not $isLaptop) { return }
    Write-Log "🔸 Aplicando otimizações para Laptop..." Magenta

    # GPU híbrida
    Write-Log "   • Ajustando GPU híbrida..." Cyan
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" `
        /v PowerPolicy /t REG_DWORD /d 2 /f | Out-Null
    if (Test-Path "HKLM\SOFTWARE\NVIDIA Corporation") {
        reg add "HKLM\SOFTWARE\NVIDIA Corporation\Global\NvControlPanel2\Client" `
            /v OptimusEnable /t REG_DWORD /d 1 /f | Out-Null
    }

    # Touchpad
    Write-Log "   • Otimizando touchpad..." Cyan
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PrecisionTouchPad" `
        /v AAPThreshold  /t REG_DWORD /d 1  /f | Out-Null
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PrecisionTouchPad" `
        /v InitialSpeed  /t REG_DWORD /d 50 /f | Out-Null

    # Brilho inteligente
    Write-Log "   • Configurando gerenciamento de brilho..." Cyan
    powercfg /setdcvalueindex SCHEME_CURRENT SUB_VIDEO ADAPTBRIGHT   1 | Out-Null
    powercfg /setdcvalueindex SCHEME_CURRENT SUB_VIDEO VIDEOCONLOCK 60 | Out-Null

    # USB e backlight
    Write-Log "   • Ajustando USB selective suspend..." Cyan
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" `
        /v USBSelectiveSuspendEnabled /t REG_DWORD /d 1 /f | Out-Null

    Write-Log "→ Otimizações de laptop concluídas" Green
}

#————————————————————————————————————————————————————————————————————
# BLOCO 7 – ATUALIZAÇÕES
#————————————————————————————————————————————————————————————————————
function Update-Windows {
    Write-Log "🔸 Verificando/Instalando Windows Update..." Yellow
    $sess = New-Object -ComObject Microsoft.Update.Session
    $search = $sess.CreateUpdateSearcher()
    $res = $search.Search("IsInstalled=0 and Type='Software'")
    if ($res.Updates.Count) {
        $col = New-Object -ComObject Microsoft.Update.UpdateColl
        $res.Updates | ForEach-Object { $col.Add($_)| Out-Null }
        $inst = $sess.CreateUpdateInstaller(); $inst.Updates = $col
        $inst.Install() | Out-Null
    }
    Write-Log "→ Windows Update OK" Green
}

function Update-Store {
    Write-Log "🔸 Atualizando apps da Microsoft Store..." Yellow
    Get-AppxPackage -AllUsers |
      Where-Object { -not $_.IsFramework -and -not $_.NonRemovable } |
      ForEach-Object {
        Try {
          Add-AppxPackage -Register -DisableDevelopmentMode `
            "$($_.InstallLocation)\AppXManifest.xml" -ErrorAction Stop
        } Catch {}
      }
    Write-Log "→ Store OK" Green
}

function Update-Drivers {
    Write-Log "🔸 Atualizando drivers via Windows Update..." Yellow
    $sess   = New-Object -ComObject Microsoft.Update.Session
    $search = $sess.CreateUpdateSearcher()
    $drv    = $search.Search("IsInstalled=0 and Type='Driver'").Updates
    if ($drv.Count) {
        $col = New-Object -ComObject Microsoft.Update.UpdateColl
        $drv | ForEach-Object { $col.Add($_)| Out-Null }
        $inst = $sess.CreateUpdateInstaller(); $inst.Updates = $col
        $inst.Install() | Out-Null
    }
    if ($ForceDriverUpdate) {
        Write-Log "   • Forçando atualização via PnPUtil" Yellow
        pnputil /scan-devices   | Out-Null
        pnputil /update-drivers | Out-Null
    }
    Write-Log "→ Drivers OK" Green
}

#————————————————————————————————————————————————————————————————————
# EXECUÇÃO SEQUENCIAL
#————————————————————————————————————————————————————————————————————
Clean-Temps
Clean-WUCache
Clean-DNS
Clean-StorageSense

Optimize-Volumes
Optimize-Registry

Repair-System
Cleanup-OldWU

Remove-Bloatware

Disable-Tasks
Disable-Services
Configure-Privacy

Optimize-Laptop

Update-Windows
Update-Store
Update-Drivers

Write-Log "=== MANUTENÇÃO SUPREMA CONCLUÍDA! Log em: $LogFile ===" Cyan

if (-not $NoReboot) {
    if (Read-Host "Reiniciar agora? [S/N]" -match '^[Ss]') {
        Write-Log "🔄 Reiniciando sistema..." Yellow
        Restart-Computer
    }
}
