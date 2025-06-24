<#
.SYNOPSIS
    Manutenção Suprema Windows 6.0 - Limpeza, Otimização, Remoção de Bloatware e Atualizações
.DESCRIPTION
    - Limpeza de temporários, DNS, Windows Update, Storage Sense
    - Reparo de sistema (DISM + SFC)
    - Otimização de volumes (TRIM p/ SSD, defrag p/ HDD)
    - Remoção de bloatware (exceto Fotos, Câmera, Notepad)
    - Desativação de serviços e tarefas de telemetria/Xbox
    - Atualizações Windows, Store e Drivers
.PARAMETER NoReboot
    Se presente, não solicitar reinicialização automática ao fim.
.NOTES
    Autor: Adaptado por PowerShellGPT  
    Versão: 6.0  
    Requisitos: PowerShell 5.1+ (Admin)
#>

param(
    [switch]$NoReboot
)

# ————————————————————————————————————————————————
# Verifica permissão de Administrador
# ————————————————————————————————————————————————
if (-not ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
    [Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "Execute este script como Administrador!"
    exit 1
}

# ————————————————————————————————————————————————
# Configurações Gerais
# ————————————————————————————————————————————————
$ErrorActionPreference = 'Continue'
$LogFile = "$env:TEMP\MaintSuprema_$(Get-Date -Format yyyyMMdd_HHmmss).log"
function Write-Log {
    param($msg, $color='White')
    $t = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    "$t  $msg" | Tee-Object -FilePath $LogFile -Append |
        Write-Host -ForegroundColor $color
}

Write-Log "=== INÍCIO DA MANUTENÇÃO SUPREMA v6.0 ===" Cyan

# ————————————————————————————————————————————————
# 1. Limpeza de Arquivos Temporários
# ————————————————————————————————————————————————
Write-Log "1. Limpando temporários..." Yellow
Try {
    $paths = @(
        "$env:TEMP\*",
        "$env:SystemRoot\Temp\*",
        "$env:LOCALAPPDATA\Temp\*"
    )
    foreach ($p in $paths) {
        Remove-Item $p -Recurse -Force -ErrorAction SilentlyContinue
    }
    Write-Log "-> OK" Green
} Catch {
    Write-Log "Erro: $_" Red
}

# ————————————————————————————————————————————————
# 2. Limpeza do Cache do Windows Update
# ————————————————————————————————————————————————
Write-Log "2. Limpando cache do Windows Update..." Yellow
Try {
    Stop-Service wuauserv -Force -ErrorAction SilentlyContinue
    Remove-Item "$env:SystemRoot\SoftwareDistribution\Download\*" `
        -Recurse -Force -ErrorAction SilentlyContinue
    Start-Service wuauserv -ErrorAction SilentlyContinue
    Write-Log "-> OK" Green
} Catch {
    Write-Log "Erro: $_" Red
}

# ————————————————————————————————————————————————
# 3. Flush DNS
# ————————————————————————————————————————————————
Write-Log "3. Flush DNS..." Yellow
ipconfig /flushdns | Out-Null
Write-Log "-> OK" Green

# ————————————————————————————————————————————————
# 4. Otimização de Volumes (TRIM ou Defrag)
# ————————————————————————————————————————————————
Write-Log "4. Otimizando volumes..." Yellow
Get-Volume | Where-Object DriveType -Eq 'Fixed' | ForEach-Object {
    $dl = $_.DriveLetter + ":"
    if ($_.FileSystem -in 'NTFS','ReFS') {
        if ($_.PhysicalSectorSize -le 4096) {
            Write-Log "  TRIM em $dl" Cyan
            Optimize-Volume -DriveLetter $_.DriveLetter -ReTrim
        } else {
            Write-Log "  Defrag em $dl" Cyan
            Optimize-Volume -DriveLetter $_.DriveLetter -Defrag
        }
    }
}
Write-Log "-> OK" Green

# ————————————————————————————————————————————————
# 5. Armazenamento Inteligente (Storage Sense)
# ————————————————————————————————————————————————
Write-Log "5. Limpando cache do Store com Storage Sense..." Yellow
Reg Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" `
    /v "01" /t REG_DWORD /d 1 /f | Out-Null
Write-Log "-> OK" Green

# ————————————————————————————————————————————————
# 6. Reparo de Sistema (DISM + SFC)
# ————————————————————————————————————————————————
Write-Log "6. Reparando SO (DISM + SFC)..." Yellow
dism /online /cleanup-image /restorehealth | Out-Null
sfc /scannow | Out-Null
Write-Log "-> OK" Green

# ————————————————————————————————————————————————
# 7. Limpeza de Atualizações Antigas
# ————————————————————————————————————————————————
Write-Log "7. Limpando componentes antigos do WinUpdate..." Yellow
dism /online /cleanup-image /startcomponentcleanup | Out-Null
Write-Log "-> OK" Green

# ————————————————————————————————————————————————
# 8. Otimização de Registro Básica
# ————————————————————————————————————————————————
Write-Log "8. Otimizando registro..." Yellow
# Exemplo: ajusta prioridade de perfil
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" `
    /v ProcessPriorityClass /t REG_DWORD /d 8 /f | Out-Null
Write-Log "-> OK" Green

# ————————————————————————————————————————————————
# 9. Reinício de Serviços Críticos
# ————————————————————————————————————————————————
Write-Log "9. Reiniciando serviços críticos..." Yellow
"wuauserv","bits","cryptSvc","DcomLaunch" | % { 
    Try { Restart-Service $_ -Force } Catch{} 
}
Write-Log "-> OK" Green

# ————————————————————————————————————————————————
# 10. Remoção de Bloatware (exceto Fotos, Câmera, Notepad)
# ————————————————————————————————————————————————
Write-Log "10. Removendo bloatware..." Yellow
$bloat = @(
    "Microsoft.BingNews","Microsoft.BingWeather","Microsoft.GetHelp",
    "Microsoft.Getstarted","Microsoft.MicrosoftOfficeHub",
    "Microsoft.MicrosoftSolitaireCollection","Microsoft.People",
    "Microsoft.SkypeApp","Microsoft.WindowsAlarms",
    "microsoft.windowscommunicationsapps","Microsoft.WindowsFeedbackHub",
    "Microsoft.WindowsMaps","Microsoft.WindowsSoundRecorder",
    "Microsoft.Xbox.TCUI","Microsoft.XboxApp","Microsoft.XboxGameOverlay",
    "Microsoft.XboxIdentityProvider","Microsoft.XboxSpeechToTextOverlay",
    "Microsoft.ZuneMusic","Microsoft.ZuneVideo","Microsoft.YourPhone",
    "Microsoft.MixedReality.Portal"
)
foreach ($app in $bloat) {
    Get-AppxPackage -Name $app -AllUsers |
        Remove-AppxPackage -ErrorAction SilentlyContinue
    Get-AppxProvisionedPackage -Online |
        Where-Object DisplayName -Like $app |
        Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
}
Write-Log "-> OK" Green

# ————————————————————————————————————————————————
# 11. Desativação de Tarefas Agendadas Inúteis
# ————————————————————————————————————————————————
Write-Log "11. Desativando tarefas inúteis..." Yellow
$scht = @(
    "\Microsoft\Windows\Application Experience\*",
    "\Microsoft\Windows\Customer Experience Improvement Program\*",
    "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem"
)
foreach ($t in $scht) {
    Get-ScheduledTask -TaskPath $t -ErrorAction SilentlyContinue |
        Disable-ScheduledTask -ErrorAction SilentlyContinue
}
Write-Log "-> OK" Green

# ————————————————————————————————————————————————
# 12. Desativação de Serviços Inúteis (Telemetria / Xbox)
# ————————————————————————————————————————————————
Write-Log "12. Desativando serviços inúteis..." Yellow
$svcs = "DiagTrack","dmwappushservice","lfsvc","MapsBroker",
        "WMPNetworkSvc","XblAuthManager","XblGameSave","XboxNetApiSvc"
foreach ($s in $svcs) {
    Stop-Service $s -Force -ErrorAction SilentlyContinue
    Set-Service $s -StartupType Disabled -ErrorAction SilentlyContinue
}
Write-Log "-> OK" Green

# ————————————————————————————————————————————————
# 13. Desativação de Telemetria / Cortana / Anúncios
# ————————————————————————————————————————————————
Write-Log "13. Ajustando políticas de privacidade..." Yellow
$keys = @{
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" = @{AllowTelemetry=0}
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" = @{AllowCortana=0}
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" = @{
        ContentDeliveryAllowed=0; "SubscribedContent-338388Enabled"=0
    }
}
foreach ($k in $keys.Keys) {
    foreach ($n in $keys[$k].Keys) {
        reg add $k /v $n /t REG_DWORD /d $keys[$k][$n] /f | Out-Null
    }
}
Write-Log "-> OK" Green

# ————————————————————————————————————————————————
# 14. Atualizações Windows Update + Microsoft Store
# ————————————————————————————————————————————————
Write-Log "14. Atualizando Windows Update e Store..." Yellow
Try {
    $session = New-Object -ComObject Microsoft.Update.Session
    $searcher = $session.CreateUpdateSearcher()
    $res = $searcher.Search("IsInstalled=0 and Type='Software'")
    if ($res.Updates.Count) {
        Write-Log "-> Instalando $($res.Updates.Count) updates..." Cyan
        $col = New-Object -ComObject Microsoft.Update.UpdateColl
        $res.Updates | % { $col.Add($_) | Out-Null }
        $installer = $session.CreateUpdateInstaller(); $installer.Updates = $col
        $installer.Install() | Out-Null
    }

    # Store: força registro dos manifests
    Get-AppxPackage -AllUsers |
        Where-Object { -not $_.IsFramework -and -not $_.NonRemovable } |
        ForEach-Object {
            Try {
                Add-AppxPackage -Register -DisableDevelopmentMode `
                    "$($_.InstallLocation)\AppXManifest.xml" -ErrorAction Stop
            } Catch {}
        }
    Write-Log "-> OK" Green
} Catch {
    Write-Log "Erro: $_" Red
}

# ————————————————————————————————————————————————
# 15. Atualização de Drivers (Windows Update + PnPUtil)
# ————————————————————————————————————————————————
Write-Log "15. Atualizando drivers..." Yellow
Try {
    $drv = $searcher.Search("IsInstalled=0 and Type='Driver'").Updates
    if ($drv.Count) {
        Write-Log "-> Instalando $($drv.Count) drivers..." Cyan
        $colD = New-Object -ComObject Microsoft.Update.UpdateColl
        $drv | % { $colD.Add($_) | Out-Null }
        $instD = $session.CreateUpdateInstaller(); $instD.Updates = $colD
        $instD.Install() | Out-Null
    }
    pnputil /scan-devices | Out-Null
    pnputil /update-drivers | Out-Null
    Write-Log "-> OK" Green
} Catch {
    Write-Log "Erro: $_" Red
}

# ————————————————————————————————————————————————
# 16. Relatório e Fim
# ————————————————————————————————————————————————
Write-Log "=== MANUTENÇÃO COMPLETA em $((Get-Date)-($LogFile -split '_')[1].Substring(0,14)) ===" Cyan
Write-Log "Log: $LogFile" Cyan

if (-not $NoReboot) {
    $r = Read-Host "Reiniciar agora? [S/N]"
    if ($r -match '^[Ss]') {
        Write-Log "Reiniciando..." Yellow
        Restart-Computer
    }
}
