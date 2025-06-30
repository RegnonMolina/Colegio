# ─────────────────────────────────────────────────────────────────
# Windows Maintenance Supreme – Versão Final
# Execute como Administrador
# Autor : Regnon Molina
# ─────────────────────────────────────────────────────────────────

#region Configurações Iniciais

param(
    [switch]$ForceDriverUpdate
)

# Política de Execução e Preferências Globais
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Unrestricted -Force
$ErrorActionPreference   = 'SilentlyContinue'
$ProgressPreference      = 'Continue'
$ConfirmPreference       = 'None'
$VerbosePreference       = 'SilentlyContinue'

# Variáveis de ambiente e paths
$StartTime      = Get-Date
$LogDate        = $StartTime.ToString('dd-MM-yyyy-HH')
$LogFile        = "$env:TEMP\WinMaint_Full_$LogDate.log"
$DaysToDelete   = 1
$winDist        = 'C:\Windows\SoftwareDistribution'
$computer       = $env:COMPUTERNAME
$currentTime    = $StartTime.ToString('dd-MM-yyyy HH:mm:ss')

# Shell OneDrive (se usar)
$objShell       = New-Object -ComObject Shell.Application
$objFolder      = $objShell.Namespace(0xA)

# Detecta SSID/Interface Wi-Fi atuais
$netIfaces      = netsh wlan show interfaces
$ssidLine       = $netIfaces | Where-Object { $_ -match ' SSID ' }
$connectionProfile = Get-NetConnectionProfile |
    Where-Object { $ssidLine -match $_.Name -and $_.IPv4Connectivity -eq 'Internet' } |
    Select-Object -First 1

if ($connectionProfile) {
    $ssid      = $connectionProfile.Name
    $interface = $connectionProfile.InterfaceAlias
} else {
    Write-Warning 'Não foi possível obter SSID/Interface do Wi-Fi.'
    $ssid      = ''
    $interface = ''
}

#endregion

#region Funções Auxiliares

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('White','Yellow','Green','Cyan','Red')]
        [string]$Color = 'White'
    )
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line = "[$ts] $Message"
    Add-Content $LogFile $line
    Write-Host    $line -ForegroundColor $Color
}

function Assert-Admin {
    if (-not ([Security.Principal.WindowsPrincipal] `
        [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Error 'Execute este script como Administrador.'; exit 1
    }
}

#endregion

#region 1. CORE MAINTENANCE

function Clean-Temps {
    Write-Log 'Limpando arquivos temporários…' Yellow
    Cleanmgr /sagerun:1 | Out-Null
    Remove-Item "$env:TEMP\*" -Recurse -Force
    Remove-Item "$env:SystemRoot\Temp\*" -Recurse -Force
    Remove-Item "$env:LOCALAPPDATA\Temp\*" -Recurse -Force
    Write-Log 'Temporários limpos.' Green
}

function Clear-WUCache {
    Write-Log 'Limpando cache do Windows Update…' Yellow
    Stop-Service wuauserv -Force
    Remove-Item "$env:SystemRoot\SoftwareDistribution\Download\*" -Recurse -Force
    Start-Service wuauserv
    Write-Log 'Cache do Windows Update limpo.' Green
}

function Flush-DNS {
    Write-Log 'Flush DNS…' Yellow
    ipconfig /flushdns | Out-Null
    Write-Log 'DNS limpo.' Green
}

function Optimize-Volumes {
    Write-Log 'Otimizando volumes…' Yellow
    Get-Volume | Where DriveType -EQ 'Fixed' | ForEach-Object {
        if ($_.FileSystem -eq 'NTFS') {
            Optimize-Volume -DriveLetter $_.DriveLetter -Defrag -Verbose
        } else {
            Optimize-Volume -DriveLetter $_.DriveLetter -ReTrim -Verbose
        }
    }
    Write-Log 'Volumes otimizados.' Green
}

function Clear-Caches {
    Write-Log 'Limpando caches do sistema…' Yellow
    Remove-Item "$env:LOCALAPPDATA\Microsoft\Windows\Explorer\thumbcache_*.db" -Force
    Remove-Item "$env:LOCALAPPDATA\Microsoft\Windows\FontCache\*" -Force
    Write-Log 'Caches do sistema limpos.' Green
}

function Repair-System {
    Write-Log 'Verificando/reparando sistema (DISM/SFC)…' Yellow
    dism /online /cleanup-image /restorehealth | Out-Null
    sfc /scannow | Out-Null
    Write-Log 'Reparo concluído.' Green
}

function Clean-OldUpdates {
    Write-Log 'Removendo componentes antigos de update…' Yellow
    dism /online /cleanup-image /startcomponentcleanup | Out-Null
    dism /online /cleanup-image /spsuperseded | Out-Null
    Write-Log 'Componentes antigos limpos.' Green
}

function Optimize-Registry {
    Write-Log 'Otimizando registro…' Yellow
    reg add 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' `
        /v ProcessPriorityClass /t REG_DWORD /d 8 /f | Out-Null
    Write-Log 'Registro otimizado.' Green
}

function Restart-CritServices {
    Write-Log 'Reiniciando serviços críticos…' Yellow
    'wuauserv','bits','cryptSvc','DcomLaunch' |
      ForEach-Object { Restart-Service $_ -Force }
    Write-Log 'Serviços reiniciados.' Green
}

function Disable-Tasks {
    Write-Log 'Desabilitando tarefas em segundo plano…' Yellow
    $tasks = @(
        '\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser',
        '\Microsoft\Windows\Application Experience\ProgramDataUpdater',
        '\Microsoft\Windows\Customer Experience Improvement Program\*',
        '\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector',
        '\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem'
    )
    foreach ($t in $tasks) {
        Get-ScheduledTask -TaskPath $t -ErrorAction SilentlyContinue |
          Disable-ScheduledTask
    }
    Write-Log 'Tarefas desativadas.' Green
}

function Disable-Services {
    Write-Log 'Desabilitando serviços de telemetria/jogos…' Yellow
    $svcs = @('DiagTrack','dmwappushservice','lfsvc','MapsBroker',
              'WMPNetworkSvc','XblAuthManager','XblGameSave','XboxNetApiSvc')
    foreach ($s in $svcs) {
        Stop-Service $s -Force -ErrorAction SilentlyContinue
        Set-Service  $s -StartupType Disabled
    }
    Write-Log 'Serviços desabilitados.' Green
}

function Remove-Bloatware {
    Write-Log 'Removendo bloatware…' Yellow
    $apps = @(
      'Microsoft.BingNews','Microsoft.BingWeather','Microsoft.GetHelp',
      'Microsoft.Getstarted','Microsoft.MicrosoftOfficeHub',
      'Microsoft.MicrosoftSolitaireCollection','Microsoft.People',
      'Microsoft.SkypeApp','Microsoft.WindowsAlarms',
      'Microsoft.WindowsSoundRecorder','Microsoft.Xbox*',
      'Microsoft.ZuneMusic','Microsoft.ZuneVideo',
      'Microsoft.YourPhone','Microsoft.MixedReality.Portal'
    )
    foreach ($app in $apps) {
        Get-AppxPackage -Name $app -AllUsers  |
          Remove-AppxPackage -ErrorAction SilentlyContinue
        Get-AppxProvisionedPackage -Online |
          Where DisplayName -Like $app |
          Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
    }
    Write-Log 'Bloatware removido.' Green
}

function Remove-OneNotePrinter {
    Write-Log 'Removendo impressoras OneNote…' Yellow
    Get-Printer | Where Name -Match 'OneNote' |
      Remove-Printer -ErrorAction SilentlyContinue
    Write-Log 'Impressoras OneNote removidas.' Green
}

function Remove-EmptyFilesAndFolders {
    param([string]$Path)
    Write-Log "Removendo arquivos/pastas vazios em '$Path'…" Yellow
    Get-ChildItem -Path $Path -Recurse -File |
      Where Length -EQ 0 |
      ForEach-Object {
        Write-Log "Removendo arquivo: $($_.FullName)" Cyan
        Remove-Item $_.FullName -Force
      }
    do {
      $emptyDirs = Get-ChildItem -Path $Path -Recurse -Directory |
        Where { -not (Get-ChildItem -Path $_.FullName) }
      foreach ($d in $emptyDirs) {
        Write-Log "Removendo pasta: $($d.FullName)" Cyan
        Remove-Item $d.FullName -Force -Recurse
      }
    } while ($emptyDirs.Count -gt 0)
    Write-Log "Limpeza de vazios pronta em '$Path'." Green
}

function Reset-ExplorerSearchLayouts {
    Write-Log 'Resetando layouts de busca do Explorer…' Yellow
    $base = 'HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell'
    Remove-Item "$base\BagMRU" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item "$base\Bags"   -Recurse -Force -ErrorAction SilentlyContinue
    $GUIDs = @(
      '7fde1a1e-8b31-49a5-93b8-6be14cfa4943',
      '4dcafe13-e6a7-4c28-be02-ca8c2126280d',
      '71689ac1-cc88-45d0-8a22-2943c3e7dfb3',
      '36011842-dccc-40fe-aa3d-6177ea401788',
      'ea25fbd7-3bf7-409e-b97f-3352240903f4'
    )
    foreach ($g in $GUIDs) {
        $k = "$base\Bags\AllFolders\Shell\{$g}"
        New-Item -Path $k -Force | Out-Null
        New-ItemProperty -Path $k -Name LogicalViewMode -PropertyType DWord -Value 1 -Force | Out-Null
        New-ItemProperty -Path $k -Name Mode            -PropertyType DWord -Value 4 -Force | Out-Null
    }
    Write-Log 'Layouts de busca resetados.' Green
}

function Optimize-Explorer {
    Write-Log 'Otimizações do Explorer…' Yellow
    $adv = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
    New-ItemProperty -Path $adv -Name LaunchTo         -PropertyType DWord -Value 1 -Force
    New-ItemProperty -Path $adv -Name Start_TrackDocs -PropertyType DWord -Value 0 -Force
    New-ItemProperty -Path $adv -Name Start_TrackProgs-PropertyType DWord -Value 0 -Force
    Remove-Item "$env:APPDATA\Microsoft\Windows\Recent\AutomaticDestinations\*" -Force -ErrorAction SilentlyContinue
    Remove-Item "$env:APPDATA\Microsoft\Windows\Recent\CustomDestinations\*"    -Force -ErrorAction SilentlyContinue
    Write-Log 'Explorer otimizado para “Este Computador” e Quick Access limpo.' Green
}

function Rename-NotebookIfDesired {
    Write-Log 'Checando renomeação de notebook…' Yellow
    $owner = (Get-WmiObject Win32_ComputerSystem).UserName.Split('\')[-1]
    $user  = $owner.Substring(0,1).ToUpper() + $owner.Substring(1).ToLower()
    $chassis = (Get-WmiObject Win32_SystemEnclosure).ChassisTypes
    if ($chassis -in 8,9,10,11,14) {
        $newName = "$user-Notebook"
        Write-Host "Atual: $env:COMPUTERNAME  |  Novo: $newName" -ForegroundColor Cyan
        if ((Read-Host 'Renomear? (S/N)') -match '^[Ss]') {
            Rename-Computer -NewName $newName -Force
            Write-Log "Renomeado para $newName" Green
            Add-Computer -WorkGroupName $ssid -ErrorAction SilentlyContinue
        }
    }
}

#endregion

#region 2. NETWORK

function Set-WiFiPrivate {
    param([string]$InterfaceAlias = 'Wi-Fi')
    Write-Log "Definindo '$InterfaceAlias' como Private…" Yellow
    Set-NetConnectionProfile -InterfaceAlias $InterfaceAlias -NetworkCategory Private
    Write-Log 'Perfil ajustado.' Green
}

function Add-WiFiNetwork {
    Write-Log 'Adicionando rede Wi-Fi…' Yellow
    $xml = @"
<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
  <name>$ssid</name>… [omissis perfil completo acima]
"@
    $tmp = "$env:TEMP\WiFiProfile.xml"; $xml | Out-File $tmp -Encoding ASCII
    netsh wlan add profile filename="$tmp" user=all | Out-Null
    Write-Log "Rede '$ssid' adicionada." Green
}

function Restart-WiFi {
    param([string]$Interface, [string]$SSID)
    Write-Log "Reset de Wi-Fi ($Interface) para '$SSID'…" Yellow
    netsh wlan disconnect interface="$Interface"
    ipconfig /release; ipconfig /renew; ipconfig /flushdns
    netsh winsock reset all; netsh int ip reset all
    Start-Sleep 2
    netsh wlan connect name="$SSID" interface="$Interface"
    Write-Log 'Wi-Fi reiniciado.' Green
}

#endregion

#region 3. PRINTERS

function Install-Printers {
    Write-Log 'Instalando impressoras…' Yellow
    $defs = @(
      @{Name='Samsung Mundo1'; Url='http://172.16.40.40:8018/16a65700-007c-1000-bb49-8425196bd027'},
      @{Name='Samsung Mundo2'; Url='http://172.17.40.25:8018/16a65700-007c-1000-bb49-8425196b796e'},
      @{Name='EpsonMundo1 (L3250)'; Url='http://172.16.40.37:80/WSD/DEVICE'},
      @{Name='EpsonMundo2 (L3250)'; Url='http://172.17.40.72:80/WSD/DEVICE'}
    )
    foreach ($p in $defs) {
        if (Get-Printer -Name $p.Name -ErrorAction SilentlyContinue) {
            Remove-Printer -Name $p.Name
        }
        & rundll32 printui.dll,PrintUIEntry /if /b $p.Name /r $p.Url /m "Microsoft PS Class Driver" /z
        Write-Log "Printer '$($p.Name)' instalada." Green
    }
}

#endregion

#region 4. UPDATES & APPS

function Create-RestorePoint {
    Write-Log 'Criando ponto de restauração…' Yellow
    Enable-ComputerRestore -Drive 'C:\' | Out-Null
    Set-ItemProperty 'HKLM:\…\SystemRestore' SystemRestorePointCreationFrequency -Value 1 -Force
    vssadmin Delete Shadows /For=C: /Oldest /Quiet
    Checkpoint-Computer -Description $currentTime -RestorePointType MODIFY_SETTINGS
    Write-Log 'Restore point criado.' Green
}

function Install-WinGet {
    Write-Log 'Verificando/install winget…' Yellow
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        $tmp="$env:TEMP\winget.msixbundle"
        Invoke-WebRequest https://aka.ms/getwinget -OutFile $tmp
        Add-AppxPackage $tmp; Remove-Item $tmp
        Write-Log 'winget instalado.' Green
    }
}

function Reset-WindowsUpdate {
    Write-Log 'Resetando Windows Update…' Yellow
    'wuauserv','bits','cryptSvc','msiserver' |
      ForEach-Object { Stop-Service $_ -Force }
    Remove-Item "$winDist\Download" -Recurse -Force
    'wuauserv','bits','cryptSvc','msiserver' |
      ForEach-Object { Start-Service $_ }
    Write-Log 'WU resetado.' Green
}

function Enable-DriverOfferWU {
    Write-Log 'Habilitando drivers via WU…' Yellow
    Set-ItemProperty 'HKLM:\…\DriverSearching' SearchOrderConfig -Type DWord -Value 1
    Remove-ItemProperty 'HKLM:\…\WindowsUpdate' ExcludeWUDriversInQualityUpdate -ErrorAction SilentlyContinue
    Write-Log 'Config driver WU ok.' Green
}

function Update-PSWindowsUpdateDrivers {
    Write-Log 'Atualizando drivers via PSWindowsUpdate…' Yellow
    if (-not (Get-Module -ListAvailable PSWindowsUpdate)) {
        Install-Module PSWindowsUpdate -Force -Scope AllUsers
    }
    Import-Module PSWindowsUpdate
    Get-WindowsDriver -Online |
      ForEach-Object { Add-DriverPackage -Online -PackagePath $_.DriverPackagePath }
    Write-Log 'Drivers atualizados.' Green
}

function Update-Windows {
    Write-Log 'Checando Windows Update…' Yellow
    $s = New-Object -ComObject Microsoft.Update.Session
    $sr= $s.CreateUpdateSearcher().Search("IsInstalled=0 and Type='Software'")
    if ($sr.Updates.Count -gt 0) {
        $col= New-Object -ComObject Microsoft.Update.UpdateColl
        $sr.Updates |%{ $col.Add($_)|Out-Null }
        $inst= $s.CreateUpdateInstaller(); $inst.Updates=$col
        $res = $inst.Install()
        Write-Log "WU Resultado: $($res.ResultCode)" Green
    } else { Write-Log 'Nenhuma atualização WU.' Green }
}

function Update-StoreApps {
    Write-Log 'Atualizando apps da Store…' Yellow
    Install-WinGet
    winget upgrade --all --accept-package-agreements --include-unknown | Out-Null
    Write-Log 'Apps Store ok.' Green
}

function Update-Drivers {
    Write-Log 'Checando drivers…' Yellow
    $s = New-Object -ComObject Microsoft.Update.Session
    $sr= $s.CreateUpdateSearcher().Search("IsInstalled=0 and Type='Driver'")
    if ($sr.Updates.Count -gt 0) {
        $col= New-Object -ComObject Microsoft.Update.UpdateColl
        $sr.Updates |%{ $col.Add($_)|Out-Null }
        $inst= $s.CreateUpdateInstaller(); $inst.Updates=$col
        $res = $inst.Install()
        Write-Log "Drivers Resultado: $($res.ResultCode)" Green
    } else { Write-Log 'Nenhum driver pendente.' Green }
}

function Update-Apps-WinGet {
    Write-Log 'Instalando/atualizando apps via winget…' Yellow
    $apps=@('7zip.7zip','AnyDeskSoftwareGmbH.AnyDesk','AutoHotkey.AutoHotkey',
            'Google.Chrome','Google.GoogleDrive','Microsoft.Office',
            'Microsoft.PCManager','Microsoft.PowerToys','Notepad++.Notepad++',
            'VideoLAN.VLC')
    foreach($id in $apps) {
        Write-Log "App: $id" Cyan
        winget install --id=$id -e --accept-package-agreements --accept-source-agreements
    }
    Write-Log 'Apps winget concluídos.' Green
}

#endregion

#region Execução Principal

Assert-Admin
Write-Log '=== INICIANDO MANUTENÇÃO COMPLETA ===' Cyan

# Core
Clean-Temps; Clear-WUCache; Flush-DNS; Optimize-Volumes
Clear-Caches; Reset-ExplorerSearchLayouts; Optimize-Explorer
Repair-System; Clean-OldUpdates; Optimize-Registry; Restart-CritServices
Disable-Tasks; Disable-Services; Remove-Bloatware; Remove-OneNotePrinter
Remove-EmptyFilesAndFolders -Path $env:OneDrive

# Network
Set-WiFiPrivate -InterfaceAlias $interface
Add-WiFiNetwork
Restart-WiFi -Interface $interface -SSID $ssid

# Printers
Install-Printers

# Updates & Apps
Create-RestorePoint
Install-WinGet
Reset-WindowsUpdate
Enable-DriverOfferWU
Update-Windows
if ($ForceDriverUpdate) { Update-Drivers; Update-PSWindowsUpdateDrivers }
Update-StoreApps
Update-Apps-WinGet

# Final
$duration = (Get-Date) - $StartTime
Write-Log "=== MANUTENÇÃO FINALIZADA em $($duration.ToString('hh\:mm\:ss')) ===" Cyan
Write-Log "Log salvo em: $LogFile" Yellow

# Uncomment para reiniciar automaticamente:
# if ((Read-Host 'Reiniciar agora? S/N') -match '^[Ss]') { Restart-Computer -Force }

#endregion
