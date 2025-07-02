<#
.SYNOPSIS
    Script Supremo de Manutenção Windows - Menu Hierárquico Completo
.DESCRIPTION
    Versão completa com todos os menus e submenus funcionais
.NOTES
    Autor: Adaptado por IA
    Versão: 7.2
    Execute como Administrador!
#>

#region → Configurações Iniciais
$Host.UI.RawUI.WindowTitle = "MANUTENÇÃO WINDOWS - NÃO FECHE ESTA JANELA"
Clear-Host

# Verifica se é administrador
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Este script precisa ser executado como Administrador." -ForegroundColor Red
    Write-Host "Por favor, feche e execute novamente como Administrador." -ForegroundColor Yellow
    pause
    exit
}

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$logFile = "$env:TEMP\WinMaintenance_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$startTime = Get-Date

function Write-Log {
    param([string]$message, [string]$color = "White")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] $message"
    Add-Content -Path $logFile -Value $logMessage
    Write-Host $logMessage -ForegroundColor $color
}

function Pause-Script {
    Write-Host "`nPressione ENTER para continuar..." -ForegroundColor Cyan
    do {
        $key = [System.Console]::ReadKey($true)
    } until ($key.Key -eq 'Enter')
}

Write-Log "Iniciando script de manutenção..." Cyan
#endregion

#region → Funções de Manutenção

# 1. Limpeza e Otimização
function Clean-TemporaryFiles {
    Write-Log "Limpando arquivos temporários..." Yellow
    Cleanmgr /sagerun:1 | Out-Null
    Remove-Item "$env:TEMP\*", "$env:SystemRoot\Temp\*", "$env:LOCALAPPDATA\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
    Write-Log "Limpeza de temporários concluída." Green
}

function Clear-WUCache {
    Write-Log "Limpando cache do Windows Update..." Yellow
    Stop-Service wuauserv -Force -ErrorAction SilentlyContinue
    Remove-Item "$env:SystemRoot\SoftwareDistribution\Download\*" -Recurse -Force -ErrorAction SilentlyContinue
    Start-Service wuauserv
    Write-Log "Cache do Windows Update limpo." Green
}

function Flush-DNS {
    Write-Log "Limpando cache DNS..." Yellow
    ipconfig /flushdns | Out-Null
    Write-Log "Cache DNS limpo." Green
}

function Optimize-Volumes {
    Write-Log "Otimizando volumes..." Yellow
    Get-Volume | Where-Object {$_.DriveType -eq 'Fixed' -and $_.DriveLetter} | ForEach-Object {
        if ($_.FileSystem -eq "NTFS") {
            Optimize-Volume -DriveLetter $_.DriveLetter -Defrag -Verbose
        } else {
            Optimize-Volume -DriveLetter $_.DriveLetter -ReTrim -Verbose
        }
    }
    Write-Log "Otimização de volumes concluída." Green
}

# 2. Bloatware
function Remove-Bloatware {
    Write-Log "Removendo bloatware padrão..." Yellow
    $bloatware = @(
        "Microsoft.BingNews", "Microsoft.BingWeather", "Microsoft.GetHelp",
        "Microsoft.Getstarted", "Microsoft.MicrosoftOfficeHub", "Microsoft.MicrosoftSolitaireCollection",
        "Microsoft.People", "Microsoft.SkypeApp", "Microsoft.WindowsAlarms",
        "microsoft.windowscommunicationsapps", "Microsoft.WindowsFeedbackHub",
        "Microsoft.WindowsMaps", "Microsoft.WindowsSoundRecorder", "Microsoft.Xbox.TCUI",
        "Microsoft.XboxApp", "Microsoft.XboxGameOverlay", "Microsoft.XboxIdentityProvider",
        "Microsoft.XboxSpeechToTextOverlay", "Microsoft.ZuneMusic", "Microsoft.ZuneVideo",
        "Microsoft.YourPhone", "Microsoft.MixedReality.Portal"
    )
    
    foreach ($app in $bloatware) {
        Get-AppxPackage -Name $app -AllUsers | Remove-AppxPackage -ErrorAction SilentlyContinue
        Get-AppxProvisionedPackage -Online | Where-Object DisplayName -Like $app | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
    }
    Write-Log "Bloatware padrão removido." Green
}

function Remove-AdditionalBloatware {
    Write-Log "Removendo aplicativos adicionais..." Yellow
    $additionalBloatware = @(
        "Microsoft.QuickAssist",                # Assistência Rápida
        "Microsoft.549981C3F5F10",             # Copilot
        "Microsoft.Windows.CommunicationsApps", # Outlook (Classic)
        "Microsoft.OneDrive",                  # Microsoft OneDrive
        "Microsoft.Teams",                     # Microsoft Teams
        "Microsoft.WindowsFeedbackHub"         # Hub de Comentários
    )

    foreach ($app in $additionalBloatware) {
        try {
            $package = Get-AppxPackage -Name $app -AllUsers -ErrorAction SilentlyContinue
            if ($package) {
                Write-Log "Removendo $app..." Cyan
                Remove-AppxPackage -Package $package -AllUsers -ErrorAction SilentlyContinue
                Get-AppxProvisionedPackage -Online | Where-Object DisplayName -Like $app | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
                Write-Log "$app removido com sucesso." Green
            }
        } catch {
				Write-Log "Erro ao remover ${app}: $_" Red
        }
    }

    # Remoção especial do OneDrive
    try {
        if (Test-Path "$env:SystemRoot\System32\OneDriveSetup.exe") {
            Write-Log "Desinstalando OneDrive..." Cyan
            Start-Process "$env:SystemRoot\System32\OneDriveSetup.exe" -ArgumentList "/uninstall" -NoNewWindow -Wait
            Remove-Item "$env:LocalAppData\Microsoft\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
            Remove-Item "$env:ProgramData\Microsoft OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
            Write-Log "OneDrive desinstalado." Green
        }
    } catch {
        Write-Log "Erro ao remover OneDrive: $_" Red
    }

    # Remoção especial do Teams
    try {
        Get-Process -Name Teams -ErrorAction SilentlyContinue | Stop-Process -Force
        Remove-Item "$env:AppData\Microsoft\Teams" -Force -Recurse -ErrorAction SilentlyContinue
        Remove-Item "$env:LocalAppData\Microsoft\Teams" -Force -Recurse -ErrorAction SilentlyContinue
        Remove-Item "$env:ProgramFiles(x86)\Microsoft\Teams" -Force -Recurse -ErrorAction SilentlyContinue
        Write-Log "Microsoft Teams removido." Green
    } catch {
        Write-Log "Erro ao remover Teams: $_" Red
    }

    Write-Log "Remoção de aplicativos adicionais concluída." Green
}

# Função para desativar tarefas agendadas de bloatware/telemetria
function Disable-BloatwareScheduledTasks {
    Write-Log "Desativando tarefas agendadas de bloatware e telemetria..." Yellow
    $tasks = @(
        # Telemetria e coleta de dados
        "\Microsoft\Windows\Application Experience\ProgramDataUpdater",
        "\Microsoft\Windows\Autochk\Proxy",
        "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
        "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
        "\Microsoft\Windows\Customer Experience Improvement Program\Uploader",
        "\Microsoft\Windows\Feedback\Siuf\DmClient",
        "\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload",
        "\Microsoft\Windows\Windows Error Reporting\QueueReporting",
        # OneDrive
        "\Microsoft\Windows\OneDrive\Standalone Update Task",
        # Xbox
        "\Microsoft\XblGameSave\XblGameSaveTask",
        # Feedback Hub
        "\Microsoft\Windows\Feedback\FeedbackUpload",
        # Outras tarefas dispensáveis
        "\Microsoft\Windows\Shell\FamilySafetyMonitor",
        "\Microsoft\Windows\Shell\FamilySafetyRefreshTask"
    )
    foreach ($task in $tasks) {
        try {
            $taskName = ($task.Split('\\'))[-1]
            $taskPath = $task.Substring(0, [string]::LastIndexOf($task, '\\') + 1)
            if (Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath -ErrorAction SilentlyContinue) {
                Disable-ScheduledTask -TaskName $taskName -TaskPath $taskPath -ErrorAction SilentlyContinue
                Write-Log "Tarefa $task desativada." Green
            }
        } catch {
            Write-Log "Erro ao desativar ${task}: $_" Red
        }
    }
    Write-Log "Desativação de tarefas agendadas concluída." Green
}

# Função para encerrar processos dispensáveis
function Stop-BloatwareProcesses {
    Write-Log "Encerrando processos dispensáveis em segundo plano..." Yellow
    $processes = @(
        "OneDrive",
        "YourPhone",
        "XboxAppServices",
        "GameBar",
        "GameBarFTServer",
        "GameBarPresenceWriter",
        "FeedbackHub",
        "PeopleApp",
        "SkypeApp",
        "Teams"
    )
    foreach ($proc in $processes) {
        try {
            Get-Process -Name $proc -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
            Write-Log "Processo $proc encerrado." Green
        } catch {
            Write-Log "Erro ao encerrar ${proc}: $_" Red
        }
    }
    Write-Log "Encerramento de processos dispensáveis concluído." Green
}

# 3. Instalação de Programas
function Install-Applications {
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Write-Log "Winget não está instalado. Pulando instalação de aplicativos." Red
        return
    }

    $apps = @(
        @{Name = "Google Chrome"; Id = "Google.Chrome"},
        @{Name = "Google Drive"; Id = "Google.GoogleDrive"},
        @{Name = "VLC Media Player"; Id = "VideoLAN.VLC"},
        @{Name = "Microsoft Office"; Id = "Microsoft.Office"},
        @{Name = "Microsoft PowerToys"; Id = "Microsoft.PowerToys"},
        @{Name = "AnyDesk"; Id = "AnyDesk.AnyDesk"},
        @{Name = "Notepad++"; Id = "Notepad++.Notepad++"},
        @{Name = "7-Zip"; Id = "7zip.7zip"}
    )

    Write-Log "Iniciando instalação de aplicativos..." Cyan

    foreach ($app in $apps) {
        try {
            Write-Log "Instalando $($app.Name)..." Yellow
            winget install --id $app.Id -e --accept-package-agreements --accept-source-agreements
            Write-Log "$($app.Name) instalado com sucesso." Green
        } catch {
            Write-Log "Falha ao instalar $($app.Name): $_" Red
        }
    }

    Write-Log "Instalação de aplicativos concluída." Green
}

# Função para instalar/atualizar o PowerShell
function Update-PowerShell {
    Write-Log "Instalando/Atualizando PowerShell..." Yellow
    try {
        Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Unrestricted -Force
        iex "& { $(irm https://aka.ms/install-powershell.ps1) } -UseMSI"
        Write-Log "PowerShell instalado/atualizado com sucesso." Green
    } catch {
        Write-Log "Erro ao instalar/atualizar PowerShell: $_" Red
    }
}

# 4. Rede e Impressoras
function Add-WiFiNetwork {
    Write-Log "Configurando rede Wi-Fi 'VemProMundo - Adm'..." Yellow
    $ssid = "VemProMundo - Adm"
    $password = "!Mund0CoC@7281%"
    
    $xmlProfile = @"
<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
  <name>$ssid</name>
  <SSIDConfig><SSID><name>$ssid</name></SSID></SSIDConfig>
  <connectionType>ESS</connectionType>
  <connectionMode>auto</connectionMode>
  <MSM>
    <security>
      <authEncryption>
        <authentication>WPA2PSK</authentication>
        <encryption>AES</encryption>
        <useOneX>false</useOneX>
      </authEncryption>
      <sharedKey>
        <keyType>passPhrase</keyType>
        <protected>false</protected>
        <keyMaterial>$password</keyMaterial>
      </sharedKey>
    </security>
  </MSM>
</WLANProfile>
"@
    
    $tempFile = "$env:TEMP\$($ssid.Replace(' ', '_')).xml"
    $xmlProfile | Out-File -FilePath $tempFile -Encoding ascii
    netsh wlan add profile filename="$tempFile" user=all
    netsh wlan set profileparameter name="$ssid" connectiontype=ESS
    Set-NetConnectionProfile -Name "$ssid" -NetworkCategory Private
    Remove-Item $tempFile
    Write-Log "Rede Wi-Fi configurada como privada." Green
}

function Install-Printers {
    Write-Log "Instalando impressoras de rede..." Yellow
    $printers = @{
        # Adicione suas impressoras aqui no formato: "Nome da Impressora" = "192.168.x.x"
    }
    
    foreach ($printer in $printers.Keys) {
        $ip = $printers[$printer]
        $portName = "IP_$($ip.Replace('.','_'))"
        
        if (-not (Get-PrinterPort -Name $portName -ErrorAction SilentlyContinue)) {
            Add-PrinterPort -Name $portName -PrinterHostAddress $ip
        }
        
        if (-not (Get-Printer -Name $printer -ErrorAction SilentlyContinue)) {
            Add-Printer -Name $printer -DriverName "Generic / Text Only" -PortName $portName
        }
        Write-Log "Impressora $printer ($ip) instalada." Green
    }
}

# Função para detectar e instalar impressoras de rede automaticamente
function Install-NetworkPrinters {
    Write-Log "Detectando e instalando impressoras de rede..." Yellow
    $printers = @(
        @{Name = "Samsung Mundo1"; IP = "172.16.40.40"; Driver = "Samsung M337x 387x 407x Series PCL6 Class Driver"},
        @{Name = "Samsung Mundo2"; IP = "172.17.40.25"; Driver = "Samsung M337x 387x 407x Series PCL6 Class Driver"},
        @{Name = "EpsonMundo1 (L3250 Series)"; IP = "172.16.40.37"; Driver = "L3250"},
        @{Name = "EpsonMundo2 (L3250 Series)"; IP = "172.17.40.72"; Driver = "L3250"}
    )
    foreach ($printer in $printers) {
        $ip = $printer.IP
        $name = $printer.Name
        $driver = $printer.Driver
        $portName = "IP_$($ip.Replace('.','_'))"
        try {
            if (-not (Get-PrinterPort -Name $portName -ErrorAction SilentlyContinue)) {
                Add-PrinterPort -Name $portName -PrinterHostAddress $ip
                Write-Log "Porta $portName criada para $ip." Green
            }
            if (-not (Get-Printer -Name $name -ErrorAction SilentlyContinue)) {
                Add-Printer -Name $name -DriverName $driver -PortName $portName
                Write-Log "Impressora $name ($ip) instalada." Green
            } else {
                Write-Log "Impressora $name já está instalada." Cyan
            }
        } catch {
            Write-Log "Erro ao instalar impressora $name ($ip): $_" Red
        }
    }
    # Remover impressora OneNote Desktop se existir
    try {
        if (Get-Printer -Name "OneNote (Desktop)" -ErrorAction SilentlyContinue) {
            Remove-Printer -Name "OneNote (Desktop)"
            Write-Log "Impressora OneNote (Desktop) removida." Green
        }
    } catch {
        Write-Log "Erro ao remover impressora OneNote (Desktop): $_" Red
    }
    Write-Log "Instalação de impressoras de rede concluída." Green
}

# 5. Diagnóstico e Informações
function Show-SystemInfo {
    Write-Log "Exibindo informações do sistema..." Cyan
    systeminfo | Out-Host
}

function Show-DiskUsage {
    Write-Log "Exibindo uso do disco..." Cyan
    Get-Volume | Select-Object DriveLetter, FileSystemLabel, @{Name="Size(GB)";Expression={[math]::Round($_.Size/1GB,2)}}, @{Name="Free(GB)";Expression={[math]::Round($_.SizeRemaining/1GB,2)}} | Format-Table -AutoSize | Out-Host
}

function Show-NetworkInfo {
    Write-Log "Exibindo informações de rede..." Cyan
    ipconfig /all | Out-Host
    Get-NetIPConfiguration | Select-Object InterfaceAlias, IPv4Address, IPv4DefaultGateway, DNSServer | Format-Table -AutoSize | Out-Host
}

# Remove UWP Bloatware mantendo apenas apps essenciais
function Remove-UWPBloatware {
    Write-Log "Removendo UWP bloatware (exceto essenciais)..." Yellow
    $whitelist = @(
        'Microsoft.WindowsCalculator',
        'Microsoft.WindowsStore',
        'Microsoft.Windows.Photos',
        'Microsoft.WindowsCamera',
        'Microsoft.ScreenSketch',
        'Microsoft.MSPaint',
        'Microsoft.DesktopAppInstaller'
    )
    Get-AppxPackage -AllUsers | Where-Object { $whitelist -notcontains $_.Name } | ForEach-Object {
        try {
            Write-Log "Removendo $($_.Name)..." Cyan
            Remove-AppxPackage -Package $_.PackageFullName -AllUsers -ErrorAction SilentlyContinue
        } catch {
            Write-Log "Erro ao remover $($_.Name): $_" Red
        }
    }
    Write-Log "Remoção de UWP bloatware concluída." Green
}

# Remover Microsoft Edge
function Remove-Edge {
    Write-Log "Removendo Microsoft Edge..." Yellow
    try {
        $edge = Get-AppxPackage -AllUsers | Where-Object { $_.Name -like 'Microsoft.MicrosoftEdge*' }
        if ($edge) {
            $edge | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
            Write-Log "Microsoft Edge removido." Green
        } else {
            Write-Log "Microsoft Edge não encontrado ou já removido." Cyan
        }
    } catch {
        Write-Log "Erro ao remover Edge: $_" Red
    }
}

# Tweaks de privacidade via registro
function Apply-PrivacyTweaks {
    Write-Log "Aplicando tweaks de privacidade..." Yellow
    try {
        reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f | Out-Null
        reg.exe add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f | Out-Null
        reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v Enabled /t REG_DWORD /d 0 /f | Out-Null
        reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v DisabledByGroupPolicy /t REG_DWORD /d 1 /f | Out-Null
        reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f | Out-Null
        reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v ContentDeliveryAllowed /t REG_DWORD /d 0 /f | Out-Null
        reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v OemPreInstalledAppsEnabled /t REG_DWORD /d 0 /f | Out-Null
        reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v PreInstalledAppsEnabled /t REG_DWORD /d 0 /f | Out-Null
        reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v PreInstalledAppsEverEnabled /t REG_DWORD /d 0 /f | Out-Null
        reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SilentInstalledAppsEnabled /t REG_DWORD /d 0 /f | Out-Null
        reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SystemPaneSuggestionsEnabled /t REG_DWORD /d 0 /f | Out-Null
        Write-Log "Tweaks de privacidade aplicados." Green
    } catch {
        Write-Log "Erro ao aplicar tweaks de privacidade: $_" Red
    }
}

# Remover pins do Menu Iniciar e Barra de Tarefas
function Remove-StartAndTaskbarPins {
    Write-Log "Removendo pins do Menu Iniciar e Barra de Tarefas..." Yellow
    try {
        $startLayout = "$env:LOCALAPPDATA\Microsoft\Windows\Shell\LayoutModification.xml"
        if (Test-Path $startLayout) { Remove-Item $startLayout -Force }
        Write-Log "Pins removidos (pode ser necessário reiniciar o Explorer)." Green
    } catch {
        Write-Log "Erro ao remover pins: $_" Red
    }
}

# Remover tarefas agendadas agressivamente usando schtasks.exe
function Remove-ScheduledTasksAggressive {
    Write-Log "Removendo tarefas agendadas de bloatware/telemetria (agressivo)..." Yellow
    $tasks = @(
        "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
        "\Microsoft\Windows\Application Experience\ProgramDataUpdater",
        "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
        "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask",
        "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
        "\Microsoft\Windows\Feedback\Siuf\DmClient",
        "\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload",
        "Microsoft\Windows\Windows Error Reporting\QueueReporting",
        "\Microsoft\Windows\Application Experience\StartupAppTask",
        "\Microsoft\Windows\Clip\License Validation",
        "\Microsoft\Windows\HelloFace\FODCleanupTask",
        "\Microsoft\Windows\Maps\MapsToastTask",
        "\Microsoft\Windows\Maps\MapsUpdateTask",
        "\MicrosoftEdgeUpdateTaskCore",
        "\MicrosoftEdgeUpdateTaskUA"
    )
    foreach ($task in $tasks) {
        try {
            schtasks.exe /change /TN $task /DISABLE | Out-Null
            schtasks.exe /delete /TN $task /f | Out-Null
            Write-Log "Tarefa $task desativada e removida." Green
        } catch {
            Write-Log "Erro ao remover/desativar ${task}: $_" Red
        }
    }
    Write-Log "Remoção agressiva de tarefas agendadas concluída." Green
}

# Função para otimizar o tema do Windows para desempenho
function Set-PerformanceTheme {
    Write-Log "Aplicando configurações de desempenho no tema do Windows..." Yellow
    try {
        # Desativa animações, transparências e efeitos
        reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v VisualFXSetting /t REG_DWORD /d 2 /f | Out-Null
        reg.exe add "HKCU\Control Panel\Desktop" /v UserPreferencesMask /t REG_BINARY /d 9012038010000000 /f | Out-Null
        reg.exe add "HKCU\Software\Microsoft\Windows\DWM" /v ColorPrevalence /t REG_DWORD /d 0 /f | Out-Null
        reg.exe add "HKCU\Software\Microsoft\Windows\DWM" /v EnableAeroPeek /t REG_DWORD /d 0 /f | Out-Null
        reg.exe add "HKCU\Software\Microsoft\Windows\DWM" /v EnableBlurBehind /t REG_DWORD /d 0 /f | Out-Null
        reg.exe add "HKCU\Software\Microsoft\Windows\DWM" /v EnableTransparency /t REG_DWORD /d 0 /f | Out-Null
        reg.exe add "HKCU\Control Panel\Desktop" /v DragFullWindows /t REG_SZ /d 0 /f | Out-Null
        reg.exe add "HKCU\Control Panel\Desktop" /v MenuShowDelay /t REG_SZ /d 0 /f | Out-Null
        reg.exe add "HKCU\Control Panel\Desktop" /v FontSmoothing /t REG_SZ /d 2 /f | Out-Null
        reg.exe add "HKCU\Control Panel\Desktop" /v FontSmoothingType /t REG_DWORD /d 1 /f | Out-Null
        reg.exe add "HKCU\Control Panel\Desktop" /v FontSmoothingGamma /t REG_DWORD /d 0 /f | Out-Null
        reg.exe add "HKCU\Control Panel\Desktop" /v FontSmoothingOrientation /t REG_DWORD /d 0 /f | Out-Null
        Write-Log "Configurações de desempenho aplicadas ao tema do Windows." Green
    } catch {
        Write-Log "Erro ao aplicar tema de desempenho: $_" Red
    }
}

# Função para otimizar o Windows Explorer para desempenho
function Optimize-ExplorerPerformance {
    Write-Log "Otimizando Windows Explorer para desempenho..." Yellow
    try {
        # Sempre mostrar ícones, nunca miniaturas
        reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v IconsOnly /t REG_DWORD /d 1 /f | Out-Null
        # Desativar painel de visualização
        reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Modules\GlobalSettings\DetailsContainer" /v DetailsContainerSizer /t REG_BINARY /d 00000000000000000000000000000000 /f | Out-Null
        # Desativar painel de detalhes
        reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Modules\GlobalSettings\PreviewPaneSizer" /v PreviewPaneSizer /t REG_BINARY /d 00000000000000000000000000000000 /f | Out-Null
        # Desativar animações
        reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ListviewAlphaSelect /t REG_DWORD /d 0 /f | Out-Null
        reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ListviewShadow /t REG_DWORD /d 0 /f | Out-Null
        reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarAnimations /t REG_DWORD /d 0 /f | Out-Null
        Write-Log "Windows Explorer otimizado para desempenho." Green
    } catch {
        Write-Log "Erro ao otimizar o Explorer: $_" Red
    }
}

# Função para criar ponto de restauração
function Create-SystemRestorePoint {
    Write-Log "Criando ponto de restauração do sistema..." Yellow
    try {
        Checkpoint-Computer -Description "Antes da manutenção Windows" -RestorePointType "MODIFY_SETTINGS"
        Write-Log "Ponto de restauração criado com sucesso." Green
    } catch {
        Write-Log "Erro ao criar ponto de restauração: $_" Red
    }
}

# Função para hardening de segurança
function Enable-WindowsHardening {
    Write-Log "Aplicando hardening de segurança..." Yellow
    try {
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
        Set-MpPreference -DisableRealtimeMonitoring $false
        Set-Service -Name RemoteRegistry -StartupType Disabled -ErrorAction SilentlyContinue
        Set-Service -Name WinRM -StartupType Disabled -ErrorAction SilentlyContinue
        Set-Service -Name TermService -StartupType Disabled -ErrorAction SilentlyContinue
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
        reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f | Out-Null
        reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v SmartScreenEnabled /t REG_SZ /d RequireAdmin /f | Out-Null
        reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f | Out-Null
        reg.exe add "HKCU\Software\Microsoft\Office\16.0\Word\Security" /v VBAWarnings /t REG_DWORD /d 4 /f | Out-Null
        reg.exe add "HKLM\Software\Microsoft\Windows Script Host\Settings" /v Enabled /t REG_DWORD /d 0 /f | Out-Null
        Disable-PSRemoting -Force
        net user guest /active:no
        Set-ProcessMitigation -System -Enable DEP,SEHOP,ASLR,BottomUp,HighEntropy
        Write-Log "Hardening de segurança aplicado." Green
    } catch {
        Write-Log "Erro ao aplicar hardening: $_" Red
    }
}

# Função para remover bloatware provisionado e instalado, mantendo whitelist
function Remove-ProvisionedBloatware {
    Write-Log "Removendo bloatware (mantendo whitelist)..." Yellow
    $whitelist = @(
        'Microsoft.WindowsNotepad',
        'Microsoft.WindowsCalculator',
        'Microsoft.WindowsStore',
        'Microsoft.Windows.Photos',
        'Microsoft.WindowsCamera',
        'Microsoft.MSPaint'
    )
    $provisioned = Get-AppxProvisionedPackage -Online | Where-Object { $whitelist -notcontains $_.DisplayName }
    foreach ($app in $provisioned) {
        try {
            Write-Log "Removendo provisionado $($app.DisplayName)..." Cyan
            Remove-AppxProvisionedPackage -PackageName $app.PackageName -Online -ErrorAction SilentlyContinue
        } catch {
            Write-Log "Erro ao remover provisionado $($app.DisplayName): $_" Red
        }
    }
    $installed = Get-AppxPackage -AllUsers | Where-Object { $whitelist -notcontains $_.Name }
    foreach ($app in $installed) {
        try {
            Write-Log "Removendo instalado $($app.Name)..." Cyan
            Remove-AppxPackage -Package $app.PackageFullName -AllUsers -ErrorAction SilentlyContinue
        } catch {
            Write-Log "Erro ao remover instalado $($app.Name): $_" Red
        }
    }
    Write-Log "Remoção de bloatware concluída." Green
}

# Função para tweaks de interface do Explorer
function Show-ExplorerTweaksMenu {
    do {
        Clear-Host
        Write-Host "==================== TWEAKS EXPLORER ====================" -ForegroundColor Cyan
        Write-Host " 1. Mostrar extensões de arquivos" -ForegroundColor Yellow
        Write-Host " 2. Mostrar arquivos ocultos" -ForegroundColor Yellow
        Write-Host " 3. Restaurar menus clássicos/contextuais" -ForegroundColor Yellow
        Write-Host " 4. Remover sugestões/anúncios" -ForegroundColor Yellow
        Write-Host " 0. Voltar" -ForegroundColor Red
        $choice = Read-Host "\nSelecione uma opção"
        switch ($choice) {
            '1' { reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v HideFileExt /t REG_DWORD /d 0 /f | Out-Null; Write-Log "Extensões de arquivos visíveis." Green; Pause-Script }
            '2' { reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Hidden /t REG_DWORD /d 1 /f | Out-Null; Write-Log "Arquivos ocultos visíveis." Green; Pause-Script }
            '3' { reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v EnableClassicContextMenu /t REG_DWORD /d 1 /f | Out-Null; Write-Log "Menus clássicos ativados." Green; Pause-Script }
            '4' { reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowSyncProviderNotifications /t REG_DWORD /d 0 /f | Out-Null; Write-Log "Sugestões/anúncios removidos." Green; Pause-Script }
            '0' { return }
            default { Write-Host "Opção inválida!" -ForegroundColor Red; Start-Sleep -Seconds 1 }
        }
    } while ($true)
}

# Função para otimizações de jogos
function Enable-GameOptimizations {
    Write-Log "Aplicando otimizações para jogos..." Yellow
    try {
        reg.exe add "HKCU\Software\Microsoft\GameBar" /v AllowAutoGameMode /t REG_DWORD /d 1 /f | Out-Null
        reg.exe add "HKCU\Software\Microsoft\GameBar" /v AutoGameModeEnabled /t REG_DWORD /d 1 /f | Out-Null
        reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v AppCaptureEnabled /t REG_DWORD /d 0 /f | Out-Null
        reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v GameDVR_Enabled /t REG_DWORD /d 0 /f | Out-Null
        Write-Log "Otimizações de jogos aplicadas." Green
    } catch {
        Write-Log "Erro ao aplicar otimizações de jogos: $_" Red
    }
}

# Função para instalar ferramentas de desenvolvimento
function Install-DevTools {
    Write-Log "Instalando ferramentas de desenvolvimento..." Yellow
    try {
        if (-not (Get-Command wsl -ErrorAction SilentlyContinue)) {
            wsl --install
        }
        winget install --id Microsoft.WindowsTerminal -e --accept-package-agreements --accept-source-agreements
        winget install --id Microsoft.VisualStudioCode -e --accept-package-agreements --accept-source-agreements
        winget install --id Scoop.Scoop -e --accept-package-agreements --accept-source-agreements
        Write-Log "Ferramentas de desenvolvimento instaladas." Green
    } catch {
        Write-Log "Erro ao instalar ferramentas de desenvolvimento: $_" Red
    }
}

# Função para desativar serviços desnecessários
function Disable-UnnecessaryServices {
    Write-Log "Desativando serviços desnecessários..." Yellow
    $services = @(
        'DiagTrack',            # Telemetria
        'dmwappushservice',     # Telemetria
        'WMPNetworkSvc',        # Compartilhamento Windows Media Player
        'XblAuthManager',       # Xbox Live Auth
        'XblGameSave',          # Xbox Live Game Save
        'XboxNetApiSvc',        # Xbox Live Networking
        'MapsBroker',           # Mapas
        'Fax',                  # Fax
        'PrintNotify',          # Notificações de Impressora
        'Spooler',              # Spooler de Impressão (desative só se não usar impressora local)
        'RemoteRegistry',       # Registro Remoto
        'RetailDemo',           # Modo Demo
        'SharedAccess',         # Compartilhamento de Internet
        'WSearch',              # Indexação de Pesquisa (desative se não usar pesquisa do Windows)
        'WerSvc',               # Relatório de Erros
        'PhoneSvc',             # Telefone
        'MessagingService',     # Mensagens
        'WalletService',        # Carteira
        'OneSyncSvc',           # Sincronização
        'PimIndexMaintenanceSvc', # Contatos/Calendário
        'SEMgrSvc',             # Pagamentos NFC
        'WbioSrvc'              # Biometria
    )
    foreach ($svc in $services) {
        try {
            Set-Service -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue
            Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
            Write-Log "Serviço ${svc} desativado." Green
        } catch {
            Write-Log "Erro ao desativar serviço ${svc}: $_" Red
        }
    }
    Write-Log "Desativação de serviços concluída." Green
}

# Função para atualizar Windows e drivers
function Update-WindowsAndDrivers {
    Write-Log "Verificando e instalando atualizações do Windows..." Yellow
    try {
        # Atualizações do Windows
        Install-Module PSWindowsUpdate -Force -Scope CurrentUser -ErrorAction SilentlyContinue
        Import-Module PSWindowsUpdate
        Get-WindowsUpdate -AcceptAll -Install -AutoReboot
        Write-Log "Atualizações do Windows concluídas." Green
    } catch {
        Write-Log "Erro ao atualizar o Windows: $_" Red
    }
    try {
        # Atualização de drivers via winget (opcional, depende do suporte do fabricante)
        Write-Log "Verificando atualizações de drivers via winget..." Yellow
        winget upgrade --all --accept-package-agreements --accept-source-agreements
        Write-Log "Atualização de drivers via winget concluída." Green
    } catch {
        Write-Log "Erro ao atualizar drivers via winget: $_" Red
    }
}
#endregion

#region → Menus Hierárquicos
function Show-CleanupMenu {
    do {
        Clear-Host
        Write-Host "=============================================" -ForegroundColor Cyan
        Write-Host " LIMPEZA E OTIMIZAÇÃO" -ForegroundColor Cyan
        Write-Host "=============================================" -ForegroundColor Cyan
        Write-Host " 1. Limpar arquivos temporários" -ForegroundColor Yellow
        Write-Host " 2. Limpar cache do Windows Update" -ForegroundColor Yellow
        Write-Host " 3. Limpar cache DNS" -ForegroundColor Yellow
        Write-Host " 4. Otimizar volumes" -ForegroundColor Yellow
        Write-Host " 0. Voltar ao menu principal" -ForegroundColor Red
        Write-Host "=============================================" -ForegroundColor Cyan
        
        $choice = Read-Host "`nSelecione uma opção"
        switch ($choice) {
            '1' { Clean-TemporaryFiles; Pause-Script }
            '2' { Clear-WUCache; Pause-Script }
            '3' { Flush-DNS; Pause-Script }
            '4' { Optimize-Volumes; Pause-Script }
            '0' { return }
            default { Write-Host "Opção inválida!" -ForegroundColor Red; Start-Sleep -Seconds 1 }
        }
    } while ($true)
}

function Show-BloatwareMenu {
    do {
        Clear-Host
        Write-Host "=============================================" -ForegroundColor Cyan
        Write-Host " BLOATWARE, PRIVACIDADE E ATUALIZAÇÕES" -ForegroundColor Cyan
        Write-Host "=============================================" -ForegroundColor Cyan
        Write-Host " 1. Aplicar tweaks de privacidade" -ForegroundColor Yellow
        Write-Host " 2. Desativar tarefas agendadas de bloatware/telemetria" -ForegroundColor Yellow
        Write-Host " 3. Encerrar processos dispensáveis em segundo plano" -ForegroundColor Yellow
        Write-Host " 4. Hardening de segurança" -ForegroundColor Yellow
        Write-Host " 5. Remover bloatware padrão" -ForegroundColor Yellow
        Write-Host " 6. Remover bloatware adicional" -ForegroundColor Yellow
        Write-Host " 7. Remover bloatware (whitelist)" -ForegroundColor Yellow
        Write-Host " 8. Remover Microsoft Edge" -ForegroundColor Yellow
        Write-Host " 9. Remover pins do Menu Iniciar/Barra de Tarefas" -ForegroundColor Yellow
        Write-Host "10. Remover tarefas agendadas (agressivo)" -ForegroundColor Yellow
        Write-Host "11. Remover UWP bloatware (exceto essenciais)" -ForegroundColor Yellow
        Write-Host "12. Verificar e instalar atualizações" -ForegroundColor Yellow
        Write-Host " 0. Voltar ao menu principal" -ForegroundColor Red
        Write-Host "=============================================" -ForegroundColor Cyan
        
        $choice = Read-Host "`nSelecione uma opção"
        switch ($choice) {
            '1' { Apply-PrivacyTweaks; Pause-Script }
            '2' { Disable-BloatwareScheduledTasks; Pause-Script }
            '3' { Stop-BloatwareProcesses; Pause-Script }
            '4' { Enable-WindowsHardening; Pause-Script }
            '5' { Remove-Bloatware; Pause-Script }
            '6' { Remove-AdditionalBloatware; Pause-Script }
            '7' { Remove-ProvisionedBloatware; Pause-Script }
            '8' { Remove-Edge; Pause-Script }
            '9' { Remove-StartAndTaskbarPins; Pause-Script }
            '10' { Remove-ScheduledTasksAggressive; Pause-Script }
            '11' { Remove-UWPBloatware; Pause-Script }
            '12' { Update-WindowsAndDrivers; Pause-Script }
            '0' { return }
            default { Write-Host "Opção inválida!" -ForegroundColor Red; Start-Sleep -Seconds 1 }
        }
    } while ($true)
}

function Show-InstallationMenu {
    do {
        Clear-Host
        Write-Host "=============================================" -ForegroundColor Cyan
        Write-Host " INSTALAÇÃO DE PROGRAMAS" -ForegroundColor Cyan
        Write-Host "=============================================" -ForegroundColor Cyan
        Write-Host " 1. Instalar todos os programas" -ForegroundColor Yellow
        Write-Host " 2. Instalar Google Chrome" -ForegroundColor Yellow
        Write-Host " 3. Instalar Google Drive" -ForegroundColor Yellow
        Write-Host " 4. Instalar VLC Media Player" -ForegroundColor Yellow
        Write-Host " 5. Instalar Microsoft Office" -ForegroundColor Yellow
        Write-Host " 6. Instalar Microsoft PowerToys" -ForegroundColor Yellow
        Write-Host " 7. Instalar AnyDesk" -ForegroundColor Yellow
        Write-Host " 8. Instalar Notepad++" -ForegroundColor Yellow
        Write-Host " 9. Instalar 7-Zip" -ForegroundColor Yellow
        Write-Host "10. Instalar/Atualizar PowerShell" -ForegroundColor Yellow
        Write-Host " 0. Voltar ao menu principal" -ForegroundColor Red
        Write-Host "=============================================" -ForegroundColor Cyan
        
        $choice = Read-Host "`nSelecione uma opção"
        switch ($choice) {
            '1' { Install-Applications; Pause-Script }
            '2' { winget install --id Google.Chrome -e --accept-package-agreements --accept-source-agreements; Pause-Script }
            '3' { winget install --id Google.GoogleDrive -e --accept-package-agreements --accept-source-agreements; Pause-Script }
            '4' { winget install --id VideoLAN.VLC -e --accept-package-agreements --accept-source-agreements; Pause-Script }
            '5' { winget install --id Microsoft.Office -e --accept-package-agreements --accept-source-agreements; Pause-Script }
            '6' { winget install --id Microsoft.PowerToys -e --accept-package-agreements --accept-source-agreements; Pause-Script }
            '7' { winget install --id AnyDesk.AnyDesk -e --accept-package-agreements --accept-source-agreements; Pause-Script }
            '8' { winget install --id Notepad++.Notepad++ -e --accept-package-agreements --accept-source-agreements; Pause-Script }
            '9' { winget install --id 7zip.7zip -e --accept-package-agreements --accept-source-agreements; Pause-Script }
            '10' { Update-PowerShell; Pause-Script }
            '0' { return }
            default { Write-Host "Opção inválida!" -ForegroundColor Red; Start-Sleep -Seconds 1 }
        }
    } while ($true)
}

function Show-NetworkMenu {
    do {
        Clear-Host
        Write-Host "=============================================" -ForegroundColor Cyan
        Write-Host " REDE E IMPRESSORAS" -ForegroundColor Cyan
        Write-Host "=============================================" -ForegroundColor Cyan
        Write-Host " 1. Configurar rede Wi-Fi" -ForegroundColor Yellow
        Write-Host " 2. Instalar impressoras de rede" -ForegroundColor Yellow
        Write-Host " 3. Limpar cache DNS" -ForegroundColor Yellow
        Write-Host " 0. Voltar ao menu principal" -ForegroundColor Red
        Write-Host "=============================================" -ForegroundColor Cyan
        
        $choice = Read-Host "`nSelecione uma opção"
        switch ($choice) {
            '1' { Add-WiFiNetwork; Pause-Script }
            '2' { Install-NetworkPrinters; Pause-Script }
            '3' { Flush-DNS; Pause-Script }
            '0' { return }
            default { Write-Host "Opção inválida!" -ForegroundColor Red; Start-Sleep -Seconds 1 }
        }
    } while ($true)
}

function Show-DiagnosticsMenu {
    do {
        Clear-Host
        Write-Host "=============================================" -ForegroundColor Cyan
        Write-Host " DIAGNÓSTICO E INFORMAÇÕES" -ForegroundColor Cyan
        Write-Host "=============================================" -ForegroundColor Cyan
        Write-Host " 1. Exibir informações do sistema" -ForegroundColor Yellow
        Write-Host " 2. Exibir uso do disco" -ForegroundColor Yellow
        Write-Host " 3. Exibir informações de rede" -ForegroundColor Yellow
        Write-Host " 0. Voltar ao menu principal" -ForegroundColor Red
        Write-Host "=============================================" -ForegroundColor Cyan
        
        $choice = Read-Host "`nSelecione uma opção"
        switch ($choice) {
            '1' { Show-SystemInfo; Pause-Script }
            '2' { Show-DiskUsage; Pause-Script }
            '3' { Show-NetworkInfo; Pause-Script }
            '0' { return }
            default { Write-Host "Opção inválida!" -ForegroundColor Red; Start-Sleep -Seconds 1 }
        }
    } while ($true)
}

function Show-MainMenu {
    do {
        Clear-Host
        Write-Host "=============================================" -ForegroundColor Cyan
        Write-Host " SCRIPT DE MANUTENÇÃO WINDOWS - MENU PRINCIPAL" -ForegroundColor Cyan
        Write-Host "=============================================" -ForegroundColor Cyan
        Write-Host " 1. Ajustar tema do Windows para desempenho" -ForegroundColor Yellow
        Write-Host " 2. Aplicar hardening de segurança" -ForegroundColor Yellow
        Write-Host " 3. Automação: criar ponto de restauração" -ForegroundColor Yellow
        Write-Host " 4. Bloatware, Privacidade e Atualizações" -ForegroundColor Yellow
        Write-Host " 5. Diagnóstico e Informações" -ForegroundColor Yellow
        Write-Host " 6. Instalação de Programas" -ForegroundColor Yellow
        Write-Host " 7. Limpeza e Otimização" -ForegroundColor Yellow
        Write-Host " 8. Otimizações para jogos" -ForegroundColor Yellow
        Write-Host " 9. Otimizar Windows Explorer para desempenho" -ForegroundColor Yellow
        Write-Host "10. Rede e Impressoras" -ForegroundColor Yellow
        Write-Host "11. Tweaks de interface do Explorer" -ForegroundColor Yellow
        Write-Host "12. Instalar ferramentas de desenvolvimento" -ForegroundColor Yellow
        Write-Host "13. Desativar serviços desnecessários" -ForegroundColor Yellow
        Write-Host "14. Abrir pasta de logs" -ForegroundColor Magenta
        Write-Host " 0. Sair" -ForegroundColor Red
        Write-Host "=============================================" -ForegroundColor Cyan
        
        $choice = Read-Host "`nSelecione uma opção"
        switch ($choice) {
            '1' { Set-PerformanceTheme; Pause-Script }
            '2' { Enable-WindowsHardening; Pause-Script }
            '3' { Create-SystemRestorePoint; Pause-Script }
            '4' { Show-BloatwareMenu }
            '5' { Show-DiagnosticsMenu }
            '6' { Show-InstallationMenu }
            '7' { Show-CleanupMenu }
            '8' { Enable-GameOptimizations; Pause-Script }
            '9' { Optimize-ExplorerPerformance; Pause-Script }
            '10' { Show-NetworkMenu }
            '11' { Show-ExplorerTweaksMenu }
            '12' { Install-DevTools; Pause-Script }
            '13' { Disable-UnnecessaryServices; Pause-Script }
            '14' { 
                Start-Process explorer.exe -ArgumentList "/select,`"$logFile`""
                Pause-Script
            }
            '0' { 
                $duration = (Get-Date) - $startTime
                Write-Log "Script concluído. Tempo total: $($duration.ToString('hh\:mm\:ss'))" Cyan
                Write-Log "Log detalhado salvo em: $logFile" Cyan
                Write-Host "Pressione qualquer tecla para sair..." -ForegroundColor Magenta
                [void][System.Console]::ReadKey($true)
                return 
            }
            default { 
                Write-Host "Opção inválida! Tente novamente." -ForegroundColor Red
                Start-Sleep -Seconds 1
            }
        }
    } while ($true)
}
#endregion

# Inicia o menu principal
try {
    Show-MainMenu
} catch {
    Write-Host "Erro fatal: $_" -ForegroundColor Red
    Write-Host "Consulte o log em: $logFile" -ForegroundColor Yellow
    Pause-Script
}
