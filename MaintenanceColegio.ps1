<#
.SYNOPSIS
    Script Supremo de Manutenção Windows - Versão Intermediária Completa
.DESCRIPTION
    Script completo para automação de manutenção, ajustes, remoção de bloatware, instalação de apps, impressoras e padronização de notebooks do colégio.
.NOTES
    Autor: Adaptado por IA
    Versão: Intermediária Completa
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

function Show-SuccessMessage {
    Write-Host "Tarefa executada com sucesso!" -ForegroundColor Green
    Start-Sleep -Seconds 2
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

# 2. Bloatwarefunction Install
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
        "Microsoft.YourPhone", "Microsoft.MixedReality.Portal",
        "Microsoft.LinkedIn"
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
        "Microsoft.WindowsFeedbackHub",         # Hub de Comentários
        "Microsoft.LinkedIn"
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
	    @{Name = "AutoHotKey"; Id = "AutoHotkey.AutoHotkey"},
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

function Run-All-NetworkAdvanced {
    Flush-DNS
    Optimize-NetworkPerformance
    Set-DnsGoogleCloudflare
    Test-InternetSpeed
    Clear-ARP
    Show-SuccessMessage
}

function Set-DnsGoogleCloudflare {
    Write-Log "Configurando DNS para Google (8.8.8.8) e Cloudflare (1.1.1.1)..." Yellow
    try {
        Get-NetIPConfiguration | Where-Object {$_.IPv4Address -and $_.InterfaceAlias -notmatch "Loopback"} | ForEach-Object {
            Set-DnsClientServerAddress -InterfaceAlias $_.InterfaceAlias -ServerAddresses ("1.1.1.1","8.8.8.8")
        }
        Write-Log "DNS configurado para Cloudflare/Google." Green
    } catch { Write-Log "Erro ao configurar DNS: $_" Red }
}

function Test-InternetSpeed {
    Write-Log "Testando velocidade de internet usando PowerShell..." Yellow
    try {
        if (-not (Get-Command speedtest -ErrorAction SilentlyContinue)) {
            winget install --id Ookla.Speedtest -e --accept-package-agreements --accept-source-agreements
        }
        speedtest
        Write-Log "Teste de velocidade concluído." Green
    } catch { Write-Log "Erro ao testar velocidade: $_" Red }
}

function Clear-ARP {
    Write-Log "Limpando cache ARP..." Yellow
    try {
        arp -d *
        Write-Log "Cache ARP limpo." Green
    } catch { Write-Log "Erro ao limpar cache ARP: $_" Red }
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

# Funções de ajustes do Painel de Controle/Configurações
function Enable-DarkTheme {
    Write-Log "Ativando tema escuro..." Yellow
    try {
        reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v AppsUseLightTheme /t REG_DWORD /d 0 /f | Out-Null
        reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v SystemUsesLightTheme /t REG_DWORD /d 0 /f | Out-Null
        Write-Log "Tema escuro ativado." Green
    } catch {
        Write-Log "Erro ao ativar tema escuro: $_" Red
    }
}

function Enable-ClipboardHistory {
    Write-Log "Ativando histórico da área de transferência..." Yellow
    try {
        reg.exe add "HKCU\Software\Microsoft\Clipboard" /v EnableClipboardHistory /t REG_DWORD /d 1 /f | Out-Null
        Write-Log "Histórico da área de transferência ativado." Green
    } catch {
        Write-Log "Erro ao ativar histórico da área de transferência: $_" Red
    }
}

function Enable-WindowsUpdateFast {
    Write-Log "Ativando atualizações antecipadas do Windows Update..." Yellow
    try {
        reg.exe add "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v IsContinuousInnovationOptedIn /t REG_DWORD /d 1 /f | Out-Null
        Write-Log "Atualizações antecipadas ativadas." Green
    } catch {
        Write-Log "Erro ao ativar atualizações antecipadas: $_" Red
    }
}

function Enable-RestartAppsAfterReboot {
    Write-Log "Ativando restauração de apps após reinicialização..." Yellow
    try {
        reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RestartApps" /v RestartApps /t REG_DWORD /d 1 /f | Out-Null
        Write-Log "Restauração de apps ativada." Green
    } catch {
        Write-Log "Erro ao ativar restauração de apps: $_" Red
    }
}

function Enable-OtherMicrosoftUpdates {
    Write-Log "Ativando updates para outros produtos Microsoft..." Yellow
    try {
        reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v EnableFeaturedSoftware /t REG_DWORD /d 1 /f | Out-Null
        Write-Log "Updates para outros produtos Microsoft ativados." Green
    } catch {
        Write-Log "Erro ao ativar updates para outros produtos Microsoft: $_" Red
    }
}

function Enable-Sudo {
    Write-Log "Habilitando Sudo embutido do Windows..." Yellow
    try {
        reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Sudo" /v EnableSudo /t REG_DWORD /d 1 /f | Out-Null
        Write-Log "Sudo embutido habilitado." Green
    } catch {
        Write-Log "Erro ao habilitar Sudo: $_" Red
    }
}

function Enable-TaskbarEndTask {
    Write-Log "Ativando 'Finalizar Tarefa' na barra de tarefas..." Yellow
    try {
        reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarEndTask /t REG_DWORD /d 1 /f | Out-Null
        Write-Log "'Finalizar Tarefa' ativado na barra de tarefas." Green
    } catch {
        Write-Log "Erro ao ativar 'Finalizar Tarefa': $_" Red
    }
}

function Enable-TaskbarSeconds {
    Write-Log "Ativando segundos no relógio da barra de tarefas..." Yellow
    try {
        reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowSecondsInSystemClock /t REG_DWORD /d 1 /f | Out-Null
        Write-Log "Segundos ativados no relógio da barra de tarefas." Green
    } catch {
        Write-Log "Erro ao ativar segundos no relógio: $_" Red
    }
}

function Show-ControlPanelTweaksMenu {
    do {
        Clear-Host
        Write-Host "==================== AJUSTES DO PAINEL DE CONTROLE/CONFIGURAÇÕES ====================" -ForegroundColor Cyan
        Write-Host " 1. Ativar tema escuro" -ForegroundColor Yellow
        Write-Host " 2. Ativar histórico da área de transferência" -ForegroundColor Yellow
        Write-Host " 3. Ativar atualizações antecipadas do Windows Update" -ForegroundColor Yellow
        Write-Host " 4. Ativar restauração de apps após reinicialização" -ForegroundColor Yellow
        Write-Host " 5. Ativar updates para outros produtos Microsoft" -ForegroundColor Yellow
        Write-Host " 6. Habilitar Sudo embutido" -ForegroundColor Yellow
        Write-Host " 7. Ativar 'Finalizar Tarefa' na barra de tarefas" -ForegroundColor Yellow
        Write-Host " 8. Ativar segundos no relógio da barra de tarefas" -ForegroundColor Yellow
        Write-Host " 0. Voltar ao menu principal" -ForegroundColor Red
        $choice = Read-Host "\nSelecione uma opção"
        switch ($choice) {
            '1' { Enable-DarkTheme; Pause-Script }
            '2' { Enable-ClipboardHistory; Pause-Script }
            '3' { Enable-WindowsUpdateFast; Pause-Script }
            '4' { Enable-RestartAppsAfterReboot; Pause-Script }
            '5' { Enable-OtherMicrosoftUpdates; Pause-Script }
            '6' { Enable-Sudo; Pause-Script }
            '7' { Enable-TaskbarEndTask; Pause-Script }
            '8' { Enable-TaskbarSeconds; Pause-Script }
            '0' { return }
            default { Write-Host "Opção inválida!" -ForegroundColor Red; Start-Sleep -Seconds 1 }
        }
    } while ($true)
}

# Função para renomear o notebook
function Renomear-Notebook {
    Write-Log "Deseja renomear este notebook? (S/N)" Yellow
    $timeout = 15
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $input = $null
    Write-Host "Digite o novo nome do notebook e pressione ENTER (ou aguarde $timeout segundos para cancelar):" -ForegroundColor Cyan
    while ($sw.Elapsed.TotalSeconds -lt $timeout -and !$input) {
        if ([System.Console]::KeyAvailable) {
            $input = Read-Host
        } else {
            Start-Sleep -Milliseconds 200
        }
    }
    $sw.Stop()
    if ([string]::IsNullOrWhiteSpace($input)) {
        Write-Log "Tempo esgotado. Renomeação cancelada." Red
        Start-Sleep -Seconds 2
        return
    }
    try {
        Rename-Computer -NewName $input -Force
        Write-Log "Nome do notebook alterado para: $input. Reinicie para aplicar." Green
    } catch {
        Write-Log "Erro ao renomear o notebook: $_" Red
    }
    Start-Sleep -Seconds 2
}
# ==== Funções Avançadas/Extras - Cole este bloco após as funções de manutenção originais ====

function Disable-ActionCenter-Notifications {
    Write-Log "Desabilitando Action Center e notificações..." Yellow
    try {
        reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v DisableNotificationCenter /t REG_DWORD /d 1 /f | Out-Null
        reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications" /v ToastEnabled /t REG_DWORD /d 0 /f | Out-Null
        reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v GlobalUserDisabled /t REG_DWORD /d 1 /f | Out-Null
        Write-Log "Action Center e notificações desativados." Green
    } catch { Write-Log "Erro ao desativar Action Center: $_" Red }
}

function Clean-WinSxS {
    Write-Log "Limpando WinSxS..." Yellow
    try {
        Dism.exe /online /Cleanup-Image /StartComponentCleanup /ResetBase | Out-Null
        Write-Log "WinSxS limpo." Green
    } catch { Write-Log "Erro ao limpar WinSxS: $_" Red }
}

function Schedule-ChkDsk {
    Write-Log "Agendando chkdsk /f /r no próximo reboot..." Yellow
    try {
        chkdsk $env:SystemDrive /f /r
        Write-Log "chkdsk agendado (confirme no prompt, se solicitado)." Green
    } catch { Write-Log "Erro ao agendar chkdsk: $_" Red }
}

function Remove-WindowsOld {
    Write-Log "Removendo Windows.old..." Yellow
    try {
        Remove-Item "$env:SystemDrive\Windows.old" -Force -Recurse -ErrorAction SilentlyContinue
        Write-Log "Windows.old removido." Green
    } catch { Write-Log "Erro ao remover Windows.old: $_" Red }
}

function Deep-SystemCleanup {
    Write-Log "Fazendo limpeza profunda (cache de update, logs, drivers antigos)..." Yellow
    try {
        Remove-Item "$env:SystemRoot\SoftwareDistribution\Download\*" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item "$env:SystemRoot\Logs\*" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item "$env:SystemRoot\System32\LogFiles\*" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item "$env:SystemRoot\INF\*.log" -Force -ErrorAction SilentlyContinue
        Write-Log "Limpeza profunda realizada." Green
    } catch { Write-Log "Erro na limpeza profunda: $_" Red }
}

function Clean-PrintSpooler {
    Write-Log "Limpando spooler de impressão..." Yellow
    try {
        Stop-Service -Name Spooler -Force
        Remove-Item -Path "$env:SystemRoot\System32\spool\PRINTERS\*" -Recurse -Force -ErrorAction SilentlyContinue
        Start-Service -Name Spooler
        Write-Log "Spooler de impressão limpo." Green
    } catch { Write-Log "Erro ao limpar spooler: $_" Red }
}

function Clean-Prefetch {
    Write-Log "Limpando Prefetch..." Yellow
    try {
        Remove-Item "$env:SystemRoot\Prefetch\*" -Force -Recurse -ErrorAction SilentlyContinue
        Write-Log "Prefetch limpo." Green
    } catch { Write-Log "Erro ao limpar Prefetch: $_" Red }
}

function Enable-ClassicContextMenu {
    Write-Log "Restaurando menu de contexto clássico (Win11)..." Yellow
    try {
        reg.exe add "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" /f /ve | Out-Null
        Write-Log "Menu de contexto clássico habilitado." Green
    } catch { Write-Log "Erro ao restaurar menu clássico: $_" Red }
}

function Remove-Copilot {
    Write-Log "Removendo Copilot (Win11)..." Yellow
    try {
        Get-AppxPackage -Name "Microsoft.549981C3F5F10" -AllUsers | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
        Write-Log "Copilot removido." Green
    } catch { Write-Log "Erro ao remover Copilot: $_" Red }
}

function Remove-OneDrive-AndRestoreFolders {
    Write-Log "Removendo OneDrive e restaurando pastas padrão..." Yellow
    try {
        taskkill /f /im OneDrive.exe
        if (Test-Path "$env:SystemRoot\System32\OneDriveSetup.exe") {
            Start-Process "$env:SystemRoot\System32\OneDriveSetup.exe" -ArgumentList "/uninstall" -Wait
        }
        $folders = @("Documents", "Desktop", "Pictures", "Music", "Videos")
        foreach ($folder in $folders) {
            $regPath = "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
            Set-ItemProperty -Path $regPath -Name $folder -Value ("%%USERPROFILE%%\" + $folder)
        }
        Write-Log "OneDrive removido e pastas restauradas." Green
    } catch { Write-Log "Erro ao remover Onedrive/restaurar pastas: $_" Red }
}

function Backup-Registry {
    Write-Log "Fazendo backup do registro (SOFTWARE, SYSTEM, HKCU)..." Yellow
    try {
        $bkpPath = "$env:USERPROFILE\Desktop\reg_backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        New-Item -Path $bkpPath -ItemType Directory | Out-Null
        reg.exe save HKLM\SOFTWARE "$bkpPath\HKLM_SOFTWARE.reg" /y | Out-Null
        reg.exe save HKLM\SYSTEM "$bkpPath\HKLM_SYSTEM.reg" /y | Out-Null
        reg.exe save HKCU "$bkpPath\HKCU.reg" /y | Out-Null
        Write-Log "Backup do registro salvo em: $bkpPath" Green
    } catch { Write-Log "Erro ao fazer backup do registro: $_" Red }
}

function Restore-Registry {
    Write-Host "Digite o caminho da pasta onde está o backup do registro:" -ForegroundColor Cyan
    $bkpPath = Read-Host "Exemplo: C:\Users\SeuUsuario\Desktop\reg_backup_20250704_140000"
    try {
        reg.exe restore HKLM\SOFTWARE "$bkpPath\HKLM_SOFTWARE.reg" | Out-Null
        reg.exe restore HKLM\SYSTEM "$bkpPath\HKLM_SYSTEM.reg" | Out-Null
        reg.exe restore HKCU "$bkpPath\HKCU.reg" | Out-Null
        Write-Log "Registro restaurado a partir de $bkpPath." Green
    } catch { Write-Log "Erro ao restaurar o registro: $_" Red }
}

function Run-ExternalDebloaters {
    $scripts = @("Win11Debloat.ps1", "WinUtil.ps1", "OOSU10.exe", "OpenShellSetup.exe", "SpeedyFox.exe", "_Win10-BlackViper.bat")
    foreach ($scr in $scripts) {
        $path = Join-Path $PSScriptRoot $scr
        if (Test-Path $path) {
            Write-Log "Executando $scr..." Yellow
            if ($scr -like "*.ps1") {
                powershell.exe -ExecutionPolicy Bypass -File $path
            } elseif ($scr -like "*.exe") {
                Start-Process $path -Wait
            } elseif ($scr -like "*.bat") {
                Start-Process "cmd.exe" -ArgumentList "/c `"$path`"" -Wait
            }
            Write-Log "$scr executado." Green
        } else {
            Write-Log "$scr não encontrado, pulando." Cyan
        }
    }
}

function Apply-ExtraTweaks {
    Write-Log "Aplicando tweaks extras..." Yellow
    try {
        # Bloqueio de anúncios
        reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338389Enabled /t REG_DWORD /d 0 /f | Out-Null
        reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338388Enabled /t REG_DWORD /d 0 /f | Out-Null
        reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338393Enabled /t REG_DWORD /d 0 /f | Out-Null
        # F8 no boot
        bcdedit /set {current} bootmenupolicy Legacy | Out-Null
        # Desativar sons do sistema
        reg.exe add "HKCU\AppEvents\Schemes" /ve /d ".None" /f | Out-Null
        # Desativar web search
        reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v BingSearchEnabled /t REG_DWORD /d 0 /f | Out-Null
        reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v CortanaConsent /t REG_DWORD /d 0 /f | Out-Null
        # Remover "Cast to Device"
        reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" /V "{7AD84985-87B4-4a16-BE58-8B72A5B390F7}" /T REG_SZ /D "Play to Menu" /F | Out-Null
        Write-Log "Tweaks extras aplicados." Green
    } catch { Write-Log "Erro ao aplicar tweaks extras: $_" Red }
}

function Disable-Cortana-AndSearch {
    Write-Log "Desativando Cortana, Windows Search, Telemetria e Relatórios de Erro..." Yellow
    try {
        reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCortana /t REG_DWORD /d 0 /f | Out-Null
        reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCloudSearch /t REG_DWORD /d 0 /f | Out-Null
        Stop-Service WSearch -Force -ErrorAction SilentlyContinue
        Set-Service WSearch -StartupType Disabled -ErrorAction SilentlyContinue
        reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f | Out-Null
        reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\ErrorReporting" /v Disabled /t REG_DWORD /d 1 /f | Out-Null
        Write-Log "Cortana, Search, Telemetria e Relatório de Erro desativados." Green
    } catch { Write-Log "Erro ao desativar Cortana/Search: $_" Red }
}

function Disable-UAC {
    Write-Log "Desabilitando UAC..." Yellow
    try {
        reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 0 /f | Out-Null
        Write-Log "UAC desativado." Green
    } catch { Write-Log "Erro ao desativar UAC: $_" Red }
}

function Enable-PrivacyHardening {
    Write-Log "Aplicando privacidade agressiva..." Yellow
    try {
        reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f | Out-Null
        reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v Enabled /t REG_DWORD /d 0 /f | Out-Null
        reg.exe add "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v RestrictImplicitTextCollection /t REG_DWORD /d 1 /f | Out-Null
        reg.exe add "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v RestrictImplicitInkCollection /t REG_DWORD /d 1 /f | Out-Null
        reg.exe add "HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /v HarvestContacts /t REG_DWORD /d 0 /f | Out-Null
        Write-Log "Privacidade agressiva aplicada." Green
    } catch { Write-Log "Erro ao aplicar privacidade agressiva: $_" Red }
}

function Optimize-NetworkPerformance {
    Write-Log "Otimizando rede (TCP tweaks, DNS customizado)..." Yellow
    try {
        netsh int tcp set global autotuninglevel=normal
        netsh int tcp set global rss=enabled
        netsh int tcp set global chimney=enabled
        Set-DnsClientServerAddress -InterfaceAlias "Wi-Fi" -ServerAddresses ("1.1.1.1","8.8.8.8")
        Write-Log "Rede otimizada (TCP+DNS)." Green
    } catch { Write-Log "Erro ao otimizar rede: $_" Red }
}

function Disable-IPv6 {
    Write-Log "Desabilitando IPv6..." Yellow
    try {
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisabledComponents" -PropertyType DWord -Value 0xFF -Force | Out-Null
        Write-Log "IPv6 desativado." Green
    } catch { Write-Log "Erro ao desativar IPv6: $_" Red }
}

function Set-VisualPerformance {
    Write-Log "Ajustando visual para melhor performance..." Yellow
    try {
        reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v VisualFXSetting /t REG_DWORD /d 2 /f | Out-Null
        reg.exe add "HKCU\Control Panel\Desktop" /v UserPreferencesMask /t REG_BINARY /d 9012038010000000 /f | Out-Null
        Write-Log "Visual ajustado para performance." Green
    } catch { Write-Log "Erro ao ajustar visual: $_" Red }
}
# ==== Diagnóstico Avançado ====
function Run-All-DiagnosticsAdvanced {
    Show-SystemInfo
    Show-DiskUsage
    Show-NetworkInfo
    Run-SFC-Scan
    Run-DISM-Scan
    Test-SMART-Drives
    Test-Memory
    Show-SuccessMessage
}

function Run-SFC-Scan {
    Write-Log "Executando verificação SFC..." Yellow
    sfc /scannow | Out-Host
    Write-Log "Verificação SFC concluída." Green
}
function Run-DISM-Scan {
    Write-Log "Executando verificação DISM..." Yellow
    DISM /Online /Cleanup-Image /RestoreHealth | Out-Host
    Write-Log "Verificação DISM concluída." Green
}
function Test-SMART-Drives {
    Write-Log "Verificando saúde dos discos (SMART)..." Yellow
    Get-WmiObject -Namespace root\wmi -Class MSStorageDriver_FailurePredictStatus | ForEach-Object {
        if ($_.PredictFailure) {
            Write-Log "Disco com problemas: $($_.InstanceName)" Red
        } else {
            Write-Log "Disco OK: $($_.InstanceName)" Green
        }
    }
}
function Test-Memory {
    Write-Log "Agendando teste de memória na próxima inicialização..." Yellow
    mdsched.exe
    Write-Log "Teste de memória agendado." Green
}

# Autologin seguro
function Enable-AutoLogin {
    Write-Host "=== Configurar Autologin ===" -ForegroundColor Cyan
    $username = Read-Host "Digite o usuário para autologin (ex: Administrator ou SeuUsuario)"
    $password = Read-Host "Digite a senha para autologin (não aparecerá na tela)" -AsSecureString
    $passwordPlain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))
    $domain = $env:USERDOMAIN
    reg export "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "$env:TEMP\backup_winlogon_autologin.reg" /y | Out-Null
    try {
        Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "AutoAdminLogon" -Value "1"
        Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "DefaultUserName" -Value $username
        Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "DefaultDomainName" -Value $domain
        Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "DefaultPassword" -Value $passwordPlain
        Write-Log "Autologin configurado para o usuário $username." Green
    } catch { Write-Log "Erro ao configurar autologin: $_" Red }
    Show-SuccessMessage
}
#endregion

# ==== PARTE 6: Bloco de Reversão/Desfazer Tweaks e Segurança Extra ====

function Restore-DefaultUAC {
    Write-Log "Restaurando UAC para padrão..." Yellow
    try {
        reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f | Out-Null
        Write-Log "UAC restaurado." Green
    } catch { Write-Log "Erro ao restaurar UAC: $_" Red }
}

function Restore-DefaultIPv6 {
    Write-Log "Reabilitando IPv6..." Yellow
    try {
        Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisabledComponents" -ErrorAction SilentlyContinue
        Write-Log "IPv6 reabilitado." Green
    } catch { Write-Log "Erro ao reabilitar IPv6: $_" Red }
}

function Restore-Registry-FromBackup {
    Write-Host "Digite o caminho do backup do registro para restaurar (pasta):" -ForegroundColor Cyan
    $bkpPath = Read-Host
    try {
        reg.exe restore HKLM\SOFTWARE "$bkpPath\HKLM_SOFTWARE.reg" | Out-Null
        reg.exe restore HKLM\SYSTEM "$bkpPath\HKLM_SYSTEM.reg" | Out-Null
        reg.exe restore HKCU "$bkpPath\HKCU.reg" | Out-Null
        Write-Log "Registro restaurado a partir de $bkpPath." Green
    } catch { Write-Log "Erro ao restaurar o registro: $_" Red }
}

function Undo-PrivacyHardening {
    Write-Log "Desfazendo ajustes de privacidade agressivos..." Yellow
    try {
        reg.exe delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v Enabled /f | Out-Null
        reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /f | Out-Null
        reg.exe delete "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v RestrictImplicitTextCollection /f | Out-Null
        reg.exe delete "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v RestrictImplicitInkCollection /f | Out-Null
        reg.exe delete "HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /v HarvestContacts /f | Out-Null
        Write-Log "Ajustes de privacidade revertidos." Green
    } catch { Write-Log "Erro ao desfazer privacidade: $_" Red }
}

function Restore-VisualPerformanceDefault {
    Write-Log "Restaurando configurações visuais para o padrão..." Yellow
    try {
        reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v VisualFXSetting /t REG_DWORD /d 0 /f | Out-Null
        Write-Log "Configurações visuais restauradas." Green
    } catch { Write-Log "Erro ao restaurar visual: $_" Red }
}

function ReEnable-ActionCenter-Notifications {
    Write-Log "Reabilitando Action Center e notificações..." Yellow
    try {
        reg.exe delete "HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v DisableNotificationCenter /f | Out-Null
        reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications" /v ToastEnabled /t REG_DWORD /d 1 /f | Out-Null
        reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v GlobalUserDisabled /t REG_DWORD /d 0 /f | Out-Null
        Write-Log "Action Center e notificações reabilitados." Green
    } catch { Write-Log "Erro ao reabilitar Action Center: $_" Red }
}

function Enable-SMBv1 {
    Write-Log "Habilitando SMBv1 (NÃO RECOMENDADO em redes modernas)..." Yellow
    try {
        Enable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -All -NoRestart
        Write-Log "SMBv1 habilitado." Green
    } catch { Write-Log "Erro ao habilitar SMBv1: $_" Red }
}

function Disable-SMBv1 {
    Write-Log "Desabilitando SMBv1 (recomendado para segurança)..." Yellow
    try {
        Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart
        Write-Log "SMBv1 desabilitado." Green
    } catch { Write-Log "Erro ao desabilitar SMBv1: $_" Red }
}

function Harden-OfficeMacros {
    Write-Log "Desabilitando macros perigosos do Office..." Yellow
    try {
        # Word
        reg.exe add "HKCU\Software\Microsoft\Office\16.0\Word\Security" /v VBAWarnings /t REG_DWORD /d 4 /f | Out-Null
        # Excel
        reg.exe add "HKCU\Software\Microsoft\Office\16.0\Excel\Security" /v VBAWarnings /t REG_DWORD /d 4 /f | Out-Null
        Write-Log "Macros do Office bloqueados." Green
    } catch { Write-Log "Erro ao bloquear macros: $_" Red }
}

function Restore-OfficeMacros {
    Write-Log "Restaurando comportamento padrão de macros do Office..." Yellow
    try {
        reg.exe delete "HKCU\Software\Microsoft\Office\16.0\Word\Security" /v VBAWarnings /f | Out-Null
        reg.exe delete "HKCU\Software\Microsoft\Office\16.0\Excel\Security" /v VBAWarnings /f | Out-Null
        Write-Log "Macros do Office retornaram ao padrão." Green
    } catch { Write-Log "Erro ao restaurar macros: $_" Red }
}

function Show-RestoreUndoMenu {
    do {
        Clear-Host
        Write-Host "=============================================" -ForegroundColor Magenta
        Write-Host " REVERTER AJUSTES & SEGURANÇA" -ForegroundColor Magenta
        Write-Host "=============================================" -ForegroundColor Magenta
        Write-Host " 1. Restaurar UAC para padrão"
        Write-Host " 2. Reabilitar IPv6"
        Write-Host " 3. Restaurar backup do registro"
        Write-Host " 4. Desfazer privacidade agressiva"
        Write-Host " 5. Restaurar visual padrão"
        Write-Host " 6. Reabilitar Action Center/Notificações"
        Write-Host " 7. Habilitar SMBv1 (NÃO RECOMENDADO)"
        Write-Host " 8. Desabilitar SMBv1 (RECOMENDADO)"
        Write-Host " 9. Bloquear macros Office (segurança)"
        Write-Host "10. Restaurar macros Office (padrão)"
        Write-Host " 0. Voltar ao menu principal"
        $choice = Read-Host "`nSelecione uma opção"
        switch ($choice) {
            '1' { Restore-DefaultUAC; Show-SuccessMessage }
            '2' { Restore-DefaultIPv6; Show-SuccessMessage }
            '3' { Restore-Registry-FromBackup; Show-SuccessMessage }
            '4' { Undo-PrivacyHardening; Show-SuccessMessage }
            '5' { Restore-VisualPerformanceDefault; Show-SuccessMessage }
            '6' { ReEnable-ActionCenter-Notifications; Show-SuccessMessage }
            '7' { Enable-SMBv1; Show-SuccessMessage }
            '8' { Disable-SMBv1; Show-SuccessMessage }
            '9' { Harden-OfficeMacros; Show-SuccessMessage }
            '10' { Restore-OfficeMacros; Show-SuccessMessage }
            '0' { return }
            default { Write-Host "Opção inválida!" -ForegroundColor Red; Start-Sleep -Seconds 1 }
        }
    } while ($true)
}

#region → Menus Hierárquicos
# ==== PARTE 2: Menus Avançados e Execução em Lote ====
# Cole abaixo dos outros menus, antes da chamada Show-MainMenu ou substitua/complete os menus existentes se desejar.

# ---------------------- BLOCO: Limpeza e Otimização (menu incrementado) ----------------------

function Run-All-CleanupAdvanced {
    Clean-TemporaryFiles
    Clear-WUCache
    Flush-DNS
    Optimize-Volumes
    Clean-WinSxS
    Schedule-ChkDsk
    Remove-WindowsOld
    Deep-SystemCleanup
    Clean-PrintSpooler
    Clean-Prefetch
    Show-SuccessMessage
}

function Show-CleanupMenu {
    do {
        Clear-Host
        Write-Host "=============================================" -ForegroundColor Cyan
        Write-Host " LIMPEZA E OTIMIZAÇÃO" -ForegroundColor Cyan
        Write-Host "=============================================" -ForegroundColor Cyan
        Write-Host " 1. Executar todas as tarefas abaixo em sequência" -ForegroundColor Green
        Write-Host " 2. Limpar arquivos temporários" -ForegroundColor Yellow
        Write-Host " 3. Limpar cache do Windows Update" -ForegroundColor Yellow
        Write-Host " 4. Limpar cache DNS" -ForegroundColor Yellow
        Write-Host " 5. Otimizar volumes" -ForegroundColor Yellow
        Write-Host " 6. Limpar WinSxS" -ForegroundColor Yellow
        Write-Host " 7. Agendar chkdsk /f /r" -ForegroundColor Yellow
        Write-Host " 8. Remover Windows.old" -ForegroundColor Yellow
        Write-Host " 9. Limpeza profunda de cache, logs, drivers antigos" -ForegroundColor Yellow
        Write-Host "10. Limpar spooler de impressão" -ForegroundColor Yellow
        Write-Host "11. Limpar Prefetch" -ForegroundColor Yellow
        Write-Host " 0. Voltar ao menu principal" -ForegroundColor Red
        Write-Host "=============================================" -ForegroundColor Cyan
        
        $choice = Read-Host "`nSelecione uma opção"
        switch ($choice) {
            '1' { Run-All-CleanupAdvanced }
            '2' { Clean-TemporaryFiles; Show-SuccessMessage }
            '3' { Clear-WUCache; Show-SuccessMessage }
            '4' { Flush-DNS; Show-SuccessMessage }
            '5' { Optimize-Volumes; Show-SuccessMessage }
            '6' { Clean-WinSxS; Show-SuccessMessage }
            '7' { Schedule-ChkDsk; Show-SuccessMessage }
            '8' { Remove-WindowsOld; Show-SuccessMessage }
            '9' { Deep-SystemCleanup; Show-SuccessMessage }
            '10' { Clean-PrintSpooler; Show-SuccessMessage }
            '11' { Clean-Prefetch; Show-SuccessMessage }
            '0' { return }
            default { Write-Host "Opção inválida!" -ForegroundColor Red; Start-Sleep -Seconds 1 }
        }
    } while ($true)
}

# ---------------------- BLOCO: Bloatware, Privacidade, Hardening (menu incrementado) ----------------------

function Run-All-BloatwareAdvanced {
    Remove-Bloatware
    Remove-AdditionalBloatware
    Remove-UWPBloatware
    Remove-ProvisionedBloatware
    Remove-Copilot
    Remove-OneDrive-AndRestoreFolders
    Remove-Edge
    Disable-ActionCenter-Notifications
    Disable-BloatwareScheduledTasks
    Stop-BloatwareProcesses
    Remove-StartAndTaskbarPins
    Remove-ScheduledTasksAggressive
    Enable-ClassicContextMenu
    Apply-ExtraTweaks
    Disable-Cortana-AndSearch
    Disable-UAC
    Enable-PrivacyHardening
    Optimize-NetworkPerformance
    Disable-IPv6
    Set-VisualPerformance
    Run-ExternalDebloaters
    Backup-Registry
    Show-SuccessMessage
}

function Show-BloatwareMenu {
    do {
        Clear-Host
        Write-Host "=============================================" -ForegroundColor Cyan
        Write-Host " BLOATWARE, PRIVACIDADE, HARDENING, EXTRAS" -ForegroundColor Cyan
        Write-Host "=============================================" -ForegroundColor Cyan
        Write-Host " 1. Executar todas as tarefas abaixo em sequência" -ForegroundColor Green
        Write-Host " 2. Remover bloatware padrão"
        Write-Host " 3. Remover aplicativos adicionais"
        Write-Host " 4. Remover UWP bloatware (exceto essenciais)"
        Write-Host " 5. Remover bloatware (whitelist)"
        Write-Host " 6. Remover Copilot"
        Write-Host " 7. Remover OneDrive e restaurar pastas"
        Write-Host " 8. Remover Microsoft Edge"
        Write-Host " 9. Desabilitar Action Center/Notificações"
        Write-Host "10. Desativar tarefas agendadas de bloatware"
        Write-Host "11. Encerrar processos dispensáveis"
        Write-Host "12. Remover pins do Menu Iniciar/Barra de Tarefas"
        Write-Host "13. Remover tarefas agendadas (agressivo)"
        Write-Host "14. Restaurar menu de contexto clássico"
        Write-Host "15. Aplicar tweaks extras (bloqueio anúncios, F8, sons, web search, Cast to Device)"
        Write-Host "16. Desativar Cortana, Search, Telemetria, Relatórios de Erro"
        Write-Host "17. Desabilitar UAC"
        Write-Host "18. Aplicar privacidade agressiva"
        Write-Host "19. Otimizar rede (TCP/DNS)"
        Write-Host "20. Desabilitar IPv6"
        Write-Host "21. Ajustar visual para performance"
        Write-Host "22. Executar debloaters de terceiros"
        Write-Host "23. Backup do registro"
        Write-Host "24. Restaurar backup do registro"
        Write-Host " 0. Voltar ao menu principal" -ForegroundColor Red
        Write-Host "=============================================" -ForegroundColor Cyan
        
        $choice = Read-Host "`nSelecione uma opção"
        switch ($choice) {
            '1' { Run-All-BloatwareAdvanced }
            '2' { Remove-Bloatware; Show-SuccessMessage }
            '3' { Remove-AdditionalBloatware; Show-SuccessMessage }
            '4' { Remove-UWPBloatware; Show-SuccessMessage }
            '5' { Remove-ProvisionedBloatware; Show-SuccessMessage }
            '6' { Remove-Copilot; Show-SuccessMessage }
            '7' { Remove-OneDrive-AndRestoreFolders; Show-SuccessMessage }
            '8' { Remove-Edge; Show-SuccessMessage }
            '9' { Disable-ActionCenter-Notifications; Show-SuccessMessage }
            '10' { Disable-BloatwareScheduledTasks; Show-SuccessMessage }
            '11' { Stop-BloatwareProcesses; Show-SuccessMessage }
            '12' { Remove-StartAndTaskbarPins; Show-SuccessMessage }
            '13' { Remove-ScheduledTasksAggressive; Show-SuccessMessage }
            '14' { Enable-ClassicContextMenu; Show-SuccessMessage }
            '15' { Apply-ExtraTweaks; Show-SuccessMessage }
            '16' { Disable-Cortana-AndSearch; Show-SuccessMessage }
            '17' { Disable-UAC; Show-SuccessMessage }
            '18' { Enable-PrivacyHardening; Show-SuccessMessage }
            '19' { Optimize-NetworkPerformance; Show-SuccessMessage }
            '20' { Disable-IPv6; Show-SuccessMessage }
            '21' { Set-VisualPerformance; Show-SuccessMessage }
            '22' { Run-ExternalDebloaters; Show-SuccessMessage }
            '23' { Backup-Registry; Show-SuccessMessage }
            '24' { Restore-Registry; Show-SuccessMessage }
            '0' { return }
            default { Write-Host "Opção inválida!" -ForegroundColor Red; Start-Sleep -Seconds 1 }
        }
    } while ($true)
}

# ---------------------- BLOCO: Menu Autologin (inclua no menu principal) ----------------------

function Show-AutoLoginMenu {
    Clear-Host
    Write-Host "===== AUTOLOGIN =====" -ForegroundColor Cyan
    Enable-AutoLogin
}



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
            '13' { Renomear-Notebook }
            '0' { return }
            default { Write-Host "Opção inválida!" -ForegroundColor Red; Start-Sleep -Seconds 1 }
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
		Write-Host "11. Instalar AutoHotKey" -ForegroundColor Yellow
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
			'11' {winget install --id AutoHotkey.AutoHotkey -e --accept-package-agreements --accept-source-agreements; Pause-Script}
            '0' { return }
            default { Write-Host "Opção inválida!" -ForegroundColor Red; Start-Sleep -Seconds 1 }
        }
    } while ($true)
}

function Show-NetworkMenu {
    do {
        Clear-Host
        Write-Host "=============================================" -ForegroundColor Cyan
        Write-Host " REDE E OTIMIZAÇÃO" -ForegroundColor Cyan
        Write-Host "=============================================" -ForegroundColor Cyan
        Write-Host " 1. Executar todas as tarefas abaixo em sequência" -ForegroundColor Green
        Write-Host " 2. Limpar cache DNS" -ForegroundColor Yellow
        Write-Host " 3. Otimizar TCP/DNS" -ForegroundColor Yellow
        Write-Host " 4. Definir DNS Google/Cloudflare" -ForegroundColor Yellow
        Write-Host " 5. Testar velocidade de internet" -ForegroundColor Yellow
        Write-Host " 6. Limpar cache ARP" -ForegroundColor Yellow
        Write-Host " 0. Voltar ao menu principal" -ForegroundColor Red
        Write-Host "=============================================" -ForegroundColor Cyan

        $choice = Read-Host "`nSelecione uma opção"
        switch ($choice) {
            '1' { Run-All-NetworkAdvanced }
            '2' { Flush-DNS; Show-SuccessMessage }
            '3' { Optimize-NetworkPerformance; Show-SuccessMessage }
            '4' { Set-DnsGoogleCloudflare; Show-SuccessMessage }
            '5' { Test-InternetSpeed; Show-SuccessMessage }
            '6' { Clear-ARP; Show-SuccessMessage }
            '0' { return }
            default { Write-Host "Opção inválida!" -ForegroundColor Red; Start-Sleep -Seconds 1 }
        }
    } while ($true)
}

function Show-DiagnosticsMenu {
    do {
        Clear-Host
        Write-Host "=============================================" -ForegroundColor Cyan
        Write-Host " DIAGNÓSTICO E INFORMAÇÕES AVANÇADO" -ForegroundColor Cyan
        Write-Host "=============================================" -ForegroundColor Cyan
        Write-Host " 1. Executar todos os diagnósticos abaixo" -ForegroundColor Green
        Write-Host " 2. Exibir informações do sistema" -ForegroundColor Yellow
        Write-Host " 3. Exibir uso do disco" -ForegroundColor Yellow
        Write-Host " 4. Exibir informações de rede" -ForegroundColor Yellow
        Write-Host " 5. SFC /scannow" -ForegroundColor Yellow
        Write-Host " 6. DISM /RestoreHealth" -ForegroundColor Yellow
        Write-Host " 7. Verificar saúde dos discos (SMART)" -ForegroundColor Yellow
        Write-Host " 8. Teste de memória RAM" -ForegroundColor Yellow
        Write-Host " 0. Voltar ao menu principal" -ForegroundColor Red
        Write-Host "=============================================" -ForegroundColor Cyan
        
        $choice = Read-Host "`nSelecione uma opção"
        switch ($choice) {
            '1' { Run-All-DiagnosticsAdvanced }
            '2' { Show-SystemInfo; Show-SuccessMessage }
            '3' { Show-DiskUsage; Show-SuccessMessage }
            '4' { Show-NetworkInfo; Show-SuccessMessage }
            '5' { Run-SFC-Scan; Show-SuccessMessage }
            '6' { Run-DISM-Scan; Show-SuccessMessage }
            '7' { Test-SMART-Drives; Show-SuccessMessage }
            '8' { Test-Memory; Show-SuccessMessage }
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
        Write-Host "15. Ajustes do Painel de Controle/Configurações" -ForegroundColor Yellow
        Write-Host "16. Reiniciar PC" -ForegroundColor Yellow
        Write-Host "17. Renomear notebook" -ForegroundColor Yellow
		Write-Host "18. Configurar Autologin" -ForegroundColor Yellow
		Write-Host "19. Reverter ajustes / Segurança extra" -ForegroundColor Magenta
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
            '15' { Show-ControlPanelTweaksMenu }
            '16' { Write-Log "Reiniciando o computador..." Cyan; Restart-Computer -Force }
            '17' { Renomear-Notebook }
			'18' { Show-AutoLoginMenu }
			'19' { Show-RestoreUndoMenu }
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
finally {
    # Garante que o script sempre pausa antes de sair, mesmo em caso de erro
    Pause-Script
}
