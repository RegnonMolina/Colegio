# ===============================
# SCRIPT SUPREMO DE MANUTENÇÃO 🛠️
# ===============================
# Iniciado em: $(Get-Date)
# Desenvolvido com sangue, café e PowerShell 💪

# === CONFIGURAÇÕES GLOBAIS ===
$global:ConfirmPreference = "None"
$global:ProgressPreference = 'Continue'  
$global:ErrorActionPreference = "SilentlyContinue"
$VerbosePreference = "SilentlyContinue" 
$global:logFile = "$PSScriptRoot\log-$((Get-Date).ToString('yyyy-MM-dd-HH')).txt"
$LogDate = Get-Date -format "dd-MM-yyyy-HH"
$currentTime = Get-Date -format "dd-MM-yyyy HH:mm:ss"
$computer = $env:COMPUTERNAME
$windowsUpdateCachePath = "C:\Windows\SoftwareDistribution"

# Detectar rede ativa (SSID)
try {
    $profile = Get-NetConnectionProfile | Where-Object { $_.IPv4Connectivity -eq 'Internet' }
    if ($profile) {
        $ssid = $profile.Name
        $interface = $profile.InterfaceAlias
    }
} catch {
    Write-Log "Rede não detectada. Algumas funções podem não funcionar corretamente." Yellow
}

$logFile = "$PSScriptRoot\log.txt"
$startTime = Get-Date

# === FUNÇÕES DE UTILIDADE ===
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
    param(
        [string]$message,
        [string]$color = "White"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    if (-not $message) {
        $message = "<mensagem vazia>"
    }

    # Garante que a cor seja válida
    $validColors = [System.Enum]::GetNames([System.ConsoleColor])
    if ($validColors -notcontains $color) {
        $color = "White"
    }

    $logMessage = "[$timestamp] $message"

    # Escreve no console
    try {
        Write-Host $logMessage -ForegroundColor $color
    } catch {
        Write-Host "[$timestamp] $message" -ForegroundColor White
    }

    # Escreve no arquivo de log
    try {
        Add-Content -Path $logFile -Value $logMessage
    } catch {
        Write-Host "⚠️ Falha ao salvar log no arquivo: $logFile" -ForegroundColor Yellow
    }
}


function Pause-Script {
    Show-SuccessMessage
}

function Show-SuccessMessage {
    Write-Log "`n✔️ Tarefa concluída com sucesso!" Green
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
    Write-Log "Iniciando remoção segura de bloatware..." Yellow

    $whitelist = @(
        "Microsoft.WindowsCalculator",
        "Microsoft.WindowsCamera",
        "Microsoft.WindowsSoundRecorder",
        "Microsoft.ScreenSketch",        # Ferramenta de Captura
        "Microsoft.WindowsNotepad",      # Notepad moderno
        "Microsoft.StorePurchaseApp",
        "Microsoft.DesktopAppInstaller",
        "Microsoft.WindowsStore"
    )

    $bloatwarePatterns = @(
        "Microsoft.3DBuilder",
        "Microsoft.BingNews",
        "Microsoft.BingWeather",
        "Microsoft.GetHelp",
        "Microsoft.Getstarted",
        "Microsoft.MicrosoftOfficeHub",
        "Microsoft.MicrosoftSolitaireCollection",
        "Microsoft.MixedReality.Portal",
        "Microsoft.People",
        "Microsoft.SkypeApp",
        "Microsoft.Todos",
        "Microsoft.Xbox",
        "Microsoft.XboxGamingOverlay",
        "Microsoft.Xbox.TCUI",
        "Microsoft.XboxGameOverlay",
        "Microsoft.XboxSpeechToTextOverlay",
        "Microsoft.XboxIdentityProvider",
        "Microsoft.ZuneMusic",
        "Microsoft.ZuneVideo",
        "Microsoft.YourPhone",
        "Microsoft.MicrosoftStickyNotes",
        "Microsoft.OneNote",
        "Microsoft.Outlook",
        "Microsoft.OutlookForWindows",
        "Microsoft.LinkedIn"
    )

    # Remover AppxPackage por usuário atual
    foreach ($pattern in $bloatwarePatterns) {
        $apps = Get-AppxPackage -Name $pattern -ErrorAction SilentlyContinue
        foreach ($app in $apps) {
            if (-not ($whitelist -contains $app.Name)) {
                Write-Log "Removendo: $($app.Name)" Cyan
                Remove-AppxPackage -Package $app.PackageFullName -ErrorAction SilentlyContinue
            }
        }
    }

    # Remover AppxProvisionedPackage (para novos usuários)
    foreach ($pattern in $bloatwarePatterns) {
        $provisioned = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -like "$pattern*" }
        foreach ($pkg in $provisioned) {
            if (-not ($whitelist -contains $pkg.DisplayName)) {
                Write-Log "Removendo provisionado: $($pkg.DisplayName)" Cyan
                Remove-AppxProvisionedPackage -Online -PackageName $pkg.PackageName -ErrorAction SilentlyContinue
            }
        }
    }

    Write-Log "Remoção segura de bloatware concluída." Green
    Show-SuccessMessage
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

    try {
        $tempFile = "$env:TEMP\$($ssid.Replace(' ', '_')).xml"
        $xmlProfile | Out-File -FilePath $tempFile -Encoding ascii

        netsh wlan add profile filename="$tempFile" user=all | Out-Null
        netsh wlan connect name="$ssid" | Out-Null

        # Espera até a rede estar conectada (timeout: 15 segundos)
        $connected = $false
        for ($i = 0; $i -lt 15; $i++) {
            Start-Sleep -Seconds 1
            $status = netsh wlan show interfaces | Select-String "SSID\s+:\s+$ssid"
            if ($status) {
                $connected = $true
                break
            }
        }

        if ($connected) {
            Set-NetConnectionProfile -InterfaceAlias "Wi-Fi" -NetworkCategory Private -ErrorAction SilentlyContinue
            Write-Log "Rede '$ssid' conectada e configurada como privada." Green
        } else {
            Write-Log "⚠️ Não foi possível confirmar a conexão com '$ssid'. Definição como privada pulada." Yellow
        }
    }
    catch {
        Write-Log "Erro ao configurar rede Wi-Fi: $_" Red
    }
    finally {
        if (Test-Path $tempFile) { Remove-Item $tempFile -Force }
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
    "Microsoft.WindowsCalculator",
    "Microsoft.WindowsCamera",
    "Microsoft.WindowsSoundRecorder",
    "Microsoft.StorePurchaseApp",
    "Microsoft.DesktopAppInstaller", # Necessário pro winget
    "Microsoft.WindowsStore"
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
        Write-Host "1. Executar todos os ajustes abaixo" -ForegroundColor Green
        Write-Host "2. Mostrar arquivos ocultos" -ForegroundColor Yellow
        Write-Host "3. Mostrar extensões de arquivos" -ForegroundColor Yellow
        Write-Host "4. Remover sugestões/anúncios" -ForegroundColor Yellow
        Write-Host "5. Restaurar menus clássicos/contextuais" -ForegroundColor Yellow
        Write-Host "0. Voltar" -ForegroundColor Red

        $choice = Read-Host "`nSelecione uma opção"
        switch ($choice) {
            '1' {
                # Executa todos em sequência
                reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Hidden /t REG_DWORD /d 1 /f | Out-Null
                Write-Log "Arquivos ocultos visíveis." Green

                reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v HideFileExt /t REG_DWORD /d 0 /f | Out-Null
                Write-Log "Extensões de arquivos visíveis." Green

                reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowSyncProviderNotifications /t REG_DWORD /d 0 /f | Out-Null
                Write-Log "Sugestões/anúncios removidos." Green

                reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v EnableClassicContextMenu /t REG_DWORD /d 1 /f | Out-Null
                Write-Log "Menus clássicos ativados." Green

                Show-SuccessMessage
            }
            '2' {
                reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Hidden /t REG_DWORD /d 1 /f | Out-Null
                Write-Log "Arquivos ocultos visíveis." Green
                Show-SuccessMessage
            }
            '3' {
                reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v HideFileExt /t REG_DWORD /d 0 /f | Out-Null
                Write-Log "Extensões de arquivos visíveis." Green
                Show-SuccessMessage
            }
            '4' {
                reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowSyncProviderNotifications /t REG_DWORD /d 0 /f | Out-Null
                Write-Log "Sugestões/anúncios removidos." Green
                Show-SuccessMessage
            }
            '5' {
                reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v EnableClassicContextMenu /t REG_DWORD /d 1 /f | Out-Null
                Write-Log "Menus clássicos ativados." Green
                Show-SuccessMessage
            }
            '0' { return }
            default {
                Write-Host "Opção inválida!" -ForegroundColor Red
                Start-Sleep -Seconds 1
            }
        }
    } while ($true)
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
    if ($PSVersionTable.PSVersion.Major -lt 7) {
        Write-Log "PowerShell 7+ é necessário para suporte ao sudo." Red
        return
    }

    $profilePath = "$HOME\Documents\PowerShell\Microsoft.PowerShell_profile.ps1"
    if (-not (Test-Path $profilePath)) {
        New-Item -ItemType File -Path $profilePath -Force | Out-Null
    }

    $content = Get-Content $profilePath -ErrorAction SilentlyContinue
    if ($content -notmatch "function sudo") {
        Add-Content -Path $profilePath -Value @"
function sudo {
    param([string]\$command)
    Start-Process pwsh -ArgumentList "-Command \$command" -Verb RunAs
}
"@
        Write-Log "Alias 'sudo' adicionado ao seu profile." Green
    } else {
        Write-Log "'sudo' já estava configurado." Cyan
    }
}


function Enable-TaskbarEndTask {
    $build = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentBuild
    if ([int]$build -lt 23430) {
        Write-Log "Este recurso exige o Windows 11 build 23430 ou superior." Red
        return
    }

    try {
        reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarEndTask /t REG_DWORD /d 1 /f | Out-Null
        Write-Log "'Finalizar tarefa' ativado no menu da barra de tarefas." Green
    } catch {
        Write-Log "Erro ao configurar TaskbarEndTask: $_" Red
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
        Write-Host "1. Executar todos os ajustes abaixo" -ForegroundColor Green
        Write-Host "2. Ativar 'Finalizar Tarefa' na barra de tarefas" -ForegroundColor Yellow
        Write-Host "3. Ativar atualizações antecipadas do Windows Update" -ForegroundColor Yellow
        Write-Host "4. Ativar dark mode (tema escuro)" -ForegroundColor Yellow
        Write-Host "5. Ativar histórico da área de transferência" -ForegroundColor Yellow
        Write-Host "6. Ativar restauração de apps após reinicialização" -ForegroundColor Yellow
        Write-Host "7. Ativar segundos no relógio da barra de tarefas" -ForegroundColor Yellow
        Write-Host "8. Ativar updates para outros produtos Microsoft" -ForegroundColor Yellow
        Write-Host "9. Habilitar Sudo embutido" -ForegroundColor Yellow
        Write-Host "0. Voltar ao menu principal" -ForegroundColor Red

        $choice = Read-Host "`nSelecione uma opção"
        switch ($choice) {
            '1' {
                Enable-TaskbarEndTask
                Enable-WindowsUpdateFast
                Enable-DarkTheme
                Enable-ClipboardHistory
                Enable-RestartAppsAfterReboot
                Enable-TaskbarSeconds
                Enable-OtherMicrosoftUpdates
                Enable-Sudo
                Show-SuccessMessage
            }
            '2' { Enable-TaskbarEndTask; Show-SuccessMessage }
            '3' { Enable-WindowsUpdateFast; Show-SuccessMessage }
            '4' { Enable-DarkTheme; Show-SuccessMessage }
            '5' { Enable-ClipboardHistory; Show-SuccessMessage }
            '6' { Enable-RestartAppsAfterReboot; Show-SuccessMessage }
            '7' { Enable-TaskbarSeconds; Show-SuccessMessage }
            '8' { Enable-OtherMicrosoftUpdates; Show-SuccessMessage }
            '9' { Enable-Sudo; Show-SuccessMessage }
            '0' { return }
            default {
                Write-Host "Opção inválida!" -ForegroundColor Red
                Start-Sleep -Seconds 1
            }
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
    $confirm = Read-Host "⚠️ Tem certeza que deseja REMOVER o OneDrive e restaurar pastas? (s/n)"
    if ($confirm -ne 's') {
        Write-Host "❌ Operação cancelada pelo usuário." -ForegroundColor Yellow
        return
    }

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
        Write-Log "✅ OneDrive removido e pastas restauradas." Green
    } catch {
        Write-Log "❌ Erro ao remover Onedrive/restaurar pastas: $_" Red
    }
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

function Run-WindowsActivator {
    Clear-Host
    Write-Host "==== ATIVAÇÃO DO WINDOWS ====" -ForegroundColor Cyan
    Write-Host "Executando script de ativação oficial (get.activated.win)..." -ForegroundColor Yellow
    try {
        irm https://get.activated.win | iex
        Write-Log "Script de ativação executado com sucesso." Green
    } catch {
        Write-Log "Erro ao executar o script de ativação: $_" Red
    }
    Show-SuccessMessage
}

function Run-ChrisTitusToolbox {
    Clear-Host
    Write-Host "==== CHRIS TITUS TOOLBOX ====" -ForegroundColor Cyan
    Write-Host "Executando toolbox oficial do site christitus.com..." -ForegroundColor Yellow
    try {
        irm christitus.com/win | iex
        Write-Log "Chris Titus Toolbox executado com sucesso." Green
    } catch {
        Write-Log "Erro ao executar o script do Chris Titus: $_" Red
    }
    Show-SuccessMessage
}

function Update-ScriptFromCloud {
    Clear-Host
    Write-Host "=======================" -ForegroundColor Cyan
    Write-Host "ATUALIZANDO SCRIPT..." -ForegroundColor Cyan
    Write-Host "=======================" -ForegroundColor Cyan

    try {
        Write-Log "Baixando script atualizado do Colégio Mundo do Saber..." Yellow
        irm script.colegiomundodosaber.com.br | iex
        Write-Log "Script carregado com sucesso a partir da versão online!" Green
        Show-SuccessMessage
    }   catch {
        Write-Log "❌ Falha ao carregar script online: $_" Red
        Show-SuccessMessage
    }
}

# Autologin seguro
function Show-AutoLoginMenu {
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

function Restore-OneDrive {
    Write-Log "🔄 Reinstalando o OneDrive via download direto..." Cyan

    $downloadUrl = "https://go.microsoft.com/fwlink/p/?LinkId=248256"
    $tempInstaller = "$env:TEMP\OneDriveSetup.exe"

    try {
        Write-Log "⬇️ Baixando instalador oficial do OneDrive..." Yellow
        Invoke-WebRequest -Uri $downloadUrl -OutFile $tempInstaller -UseBasicParsing
        Write-Log "✅ Download concluído." Green
    } catch {
        Write-Log "❌ Falha ao baixar o OneDrive: $_" Red
        return
    }

    if (Test-Path $tempInstaller) {
        try {
            Start-Process -FilePath $tempInstaller -ArgumentList "/silent" -Wait
            Write-Log "✅ OneDrive reinstalado com sucesso." Green
        } catch {
            Write-Log "❌ Erro ao executar o instalador: $_" Red
        }
    } else {
        Write-Log "❌ Instalador não encontrado após o download." Red
    }

    Show-SuccessMessage
}

function Restore-BloatwareSafe {
    Write-Log "Restaurando aplicativos padrão essenciais..." Yellow

    $appsToRestore = @(
        "Microsoft.WindowsCalculator",
        "Microsoft.WindowsCamera",
        "Microsoft.WindowsSoundRecorder",  # Gravador de Voz
        "Microsoft.ScreenSketch",          # Ferramenta de Captura
        "Microsoft.WindowsNotepad",
        "Microsoft.OutlookForWindows",
        "Microsoft.LinkedIn.LinkedIn"
    )

    foreach ($app in $appsToRestore) {
        try {
            Write-Log "Reinstalando $app..." Cyan
            Get-AppxPackage -AllUsers -Name $app -ErrorAction SilentlyContinue |
                ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" }
        } catch {
            Write-Log "Erro ao restaurar ${app}: $_" Red
        }
    }

    Write-Log "Aplicativos essenciais restaurados." Green
    Show-SuccessMessage
}

function Apply-ControlPanelTweaks {
    Write-Host "Aplicando ajustes visuais e de desempenho..." -ForegroundColor Cyan

    # Função interna para setar valores no registro
    function Set-RegistryValue {
        param (
            [string]$Path,
            [string]$Name,
            [object]$Value,
            [Microsoft.Win32.RegistryValueKind]$Type
        )
        try {
            New-Item -Path $Path -Force | Out-Null
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type
        } catch {
            Write-Warning "Falha ao definir $Name em $Path"
        }
    }

    # === Ajustes: Control Panel\Desktop ===
    $desktopKey = "HKCU:\Control Panel\Desktop"
    Set-RegistryValue $desktopKey "DragFullWindows" 0 DWord
    Set-RegistryValue $desktopKey "MenuShowDelay" 0 String
    Set-RegistryValue $desktopKey "CursorBlinkRate" "530" String
    Set-RegistryValue $desktopKey "CaretWidth" 1 DWord
    Set-RegistryValue $desktopKey "PaintDesktopVersion" 0 DWord
    Set-RegistryValue $desktopKey "SnapSizing" 1 String
    Set-RegistryValue $desktopKey "FontSmoothingType" 1 DWord
    Set-RegistryValue $desktopKey "ForegroundFlashCount" 7 DWord
    Set-RegistryValue $desktopKey "MouseWheelRouting" 2 DWord
    Set-RegistryValue $desktopKey "ScreenSaveActive" 1 String
    Set-RegistryValue $desktopKey "WallpaperStyle" "10" String
    Set-RegistryValue $desktopKey "WheelScrollLines" 3 String
    Set-RegistryValue $desktopKey "WindowArrangementActive" 1 String

    # === Ajustes: Explorer\Advanced ===
    $advKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    Set-RegistryValue $advKey "HideFileExt" 1 DWord
    Set-RegistryValue $advKey "ShowSuperHidden" 0 DWord
    Set-RegistryValue $advKey "TaskbarAnimations" 1 DWord
    Set-RegistryValue $advKey "ShowSecondsInSystemClock" 1 DWord
    Set-RegistryValue $advKey "IconsOnly" 0 DWord
    Set-RegistryValue $advKey "ShowStatusBar" 1 DWord
    Set-RegistryValue $advKey "ShowCompColor" 1 DWord
    Set-RegistryValue $advKey "ListviewAlphaSelect" 1 DWord
    Set-RegistryValue $advKey "ListviewShadow" 1 DWord
    Set-RegistryValue "$advKey\TaskbarDeveloperSettings" "TaskbarEndTask" 1 DWord

    # === Ajustes: Explorer\VisualEffects ===
    $veBase = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects"
    Set-RegistryValue $veBase "VisualFXSetting" 2 DWord
    $visualTweaks = @(
        "AnimateMinMax", "ComboBoxAnimation", "ControlAnimations", "CursorShadow",
        "DragFullWindows", "DropShadow", "DWMAeroPeekEnabled", "DWMEnabled",
        "DWMSaveThumbnailEnabled", "ListBoxSmoothScrolling", "ListviewAlphaSelect",
        "ListviewShadow", "MenuAnimation", "SelectionFade", "TaskbarAnimations",
        "Themes", "ThumbnailsOrIcon", "TooltipAnimation"
    )
    foreach ($vt in $visualTweaks) {
        Set-RegistryValue "$veBase\$vt" "DefaultApplied" 1 DWord
    }

    # === Ajustes: Themes e Personalização ===
    $themesKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes"
    Set-RegistryValue $themesKey "ColorSetFromTheme" 1 DWord
    Set-RegistryValue $themesKey "WallpaperSetFromTheme" 1 DWord
    Set-RegistryValue "$themesKey\Personalize" "EnableTransparency" 1 DWord
    Set-RegistryValue "$themesKey\Personalize" "SystemUsesLightTheme" 0 DWord
    Set-RegistryValue "$themesKey\Personalize" "AppsUseLightTheme" 0 DWord

    Write-Host "✔️ Ajustes aplicados com sucesso!" -ForegroundColor Green
}

function Restore-ControlPanelTweaks {
    Write-Host "Restaurando configurações visuais e de desempenho padrão..." -ForegroundColor Cyan

    function Set-RegistryValue {
        param (
            [string]$Path,
            [string]$Name,
            [object]$Value,
            [Microsoft.Win32.RegistryValueKind]$Type
        )
        try {
            New-Item -Path $Path -Force | Out-Null
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type
        } catch {
            Write-Warning "Falha ao definir $Name em $Path"
        }
    }

    # === Restaurar Desktop ===
    $desktopKey = "HKCU:\Control Panel\Desktop"
    Set-RegistryValue $desktopKey "DragFullWindows" 1 DWord
    Set-RegistryValue $desktopKey "MenuShowDelay" "400" String
    Set-RegistryValue $desktopKey "CursorBlinkRate" "530" String
    Set-RegistryValue $desktopKey "CaretWidth" 1 DWord
    Set-RegistryValue $desktopKey "PaintDesktopVersion" 1 DWord
    Set-RegistryValue $desktopKey "SnapSizing" 1 String
    Set-RegistryValue $desktopKey "FontSmoothingType" 2 DWord
    Set-RegistryValue $desktopKey "ForegroundFlashCount" 7 DWord
    Set-RegistryValue $desktopKey "MouseWheelRouting" 0 DWord
    Set-RegistryValue $desktopKey "ScreenSaveActive" 0 String
    Set-RegistryValue $desktopKey "WallpaperStyle" "10" String
    Set-RegistryValue $desktopKey "WheelScrollLines" 3 String
    Set-RegistryValue $desktopKey "WindowArrangementActive" 1 String

    # === Restaurar Explorer\Advanced ===
    $advKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    Set-RegistryValue $advKey "HideFileExt" 0 DWord
    Set-RegistryValue $advKey "ShowSuperHidden" 0 DWord
    Set-RegistryValue $advKey "TaskbarAnimations" 1 DWord
    Set-RegistryValue $advKey "ShowSecondsInSystemClock" 0 DWord
    Set-RegistryValue $advKey "IconsOnly" 1 DWord
    Set-RegistryValue $advKey "ShowStatusBar" 0 DWord
    Set-RegistryValue $advKey "ShowCompColor" 0 DWord
    Set-RegistryValue $advKey "ListviewAlphaSelect" 1 DWord
    Set-RegistryValue $advKey "ListviewShadow" 1 DWord
    Set-RegistryValue "$advKey\TaskbarDeveloperSettings" "TaskbarEndTask" 0 DWord

    # === Restaurar Visual Effects ===
    $veBase = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects"
    Set-RegistryValue $veBase "VisualFXSetting" 1 DWord
    $visualTweaks = @(
        "AnimateMinMax", "ComboBoxAnimation", "ControlAnimations", "CursorShadow",
        "DragFullWindows", "DropShadow", "DWMAeroPeekEnabled", "DWMEnabled",
        "DWMSaveThumbnailEnabled", "ListBoxSmoothScrolling", "ListviewAlphaSelect",
        "ListviewShadow", "MenuAnimation", "SelectionFade", "TaskbarAnimations",
        "Themes", "ThumbnailsOrIcon", "TooltipAnimation"
    )
    foreach ($vt in $visualTweaks) {
        Set-RegistryValue "$veBase\$vt" "DefaultApplied" 1 DWord
    }

    # === Restaurar Personalize ===
    $themesKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes"
    Set-RegistryValue $themesKey "ColorSetFromTheme" 1 DWord
    Set-RegistryValue $themesKey "WallpaperSetFromTheme" 1 DWord
    Set-RegistryValue "$themesKey\Personalize" "EnableTransparency" 1 DWord
    Set-RegistryValue "$themesKey\Personalize" "SystemUsesLightTheme" 1 DWord
    Set-RegistryValue "$themesKey\Personalize" "AppsUseLightTheme" 1 DWord

    Write-Host "✔️ Configurações restauradas para o padrão!" -ForegroundColor Green
}


# === MENU: SISTEMA E DESEMPENHO ===
function Show-SystemPerformanceMenu {
    do {
        Clear-Host
        Write-Host "==== MENU: SISTEMA E DESEMPENHO ====" -ForegroundColor Cyan
        Write-Host "1. Executar todas as opções abaixo" -ForegroundColor Green
        Write-Host "2. Aplicar ajustes do Painel de Controle (visual e desempenho)"
        Write-Host "3. Ajustar tema do Windows para desempenho"
        Write-Host "4. Desativar serviços desnecessários"
        Write-Host "5. Otimizar Windows Explorer para desempenho"
        Write-Host "6. Renomear notebook"
        Write-Host "0. Voltar ao menu principal" -ForegroundColor Magenta

        $choice = Read-Host "`nEscolha uma opção"
        switch ($choice) {
            '1' {
                Apply-ControlPanelTweaks
                Set-PerformanceTheme
                Disable-UnnecessaryServices
                Optimize-ExplorerPerformance
                Renomear-Notebook
                Show-SuccessMessage
            }
            '2' { Apply-ControlPanelTweaks; Show-SuccessMessage }
            '3' { Set-PerformanceTheme; Show-SuccessMessage }
            '4' { Disable-UnnecessaryServices; Show-SuccessMessage }
            '5' { Optimize-ExplorerPerformance; Show-SuccessMessage }
            '6' { Renomear-Notebook; Show-SuccessMessage }
            '0' { return }
            default { Write-Host "Opção inválida!" -ForegroundColor Red; Start-Sleep 1 }
        }
    } while ($true)
}

# === MENU: PRIVACIDADE E SEGURANÇA ===
function Show-PrivacySecurityMenu {
    do {
        Clear-Host
        Write-Host "==== MENU: PRIVACIDADE E SEGURANÇA ====" -ForegroundColor Cyan
        Write-Host "1. Aplicar hardening de segurança"
        Write-Host "2. Bloatware, Privacidade e Atualizações"
        Write-Host "3. Reverter ajustes / Segurança extra"
        Write-Host "0. Voltar ao menu principal" -ForegroundColor Magenta

        $choice = Read-Host "`nEscolha uma opção"
        switch ($choice) {
            '1' { Enable-WindowsHardening; Show-SuccessMessage }
            '2' { Show-BloatwareMenu }
            '3' { Show-RestoreUndoMenu }
            '0' { return }
            default { Write-Host "Opção inválida!" -ForegroundColor Red; Start-Sleep 1 }
        }
    } while ($true)
}

# === MENU: INSTALAÇÃO E FERRAMENTAS ===
function Show-InstallationMenu {
    do {
        Clear-Host
        Write-Host "==== MENU: INSTALAÇÃO DE PROGRAMAS ====" -ForegroundColor Cyan
        Write-Host "1. Instalar todos os programas" -ForegroundColor Green
        Write-Host "2. Instalar 7-Zip"
        Write-Host "3. Instalar AnyDesk"
        Write-Host "4. Instalar AutoHotKey"
        Write-Host "5. Instalar Google Chrome"
        Write-Host "6. Instalar Google Drive"
        Write-Host "7. Instalar Microsoft Office"
        Write-Host "8. Instalar Microsoft PowerToys"
        Write-Host "9. Instalar Notepad++"
        Write-Host "10. Instalar VLC Media Player"
        Write-Host "11. Instalar/Atualizar PowerShell"
        Write-Host "0. Voltar ao menu principal" -ForegroundColor Magenta

        $choice = Read-Host "`nEscolha uma opção"
        switch ($choice) {
            '1' { Install-Applications; Show-SuccessMessage }
            '2' { winget install --id 7zip.7zip -e --accept-package-agreements --accept-source-agreements; Show-SuccessMessage }
            '3' { winget install --id AnyDesk.AnyDesk -e --accept-package-agreements --accept-source-agreements; Show-SuccessMessage }
            '4' { winget install --id AutoHotkey.AutoHotkey -e --accept-package-agreements --accept-source-agreements; Show-SuccessMessage }
            '5' { winget install --id Google.Chrome -e --accept-package-agreements --accept-source-agreements; Show-SuccessMessage }
            '6' { winget install --id Google.GoogleDrive -e --accept-package-agreements --accept-source-agreements; Show-SuccessMessage }
            '7' { winget install --id Microsoft.Office -e --accept-package-agreements --accept-source-agreements; Show-SuccessMessage }
            '8' { winget install --id Microsoft.PowerToys -e --accept-package-agreements --accept-source-agreements; Show-SuccessMessage }
            '9' { winget install --id Notepad++.Notepad++ -e --accept-package-agreements --accept-source-agreements; Show-SuccessMessage }
            '10' { winget install --id VideoLAN.VLC -e --accept-package-agreements --accept-source-agreements; Show-SuccessMessage }
            '11' { Update-PowerShell; Show-SuccessMessage }
            '0' { return }
            default { Write-Host "Opção inválida!" -ForegroundColor Red; Start-Sleep 1 }
        }
    } while ($true)
}

# === MENU: CONFIGURAÇÕES AVANÇADAS ===
function Show-AdvancedSettingsMenu {
    do {
        Clear-Host
        Write-Host "==== MENU: CONFIGURAÇÕES AVANÇADAS ====" -ForegroundColor Cyan
        Write-Host "1. Executar todos os ajustes abaixo" -ForegroundColor Green
        Write-Host "2. Ajustes do Painel de Controle/Configurações"
        Write-Host "3. Configurar Autologin"
        Write-Host "4. Tweaks de interface do Explorer"
        Write-Host "5. Scripts externos (Ativador e Chris Titus)"
        Write-Host "0. Voltar ao menu principal" -ForegroundColor Magenta

        $choice = Read-Host "`nEscolha uma opção"
        switch ($choice) {
            '1' {
                Show-ControlPanelTweaksMenu
                Show-AutoLoginMenu
                Show-ExplorerTweaksMenu
                Show-ExternalScriptsMenu
            }
            '2' { Show-ControlPanelTweaksMenu }
            '3' { Show-AutoLoginMenu }
            '4' { Show-ExplorerTweaksMenu }
            '5' { Show-ExternalScriptsMenu }
            '0' { return }
            default {
                Write-Host "Opção inválida!" -ForegroundColor Red
                Start-Sleep -Seconds 1
            }
        }
    } while ($true)
}

function Show-ExternalScriptsMenu {
    do {
        Clear-Host
        Write-Host "==== SCRIPTS EXTERNOS ====" -ForegroundColor Cyan
        Write-Host "1. Executar todos os scripts abaixo" -ForegroundColor Green
        Write-Host "2. Ativar Windows (get.activated.win)"
        Write-Host "3. Toolbox Chris Titus (christitus.com)"
		Write-Host "4. Executar Script Supremo" -ForegroundColor Yellow
        Write-Host "0. Voltar ao menu principal" -ForegroundColor Magenta

        $choice = Read-Host "`nEscolha uma opção"
        switch ($choice) {
            '1' {
                Run-WindowsActivator
                Run-ChrisTitusToolbox
            }
            '2' { Run-WindowsActivator }
            '3' { Run-ChrisTitusToolbox }
			'4' { Update-ScriptFromCloud }
            '0' { return }
            default {
                Write-Host "Opção inválida!" -ForegroundColor Red
                Start-Sleep -Seconds 1
            }
        }
    } while ($true)
}


function Show-NetworkMenu {
    do {
        Clear-Host
        Write-Host "==== MENU: REDE E IMPRESSORAS ====" -ForegroundColor Cyan
        Write-Host "1. Executar todas as tarefas abaixo" -ForegroundColor Green
        Write-Host "2. Adicionar rede Wi-Fi administrativa"
        Write-Host "3. Definir DNS Google/Cloudflare"
        Write-Host "4. Instalar impressoras de rede"
        Write-Host "5. Limpar cache ARP"
        Write-Host "6. Limpar cache DNS"
        Write-Host "7. Otimizar TCP/DNS"
        Write-Host "8. Testar velocidade de internet"
        Write-Host "0. Voltar ao menu principal" -ForegroundColor Magenta

        $choice = Read-Host "`nEscolha uma opção"
        switch ($choice) {
            '1' {
                Add-WiFiNetwork
                Set-DnsGoogleCloudflare
                Install-NetworkPrinters
                Clear-ARP
                Flush-DNS
                Optimize-NetworkPerformance
                Test-InternetSpeed
                Show-SuccessMessage
            }
            '2' { Add-WiFiNetwork; Show-SuccessMessage }
            '3' { Set-DnsGoogleCloudflare; Show-SuccessMessage }
            '4' { Install-NetworkPrinters; Show-SuccessMessage }
            '5' { Clear-ARP; Show-SuccessMessage }
            '6' { Flush-DNS; Show-SuccessMessage }
            '7' { Optimize-NetworkPerformance; Show-SuccessMessage }
            '8' { Test-InternetSpeed; Show-SuccessMessage }
            '0' { return }
            default { Write-Host "Opção inválida!" -ForegroundColor Red; Start-Sleep 1 }
        }
    } while ($true)
}


# === MENU: DIAGNÓSTICO E INFORMAÇÕES ===
function Show-DiagnosticsMenu {
    do {
        Clear-Host
        Write-Host "==== MENU: DIAGNÓSTICO E INFORMAÇÕES ====" -ForegroundColor Cyan
        Write-Host "1. Executar todos os diagnósticos abaixo" -ForegroundColor Green
        Write-Host "2. DISM /RestoreHealth"
        Write-Host "3. Exibir informações de rede"
        Write-Host "4. Exibir informações do sistema"
        Write-Host "5. Exibir uso do disco"
        Write-Host "6. SFC /scannow"
        Write-Host "7. Testar memória RAM"
        Write-Host "8. Verificar saúde dos discos (SMART)"
        Write-Host "0. Voltar ao menu principal" -ForegroundColor Magenta

        $choice = Read-Host "`nEscolha uma opção"
        switch ($choice) {
            '1' {
                Run-DISM-Scan
                Show-NetworkInfo
                Show-SystemInfo
                Show-DiskUsage
                Run-SFC-Scan
                Test-Memory
                Test-SMART-Drives
                Show-SuccessMessage
            }
            '2' { Run-DISM-Scan; Show-SuccessMessage }
            '3' { Show-NetworkInfo; Show-SuccessMessage }
            '4' { Show-SystemInfo; Show-SuccessMessage }
            '5' { Show-DiskUsage; Show-SuccessMessage }
            '6' { Run-SFC-Scan; Show-SuccessMessage }
            '7' { Test-Memory; Show-SuccessMessage }
            '8' { Test-SMART-Drives; Show-SuccessMessage }
            '0' { return }
            default { Write-Host "Opção inválida!" -ForegroundColor Red; Start-Sleep 1 }
        }
    } while ($true)
}

# === MENU: LIMPEZA E OTIMIZAÇÃO ===
function Show-CleanupMenu {
    do {
        Clear-Host
        Write-Host "==== MENU: LIMPEZA E OTIMIZAÇÃO ====" -ForegroundColor Cyan
        Write-Host "1. Executar todas as tarefas abaixo" -ForegroundColor Green
        Write-Host "2. Agendar chkdsk /f /r"
        Write-Host "3. Limpar cache DNS"
        Write-Host "4. Limpar cache do Windows Update"
        Write-Host "5. Limpar arquivos temporários"
        Write-Host "6. Limpar Prefetch"
        Write-Host "7. Limpar spooler de impressão"
        Write-Host "8. Limpeza profunda (cache, logs, drivers)"
        Write-Host "9. Otimizar volumes"
        Write-Host "10. Remover Windows.old"
        Write-Host "11. Remover pasta WinSxS"
        Write-Host "0. Voltar ao menu principal" -ForegroundColor Magenta

        $choice = Read-Host "`nEscolha uma opção"
        switch ($choice) {
            '1' { Run-All-CleanupAdvanced }
            '2' { Schedule-ChkDsk; Show-SuccessMessage }
            '3' { Flush-DNS; Show-SuccessMessage }
            '4' { Clear-WUCache; Show-SuccessMessage }
            '5' { Clean-TemporaryFiles; Show-SuccessMessage }
            '6' { Clean-Prefetch; Show-SuccessMessage }
            '7' { Clean-PrintSpooler; Show-SuccessMessage }
            '8' { Deep-SystemCleanup; Show-SuccessMessage }
            '9' { Optimize-Volumes; Show-SuccessMessage }
            '10' { Remove-WindowsOld; Show-SuccessMessage }
            '11' { Clean-WinSxS; Show-SuccessMessage }
            '0' { return }
            default { Write-Host "Opção inválida!" -ForegroundColor Red; Start-Sleep 1 }
        }
    } while ($true)
}

# === MENU: BLOATWARE, PRIVACIDADE E HARDENING ===
function Show-BloatwareMenu {
    do {
        Clear-Host
        Write-Host "==== MENU: BLOATWARE, PRIVACIDADE, EXTRAS ====" -ForegroundColor Cyan
        Write-Host "1. Executar todas as tarefas abaixo" -ForegroundColor Green
        Write-Host "2. Aplicar privacidade agressiva"
        Write-Host "3. Aplicar tweaks extras"
        Write-Host "4. Ajustar visual para performance"
        Write-Host "5. Backup do registro"
        Write-Host "6. Desabilitar IPv6"
        Write-Host "7. Desabilitar UAC"
        Write-Host "8. Desativar Cortana, Search, Telemetria"
        Write-Host "9. Desativar notificações (Action Center)"
        Write-Host "10. Desativar tarefas agendadas de bloatware"
        Write-Host "11. Encerrar processos dispensáveis"
        Write-Host "12. Executar debloaters de terceiros"
        Write-Host "13. Otimizar rede (TCP/DNS)"
        Write-Host "14. Remover bloatware (versão segura e consolidada)"
        Write-Host "15. Remover OneDrive e restaurar pastas"
        Write-Host "16. Remover pins do Menu Iniciar/Barra de Tarefas"
        Write-Host "17. Remover tarefas agendadas (agressivo)"
        Write-Host "0. Voltar ao menu principal" -ForegroundColor Magenta

        $choice = Read-Host "`nEscolha uma opção"
        switch ($choice) {
            '1' {
                Enable-PrivacyHardening
                Apply-ExtraTweaks
                Set-VisualPerformance
                Backup-Registry
                Disable-IPv6
                Disable-UAC
                Disable-Cortana-AndSearch
                Disable-ActionCenter-Notifications
                Disable-BloatwareScheduledTasks
                Stop-BloatwareProcesses
                Run-ExternalDebloaters
                Optimize-NetworkPerformance
                Remove-BloatwareSafe
                Remove-OneDrive-AndRestoreFolders
                Remove-StartAndTaskbarPins
                Remove-ScheduledTasksAggressive
                Show-SuccessMessage
            }
            '2'  { Enable-PrivacyHardening; Show-SuccessMessage }
            '3'  { Apply-ExtraTweaks; Show-SuccessMessage }
            '4'  { Set-VisualPerformance; Show-SuccessMessage }
            '5'  { Backup-Registry; Show-SuccessMessage }
            '6'  { Disable-IPv6; Show-SuccessMessage }
            '7'  { Disable-UAC; Show-SuccessMessage }
            '8'  { Disable-Cortana-AndSearch; Show-SuccessMessage }
            '9'  { Disable-ActionCenter-Notifications; Show-SuccessMessage }
            '10' { Disable-BloatwareScheduledTasks; Show-SuccessMessage }
            '11' { Stop-BloatwareProcesses; Show-SuccessMessage }
            '12' { Run-ExternalDebloaters; Show-SuccessMessage }
            '13' { Optimize-NetworkPerformance; Show-SuccessMessage }
            '14' { Remove-BloatwareSafe }
            '15' { Remove-OneDrive-AndRestoreFolders; Show-SuccessMessage }
            '16' { Remove-StartAndTaskbarPins; Show-SuccessMessage }
            '17' { Remove-ScheduledTasksAggressive; Show-SuccessMessage }
            '0'  { return }
            default { Write-Host "Opção inválida!" -ForegroundColor Red; Start-Sleep 1 }
        }
    } while ($true)
}

# === MENU: RESTAURAÇÃO E SEGURANÇA (UNDO) ===
function Show-RestoreUndoMenu {
    do {
        Clear-Host
        Write-Host "==== MENU: REVERTER AJUSTES / RESTAURAR APLICATIVOS ====" -ForegroundColor Magenta
        Write-Host "1. Executar todas as tarefas abaixo" -ForegroundColor Green
        Write-Host "2. Bloquear macros Office (segurança)"
        Write-Host "3. Desabilitar SMBv1 (RECOMENDADO)"
        Write-Host "4. Desfazer privacidade agressiva"
        Write-Host "5. Habilitar SMBv1 (NÃO RECOMENDADO)"
        Write-Host "6. Reabilitar Action Center/Notificações"
        Write-Host "7. Reabilitar IPv6"
        Write-Host "8. Restaurar backup do registro"
        Write-Host "9. Restaurar backup do registro (alternativo)"
        Write-Host "10. Restaurar configurações do Painel de Controle"
        Write-Host "11. Restaurar macros Office (padrão)"
        Write-Host "12. Restaurar menu de contexto clássico"
        Write-Host "13. Restaurar UAC para padrão"
        Write-Host "14. Restaurar visual padrão"
        Write-Host "15. Reinstalar aplicativos essenciais (Calculadora, Notepad, Ferramenta de Captura etc)"
        Write-Host "16. Reinstalar o OneDrive"
        Write-Host "0. Voltar ao menu principal" -ForegroundColor Magenta

        $choice = Read-Host "`nEscolha uma opção"
        switch ($choice) {
            '1' {
                Harden-OfficeMacros
                Disable-SMBv1
                Undo-PrivacyHardening
                Enable-SMBv1
                ReEnable-ActionCenter-Notifications
                Restore-DefaultIPv6
                Restore-Registry-FromBackup
                Restore-Registry
                Restore-ControlPanelTweaks
                Restore-OfficeMacros
                Enable-ClassicContextMenu
                Restore-DefaultUAC
                Restore-VisualPerformanceDefault
                Restore-BloatwareSafe
                Restore-OneDrive
                Show-SuccessMessage
            }
            '2'  { Harden-OfficeMacros; Show-SuccessMessage }
            '3'  { Disable-SMBv1; Show-SuccessMessage }
            '4'  { Undo-PrivacyHardening; Show-SuccessMessage }
            '5'  { Enable-SMBv1; Show-SuccessMessage }
            '6'  { ReEnable-ActionCenter-Notifications; Show-SuccessMessage }
            '7'  { Restore-DefaultIPv6; Show-SuccessMessage }
            '8'  { Restore-Registry-FromBackup; Show-SuccessMessage }
            '9'  { Restore-Registry; Show-SuccessMessage }
            '10' { Restore-ControlPanelTweaks; Show-SuccessMessage }
            '11' { Restore-OfficeMacros; Show-SuccessMessage }
            '12' { Enable-ClassicContextMenu; Show-SuccessMessage }
            '13' { Restore-DefaultUAC; Show-SuccessMessage }
            '14' { Restore-VisualPerformanceDefault; Show-SuccessMessage }
            '15' { Restore-BloatwareSafe; Show-SuccessMessage }
            '16' { Restore-OneDrive; Show-SuccessMessage }
            '0'  { return }
            default { Write-Host "Opção inválida!" -ForegroundColor Red; Start-Sleep 1 }
        }
    } while ($true)
}

# === MENU PRINCIPAL ===
function Show-MainMenu {
    do {
        Clear-Host
        Write-Host "=============================================" -ForegroundColor Cyan
        Write-Host " SCRIPT DE MANUTENÇÃO WINDOWS - MENU PRINCIPAL" -ForegroundColor Cyan
        Write-Host "=============================================" -ForegroundColor Cyan
        Write-Host " 1. Configurações Avançadas" -ForegroundColor Yellow
        Write-Host " 2. Instalação e Ferramentas" -ForegroundColor Yellow
        Write-Host " 3. Privacidade e Segurança" -ForegroundColor Yellow
        Write-Host " 4. Rede e Outros" -ForegroundColor Yellow
        Write-Host " 5. Sistema e Desempenho" -ForegroundColor Yellow
        Write-Host " 6. Reiniciar PC" -ForegroundColor Yellow
        Write-Host " 0. Sair" -ForegroundColor Red
        Write-Host "=============================================" -ForegroundColor Cyan

        $choice = Read-Host "`nSelecione uma opção"
        switch ($choice) {
            '1' { Show-AdvancedSettingsMenu }
            '2' { Show-InstallationMenu }
            '3' { Show-PrivacySecurityMenu }
            '4' { Show-NetworkMenu }
            '5' { Show-SystemPerformanceMenu }
            '6' { Write-Log "Reiniciando o computador..." Cyan; Restart-Computer -Force }
            '0' {
                $duration = (Get-Date) - $startTime
                Write-Log "Script concluído. Tempo total: $($duration.ToString('hh\:mm\:ss'))" Cyan
                Write-Log "Log salvo em: $logFile" Cyan
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

# ==== EXECUÇÃO COM SEGURANÇA ====
try {
    Show-MainMenu
}
catch {
    Write-Log "❌ Erro fatal: $_" Red
    Write-Log "Consulte o log em: $logFile" Yellow
}
finally {
    Show-SuccessMessage
}
