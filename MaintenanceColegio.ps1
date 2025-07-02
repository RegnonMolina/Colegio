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
        Write-Host " BLOATWARE E ATUALIZAÇÕES" -ForegroundColor Cyan
        Write-Host "=============================================" -ForegroundColor Cyan
        Write-Host " 1. Remover bloatware padrão" -ForegroundColor Yellow
        Write-Host " 2. Remover aplicativos adicionais" -ForegroundColor Yellow
        Write-Host " 3. Desativar tarefas agendadas de bloatware/telemetria" -ForegroundColor Yellow
        Write-Host " 4. Encerrar processos dispensáveis em segundo plano" -ForegroundColor Yellow
        Write-Host " 5. Verificar e instalar atualizações" -ForegroundColor Yellow
        Write-Host " 0. Voltar ao menu principal" -ForegroundColor Red
        Write-Host "=============================================" -ForegroundColor Cyan
        
        $choice = Read-Host "`nSelecione uma opção"
        switch ($choice) {
            '1' { Remove-Bloatware; Pause-Script }
            '2' { Remove-AdditionalBloatware; Pause-Script }
            '3' { Disable-BloatwareScheduledTasks; Pause-Script }
            '4' { Stop-BloatwareProcesses; Pause-Script }
            '5' { Update-WindowsAndDrivers; Pause-Script }
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
            '2' { Install-Printers; Pause-Script }
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
        Write-Host " 1. Limpeza e Otimização" -ForegroundColor Yellow
        Write-Host " 2. Bloatware e Atualizações" -ForegroundColor Yellow
        Write-Host " 3. Instalação de Programas" -ForegroundColor Yellow
        Write-Host " 4. Rede e Impressoras" -ForegroundColor Yellow
        Write-Host " 5. Diagnóstico e Informações" -ForegroundColor Yellow
        Write-Host " 6. Abrir pasta de logs" -ForegroundColor Magenta
        Write-Host " 0. Sair" -ForegroundColor Red
        Write-Host "=============================================" -ForegroundColor Cyan
        
        $choice = Read-Host "`nSelecione uma opção"
        switch ($choice) {
            '1' { Show-CleanupMenu }
            '2' { Show-BloatwareMenu }
            '3' { Show-InstallationMenu }
            '4' { Show-NetworkMenu }
            '5' { Show-DiagnosticsMenu }
            '6' { 
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
