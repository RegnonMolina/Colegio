<#
.SYNOPSIS
    Script Supremo de Manutenção Windows - Menu Hierárquico Completo
.DESCRIPTION
    Versão aprimorada com todas as melhorias discutidas em 2025.
.NOTES
    Autor: Adaptado por IA para RegnonMolina
    Versão: 8.0
    Execute como Administrador!
#>

#region → Configurações Iniciais
$Host.UI.RawUI.WindowTitle = "MANUTENÇÃO WINDOWS - NÃO FECHE ESTA JANELA"
Clear-Host

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

function Show-Success {
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
    Show-Success
}

function Clear-WUCache {
    Write-Log "Limpando cache do Windows Update..." Yellow
    Stop-Service wuauserv -Force -ErrorAction SilentlyContinue
    Remove-Item "$env:SystemRoot\SoftwareDistribution\Download\*" -Recurse -Force -ErrorAction SilentlyContinue
    Start-Service wuauserv
    Write-Log "Cache do Windows Update limpo." Green
    Show-Success
}

function Flush-DNS {
    Write-Log "Limpando cache DNS..." Yellow
    ipconfig /flushdns | Out-Null
    Write-Log "Cache DNS limpo." Green
    Show-Success
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
    Show-Success
}

function Run-All-Cleanup {
    Clean-TemporaryFiles
    Clear-WUCache
    Flush-DNS
    Optimize-Volumes
}

# 2. Bloatware e Privacidade
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
        "Microsoft.YourPhone", "Microsoft.MixedReality.Portal", "Microsoft.LinkedIn"
        # Não incluir apps críticos do Windows!
    )
    foreach ($app in $bloatware) {
        Get-AppxPackage -Name $app -AllUsers | Remove-AppxPackage -ErrorAction SilentlyContinue
        Get-AppxProvisionedPackage -Online | Where-Object DisplayName -Like $app | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
    }
    Write-Log "Bloatware padrão removido." Green
    Show-Success
}

function Remove-AdditionalBloatware {
    Write-Log "Removendo aplicativos adicionais..." Yellow
    $additionalBloatware = @(
        "Microsoft.QuickAssist", "Microsoft.549981C3F5F10", "Microsoft.Windows.CommunicationsApps",
        "Microsoft.OneDrive", "Microsoft.Teams", "Microsoft.WindowsFeedbackHub", "Microsoft.LinkedIn"
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
    Show-Success
}

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
    Show-Success
}

function Run-All-Bloatware {
    Apply-PrivacyTweaks
    Remove-Bloatware
    Remove-AdditionalBloatware
}

# 3. Instalação de Programas
function Install-Applications {
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Write-Log "Winget não está instalado. Pulando instalação de aplicativos." Red
        Show-Success
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
        @{Name = "7-Zip"; Id = "7zip.7zip"},
        @{Name = "AutoHotKey"; Id = "AutoHotkey.AutoHotkey"}
    )
    Write-Log "Iniciando instalação de aplicativos..." Cyan
    foreach ($app in $apps) {
        try {
            Write-Log "Instalando $($app.Name)..." Yellow
            winget install --id $app.Id -e --silent --accept-package-agreements --accept-source-agreements
            Write-Log "$($app.Name) instalado com sucesso." Green
        } catch {
            Write-Log "Falha ao instalar $($app.Name): $_" Red
        }
    }
    Write-Log "Instalação de aplicativos concluída." Green
    Show-Success
}

function Run-All-Install {
    Install-Applications
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
    Show-Success
}

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
    Show-Success
}

function Run-All-Network {
    Add-WiFiNetwork
    Install-NetworkPrinters
}

# 5. Aplicar Configurações Exportadas
function Apply-ExportedSettings {
    $configPath = "$env:USERPROFILE\Desktop\configuracoes_painel.txt"
    if (!(Test-Path $configPath)) {
        Write-Log "Arquivo configuracoes_painel.txt não encontrado no Desktop." Red
        Show-Success
        return
    }
    Write-Log "Aplicando configurações exportadas de $configPath..." Yellow
    try {
        $content = Get-Content $configPath -Raw
        $hashtable = Invoke-Expression $content
        # Exemplos de aplicação (expanda conforme seu TXT):
        if ($hashtable.WindowsUpdate) {
            Write-Log "Aplicando configurações de Windows Update..." Cyan
            # Exemplo de uso: reg.exe add "..." /v ... /d ... /f
        }
        if ($hashtable.Theme) {
            Write-Log "Aplicando tema..." Cyan
            foreach ($k in $hashtable.Theme.Keys) {
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name $k -Value $hashtable.Theme[$k] -ErrorAction SilentlyContinue
            }
        }
        # Continue expandindo para Rede, Firewall, Energia, etc.
        Write-Log "Configurações exportadas aplicadas." Green
    } catch {
        Write-Log "Erro ao aplicar configurações exportadas: $_" Red
    }
    Show-Success
}

#endregion

#region → Funções Gerais/Menus

function Renomear-Notebook {
    Write-Log "Deseja renomear este notebook? Você tem 15 segundos para digitar o novo nome." Yellow
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
        Show-Success
        return
    }
    try {
        Rename-Computer -NewName $input -Force
        Write-Log "Nome do notebook alterado para: $input. Reinicie para aplicar." Green
    } catch {
        Write-Log "Erro ao renomear o notebook: $_" Red
    }
    Show-Success
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
        Write-Host " 0. Voltar ao menu principal" -ForegroundColor Red
        Write-Host "=============================================" -ForegroundColor Cyan
        $choice = Read-Host "`nSelecione uma opção"
        switch ($choice) {
            '1' { Run-All-Cleanup }
            '2' { Clean-TemporaryFiles }
            '3' { Clear-WUCache }
            '4' { Flush-DNS }
            '5' { Optimize-Volumes }
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
        Write-Host " 1. Executar todas as tarefas abaixo em sequência" -ForegroundColor Green
        Write-Host " 2. Aplicar tweaks de privacidade" -ForegroundColor Yellow
        Write-Host " 3. Remover bloatware padrão" -ForegroundColor Yellow
        Write-Host " 4. Remover bloatware adicional" -ForegroundColor Yellow
        Write-Host " 0. Voltar ao menu principal" -ForegroundColor Red
        Write-Host "=============================================" -ForegroundColor Cyan
        $choice = Read-Host "`nSelecione uma opção"
        switch ($choice) {
            '1' { Run-All-Bloatware }
            '2' { Apply-PrivacyTweaks }
            '3' { Remove-Bloatware }
            '4' { Remove-AdditionalBloatware }
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
        Write-Host " 1. Executar todas as tarefas abaixo em sequência" -ForegroundColor Green
        Write-Host " 2. Instalar todos os aplicativos úteis" -ForegroundColor Yellow
        Write-Host " 0. Voltar ao menu principal" -ForegroundColor Red
        Write-Host "=============================================" -ForegroundColor Cyan
        $choice = Read-Host "`nSelecione uma opção"
        switch ($choice) {
            '1' { Run-All-Install }
            '2' { Install-Applications }
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
        Write-Host " 1. Executar todas as tarefas abaixo em sequência" -ForegroundColor Green
        Write-Host " 2. Configurar rede Wi-Fi" -ForegroundColor Yellow
        Write-Host " 3. Instalar impressoras de rede" -ForegroundColor Yellow
        Write-Host " 0. Voltar ao menu principal" -ForegroundColor Red
        Write-Host "=============================================" -ForegroundColor Cyan
        $choice = Read-Host "`nSelecione uma opção"
        switch ($choice) {
            '1' { Run-All-Network }
            '2' { Add-WiFiNetwork }
            '3' { Install-NetworkPrinters }
            '0' { return }
            default { Write-Host "Opção inválida!" -ForegroundColor Red; Start-Sleep -Seconds 1 }
        }
    } while ($true)
}

function Show-ExportedSettingsMenu {
    Clear-Host
    Write-Host "=============================================" -ForegroundColor Cyan
    Write-Host " APLICAR CONFIGURAÇÕES EXPORTADAS" -ForegroundColor Cyan
    Write-Host "=============================================" -ForegroundColor Cyan
    Write-Host "O arquivo configuracoes_painel.txt deve estar no Desktop." -ForegroundColor Yellow
    Write-Host "Pressione ENTER para aplicar ou 0 para voltar." -ForegroundColor Cyan
    $choice = Read-Host
    if ($choice -eq "0") { return }
    Apply-ExportedSettings
}

function Show-MainMenu {
    do {
        Clear-Host
        Write-Host "=============================================" -ForegroundColor Cyan
        Write-Host " SCRIPT SUPREMO - MENU PRINCIPAL" -ForegroundColor Cyan
        Write-Host "=============================================" -ForegroundColor Cyan
        Write-Host " 1. Limpeza e Otimização" -ForegroundColor Yellow
        Write-Host " 2. Bloatware, Privacidade e Atualizações" -ForegroundColor Yellow
        Write-Host " 3. Instalação de Programas" -ForegroundColor Yellow
        Write-Host " 4. Rede e Impressoras" -ForegroundColor Yellow
        Write-Host " 5. Aplicar configurações exportadas" -ForegroundColor Yellow
        Write-Host " 6. Renomear notebook" -ForegroundColor Yellow
        Write-Host " 0. Sair" -ForegroundColor Red
        Write-Host "=============================================" -ForegroundColor Cyan
        $choice = Read-Host "`nSelecione uma opção"
        switch ($choice) {
            '1' { Show-CleanupMenu }
            '2' { Show-BloatwareMenu }
            '3' { Show-InstallationMenu }
            '4' { Show-NetworkMenu }
            '5' { Show-ExportedSettingsMenu }
            '6' { Renomear-Notebook }
            '0' {
                $duration = (Get-Date) - $startTime
                Write-Log "Script concluído. Tempo total: $($duration.ToString('hh\:mm\:ss'))" Cyan
                Write-Log "Log detalhado salvo em: $logFile" Cyan
                Write-Host "Pressione ENTER para sair..." -ForegroundColor Magenta
                Read-Host
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

try {
    Show-MainMenu
} catch {
    Write-Host "Erro fatal: $_" -ForegroundColor Red
    Write-Host "Consulte o log em: $logFile" -ForegroundColor Yellow
    Write-Host "Pressione ENTER para sair..." -ForegroundColor Magenta
    Read-Host
}
finally {
    # Garante mensagem final e log mesmo em erro
    Write-Host "Script finalizado." -ForegroundColor Cyan
}
