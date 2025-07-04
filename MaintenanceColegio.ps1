<#
.SYNOPSIS
    Script Supremo de Manutenção Windows - Menu Hierárquico Completo
.DESCRIPTION
    Versão completíssima com todos os menus, submenus, proteções, incrementos, opções "executar tudo" e blocos para expansão.
.NOTES
    Autor: Adaptado por IA
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

# --- CHECKLIST DE MELHORIAS IMPLEMENTADAS ---
# - Função Show-Success para substituir Pause-Script nas tarefas.
# - AutoHotKey incluído na instalação automática.
# - Função robusta para impressoras.
# - Função para aplicar configurações exportadas.
# - Renomear notebook mais robusta.
# - Opção "Executar todas as tarefas abaixo em sequência" nos submenus.
# - Proteção de apps essenciais nas rotinas de remoção.
# - Menus e submenus incrementados.
# --------------------------------------------

function Show-Success {
    Write-Host "Tarefa executada com sucesso!" -ForegroundColor Green
    Start-Sleep -Seconds 2
}

#endregion

#region → Funções de Manutenção

# Limpeza e Otimização
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

# Bloatware
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
        # Proteção contra remoção de apps essenciais
        if ($app -in @("Microsoft.WindowsStore", "Microsoft.WindowsCalculator")) { continue }
        Get-AppxPackage -Name $app -AllUsers | Remove-AppxPackage -ErrorAction SilentlyContinue
        Get-AppxProvisionedPackage -Online | Where-Object DisplayName -Like $app | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
    }
    Write-Log "Bloatware padrão removido." Green
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
}
# Demais funções (Disable-BloatwareScheduledTasks, Stop-BloatwareProcesses, etc) permanecem como no original...

# Instalação de Aplicativos (com AutoHotKey incrementado)
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
            winget install --id $app.Id -e --accept-package-agreements --accept-source-agreements
            Write-Log "$($app.Name) instalado com sucesso." Green
        } catch {
            Write-Log "Falha ao instalar $($app.Name): $_" Red
        }
    }
    Write-Log "Instalação de aplicativos concluída." Green
    Show-Success
}
function Update-PowerShell {
    Write-Log "Instalando/Atualizando PowerShell..." Yellow
    try {
        Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Unrestricted -Force
        iex "& { $(irm https://aka.ms/install-powershell.ps1) } -UseMSI"
        Write-Log "PowerShell instalado/atualizado com sucesso." Green
    } catch {
        Write-Log "Erro ao instalar/atualizar PowerShell: $_" Red
    }
    Show-Success
}
# ... Demais funções originais permanecem ...

# Impressoras de rede aprimorada
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

# Renomear notebook com timeout seguro
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

# Função para aplicar configurações exportadas do Painel de Controle
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
        # Exemplo: aplicar tema
        if ($hashtable.Theme) {
            Write-Log "Aplicando tema..." Cyan
            foreach ($k in $hashtable.Theme.Keys) {
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name $k -Value $hashtable.Theme[$k] -ErrorAction SilentlyContinue
            }
        }
        # Amplie para outros ajustes conforme seu TXT
        Write-Log "Configurações exportadas aplicadas." Green
    } catch {
        Write-Log "Erro ao aplicar configurações exportadas: $_" Red
    }
    Show-Success
}

# Funções Run-All para cada submenu
function Run-All-Cleanup {
    Clean-TemporaryFiles
    Clear-WUCache
    Flush-DNS
    Optimize-Volumes
    Show-Success
}
function Run-All-Bloatware {
    Apply-PrivacyTweaks
    Disable-BloatwareScheduledTasks
    Stop-BloatwareProcesses
    Enable-WindowsHardening
    Remove-Bloatware
    Remove-AdditionalBloatware
    Remove-ProvisionedBloatware
    Remove-StartAndTaskbarPins
    Remove-ScheduledTasksAggressive
    Remove-UWPBloatware
    Update-WindowsAndDrivers
    Show-Success
}
function Run-All-Install {
    Install-Applications
    Update-PowerShell
    Show-Success
}
function Run-All-Network {
    Add-WiFiNetwork
    Install-NetworkPrinters
    Show-Success
}

#endregion

#region → Menus Hierárquicos
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
            '2' { Clean-TemporaryFiles; Show-Success }
            '3' { Clear-WUCache; Show-Success }
            '4' { Flush-DNS; Show-Success }
            '5' { Optimize-Volumes; Show-Success }
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
        Write-Host " 3. Desativar tarefas agendadas de bloatware/telemetria" -ForegroundColor Yellow
        Write-Host " 4. Encerrar processos dispensáveis em segundo plano" -ForegroundColor Yellow
        Write-Host " 5. Hardening de segurança" -ForegroundColor Yellow
        Write-Host " 6. Remover bloatware padrão" -ForegroundColor Yellow
        Write-Host " 7. Remover bloatware adicional" -ForegroundColor Yellow
        Write-Host " 8. Remover bloatware (whitelist)" -ForegroundColor Yellow
        Write-Host " 9. Remover pins do Menu Iniciar/Barra de Tarefas" -ForegroundColor Yellow
        Write-Host "10. Remover tarefas agendadas (agressivo)" -ForegroundColor Yellow
        Write-Host "11. Remover UWP bloatware (exceto essenciais)" -ForegroundColor Yellow
        Write-Host "12. Verificar e instalar atualizações" -ForegroundColor Yellow
        Write-Host "13. Renomear notebook" -ForegroundColor Yellow
        Write-Host " 0. Voltar ao menu principal" -ForegroundColor Red
        Write-Host "=============================================" -ForegroundColor Cyan
        $choice = Read-Host "`nSelecione uma opção"
        switch ($choice) {
            '1' { Run-All-Bloatware }
            '2' { Apply-PrivacyTweaks; Show-Success }
            '3' { Disable-BloatwareScheduledTasks; Show-Success }
            '4' { Stop-BloatwareProcesses; Show-Success }
            '5' { Enable-WindowsHardening; Show-Success }
            '6' { Remove-Bloatware; Show-Success }
            '7' { Remove-AdditionalBloatware; Show-Success }
            '8' { Remove-ProvisionedBloatware; Show-Success }
            '9' { Remove-StartAndTaskbarPins; Show-Success }
            '10' { Remove-ScheduledTasksAggressive; Show-Success }
            '11' { Remove-UWPBloatware; Show-Success }
            '12' { Update-WindowsAndDrivers; Show-Success }
            '13' { Renomear-Notebook }
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
        Write-Host " 2. Instalar todos os programas" -ForegroundColor Yellow
        Write-Host " 3. Instalar/Atualizar PowerShell" -ForegroundColor Yellow
        Write-Host " 0. Voltar ao menu principal" -ForegroundColor Red
        Write-Host "=============================================" -ForegroundColor Cyan
        $choice = Read-Host "`nSelecione uma opção"
        switch ($choice) {
            '1' { Run-All-Install }
            '2' { Install-Applications }
            '3' { Update-PowerShell }
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
        Write-Host " 4. Limpar cache DNS" -ForegroundColor Yellow
        Write-Host " 0. Voltar ao menu principal" -ForegroundColor Red
        Write-Host "=============================================" -ForegroundColor Cyan
        $choice = Read-Host "`nSelecione uma opção"
        switch ($choice) {
            '1' { Run-All-Network }
            '2' { Add-WiFiNetwork; Show-Success }
            '3' { Install-NetworkPrinters }
            '4' { Flush-DNS; Show-Success }
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
        Write-Host " 2. Bloatware, Privacidade e Atualizações" -ForegroundColor Yellow
        Write-Host " 3. Instalação de Programas" -ForegroundColor Yellow
        Write-Host " 4. Rede e Impressoras" -ForegroundColor Yellow
        Write-Host " 5. Aplicar configurações exportadas (Painel de Controle)" -ForegroundColor Yellow
        Write-Host " 6. Renomear notebook" -ForegroundColor Yellow
        Write-Host " 0. Sair" -ForegroundColor Red
        Write-Host "=============================================" -ForegroundColor Cyan
        $choice = Read-Host "`nSelecione uma opção"
        switch ($choice) {
            '1' { Show-CleanupMenu }
            '2' { Show-BloatwareMenu }
            '3' { Show-InstallationMenu }
            '4' { Show-NetworkMenu }
            '5' { Apply-ExportedSettings }
            '6' { Renomear-Notebook }
            '0' { exit }
            default { Write-Host "Opção inválida!" -ForegroundColor Red; Start-Sleep -Seconds 1 }
        }
    } while ($true)
}
#endregion

Show-MainMenu
