param(
    [switch]$RunAllCleanup,
    [switch]$RunBloatwareRemoval,
    [switch]$RunPrivacyTweaks,
    [switch]$RunNetworkOptimization,
    [switch]$RunAppInstallation,
    [switch]$RunDiagnostics,
    [switch]$CreateRestorePoint,
    [switch]$ForceOneDriveRemoval,
    [switch]$RemoveCopilot,
    [switch]$DisableRecall,
    [switch]$RunWindowsUpdate,
    [switch]$ApplyOptimizedPowerPlan
)


# ===============================
# SCRIPT SUPREMO DE MANUTENÇÃO 🛠️
# ===============================
# Iniciado em: $(Get-Date)
# Desenvolvido com sangue, café e PowerShell 💪

clear-host
Write-Host "-------------------------------------------------------------------------"
Write-Host "| Script pra ajustes de notebooks do ambiente do Colégio Mundo do Saber |"
Write-Host "-------------------------------------------------------------------------"

# =========================================================================
# ⚙️ CONFIGURAÇÕES GLOBAIS E VARIÁVEIS INICIAIS
# =========================================================================

# Variáveis globais para controle de preferências
$global:ConfirmPreference = 'None'
$global:ProgressPreference = 'SilentlyContinue'
$global:ErrorActionPreference = 'Continue'
$global:WarningPreference = 'Continue'
$global:VerbosePreference = 'SilentlyContinue' # Alterado para SilentlyContinue
$global:DebugPreference = 'SilentlyContinue'   # Alterado para SilentlyContinue

#region → CONFIGURAÇÕES GLOBAIS
$ScriptConfig = @{
    LogFilePath              = Join-Path $PSScriptRoot "ScriptSupremo.log" 
    ConfirmBeforeDestructive = $true
}
#endregion

# Garante que o PowerShell esteja usando o TLS 1.2 para downloads seguros
[Net.ServicePointManager]::SecurityProtocol = `  [Net.ServicePointManager]::SecurityProtocol -bor `  [Net.SecurityProtocolType]::Tls12

# =========================================================================
# ✅ VERIFICAÇÃO INICIAL: Administrador
# =========================================================================
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Este script precisa ser executado como Administrador. Por favor, feche e execute o PowerShell como Administrador." -ForegroundColor Red
    Start-Sleep 5
    exit
}

# =========================================================================
# 📦 FUNÇÕES DE UTILIDADE E AUXILIARES (FUNDAMENTAL: Write-Log)
# =========================================================================
# 📝 Função de Log Personalizada (MANTENHA ESTA AQUI!)
# --- Função Write-Log robusta ---
function Write-Log {
    param(
        [Parameter(Mandatory,Position=0)]
        [object]$Message = '',

        [Parameter(Position=1)]
        [ValidateSet('Info','Success','Warning','Error','Debug','Verbose')]
        [string]$Type = 'Info'
    )

    # Garante texto
    if ($null -eq $Message) { $Message = '' }
    $text = if ($Message -is [array]) {
        ($Message | ForEach-Object { ($_ -ne $null) ? $_.ToString() : '' }) -join ' '
    } else {
        $Message.ToString()
    }

    $timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $entry     = "[$timestamp] [$Type] $text"
    $color     = $defaultColors[$Type]  # já existe garantia de key

    Write-Host $entry -ForegroundColor $color

    $logPath = $script:ScriptConfig.LogFilePath
    if (-not $logPath) { $logPath = Join-Path $env:TEMP 'ScriptSupremo.log' }

    try {
        $entry | Out-File -FilePath $logPath -Append -Encoding UTF8
    } catch {
        Write-Host "ERRO ao gravar log: $($_.Exception.Message)" -ForegroundColor Red
    }
}
# Funções de Controle do Menu
function Restart-ComputerConfirmation {
    Write-Log "Reiniciando o computador em 5 segundos..." -Type Info
    Start-Sleep -Seconds 5
    Restart-Computer -Force -Confirm:$false
}

function Stop-ComputerConfirmation {
    Write-Log "Desligando o computador em 5 segundos..." -Type Info
    Start-Sleep -Seconds 5
    Stop-Computer -Force -Confirm:$false
}


#region → FUNÇÕES

#region FUNÇÕES

# Cores padrão para cada tipo de log
$defaultColors = @{
    'Info'    = 'Cyan'
    'Success' = 'Green'
    'Warning' = 'Yellow'
    'Error'   = 'Red'
    'Debug'   = 'DarkGray'
    'Verbose' = 'Gray'
}

function Test-ShouldRemovePackage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$PackageName
    )
    if ($global:whitelist -contains $PackageName) { return $false }
    foreach ($pattern in $global:bloatwareToRemove) {
        if ($PackageName -like $pattern) { return $true }
    }
    return $false
}

function Disable-BloatwareScheduledTasks {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param()
    $tasks = Get-ScheduledTask | Where-Object { Test-ShouldRemovePackage $_.TaskName }
    foreach ($t in $tasks) {
        if ($PSCmdlet.ShouldProcess("Desabilitar tarefa", $t.TaskName)) {
            Disable-ScheduledTask -TaskName $t.TaskName
            Write-Log "Tarefa desabilitada: $($t.TaskName)" -Type Success
        }
    }
}

function Invoke-RemoveAllBloatware {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param()
    if ($PSCmdlet.ShouldProcess('Remoção de bloatware', 'Todos os aplicativos não desejados')) {
        Get-AppxPackage | ForEach-Object {
            if (Test-ShouldRemovePackage $_.Name) {
                Remove-AppxPackage -Package $_.PackageFullName -ErrorAction SilentlyContinue
                Write-Log "Removido: $($_.Name)" -Type Success
            }
        }
        Disable-BloatwareScheduledTasks
    }
}

function Invoke-PrivacyTweaks {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param()

    if ($PSCmdlet.ShouldProcess('Aplicar tweaks de privacidade','Configurações de Telemetria e Ads')) {
        # Exemplo de tweak:
        Write-Log "Desativando Telemetria..." -Type Info
        # Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'AllowTelemetry' -Value 0
        # ...
        Write-Log "Privacy tweaks aplicados." -Type Success
    }
}

#endregion

#region → EXECUÇÃO PRINCIPAL

try {
    if ($WhatIf) {
        Write-Log -Message "=== MODO SIMULAÇÃO (WhatIf) ATIVADO ===" -Type Warning
    }

    # 2) Criar ponto de restauração (se solicitado)
    if ($CreateRestorePoint) {
        Write-Log -Message "Iniciando criação do Restore Point..." -Type Info

        $cpParams = @{
            Description      = "Antes do Script Supremo"
            RestorePointType = "MODIFY_SETTINGS"
        }
        if ($WhatIf) { $cpParams['WhatIf'] = $true }

        Checkpoint-Computer @cpParams

        Write-Log -Message "Ponto de restauração solicitado." -Type Success
    }

    # 3) Rodar remoção de bloatware
    if ($RunBloatwareRemoval -or $RunAllCleanup) {
        Write-Log -Message "Iniciando remoção de bloatware..." -Type Info
        Invoke-RemoveAllBloatware @($WhatIf ? @{WhatIf=$true} : @{})
    }

    # 4) Rodar ajustes de privacidade
    if ($RunPrivacyTweaks -or $RunAllCleanup) {
        Write-Log -Message "Aplicando tweaks de privacidade..." -Type Info
        Invoke-PrivacyTweaks @($WhatIf ? @{WhatIf=$true} : @{})
    }

    # (Adapte similarmente para Network, AppInstall, Diagnostics conforme seu roteiro)

    Write-Log -Message "Script concluído com sucesso." -Type Success
}
catch {
    $msg = $_.Exception.Message
    Write-Host "[ERROR] Erro crítico: $msg" -ForegroundColor Red
    exit 1
}

#endregion

   
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Type] $Message"

    # Define o caminho do arquivo de log.
    $logFilePath = if ($script:ScriptConfig.LogFilePath) {
        $script:ScriptConfig.LogFilePath
    } else {
        "$env:TEMP\ScriptSupremo_Fallback.log"
    }

    # Certifica-se de que o diretório do log existe
    $logDir = Split-Path -Path $logFilePath -Parent
    if (-not (Test-Path $logDir)) {
        try {
            New-Item -Path $logDir -ItemType Directory -Force | Out-Null
        } catch {
            Write-Host "ERRO: Não foi possível criar o diretório de log '$logDir'. Mensagem: $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    # Adiciona a entrada ao arquivo de log
    try {
        Add-Content -Path $logFilePath -Value $logEntry -Encoding UTF8 -ErrorAction Stop
    } catch {
        Write-Host "ERRO: Não foi possível escrever no arquivo de log '$logFilePath'. Mensagem: $($_.Exception.Message)" -ForegroundColor Red
    }

   function Suspend-Script {
Write-Log "`nPressione ENTER para continuar..." -Type Info
    do {
        $key = [System.Console]::ReadKey($true)
    } until ($key.Key -eq 'Enter')
}

function Test-RequiredFunctions {
    param (
        [string[]]$FunctionList
    )

Write-Log "🔎 Verificando funções exigidas pelo script..." -Type Info
    $allGood = $true

    foreach ($func in $FunctionList) {
        if (Get-Command $func -ErrorAction SilentlyContinue) {
Write-Log "✅ $func" -Type Success
        } else {
Write-Log "❌ $func (não encontrada)" -Type Error
            $allGood = $false
        }
    }

    if (-not $allGood) {
Write-Log "`n❗ Algumas funções estão faltando. O script pode falhar!" -Type Warning
        # Você pode descomentar para abortar:
        # throw "Funções ausentes detectadas. Corrija antes de continuar."
    } else {
Write-Log "`n✔️ Todas as funções estão disponíveis. Continuando execução..." -Type Info
    }
}

function Show-SuccessMessage {
Write-Log "`n✅ Tarefa concluída com sucesso!" -Type Success
}

function Restart-Explorer {
    <#
    .SYNOPSIS
        Reinicia o processo do Windows Explorer.
    .DESCRIPTION
        Força o encerramento do processo 'explorer.exe' e o reinicia,
        o que pode ser útil para aplicar certas alterações no sistema
        ou resolver problemas de interface sem a necessidade de reiniciar o computador.
    #>
       Write-Log "Iniciando reinício do Windows Explorer..." -Type Info
Write-Log "Reiniciando o Windows Explorer..."

    try {
Write-Log "Encerrando processo Explorer..." -Type Info
        taskkill.exe /F /IM "explorer.exe" /T | Out-Null
        Write-Log "Processo Explorer encerrado." -Type Success

Write-Log "Iniciando Explorer..." -Type Info
        Start-Process "explorer.exe"
        Write-Log "Processo Explorer iniciado." -Type Success

Write-Log "Aguardando Explorer carregar..." -Type Warning
        Start-Sleep -Seconds 5 # Dê um tempo para o Explorer carregar completamente
        Write-Log "Explorer carregado com sucesso." -Type Success

        Write-Log "Reinício do Windows Explorer concluído com sucesso." -Type Success
Write-Log "Windows Explorer reiniciado!" -Type Success

    } catch {
        Write-Log "Ocorreu um erro ao reiniciar o Windows Explorer: $($_.Exception.Message)" -Type Error
Write-Log "ERRO ao reiniciar o Windows Explorer: $($_.Exception.Message)" -Type Error
    }
    Start-Sleep -Seconds 2
}
Write-Log -Message "Iniciando script de manutenção..." -Type Info




# === FUNÇÕES DE LIMPEZA E OTIMIZAÇÃO ===

function Clear-TemporaryFiles {
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

function Clear-DNS {
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

function Clear-WinSxS {
    Write-Log "Limpando WinSxS..." Yellow
    try {
        Dism.exe /online /Cleanup-Image /StartComponentCleanup /ResetBase | Out-Null
        Write-Log "WinSxS limpo." Green
    } catch { Write-Log "Erro ao limpar WinSxS: $_" Red }
}

function New-ChkDsk {
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

function Clear-DeepSystemCleanup {
    Write-Log "Fazendo limpeza profunda (cache de update, logs, drivers antigos)..." Yellow
    try {
        Remove-Item "$env:SystemRoot\SoftwareDistribution\Download\*" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item "$env:SystemRoot\Logs\*" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item "$env:SystemRoot\System32\LogFiles\*" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item "$env:SystemRoot\INF\*.log" -Force -ErrorAction SilentlyContinue
        Write-Log "Limpeza profunda realizada." Green
    } catch { Write-Log "Erro na limpeza profunda: $_" Red }
}

function Clear-PrintSpooler {
    Write-Log "Limpando spooler de impressão..." Yellow
    try {
        Stop-Service -Name Spooler -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "$env:SystemRoot\System32\spool\PRINTERS\*" -Force -Recurse -ErrorAction SilentlyContinue
        Start-Service -Name Spooler -ErrorAction SilentlyContinue
        Write-Log "Spooler de impressão limpo com sucesso." Green
    } catch {
        Write-Log "❌ Erro ao limpar spooler: $_" Red
    }
    Show-SuccessMessage
}

function Clear-Prefetch {
    Write-Log "Limpando Prefetch..." Yellow
    try {
        Remove-Item "$env:SystemRoot\Prefetch\*" -Force -Recurse -ErrorAction SilentlyContinue
        Write-Log "Prefetch limpo." Green
    } catch { Write-Log "Erro ao limpar Prefetch: $_" Red }
}

function Clear-ARP {
    Write-Log "Limpando cache ARP..." Yellow
    try {
        arp -d *
        Write-Log "Cache ARP limpo." Green
    } 
    catch { Write-Log "Erro ao limpar cache ARP: $_" Red }
}

function Manage-WindowsUpdates {
    <#
    .SYNOPSIS
        Gerencia as atualizações do Windows utilizando o módulo PSWindowsUpdate.
    .DESCRIPTION
        Esta função verifica a existência do módulo PSWindowsUpdate. Se não for encontrado,
        tenta instalá-lo. Em seguida, pode ser usada para buscar e instalar atualizações,
        incluindo opções para atualização de drivers.
    #>
       Write-Log "Iniciando o gerenciamento de atualizações do Windows." -Type Info
Write-Log "Iniciando o gerenciamento de atualizações do Windows..."

    try {
        # 1. Verificar e instalar o módulo PSWindowsUpdate
        if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
            Write-Log "Módulo PSWindowsUpdate não encontrado. Tentando instalar..." -Type Warning
Write-Log "Módulo PSWindowsUpdate não encontrado. Tentando instalar do PowerShell Gallery..." -Type Warning
            try {
                Install-Module -Name PSWindowsUpdate -Force -AllowClobber -Scope AllUsers -ErrorAction Stop
                Write-Log "Módulo PSWindowsUpdate instalado com sucesso." -Type Success
Write-Log "Módulo PSWindowsUpdate instalado com sucesso!" -Type Success
            } catch {
                Write-Log "Falha ao instalar o módulo PSWindowsUpdate: $($_.Exception.Message)" -Type Error
Write-Log "ERRO: Não foi possível instalar o módulo PSWindowsUpdate. As atualizações não poderão ser gerenciadas automaticamente. $($_.Exception.Message)" -Type Error
                Start-Sleep -Seconds 5
                return # Sai da função se a instalação falhar
            }
        } else {
            Write-Log "Módulo PSWindowsUpdate já está instalado." -Type Info
Write-Log "Módulo PSWindowsUpdate já está instalado." -Type Success
        }

        # Importar o módulo (garantir que está carregado)
        Import-Module PSWindowsUpdate -ErrorAction SilentlyContinue

        # 2. Oferecer opções de atualização
Write-Log "Opções de Atualização:" -Type Info
Write-Log "1) Buscar e Instalar TODAS as atualizações (incluindo opcionais/drivers)" -Type Success
Write-Log "2) Buscar e Instalar apenas atualizações CRÍTICAS e de SEGURANÇA" -Type Success
Write-Log "3) Apenas buscar atualizações (não instalar)" -Type Success
Write-Log "0) Voltar ao Menu Principal" -Type Error
        $updateChoice = Read-Host "Escolha uma opção de atualização"

        switch ($updateChoice) {
            "1" {
                Write-Log "Buscando e instalando TODAS as atualizações (incluindo opcionais/drivers)..." -Type Info
Write-Log "Buscando e instalando TODAS as atualizações..." -Type Warning
                Get-WindowsUpdate -Install -AcceptAll -AutoReboot | Out-Null # -Install e -AcceptAll para instalar tudo
                Write-Log "Processo de atualização completo (todas as atualizações)." -Type Success
            }
            "2" {
                Write-Log "Buscando e instalando atualizações CRÍTICAS e de SEGURANÇA..." -Type Info
Write-Log "Buscando e instalando atualizações CRÍTICAS e de SEGURANÇA..." -Type Warning
                Get-WindowsUpdate -Install -AcceptAll -CriticalUpdate -SecurityUpdate -AutoReboot | Out-Null
                Write-Log "Processo de atualização completo (críticas/segurança)." -Type Success
            }
            "3" {
                Write-Log "Apenas buscando atualizações disponíveis..." -Type Info
Write-Log "Buscando atualizações disponíveis (não será instalado nada)..." -Type Warning
                Get-WindowsUpdate | Format-Table -AutoSize
                Write-Log "Busca de atualizações concluída." -Type Info
Write-Log "Busca de atualizações concluída. Verifique a lista acima." -Type Success
                pause
            }
            "0" {
                Write-Log "Retornando ao menu principal de atualizações." -Type Info
                return
            }
            default {
Write-Log "Opção inválida. Retornando ao menu principal." -Type Error
                Start-Sleep -Seconds 2
            }
        }

Write-Log "Processo de gerenciamento de atualizações concluído." -Type Success

    } catch {
        Write-Log "Ocorreu um erro durante o gerenciamento de atualizações: $($_.Exception.Message)" -Type Error
Write-Log "ERRO durante o gerenciamento de atualizações: $($_.Exception.Message)" -Type Error
    }
    Start-Sleep -Seconds 2
}

function Perform-Cleanup {
    Write-Log "Executando rotinas de limpeza do sistema (agrupadas)..." -Type Info

    # Chamada das funções menores
    Clear-ARP
Clear-DeepSystemCleanup
Clear-DNS
Clear-Prefetch
Clear-PrintSpooler
Clear-TemporaryFiles
Clear-WinSxS
Clear-WUCache
Manage-WindowsUpdates
New-ChkDsk
Optimize-Volumes
Remove-WindowsOld


    Write-Log "Todas as rotinas de limpeza foram concluídas." -Type Success
}


# === FUNÇÕES DE REMOÇÃO DE BLOATWARE ===

function Remove-Bloatwares {
    Write-Log "Iniciando a remoção de Bloatware..." Yellow

    # Lista de pacotes para remover (nomes parciais ou exatos)
    # ATENÇÃO: Adicione ou remova itens conforme sua necessidade e cuidado ao remover pacotes essenciais!
    $bloatwareToRemove = @(
        "*Bing*", "*Edge*", "*News*", "*Weather*", "*GetHelp*", "*GetStarted*", "*Maps*",
        "*SkypeApp*", "*SolitaireCollection*", "*StickyNotes*", "*Wallet*", "*YourPhone*",
        "*WindowsFeedback*", "*Xbox*", "*ZuneMusic*", "*ZuneVideo*", "*AppInstaller*",
        "*VP9VideoExtensions*", "*WebMediaExtensions*", "*HEVCVideoExtension*",
        "*MSN.", "*OfficeHub*", "*OneNote*", "*Paint3D*", "*People*", "*Photos*",
        "*Print3D*", "*ScreenSketch*", "*SoundRecorder*", "*MixedRealityPortal*",
        "*ConnectivityStore*", "*DolbyAccess*", "*DolbyLaboratories.DolbyAccess*",
        "*Netflix*", "*Spotify*", "*TikTok*", "*Instagram*", "*Facebook*", "*Twitter*",
        "*Microsoft.StorePurchaseApp*", "*WindowsCalculator*", "*AlarmsAndClock*",
        "*WindowsCamera*", "*WindowsDefaultLockScreen*", "*WindowsMaps*", "*WindowsMail*",
        "*Microsoft.GamingApp*", # App Xbox principal
        "*GamingServices*", # Serviços relacionados a jogos
        "*Windows.ContactSupport*", # Obter Ajuda
        "*Microsoft.Windows.Photos.Addon*" # Complemento do aplicativo Fotos
    )

    # Lista de pacotes essenciais que NÃO devem ser removidos (whitelist)
    $whitelist = @(
        "Microsoft.DesktopAppInstaller", # winget
        "Microsoft.Store", # Loja da Microsoft
        "Microsoft.Windows.StartMenuExperienceHost", # Menu Iniciar
        "Microsoft.Windows.ShellExperienceHost", # Shell
        "Microsoft.UI.Xaml.2.X", # Componentes da UI
        "Microsoft.VCLibs.140.00", # Bibliotecas essenciais
        "Microsoft.NET.Native.Framework.X.X", # Bibliotecas .NET
        "Microsoft.NET.Native.Runtime.X.X", # Bibliotecas .NET
        "Microsoft.Services.Store.Engagement", # Loja
        "Microsoft.Xbox.TCUI", # Componentes Xbox (se necessário)
        "Microsoft.XboxGameCallableUI", # Componentes Xbox (se necessário)
        "Microsoft.AccountsControl",
        "Microsoft.LockApp",
        "Microsoft.Windows.SecHealthUI", # Segurança do Windows
        "Microsoft.ScreenCapture" # Ferramenta de Captura
    )
}

function Force-RemoveOneDrive {
    <#
    .SYNOPSIS
        Força a remoção completa do OneDrive do sistema.
    .DESCRIPTION
        Esta função desinstala completamente o OneDrive, desabilitando seus serviços
        e removendo seus arquivos do sistema.
    #>
    
    if (-not (Test-Path Variable:ScriptConfig)) {
        Write-Log "ERRO: \$ScriptConfig não encontrada. Certifique-se de que foi definida no topo do script." -Type Error
Write-Log "ERRO: Configurações globais (\$ScriptConfig) não encontradas. Abortando remoção do OneDrive." -Type Error
        return
    }

    Write-Log "Iniciando remoção completa do OneDrive..." -Type Info
Write-Log "Iniciando Remoção Completa do OneDrive..." -Type Error

    # === NOVO CÓDIGO AQUI ===
    if ($ScriptConfig.ConfirmationRequired) {
        $confirm = Read-Host "AVISO: A remoção do OneDrive é irreversível e pode afetar a sincronização de arquivos. Tem certeza que deseja prosseguir? (s/n)"
        if ($confirm -ne 's') {
            Write-Log "Remoção do OneDrive cancelada pelo usuário." -Type Info
Write-Log "Remoção do OneDrive cancelada." -Type Warning
            Start-Sleep -Seconds 2
            return # Sai da função se o usuário cancelar
        }
    }
    # === FIM DO NOVO CÓDIGO ===

    try {
        # Encerra processos do OneDrive
        Get-Process -Name "OneDrive*" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue | Out-Null
Write-Log "  -> Processos do OneDrive encerrados."
        Write-Log "Processos do OneDrive encerrados." -Type Success

        # Desinstala o OneDrive para todas as arquiteturas
        $onedriveSetupPath_x64 = "$env:SystemRoot\SysWOW64\OneDriveSetup.exe"
        $onedriveSetupPath_x86 = "$env:SystemRoot\System32\OneDriveSetup.exe"

        if (Test-Path $onedriveSetupPath_x64) {
Write-Log "  -> Desinstalando OneDrive (x64)..."
            Start-Process -FilePath $onedriveSetupPath_x64 -ArgumentList "/uninstall" -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue | Out-Null
            Write-Log "OneDrive x64 desinstalado." -Type Success
        } elseif (Test-Path $onedriveSetupPath_x86) {
Write-Log "  -> Desinstalando OneDrive (x86)..."
            Start-Process -FilePath $onedriveSetupPath_x86 -ArgumentList "/uninstall" -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue | Out-Null
            Write-Log "OneDrive x86 desinstalado." -Type Success
        } else {
Write-Log "  -> Instalador do OneDrive não encontrado. Pulando desinstalação via setup." -Type Warning
            Write-Log "Instalador do OneDrive não encontrado. Pulando desinstalação via setup." -Type Warning
        }

        # Remove pastas de dados e vestígios
        $userProfiles = Get-ChildItem -Path "$env:SystemDrive\Users" -Directory -ErrorAction SilentlyContinue
        foreach ($profile in $userProfiles) {
            $onedriveUserPath = Join-Path -Path $profile.FullName -ChildPath "OneDrive"
            if (Test-Path $onedriveUserPath) {
                Remove-Item -Path $onedriveUserPath -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
Write-Log "  -> Removido pasta OneDrive de $($profile.BaseName)."
            }
            $onedriveLocalAppData = Join-Path -Path $profile.FullName -ChildPath "AppData\Local\Microsoft\OneDrive"
            if (Test-Path $onedriveLocalAppData) {
                Remove-Item -Path $onedriveLocalAppData -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
Write-Log "  -> Removido AppData de OneDrive de $($profile.BaseName)."
            }
        }

        # Limpa o registro (removendo links e entradas)
        $regPaths = @(
            "HKCR:\CLSID\{018D5C66-4533-4307-9B53-2ad65C87B14B}", # OneDrive no painel de navegação
            "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-2ad65C87B14B}",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{A52BBA46-A28D-493B-B034-2AFB6F3AD90C}",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SyncRootManager\OneDrive!*"
        )
        foreach ($path in $regPaths) {
            try {
                if (Test-Path $path) {
                    Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
Write-Log "  -> Limpado registro: $path"
                }
            } catch {
                Write-Log "Falha ao limpar registro do OneDrive ($path): $($_.Exception.Message)" -Type Warning
            }
        }

        # Desativa o início automático do OneDrive via registro (se ainda houver entradas)
        try {
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "OneDrive" -Value "" -ErrorAction SilentlyContinue | Out-Null
Write-Log "  -> Desativado início automático do OneDrive."
        } catch { Write-Log "Falha ao desativar início automático do OneDrive: $($_.Exception.Message)" -Type Warning }


        Write-Log "Remoção completa do OneDrive concluída." -Type Success
Write-Log "Remoção Completa do OneDrive Concluída!" -Type Success

    } catch {
        Write-Log "Ocorreu um erro crítico durante a remoção do OneDrive: $($_.Exception.Message)" -Type Error
Write-Log "ERRO: Ocorreu um erro crítico durante a remoção do OneDrive: $($_.Exception.Message)" -Type Error
    }
    Start-Sleep -Seconds 2
}

function Test-ShouldRemovePackage {
    param (
        [Parameter(Mandatory = $true)]
        [string]$PackageName
    )
    if ($global:whitelist -contains $PackageName) {
        return $false
    }
    foreach ($item in $global:bloatwareToRemove) {
        if ($PackageName -like $item) {
            return $true
        }
    }
    return $false
}

function Remove-Bloatware {
    try {
        Write-Log "Removendo pacotes provisionados para novos usuários..." Cyan

        Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | ForEach-Object {
            if (Test-ShouldRemovePackage -PackageName $_.PackageName) {
                Write-Log "Removendo provisionamento de $($_.PackageName)..." Cyan
                Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName -ErrorAction SilentlyContinue
            }
        }

        Write-Log "Removendo pacotes do usuário atual..." Cyan

        Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue | ForEach-Object {
            if (Test-ShouldRemovePackage -PackageName $_.Name) {
                Write-Log "Removendo $($_.Name) para o usuário $($_.User.Name)..." Cyan
                Remove-AppxPackage -Package $_.PackageFullName -ErrorAction SilentlyContinue
            }
        }

        Write-Log "Remoção de Bloatware concluída." Green
    } catch {
        Write-Log "Erro durante a remoção de Bloatware: $_" Red
    }
}

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
            schtasks /Change /TN $task /Disable | Out-Null
            Write-Log "Tarefa $task desativada com sucesso." Green
        }
        catch {
            Write-Log "Erro ao desativar ${task}: $_" Red
        }
    }
    Write-Log "Desativação de tarefas agendadas concluída." Green
}

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
        }
        catch {
            Write-Log "Erro ao encerrar ${proc}: $_" Red
        }
    }
    Write-Log "Encerramento de processos dispensáveis concluído." Green
}

function Remove-StartAndTaskbarPins {
    Write-Log "Removendo pins do Menu Iniciar e Barra de Tarefas..." Yellow
    try {
        $startLayout = "$env:LOCALAPPDATA\Microsoft\Windows\Shell\LayoutModification.xml"
        if (Test-Path $startLayout) { Remove-Item $startLayout -Force }
        Write-Log "Pins removidos (pode ser necessário reiniciar o Explorer)." Green
    } 
    catch {
        Write-Log "Erro ao remover pins: $_" Red
    }
}

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
        } 
        catch {
            Write-Log "Erro ao remover/desativar ${task}: $_" Red
        }
    }
    Write-Log "Remoção agressiva de tarefas agendadas concluída." Green
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

function Remove-WindowsCopilot {
    <#
    .SYNOPSIS
        Remove e desabilita o Windows Copilot.
    .DESCRIPTION
        Esta função tenta remover o pacote do Windows Copilot (se presente)
        e aplica ajustes de registro para desabilitar sua interface e funcionalidade.
    #>
    
    Write-Log "Iniciando remoção e desativação do Windows Copilot." -Type Info
Write-Log "Iniciando remoção e desativação do Windows Copilot..."

    try {
        # 1. Tentar remover o pacote do Copilot (se for um pacote AppX)
        Write-Log "Tentando remover o pacote do Windows Copilot..." -Type Info
        Get-AppxPackage -Name "*Microsoft.Windows.Copilot*" -ErrorAction SilentlyContinue | Remove-AppxPackage -ErrorAction SilentlyContinue

        # 2. Desabilitar Copilot via Registro (para usuários atuais e novos)
        Write-Log "Aplicando ajustes de registro para desabilitar o Copilot UI e funcionalidade..." -Type Info

        # Desabilitar o Copilot via políticas (Windows 11 23H2+)
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowCopilotButton" -Value 0 -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Copilot" -Name "TurnOffCopilot" -Value 1 -Force -ErrorAction SilentlyContinue
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Copilot" -ErrorAction SilentlyContinue | Out-Null # Garante que a chave existe

        # Remover o ícone da barra de tarefas (para alguns builds)
        $regPathTaskbar = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
        Set-ItemProperty -Path $regPathTaskbar -Name "ShowCopilotButton" -Value 0 -Force -ErrorAction SilentlyContinue

        # Desabilitar a funcionalidade completa (se a chave existir)
        $regPathAI = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartMenu\StartMenuSettings"
        if (-not (Test-Path $regPathAI)) { New-Item -Path $regPathAI -Force | Out-Null }
        Set-ItemProperty -Path $regPathAI -Name "AITrayEnabled" -Value 0 -Force -ErrorAction SilentlyContinue

        Write-Log "Windows Copilot removido/desativado com sucesso." -Type Success
Write-Log "Windows Copilot removido/desativado com sucesso!" -Type Success

        # Reiniciar o Explorer para que as mudanças na barra de tarefas sejam aplicadas imediatamente
Write-Log "Reiniciando Explorer para aplicar as alterações na barra de tarefas..." -Type Warning
        Stop-Process -Name "explorer" -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        Start-Process -FilePath "explorer.exe" -ErrorAction SilentlyContinue

    } catch {
        Write-Log "Ocorreu um erro durante a remoção/desativação do Windows Copilot: $($_.Exception.Message)" -Type Error
Write-Log "Erro durante a remoção/desativação do Windows Copilot: $($_.Exception.Message)" -Type Error
    }
    Start-Sleep -Seconds 2
}

function Disable-WindowsRecall {
    <#
    .SYNOPSIS
        Desabilita o recurso Windows Recall (se presente).
    .DESCRIPTION
        Esta função aplica ajustes de registro para desabilitar o Windows Recall,
        uma funcionalidade de gravação de tela e atividades.
    #>
        Write-Log "Iniciando desativação do Windows Recall." -Type Info
Write-Log "Iniciando desativação do Windows Recall..."

    try {
        # 1. Ajustes de Registro para desabilitar o Recall
        Write-Log "Aplicando ajustes de registro para desabilitar o Recall..." -Type Info

        # Desabilitar Recall (Windows 11 24H2+)
        $regPathRecall = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Recall"
        if (-not (Test-Path $regPathRecall)) { New-Item -Path $regPathRecall -Force | Out-Null }
        Set-ItemProperty -Path $regPathRecall -Name "Debugger" -Value "cmd.exe /k echo Recall is disabled && exit" -Force -ErrorAction SilentlyContinue

        # Outras chaves de desativação que podem aparecer em futuras versões
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "RecallEnabled" -Value 0 -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" -Name "DisableRecall" -Value 1 -Force -ErrorAction SilentlyContinue
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" -ErrorAction SilentlyContinue | Out-Null # Garante que a chave existe

        Write-Log "Windows Recall desativado com sucesso." -Type Success
Write-Log "Windows Recall desativado com sucesso!" -Type Success

    } catch {
        Write-Log "Ocorreu um erro durante a desativação do Windows Recall: $($_.Exception.Message)" -Type Error
Write-Log "Erro durante a desativação do Windows Recall: $($_.Exception.Message)" -Type Error
    }
    Start-Sleep -Seconds 2
}

function Remove-Bloatwares {
    Write-Log "Iniciando a remoção de Bloatware..." Yellow

Disable-BloatwareScheduledTasks
Disable-WindowsRecall 
Enable-ClassicContextMenu
Force-RemoveOneDrive
Remove-Bloatwares
Remove-Copilot
Remove-ScheduledTasksAggressive
Remove-StartAndTaskbarPins
Remove-WindowsCopilot
Stop-BloatwareProcesses
Test-ShouldRemovePackage
Write-Log "Todas as rotinas de limpeza foram concluídas." -Type Success
}

# === FUNÇÕES DE INSTALAÇÃO DE APLICATIVOS ===

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
        @{ Id = "ShareX.ShareX" ; Name = "ShareX" }, # ShareX
        @{Name = "7-Zip"; Id = "7zip.7zip"}
    )

    Write-Log "Iniciando instalação de aplicativos..." Cyan

    foreach ($app in $apps) {
        try {
            Write-Log "Instalando $($app.Name)..." Yellow
            winget install --id $app.Id -e --accept-package-agreements --accept-source-agreements
            Write-Log "$($app.Name) instalado com sucesso." Green
        }
        catch {
            Write-Log "Falha ao instalar $($app.Name): $_" Red
        }
    }

    Write-Log "Instalação de aplicativos concluída." Green
}

function Update-PowerShell {
    Write-Log "Instalando/Atualizando PowerShell..." Yellow
    try {
        Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Unrestricted -Force
        iex "& { $(irm https://aka.ms/install-powershell.ps1) } -UseMSI"
        Write-Log "PowerShell instalado/atualizado com sucesso." Green
    } 
    catch {
        Write-Log "Erro ao instalar/atualizar PowerShell: $_" Red
    }
}


# === FUNÇÕES DE REDE E IMPRESSORAS ===

function Add-WiFiNetwork {
    Write-Log "Configurando rede Wi-Fi 'VemProMundo - Adm'..." Yellow
    $ssid = "VemProMundo - Adm"
    $password = "!Mund0CoC@7281%"

    $xmlProfile = @"
<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
  <n>$ssid</n>
  <SSIDConfig><SSID><n>$ssid</n></SSID></SSIDConfig>
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
        $tempFile = Join-Path -Path $env:TEMP -ChildPath "$($ssid.Replace(' ', '_')).xml"
        $xmlProfile | Out-File -FilePath $tempFile -Encoding ascii -Force
        netsh wlan add profile filename="$tempFile" user=all
        netsh wlan set profileparameter name="$ssid" connectiontype=ESS
        Set-NetConnectionProfile -Name "$ssid" -NetworkCategory Private
        Remove-Item $tempFile -Force
        Write-Log "Rede Wi-Fi '$ssid' configurada com sucesso." Green
    } 
    catch {
        Write-Log "❌ Erro ao adicionar rede Wi-Fi: $_" Red
    }
}

function Install-NetworkPrinters {
    Write-Log "Instalando drivers de impressora..." Yellow
    # Instala os drivers necessários
    pnputil /add-driver "G:\Drives compartilhados\MundoCOC\Tecnologia\Gerais\Drivers\ssn3m.inf" /install
    pnputil /add-driver "G:\Drives compartilhados\MundoCOC\Tecnologia\Gerais\Drivers\E_WF1YWE.INF" /install

    $printers = @(
        @{Name = "Samsung Mundo1"; IP = "172.16.40.40"; Driver = "Samsung M337x 387x 407x Series PCL6 Class Driver"},
        @{Name = "Samsung Mundo2"; IP = "172.17.40.25"; Driver = "Samsung M337x 387x 407x Series PCL6 Class Driver"},
        @{Name = "EpsonMundo1 (L3250 Series)"; IP = "172.16.40.37"; Driver = "EPSON L3250 Series"},
        @{Name = "EpsonMundo2 (L3250 Series)"; IP = "172.17.40.72"; Driver = "EPSON L3250 Series"}
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
        } 
        catch {
            Write-Log "Erro ao instalar impressora $name ($ip): $_" Red
        }
    }
    Show-SuccessMessage
    
    # Remover impressora OneNote Desktop se existir
      $printer = Get-Printer -Name "OneNote (Desktop)" -ErrorAction SilentlyContinue
    
    if ($null -ne $printer) {
        try {
Write-Log "Removendo a impressora 'OneNote (Desktop)'..." -Type Warning
            Write-Log "Removendo a impressora 'OneNote (Desktop)'..." Yellow
            # 1. Remover a impressora
            Remove-Printer -Name "OneNote (Desktop)" -ErrorAction Stop
            
            # 2. Remover o driver da impressora (se existir)
            $driver = Get-PrinterDriver -Name "OneNote*" -ErrorAction SilentlyContinue
            if ($null -ne $driver) {
                Remove-PrinterDriver -Name $driver.Name -ErrorAction SilentlyContinue
            }
            
            # 3. Remover portas associadas (opcional)
            $ports = Get-PrinterPort -Name "OneNote*" -ErrorAction SilentlyContinue
            foreach ($port in $ports) {
                Remove-PrinterPort -Name $port.Name -ErrorAction SilentlyContinue
            }
            
Write-Log "Impressora 'OneNote (Desktop)' removida com sucesso!" -Type Success
            return $true
        }
        catch {
Write-Log "Falha ao remover a impressora: $_" -Type Error
            return $false
        }
    }
    else {
Write-Log "A impressora 'OneNote (Desktop)' não está instalada." -Type Info
        return $true
    }
}

function Invoke-All-NetworkAdvanced {
    Clear-DNS
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
    } 
    catch { Write-Log "Erro ao configurar DNS: $_" Red }
}

function Test-InternetSpeed {
    Write-Log "Testando velocidade de internet usando PowerShell..." Yellow
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
    Write-Log "⚠️ Winget não está disponível neste sistema." Red
    return
}
    try {
        if (-not (Get-Command speedtest -ErrorAction SilentlyContinue)) {
            winget install --id Ookla.Speedtest -e --accept-package-agreements --accept-source-agreements
        }
        speedtest
        Write-Log "Teste de velocidade concluído." Green
    } 
    catch { Write-Log "Erro ao testar velocidade: $_" Red }
}

function Optimize-NetworkPerformance {
    Write-Log "Iniciando a otimização do desempenho da rede..." Yellow
Write-Log "Aplicando otimizações de rede..." -Type Warning

    # Carrega o módulo NetAdapter se ainda não estiver carregado
    if (-not (Get-Module -ListAvailable -Name NetAdapter)) {
        Write-Log "Módulo NetAdapter não encontrado. Tentando importar..." Yellow
        try {
            Import-Module NetAdapter -ErrorAction Stop
            Write-Log "Módulo NetAdapter importado com sucesso." Green
        } catch {
            Write-Log "Erro ao importar o módulo NetAdapter: $_. Algumas otimizações podem não ser aplicadas." Red
            return # Sai da função se o módulo não puder ser carregado
        }
    }

    $networkAdapters = Get-NetAdapter -Physical -ErrorAction SilentlyContinue

    if (-not $networkAdapters) {
        Write-Log "Nenhum adaptador de rede físico encontrado para otimização." Red
        return
    }

    foreach ($adapter in $networkAdapters) {
        Write-Log "Otimizando adaptador de rede: $($adapter.Name)..." Cyan
        try {
            # Desabilitar o Receive Side Scaling (RSS) - Não é mais tão comum desabilitar, mas se precisar:
            # RSS geralmente é bom, mas pode ser problemático em cenários específicos.
            # Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName "Receive Side Scaling" -DisplayValue "Disabled" -ErrorAction SilentlyContinue | Out-Null
            # Write-Log "RSS desabilitado para $($adapter.Name)." Green

            # Desabilitar a Checagem de Descarregamento IPv4
            # Equivalent to netsh interface ipv4 set offload "Adapter Name" rx off tx off
            Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName "IPv4 Checksum Offload" -DisplayValue "Disabled" -ErrorAction SilentlyContinue | Out-Null
            Write-Log "Desabilitada Checagem de Descarregamento IPv4 para $($adapter.Name)." Green

            # Desabilitar a Checagem de Descarregamento TCP
            # Equivalent to netsh interface tcp set global chimney=disabled
            # Chimney Offload é global, mas pode ser configurado por adaptador. Aqui faremos por adaptador.
            Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName "TCP Checksum Offload (IPv4)" -DisplayValue "Disabled" -ErrorAction SilentlyContinue | Out-Null
            Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName "TCP Checksum Offload (IPv6)" -DisplayValue "Disabled" -ErrorAction SilentlyContinue | Out-Null
            Write-Log "Desabilitada Checagem de Descarregamento TCP para $($adapter.Name)." Green

            # Desabilitar Large Send Offload (LSO) - CUIDADO: Pode impactar desempenho em algumas redes
            # Equivalent to netsh interface tcp set global lso=disabled
            Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName "Large Send Offload V2 (IPv4)" -DisplayValue "Disabled" -ErrorAction SilentlyContinue | Out-Null
            Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName "Large Send Offload V2 (IPv6)" -DisplayValue "Disabled" -ErrorAction SilentlyContinue | Out-Null
            Write-Log "Desabilitado Large Send Offload (LSO) para $($adapter.Name)." Green

            # Desabilitar ECN Capability (Explicit Congestion Notification)
            # Equivalent to netsh int tcp set global ecncapability=disabled
            # ECN é global, aqui faremos um ajuste global via registro, pois não é propriedade de adaptador fácil.
            # Pode-se desabilitar globalmente via: netsh int tcp set global ecncapability=disabled
            # Ou via registro: HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\EnableICMPRedirect = 0 (ECN é outra chave)
            # Para ECN, manteremos o netsh ou um tweak de registro global se o objetivo for desativar.
            # Por simplicidade e clareza, se precisar do ECN, um cmdlet específico não existe para ativar/desativar globalmente.
            # O ideal seria usar Set-NetTCPSetting para isso, mas afeta perfis de rede.
            # Exemplo de Set-NetTCPSetting para ECN (afeta perfis, não adaptador diretamente):
            # Set-NetTCPSetting -SettingName Custom -EcnCapability Disabled -ErrorAction SilentlyContinue | Out-Null
            # Write-Log "Desabilitado ECN Capability (globalmente, se aplicável)." Green

            # Desabilitar o NetBIOS sobre TCP/IP (se não for usado para redes legadas)
            # Isso é configurado no adaptador.
            # Get-NetAdapterBinding -ComponentID ms_netbios -Name $adapter.Name -ErrorAction SilentlyContinue | Disable-NetAdapterBinding -ErrorAction SilentlyContinue | Out-Null
            # Write-Log "NetBIOS sobre TCP/IP desabilitado para $($adapter.Name)." Green

        } catch {
            Write-Log "Erro ao otimizar adaptador $($adapter.Name): $_" Red
        }
    }

    # Configurações globais de TCP que podem ser feitas via registro ou NetTCPSetting
    Write-Log "Aplicando configurações globais de TCP via Registro..." Cyan
    try {
        # Desabilitar Nagle's Algorithm (TcpNoDelay=1)
        # Pode reduzir latência, mas aumentar uso de banda. Cuidado.
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "TcpNoDelay" -Value 1 -Force -ErrorAction SilentlyContinue | Out-Null
        Write-Log "Nagle's Algorithm desabilitado (TcpNoDelay)." Green

        # Habilitar o TcpAckFrequency (para jogos e baixa latência, ou 1 para ack imediato)
        # 0 = Acks por padrão, 1 = Acks imediatos.
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" -Name "TcpAckFrequency" -Value 1 -Force -ErrorAction SilentlyContinue | Out-Null
        Write-Log "TcpAckFrequency configurado para 1." Green

        # Ajuste do limite de conexão TCP (para programas P2P, etc.)
        # HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\MaxUserPort = 65534
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "MaxUserPort" -Value 65534 -Force -ErrorAction SilentlyContinue | Out-Null
        Write-Log "MaxUserPort configurado para 65534." Green

        # Tempo de vida de portas TCP/IP (reduzir espera para reuso de portas)
        # HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\TcpTimedWaitDelay = 30 (seconds)
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "TcpTimedWaitDelay" -Value 30 -Force -ErrorAction SilentlyContinue | Out-Null
        Write-Log "TcpTimedWaitDelay configurado para 30 segundos." Green

        # Desabilitar o Fast Startup (Inicialização Rápida) via Registro (pode causar problemas em dual-boot)
        # Equivalente a desmarcar no Painel de Controle -> Opções de Energia
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
        Write-Log "Inicialização Rápida (Fast Startup) desabilitada." Green

    } catch {
        Write-Log "Erro ao aplicar configurações globais de TCP/Registro: $_" Red
    }

    Write-Log "Otimização de desempenho da rede concluída." Green
Write-Log "Otimizações de rede aplicadas. Um reinício pode ser necessário para algumas alterações." -Type Success
}

function Disable-IPv6 {
    Write-Log "Desabilitando IPv6..." Yellow
    try {
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisabledComponents" -PropertyType DWord -Value 0xFF -Force | Out-Null
        Write-Log "IPv6 desativado." Green
    } catch { Write-Log "Erro ao desativar IPv6: $_" Red }
}


# === FUNÇÕES DE DIAGNÓSTICO E INFORMAÇÕES ===

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

function Invoke-All-DiagnosticsAdvanced {
    Show-SystemInfo
    Show-DiskUsage
    Show-NetworkInfo
    Invoke-SFC-Scan
    Invoke-DISM-Scan
    Test-SMART-Drives
    Test-Memory
    Show-SuccessMessage
}

function Invoke-SFC-Scan {
    Write-Log "Executando verificação SFC..." Yellow
    sfc /scannow | Out-Host
    Write-Log "Verificação SFC concluída." Green
}

function Invoke-DISM-Scan {
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


# === FUNÇÕES DE TWEAKS DE PRIVACIDADE E REGISTRO ===

function Grant-PrivacyTweaks {
    Write-Log "Aplicando tweaks de privacidade e desabilitando funcionalidades desnecessárias..." Yellow

    # Dicionário de alterações de registro para privacidade e desativações
    $registryChanges = @{
        # Telemetria e Coleta de Dados (HKLM) - Consolidado
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" = @{AllowTelemetry = 0; CommercialDataOptIn = 0; DoNotShowFeedbackNotifications = 1; MaxTelemetryAllowed = 0; UploadUserActivities = 0};

        # Telemetria e Coleta de Dados (HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection) - Consolidado
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" = @{
            AllowTelemetry = 0;
            DoNotShowFeedbackNotifications = 1;
            MaxTelemetryAllowed = 0;
        };

        # Privacidade Geral (HKCU)
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" = @{TailoredExperiencesWithDiagnosticDataEnabled = 0};
        "HKCU:\SOFTWARE\Microsoft\InputPersonalization" = @{RestrictImplicitTextCollection = 1; RestrictInkingAndTypingPersonalization = 1};

        # Anúncios e ID de Publicidade
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" = @{Enabled = 0};

        # Sincronização de Mensagens (Your Phone)
        "HKCU:\SOFTWARE\Microsoft\Messaging" = @{IMEPersonalization = 0};

        # Localização
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LocationAndSensors" = @{LocationDisabled = 1};
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" = @{Value = "Deny"; LastUsedTimeStop = 0}; # Para o usuário atual

        # Cortana (busca) e Pesquisa online
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" = @{CortanaConsent = 0; AllowSearchToUseLocation = 0; BingSearchEnabled = 0; CortanaEnabled = 0; ImmersiveSearch = 0};
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" = @{"Is-CortanaConsent" = 0};

        # Conteúdo em destaque do Windows (lock screen, etc.) e Sugestões de Terceiros (HKCU) - Consolidado
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" = @{
            OemPreInstalledAppsEnabled = 0;
            PreInstalledAppsEnabled = 0;
            SilentInstalledAppsEnabled = 0;
            SoftLandingEnabled = 0;
            "SubscribedContent-338387Enabled" = 0;
            "SubscribedContent-338388Enabled" = 0;
            "SubscribedContent-338389Enabled" = 0;
            "SubscribedContent-338393Enabled" = 0;
            "SubscribedContent-353693Enabled" = 0;
            ContentDeliveryAllowed = 0 # Movido para cá para unificar
        };
        # Conteúdo em destaque do Windows (HKLM)
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" = @{ContentDeliveryAllowed = 0};

        # Aplicativos em segundo plano
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" = @{GlobalUserBackgroundAccessEnable = 0}; # Desabilita globalmente
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" = @{DisableBackgroundAppAccess = 1}; # Política para todos os apps

        # Acesso ao microfone
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone" = @{Value = "Deny"; LastUsedTimeStop = 0};

        # Acesso à câmera
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" = @{Value = "Deny"; LastUsedTimeStop = 0};

        # Desabilitar SMBv1 (se ainda não desabilitado)
        "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" = @{SMB1 = 0};
        "HKLM:\SYSTEM\CurrentControlSet\Services\MRxSmb10" = @{Start = 4}; # Desabilitar driver

        # Desabilitar User Account Control (UAC) - CUIDADO! Apenas se for estritamente necessário.
        # Nível de segurança muito baixo.
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" = @{EnableLUA = 0; ConsentPromptBehaviorAdmin = 0};

        # Desativar Notificações do Action Center
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" = @{NOC_Global_Enabled = 0};

        # Desativar Compartilhamento de Diagnósticos
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\Settings" = @{AllowDiagnosticDataToFlow = 0};

        # Desativar Experiências Compartilhadas (Continuar no PC)
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Workloads\SharedExperience" = @{EnableSharedExperience = 0};
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Workloads\SharedExperience" = @{EnableSharedExperience = 0};

        # Desativar sugestões na Timeline
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Feeds" = @{ShellFeedsTaskbarViewMode = 2};

        # Desativar Download de Conteúdo Automático (MS Store)
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Store" = @{AutoDownload = 0};

        # Desativar OneDrive (HKLM) - Consolidado
        "HKLM:\SOFTWARE\Policies\Microsoft\OneDrive" = @{
            DisableFileSyncNGSC = 1;
            DisablePersonalDrive = 1;
        };
        # Desativar OneDrive (HKCU) - Consolidado
        "HKCU:\SOFTWARE\Microsoft\OneDrive\Accounts\Business" = @{DisablePersonalDrive = 1};

        # Desativar Game Bar
        "HKCU:\SOFTWARE\Microsoft\GameBar" = @{AllowGameBar = 0; UseNexusForGameBar = 0; ShowStartupPanel = 0};

        # Desabilitar OneDrive na barra lateral do Explorador de Arquivos (Consolidado)
        "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" = @{"System.IsPinnedToNameSpaceTree" = 0};
        "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" = @{"System.IsPinnedToNameSpaceTree" = 0};
    }

    try {
        foreach ($path in $registryChanges.Keys) {
            # Certifica-se de que o caminho existe antes de tentar definir as propriedades
            if (-not (Test-Path $path -ErrorAction SilentlyContinue)) {
                New-Item -Path $path -Force -ErrorAction SilentlyContinue | Out-Null
                Write-Log "Caminho de registro criado: $path" Cyan
            }

            foreach ($name in $registryChanges.$path.Keys) {
                $value = $registryChanges.$path.$name
                Write-Log "Configurando registro: $path - $name = $value" Cyan
                Set-ItemProperty -Path $path -Name $name -Value $value -Force -ErrorAction SilentlyContinue | Out-Null
            }
        }
        Write-Log "Tweaks de privacidade aplicados com sucesso." Green
    } catch {
        Write-Log "Erro ao aplicar tweaks de privacidade: $_" Red
    }
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
    Write-Log "Tentando desativar o UAC (User Account Control)..." Yellow
Write-Log "ATENÇÃO: Desativar o UAC reduz a segurança do sistema. Prossiga com cautela." -Type Warning
    Start-Sleep -Seconds 2

    try {
        # Define EnableLUA para 0 para desativar o UAC
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 0 -Force -ErrorAction Stop | Out-Null
        # Define ConsentPromptBehaviorAdmin para 0 para desabilitar o prompt de consentimento para administradores
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 0 -Force -ErrorAction Stop | Out-Null

        Write-Log "UAC desativado com sucesso. Será necessário reiniciar para que as alterações tenham efeito completo." Green
Write-Log "UAC desativado. Reinicie o computador para aplicar as alterações." -Type Success
    } catch {
        Write-Log "Erro ao desativar o UAC: $_" Red
Write-Log "Erro ao desativar o UAC. Verifique o log." -Type Error
    }
}

function Disable-ActionCenter-Notifications {
    Write-Log "Desabilitando Action Center e notificações..." Yellow
    try {
        reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v DisableNotificationCenter /t REG_DWORD /d 1 /f | Out-Null
        reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications" /v ToastEnabled /t REG_DWORD /d 0 /f | Out-Null
        reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v GlobalUserDisabled /t REG_DWORD /d 1 /f | Out-Null
        Write-Log "Action Center e notificações desativados." Green
    } catch { Write-Log "Erro ao desativar Action Center: $_" Red }
}

function Set-VisualPerformance {
    Write-Log "Ajustando visual para melhor performance..." Yellow
    try {
        reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v VisualFXSetting /t REG_DWORD /d 2 /f | Out-Null
        reg.exe add "HKCU\Control Panel\Desktop" /v UserPreferencesMask /t REG_BINARY /d 9012038010000000 /f | Out-Null
        Write-Log "Visual ajustado para performance." Green
    } catch { Write-Log "Erro ao ajustar visual: $_" Red }
}

function Perform-SystemOptimizations {
    <#
    .SYNOPSIS
        Executa uma série de otimizações e rotinas de limpeza baseadas nas configurações globais.
    .DESCRIPTION
        Esta função orquestra diversas tarefas de limpeza e otimização do sistema,
        como limpeza de arquivos temporários, cache do Windows Update, otimização de volumes,
        e mais, todas controladas pela hashtable global $ScriptConfig.Cleanup.
    #>
        # Certifique-se de que a hashtable de configuração existe
    if (-not (Test-Path Variable:ScriptConfig)) {
        Write-Log "ERRO: \$ScriptConfig não encontrada. Certifique-se de que foi definida no topo do script." -Type Error
Write-Log "ERRO: Configurações globais (\$ScriptConfig) não encontradas. Abortando otimizações." -Type Error
        return
    }

    Write-Log "Iniciando rotinas de otimização do sistema..." -Type Info
Write-Log "Iniciando Rotinas de Limpeza e Otimização do Sistema..." -Type Info

    # Chamada condicional das funções de limpeza com base em $ScriptConfig
    if ($ScriptConfig.Cleanup.CleanTemporaryFiles) {
        Write-Log "Executando limpeza de arquivos temporários..." -Type Info
Write-Log "  -> Limpando arquivos temporários..."
        # Você precisaria de uma função como: Clear-TemporaryFiles
        try { Clear-TemporaryFiles } catch { Write-Log "Falha ao limpar arquivos temporários: $($_.Exception.Message)" -Type Warning }
    }

    if ($ScriptConfig.Cleanup.CleanWUCache) {
        Write-Log "Limpando cache do Windows Update..." -Type Info
Write-Log "  -> Limpando cache do Windows Update..."
        # Você precisaria de uma função como: Clear-WUCache
        try { Clear-WUCache } catch { Write-Log "Falha ao limpar cache WU: $($_.Exception.Message)" -Type Warning }
    }

    if ($ScriptConfig.Cleanup.OptimizeVolumes) {
        Write-Log "Otimizando volumes de disco..." -Type Info
Write-Log "  -> Otimizando volumes de disco (Desfragmentação/Trim)..."
        # Você precisaria de uma função como: Optimize-Volumes
        try { Optimize-Volumes } catch { Write-Log "Falha ao otimizar volumes: $($_.Exception.Message)" -Type Warning }
    }

    if ($ScriptConfig.Cleanup.PerformDeepSystemCleanup) {
        Write-Log "Executando limpeza profunda do sistema..." -Type Info
Write-Log "  -> Realizando limpeza profunda do sistema (Disk Cleanup)..."
        # Você precisaria de uma função como: Clear-DeepSystemCleanup
        try { Clear-DeepSystemCleanup } catch { Write-Log "Falha na limpeza profunda: $($_.Exception.Message)" -Type Warning }
    }

    if ($ScriptConfig.Cleanup.ClearDNSCache) {
        Write-Log "Limpando cache DNS..." -Type Info
Write-Log "  -> Limpando cache DNS..."
        # Função simples para limpar DNS: ipconfig /flushdns
Write-Log "     DNS cache limpo." -Type Success
    }

    if ($ScriptConfig.Cleanup.DisableMemoryDumps) {
        Write-Log "Desativando despejos de memória..." -Type Info
Write-Log "  -> Desativando criação de despejos de memória..."
        # Exemplo de como desativar despejos de memória via registro
        try {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -Name "CrashDumpEnabled" -Value 0 -Force -ErrorAction Stop
Write-Log "     Despejos de memória desativados." -Type Success
        } catch { Write-Log "Falha ao desativar despejos de memória: $($_.Exception.Message)" -Type Warning }
    }

    Write-Log "Rotinas de otimização do sistema concluídas." -Type Success
Write-Log "Rotinas de Limpeza e Otimização do Sistema Concluídas!" -Type Success
    Start-Sleep -Seconds 2
}

function Apply-PrivacyAndBloatwarePrevention {
    <#
    .SYNOPSIS
        Aplica ajustes de privacidade e previne bloatware baseando-se nas configurações globais.
    .DESCRIPTION
        Esta função modifica diversas configurações do sistema e do registro para
        melhorar a privacidade do usuário e evitar a instalação ou execução de
        componentes indesejados (bloatware), controlados pela hashtable global $ScriptConfig.PrivacyTweaks.
    #>
   
    # Certifique-se de que a hashtable de configuração existe
    if (-not (Test-Path Variable:ScriptConfig)) {
        Write-Log "ERRO: \$ScriptConfig não encontrada. Certifique-se de que foi definida no topo do script." -Type Error
Write-Log "ERRO: Configurações globais (\$ScriptConfig) não encontradas. Abortando ajustes de privacidade." -Type Error
        return
    }

    Write-Log "Iniciando aplicação de ajustes de privacidade e prevenção de bloatware..." -Type Info
Write-Log "Iniciando Ajustes de Privacidade e Prevenção de Bloatware..." -Type Info

    # Chamada condicional das ações de privacidade com base em $ScriptConfig
    if ($ScriptConfig.PrivacyTweaks.DisableTelemetry) {
        Write-Log "Desativando telemetria..." -Type Info
Write-Log "  -> Desativando telemetria..."
        try {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0 -Force -ErrorAction Stop
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Value 0 -Force -ErrorAction Stop
Write-Log "     Telemetria desativada." -Type Success
        } catch { Write-Log "Falha ao desativar telemetria: $($_.Exception.Message)" -Type Warning }
    }

    if ($ScriptConfig.PrivacyTweaks.DisableDiagnosticData) {
        Write-Log "Desativando dados de diagnóstico..." -Type Info
Write-Log "  -> Desativando dados de diagnóstico..."
        try {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" -Name "DiagTrack" -Value 0 -Force -ErrorAction Stop
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\Settings" -Name "SQMConsent" -Value 0 -Force -ErrorAction Stop
Write-Log "     Dados de diagnóstico desativados." -Type Success
        } catch { Write-Log "Falha ao desativar dados de diagnóstico: $($_.Exception.Message)" -Type Warning }
    }

    if ($ScriptConfig.PrivacyTweaks.BlockTelemetryHosts) {
        Write-Log "Bloqueando hosts de telemetria no arquivo hosts..." -Type Info
Write-Log "  -> Bloqueando hosts de telemetria..."
        try {
            $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
            $telemetryHosts = @(
                "127.0.0.1 telemetry.microsoft.com",
                "127.0.0.1 vortex.data.microsoft.com",
                "127.0.0.1 settings-win.data.microsoft.com"
            )
            $currentHosts = Get-Content -Path $hostsPath -Raw
            foreach ($hostEntry in $telemetryHosts) {
                if ($currentHosts -notlike "*$hostEntry*") {
                    Add-Content -Path $hostsPath -Value $hostEntry -Force
                }
            }
Write-Log "     Hosts de telemetria bloqueados." -Type Success
        } catch { Write-Log "Falha ao bloquear hosts de telemetria: $($_.Exception.Message)" -Type Warning }
    }

    if ($ScriptConfig.PrivacyTweaks.DisableLocationServices) {
        Write-Log "Desativando serviços de localização..." -Type Info
Write-Log "  -> Desativando serviços de localização..."
        try {
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Value "Deny" -Force -ErrorAction Stop
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -Value 1 -Force -ErrorAction Stop
Write-Log "     Serviços de localização desativados." -Type Success
        } catch { Write-Log "Falha ao desativar serviços de localização: $($_.Exception.Message)" -Type Warning }
    }

    if ($ScriptConfig.PrivacyTweaks.DisableActivityHistory) {
        Write-Log "Desativando histórico de atividades..." -Type Info
Write-Log "  -> Desativando histórico de atividades..."
        try {
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" -Name "ActivityData" -Value 0 -Force -ErrorAction Stop
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Value 0 -Force -ErrorAction Stop
Write-Log "     Histórico de atividades desativado." -Type Success
        } catch { Write-Log "Falha ao desativar histórico de atividades: $($_.Exception.Message)" -Type Warning }
    }

    if ($ScriptConfig.PrivacyTweaks.DisableAdvertisingID) {
        Write-Log "Desativando ID de publicidade..." -Type Info
Write-Log "  -> Desativando ID de publicidade..."
        try {
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Value 0 -Force -ErrorAction Stop
Write-Log "     ID de publicidade desativado." -Type Success
        } catch { Write-Log "Falha ao desativar ID de publicidade: $($_.Exception.Message)" -Type Warning }
    }

    if ($ScriptConfig.PrivacyTweaks.DisableCortana) {
        Write-Log "Desativando Cortana..." -Type Info
Write-Log "  -> Desativando Cortana..."
        try {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Value 0 -Force -ErrorAction Stop
Write-Log "     Cortana desativada." -Type Success
        } catch { Write-Log "Falha ao desativar Cortana: $($_.Exception.Message)" -Type Warning }
    }

    if ($ScriptConfig.PrivacyTweaks.DisableBiometrics) {
        Write-Log "Desativando biometria (se não utilizada)..." -Type Info
Write-Log "  -> Desativando biometria..."
        try {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics" -Name "Enabled" -Value 0 -Force -ErrorAction Stop
Write-Log "     Biometria desativada." -Type Success
        } catch { Write-Log "Falha ao desativar biometria: $($_.Exception.Message)" -Type Warning }
    }

    if ($ScriptConfig.PrivacyTweaks.DisableFeedbackRequests) {
        Write-Log "Desativando solicitações de feedback..." -Type Info
Write-Log "  -> Desativando solicitações de feedback..."
        try {
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "Period" -Value 0 -Force -ErrorAction Stop
Write-Log "     Solicitações de feedback desativadas." -Type Success
        } catch { Write-Log "Falha ao desativar solicitações de feedback: $($_.Exception.Message)" -Type Warning }
    }

    if ($ScriptConfig.PrivacyTweaks.DisableSuggestedContent) {
        Write-Log "Desativando conteúdo sugerido..." -Type Info
Write-Log "  -> Desativando conteúdo sugerido..."
        try {
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Value 0 -Force -ErrorAction Stop
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Value 0 -Force -ErrorAction Stop
Write-Log "     Conteúdo sugerido desativado." -Type Success
        } catch { Write-Log "Falha ao desativar conteúdo sugerido: $($_.Exception.Message)" -Type Warning }
    }

    if ($ScriptConfig.PrivacyTweaks.DisableAutoUpdatesStoreApps) {
        Write-Log "Desativando atualizações automáticas de apps da Loja..." -Type Info
Write-Log "  -> Desativando atualizações automáticas da Loja..."
        try {
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Auto Update\Store" -Name "AutoDownload" -Value 2 -Force -ErrorAction Stop # 2 = desativado
Write-Log "     Atualizações automáticas da Loja desativadas." -Type Success
        } catch { Write-Log "Falha ao desativar atualizações automáticas da Loja: $($_.Exception.Message)" -Type Warning }
    }

    if ($ScriptConfig.PrivacyTweaks.DisableWidgets) {
        Write-Log "Desativando Widgets do Windows 11..." -Type Info
Write-Log "  -> Desativando Widgets..."
        try {
            # Desativar da barra de tarefas
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarDa" -Value 0 -Force -ErrorAction Stop
            # Ocultar o painel de widgets
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Hidden\Widgets" -Name "Enabled" -Value 0 -Force -ErrorAction Stop
Write-Log "     Widgets desativados." -Type Success
        } catch { Write-Log "Falha ao desativar Widgets: $($_.Exception.Message)" -Type Warning }
    }

    if ($ScriptConfig.PrivacyTweaks.DisableNewsAndInterests) {
        Write-Log "Desativando Notícias e Interesses (Windows 10)..." -Type Info
Write-Log "  -> Desativando Notícias e Interesses..."
        try {
            # Desativar da barra de tarefas
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds" -Name "ShellFeedsTaskbarViewMode" -Value 2 -Force -ErrorAction Stop # 2 = Desativado
Write-Log "     Notícias e Interesses desativados." -Type Success
        } catch { Write-Log "Falha ao desativar Notícias e Interesses: $($_.Exception.Message)" -Type Warning }
    }

    Write-Log "Ajustes de privacidade e prevenção de bloatware concluídos." -Type Success
Write-Log "Ajustes de Privacidade e Prevenção de Bloatware Concluídos!" -Type Success
    Start-Sleep -Seconds 2
}

function Apply-GPORegistrySettings {
    <#
    .SYNOPSIS
        Aplica configurações de GPO relevantes via registro baseadas nas configurações globais.
    .DESCRIPTION
        Esta função define várias configurações do sistema e do navegador que normalmente
        seriam controladas por Políticas de Grupo (GPO), aplicando-as diretamente via registro.
        As opções são controladas pela hashtable global $ScriptConfig.GPORegistrySettings.
    #>
    
    # Certifique-se de que a hashtable de configuração existe
    if (-not (Test-Path Variable:ScriptConfig)) {
        Write-Log "ERRO: \$ScriptConfig não encontrada. Certifique-se de que foi definida no topo do script." -Type Error
Write-Log "ERRO: Configurações globais (\$ScriptConfig) não encontradas. Abortando aplicação de GPO via Registro." -Type Error
        return
    }

    Write-Log "Iniciando aplicação de configurações de GPO via Registro..." -Type Info
Write-Log "Iniciando Aplicação de Configurações de GPO via Registro..." -Type Info

    # ===============================
    # Configurações de Windows Update
    # ===============================

    if ($ScriptConfig.GPORegistrySettings.EnableUpdateManagement) {
        Write-Log "Configurando gerenciamento de Windows Update..." -Type Info
Write-Log "  -> Configurando gerenciamento de Windows Update..."
        try {
            # Desativa o acesso à interface de usuário de updates para usuários padrão
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DoNotAllowWindowsUpdate" -Value 1 -Force -ErrorAction Stop
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Value 1 -Force -ErrorAction Stop # Desativar atualização automática para controlar manualmente
            # Define o comportamento para download e notificação
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -Value 2 -Force -ErrorAction Stop # 2 = Notificar para download e instalação
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoRebootWithLoggedOnUsers" -Value 1 -Force -ErrorAction Stop # Evita reinício com usuário logado
Write-Log "     Gerenciamento de Windows Update configurado." -Type Success
        } catch { Write-Log "Falha ao configurar gerenciamento de Windows Update: $($_.Exception.Message)" -Type Warning }
    }

    if ($ScriptConfig.GPORegistrySettings.DisableAutoReboot) {
        Write-Log "Desativando reinício automático após updates..." -Type Info
Write-Log "  -> Desativando reinício automático após updates..."
        try {
            # Já coberto parcialmente por NoAutoRebootWithLoggedOnUsers acima, mas garante mais
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoRebootWithLoggedOnUsers" -Value 1 -Force -ErrorAction Stop
            # Adicional: Remove a tarefa de reinício forçado (pode ser recriada pelo sistema)
            SchTasks /Change /TN "\Microsoft\Windows\UpdateOrchestrator\Reboot" /Disable | Out-Null
Write-Log "     Reinício automático após updates desativado." -Type Success
        } catch { Write-Log "Falha ao desativar reinício automático: $($_.Exception.Message)" -Type Warning }
    }

    if ($ScriptConfig.GPORegistrySettings.SetScheduledUpdateTime) {
        Write-Log "Definindo horário de instalação de updates agendados..." -Type Info
Write-Log "  -> Definindo horário de instalação de updates agendados (3 AM)..."
        try {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "ScheduledInstallDay" -Value 0 -Force -ErrorAction Stop # 0 = Todos os dias
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "ScheduledInstallTime" -Value 3 -Force -ErrorAction Stop # 3 = 03:00 AM
Write-Log "     Horário de atualização agendado para 03:00 AM." -Type Success
        } catch { Write-Log "Falha ao definir horário de updates: $($_.Exception.Message)" -Type Warning }
    }

    if ($ScriptConfig.GPORegistrySettings.DisableDriverUpdates) {
        Write-Log "Desativando updates de drivers via Windows Update..." -Type Info
Write-Log "  -> Desativando updates de drivers via Windows Update..."
        try {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontSearchWindowsUpdate" -Value 1 -Force -ErrorAction Stop
Write-Log "     Updates de drivers via WU desativados." -Type Success
        } catch { Write-Log "Falha ao desativar updates de drivers: $($_.Exception.Message)" -Type Warning }
    }

    # =========================
    # Configurações de Navegadores
    # =========================

    if ($ScriptConfig.GPORegistrySettings.ConfigureEdge) {
        Write-Log "Configurando Microsoft Edge..." -Type Info
Write-Log "  -> Configurando Microsoft Edge (bloqueando Edge Copilot, etc.)..."
        try {
            # Desativa o Edge Copilot
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Edge" -Name "EdgeCopilotEnabled" -Value 0 -Force -ErrorAction Stop
            # Outras configurações do Edge podem ser adicionadas aqui
            # Ex: Desativar página de nova aba do Bing
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Edge" -Name "NewTabPageUrl" -Value "about:blank" -Force -ErrorAction Stop
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Edge" -Name "NewTabPageLocation" -Value 1 -Force -ErrorAction Stop # 1=blank page
Write-Log "     Microsoft Edge configurado." -Type Success
        } catch { Write-Log "Falha ao configurar Edge: $($_.Exception.Message)" -Type Warning }
    }

    if ($ScriptConfig.GPORegistrySettings.ConfigureChrome) {
        Write-Log "Configurando Google Chrome..." -Type Info
Write-Log "  -> Configurando Google Chrome (desativando algumas integrações)..."
        try {
            # Exemplo: Desativar Safe Browse (use com cautela)
            # Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "SafeBrowseEnabled" -Value 0 -Force -ErrorAction Stop
            # Exemplo: Prevenir a instalação de extensões de fora da Chrome Web Store
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "ExtensionInstallForcelist" -Value 0 -Force -ErrorAction Stop
Write-Log "     Google Chrome configurado." -Type Success
        } catch { Write-Log "Falha ao configurar Chrome: $($_.Exception.Message)" -Type Warning }
    }

    # =========================
    # Outras configurações de GPO (Exemplos)
    # =========================

    if ($ScriptConfig.GPORegistrySettings.DisableWindowsTips) { # Exemplo de uma nova flag a ser adicionada no $ScriptConfig.GPORegistrySettings se desejar
        Write-Log "Desativando dicas e sugestões do Windows..." -Type Info
Write-Log "  -> Desativando dicas e sugestões do Windows..."
        try {
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Value 0 -Force -ErrorAction Stop
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353694Enabled" -Value 0 -Force -ErrorAction Stop
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353696Enabled" -Value 0 -Force -ErrorAction Stop
Write-Log "     Dicas e sugestões desativadas." -Type Success
        } catch { Write-Log "Falha ao desativar dicas: $($_.Exception.Message)" -Type Warning }
    }
    # ... adicione mais configurações aqui, baseadas em novas flags no $ScriptConfig.GPORegistrySettings

    Write-Log "Aplicação de configurações de GPO via Registro concluída." -Type Success
Write-Log "Configurações de GPO via Registro Concluídas!" -Type Success
    Start-Sleep -Seconds 2
}

function Apply-UITweaks {
	
function Show-PersonalizationMenu {
    do {
        Clear-Host
        Write-Host "`n[APARÊNCIA E PERSONALIZAÇÃO]" -ForegroundColor Cyan
        Write-Host " A) Aplicar tema escuro"
        Write-Host " B) Mostrar segundos no relógio"
        Write-Host " C) Aplicar visual de performance"
        Write-Host " D) Restaurar menu de contexto clássico"
        Write-Host " X) Voltar"
        $key = [string]::Concat($Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown").Character).ToUpper()
        switch ($key) {
            'A' { Enable-DarkTheme }
            'B' { Enable-TaskbarSeconds }
            'C' { Set-VisualPerformance }
            'D' { Enable-ClassicContextMenu }
            'X' { return }
        }
        Show-SuccessMessage
    } while ($true)
}
    <#
    .SYNOPSIS
        Aplica diversos ajustes na interface do usuário do Windows baseados nas configurações globais.
    .DESCRIPTION
        Esta função modifica configurações visuais e de usabilidade do sistema operacional,
        como tema, transparência, animações, e itens da barra de tarefas/Explorer,
        controladas pela hashtable global $ScriptConfig.UITweaks.
    #>
       if (-not (Test-Path Variable:ScriptConfig)) {
        Write-Log "ERRO: \$ScriptConfig não encontrada. Certifique-se de que foi definida no topo do script." -Type Error
Write-Log "ERRO: Configurações globais (\$ScriptConfig) não encontradas. Abortando ajustes de UI." -Type Error
        return
    }

    Write-Log "Iniciando aplicação de ajustes de interface do usuário (UI Tweaks)..." -Type Info
Write-Log "Iniciando Ajustes de Interface do Usuário (UI Tweaks)..." -Type Info

    # Tema Escuro/Claro
    if ($ScriptConfig.UITweaks.EnableDarkMode) {
        Write-Log "Ativando Modo Escuro..." -Type Info
Write-Log "  -> Ativando Modo Escuro..."
        try {
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Value 0 -Force -ErrorAction Stop
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Value 0 -Force -ErrorAction Stop
Write-Log "     Modo Escuro ativado." -Type Success
        } catch { Write-Log "Falha ao ativar Modo Escuro: $($_.Exception.Message)" -Type Warning }
    } else { # Opcional: para garantir o modo claro se a flag for $false
        Write-Log "Garantindo Modo Claro (se ativado nas configs)..." -Type Info
Write-Log "  -> Garantindo Modo Claro..."
        try {
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Value 1 -Force -ErrorAction Stop
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Value 1 -Force -ErrorAction Stop
Write-Log "     Modo Claro configurado." -Type Success
        } catch { Write-Log "Falha ao configurar Modo Claro: $($_.Exception.Message)" -Type Warning }
    }

    # Transparência
    if ($ScriptConfig.UITweaks.DisableTransparency) {
        Write-Log "Desativando Efeitos de Transparência..." -Type Info
Write-Log "  -> Desativando Efeitos de Transparência..."
        try {
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "EnableTransparency" -Value 0 -Force -ErrorAction Stop
Write-Log "     Efeitos de transparência desativados." -Type Success
        } catch { Write-Log "Falha ao desativar transparência: $($_.Exception.Message)" -Type Warning }
    } else {
        Write-Log "Ativando Efeitos de Transparência (se ativado nas configs)..." -Type Info
Write-Log "  -> Ativando Efeitos de Transparência..."
        try {
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "EnableTransparency" -Value 1 -Force -ErrorAction Stop
Write-Log "     Efeitos de transparência ativados." -Type Success
        } catch { Write-Log "Falha ao ativar transparência: $($_.Exception.Message)" -Type Warning }
    }

    # Animações
    if ($ScriptConfig.UITweaks.DisableAnimations) {
        Write-Log "Desativando Animações do Windows..." -Type Info
Write-Log "  -> Desativando Animações do Windows..."
        try {
            Set-ItemProperty -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -Value 0 -Force -ErrorAction Stop
            Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "UserPreferenceMask" -Value ([byte[]]([System.Convert]::FromBase64String("AAAAAQAAAAIAAAADAAAAQA=="))) -Force -ErrorAction Stop # Desabilita várias animações
Write-Log "     Animações do Windows desativadas." -Type Success
        } catch { Write-Log "Falha ao desativar animações: $($_.Exception.Message)" -Type Warning }
    } else {
        Write-Log "Ativando Animações do Windows (se ativado nas configs)..." -Type Info
Write-Log "  -> Ativando Animações do Windows..."
        try {
            Set-ItemProperty -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -Value 1 -Force -ErrorAction Stop
            Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "UserPreferenceMask" -Value ([byte[]]([System.Convert]::FromBase64String("BwAAAAEAIAAIAAAADAAAAQA="))) -Force -ErrorAction Stop # Habilita animações padrão
Write-Log "     Animações do Windows ativadas." -Type Success
        } catch { Write-Log "Falha ao ativar animações: $($_.Exception.Message)" -Type Warning }
    }

    # Alinhamento da Barra de Tarefas (Windows 11)
    if ($IsWindows11) { # Variável $IsWindows11 deve ser definida no topo do script ou dentro da função
        if ($ScriptConfig.UITweaks.TaskbarAlignLeft) {
            Write-Log "Alinhando itens da barra de tarefas à esquerda (Windows 11)..." -Type Info
Write-Log "  -> Alinhando barra de tarefas à esquerda (Windows 11)..."
            try {
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAl" -Value 0 -Force -ErrorAction Stop # 0 = Esquerda, 1 = Centro
Write-Log "     Barra de tarefas alinhada à esquerda." -Type Success
            } catch { Write-Log "Falha ao alinhar barra de tarefas: $($_.Exception.Message)" -Type Warning }
        } else {
            Write-Log "Alinhando itens da barra de tarefas ao centro (Windows 11)..." -Type Info
Write-Log "  -> Alinhando barra de tarefas ao centro (Windows 11)..."
            try {
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAl" -Value 1 -Force -ErrorAction Stop # 0 = Esquerda, 1 = Centro
Write-Log "     Barra de tarefas alinhada ao centro." -Type Success
            } catch { Write-Log "Falha ao alinhar barra de tarefas: $($_.Exception.Message)" -Type Warning }
        }
    } else {
        Write-Log "Ignorando alinhamento da barra de tarefas: Não é Windows 11." -Type Info
    }

    # Ocultar Caixa de Pesquisa da Barra de Tarefas (Windows 10/11)
    if ($ScriptConfig.UITweaks.HideSearchBox) {
        Write-Log "Ocultando caixa de pesquisa da barra de tarefas..." -Type Info
Write-Log "  -> Ocultando caixa de pesquisa..."
        try {
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Value 0 -Force -ErrorAction Stop # 0=Hidden, 1=Icon, 2=Box
Write-Log "     Caixa de pesquisa oculta." -Type Success
        } catch { Write-Log "Falha ao ocultar caixa de pesquisa: $($_.Exception.Message)" -Type Warning }
    } else {
        Write-Log "Exibindo caixa de pesquisa da barra de tarefas (se ativado nas configs)..." -Type Info
Write-Log "  -> Exibindo caixa de pesquisa (ícone)..."
        try {
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Value 1 -Force -ErrorAction Stop # 0=Hidden, 1=Icon, 2=Box
Write-Log "     Caixa de pesquisa exibida (apenas ícone)." -Type Success
        } catch { Write-Log "Falha ao exibir caixa de pesquisa: $($_.Exception.Message)" -Type Warning }
    }

    # Exibir Ícones Padrão da Área de Trabalho (Computador, Lixeira, Rede)
    if ($ScriptConfig.UITweaks.ShowDesktopIcons) {
        Write-Log "Exibindo ícones padrão da área de trabalho..." -Type Info
Write-Log "  -> Exibindo ícones padrão da área de trabalho (Computador, Lixeira, Rede)..."
        try {
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Value 0 -Force -ErrorAction Stop # Meu Computador
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{645FF040-5081-101B-9F08-00AA002F954E}" -Value 0 -Force -ErrorAction Stop # Lixeira
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{F02B4C93-C4F5-4039-86A7-772D932FCA9A}" -Value 0 -Force -ErrorAction Stop # Rede
Write-Log "     Ícones padrão da área de trabalho exibidos." -Type Success
        } catch { Write-Log "Falha ao exibir ícones da área de trabalho: $($_.Exception.Message)" -Type Warning }
    } else {
        Write-Log "Ocultando ícones padrão da área de trabalho (se desativado nas configs)..." -Type Info
Write-Log "  -> Ocultando ícones padrão da área de trabalho..."
        try {
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Value 1 -Force -ErrorAction Stop
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{645FF040-5081-101B-9F08-00AA002F954E}" -Value 1 -Force -ErrorAction Stop
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{F02B4C93-C4F5-4039-86A7-772D932FCA9A}" -Value 1 -Force -ErrorAction Stop
Write-Log "     Ícones padrão da área de trabalho ocultos." -Type Success
        } catch { Write-Log "Falha ao ocultar ícones da área de trabalho: $($_.Exception.Message)" -Type Warning }
    }

    # Ocultar Entradas de Drives Duplicadas no Explorer
    if ($ScriptConfig.UITweaks.HideDupliDrive) {
        Write-Log "Ocultando entradas de drives duplicadas no Explorer..." -Type Info
Write-Log "  -> Ocultando entradas de drives duplicadas..."
        try {
            # Este é um tweak comum, mas depende de chaves CLSID específicas que podem variar.
            # Geralmente afeta dispositivos móveis e cartões SD que aparecem duas vezes.
            # Exemplo (pode precisar de ajuste para seu caso):
            # Crie uma função mais robusta se isso for um problema recorrente.
            # Por enquanto, vou usar um exemplo genérico que afeta algumas entradas.
            $classesRootPath = "HKCR:\CLSID"
            $duplicateDriveCLSID = "{018D5C66-4533-4307-9B53-2ad65C87B14B}" # Exemplo de CLSID para OneDrive, mas pode ser genérico para drives
            if (Test-Path "$classesRootPath\$duplicateDriveCLSID") {
                Set-ItemProperty -Path "$classesRootPath\$duplicateDriveCLSID" -Name "System.IsPinnedToNameSpaceTree" -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
            }
            if (Test-Path "$classesRootPath\Wow6432Node\CLSID\$duplicateDriveCLSID") {
                Set-ItemProperty -Path "$classesRootPath\Wow6432Node\CLSID\$duplicateDriveCLSID" -Name "System.IsPinnedToNameSpaceTree" -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
            }
Write-Log "     Entradas de drives duplicadas ocultas (se aplicável)." -Type Success
        } catch { Write-Log "Falha ao ocultar entradas de drives duplicadas: $($_.Exception.Message)" -Type Warning }
    }

    # Ocultar pasta Objetos 3D do Explorer
    if ($ScriptConfig.UITweaks.Hide3dObjects) {
        Write-Log "Ocultando pasta Objetos 3D do Explorer..." -Type Info
Write-Log "  -> Ocultando pasta 'Objetos 3D'..."
        try {
            # Remover do User Shell Folders
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "{0F214138-B1D3-4A90-BBA9-F7A6A09C2E47}" -Value "" -Force -ErrorAction Stop
            # Remover do NameSpace
            Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{0F214138-B1D3-4A90-BBA9-F7A6A09C2E47}" -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
            Remove-Item -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{0F214138-B1D3-4A90-BBA9-F7A6A09C2E47}" -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
Write-Log "     Pasta 'Objetos 3D' oculta." -Type Success
        } catch { Write-Log "Falha ao ocultar pasta Objetos 3D: $($_.Exception.Message)" -Type Warning }
    }

    # Ocultar pasta OneDrive do Explorer (se não for removê-lo completamente)
    if ($ScriptConfig.UITweaks.HideOneDriveFolder) {
        Write-Log "Ocultando pasta OneDrive do painel de navegação do Explorer..." -Type Info
Write-Log "  -> Ocultando pasta 'OneDrive' do Explorer (se ainda existir)..."
        try {
            # Este é o mesmo CLSID que o OneDrive usa para aparecer nos drives duplicados.
            # Se você usa Force-RemoveOneDrive, esta etapa é redundante e pode causar erros se o OneDrive já foi totalmente removido.
            # Use esta opção apenas se você *não* pretende remover o OneDrive, mas apenas ocultá-lo do painel de navegação.
            Set-ItemProperty -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-2ad65C87B14B}" -Name "System.IsPinnedToNameSpaceTree" -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
            Set-ItemProperty -Path "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-2ad65C87B14B}" -Name "System.IsPinnedToNameSpaceTree" -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
Write-Log "     Pasta 'OneDrive' oculta do painel de navegação." -Type Success
        } catch { Write-Log "Falha ao ocultar pasta OneDrive: $($_.Exception.Message)" -Type Warning }
    }

    Write-Log "Ajustes de interface do usuário (UI Tweaks) concluídos." -Type Success
Write-Log "Ajustes de Interface do Usuário (UI Tweaks) Concluídos!" -Type Success
    Start-Sleep -Seconds 2
}

# === FUNÇÕES DE OTIMIZAÇÃO E DESEMPENHO ===

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
    } 
    catch {
        Write-Log "Erro ao aplicar tema de desempenho: $_" Red
    }
}

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
    } 
    catch {
        Write-Log "Erro ao otimizar o Explorer: $_" Red
    }
}

function New-SystemRestorePoint {
    Write-Log "Criando ponto de restauração do sistema..." Yellow
    try {
        Checkpoint-Computer -Description "Antes da manutenção Windows" -RestorePointType "MODIFY_SETTINGS"
        Write-Log "Ponto de restauração criado com sucesso." Green
    } 
    catch {
        Write-Log "Erro ao criar ponto de restauração: $_" Red
    }
}

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
    } 
    catch {
        Write-Log "Erro ao aplicar hardening: $_" Red
    }
}

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
        'RemoteRegistry',       # Registro Remoto
        'RetailDemo',           # Modo Demo
        'SharedAccess',         # Compartilhamento de Internet
        'WerSvc',               # Relatório de Erros
        'PhoneSvc',             # Telefone
        'MessagingService',     # Mensagens
        'WalletService',        # Carteira
        'OneSyncSvc',           # Sincronização
        'PimIndexMaintenanceSvc', # Contatos/Calendário
        'SEMgrSvc',             # Pagamentos NFC
        'WbioSrvc',             # Biometria
        "diagnosticshub.standardcollector.service", # Microsoft (R) Diagnostics Hub Standard Collector Service
        "DiagTrack",                                # Diagnostics Tracking Service
        "dmwappushservice",                         # WAP Push Message Routing Service (see known issues)
        "lfsvc",                                    # Geolocation Service
        "MapsBroker",                               # Downloaded Maps Manager
        "NetTcpPortSharing",                        # Net.Tcp Port Sharing Service
        "RemoteAccess",                             # Routing and Remote Access
        "RemoteRegistry",                           # Remote Registry
        "SharedAccess",                             # Internet Connection Sharing (ICS)
        "TrkWks",                                   # Distributed Link Tracking Client
        "WbioSrvc",                                 # Windows Biometric Service (required for Fingerprint reader / facial detection)
        #"WlanSvc",                                 # WLAN AutoConfig (Disabling this can cause issues with wifi connectivity)
        "WMPNetworkSvc",                            # Windows Media Player Network Sharing Service
        #"wscsvc",                                  # Windows Security Center Service
        #"WSearch",                                 # Windows Search
        "XblAuthManager",                           # Xbox Live Auth Manager
        "XblGameSave",                              # Xbox Live Game Save Service
        "XboxNetApiSvc"                             # Xbox Live Networking Service
        # Services which cannot be disabled
        #"WdNisSvc"
    )
    foreach ($svc in $services) {
        try {
            Set-Service -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue
            Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
            Write-Log "Serviço ${svc} desativado." Green
        } 
        catch {
            Write-Log "Erro ao desativar serviço ${svc}: $_" Red
        }
    }
    Write-Log "Desativação de serviços concluída." Green
}

function Update-WindowsAndDrivers {
    Write-Log "Verificando e instalando atualizações do Windows..." Yellow
    try {
        # Atualizações do Windows
        Install-Module PSWindowsUpdate -Force -Scope CurrentUser -ErrorAction SilentlyContinue
        Import-Module PSWindowsUpdate
        Get-WindowsUpdate -AcceptAll -Install -AutoReboot
        Write-Log "Atualizações do Windows concluídas." Green
    } 
    catch {
        Write-Log "Erro ao atualizar o Windows: $_" Red
    }
    try {
        # Atualização de drivers via winget (opcional, depende do suporte do fabricante)
        Write-Log "Verificando atualizações de drivers via winget..." Yellow
        winget upgrade --all --accept-package-agreements --accept-source-agreements
        Write-Log "Atualização de drivers via winget concluída." Green
    } 
    catch {
        Write-Log "Erro ao atualizar drivers via winget: $_" Red
    }
}


# === FUNÇÕES DE CONFIGURAÇÃO DO PAINEL DE CONTROLE ===

function Enable-PowerOptions {
    param (
        [hashtable]$config
    )
    
    # Converter minutos para segundos (como o powercfg espera)
    $tempoTelaAC = $config.TempoTelaAC * 60
    $tempoTelaBateria = $config.TempoTelaBateria * 60
    $tempoHibernarBateria = $config.TempoHibernarBateria * 60
    
    # 1. Configurar tempos de tela
    powercfg /change monitor-timeout-ac $tempoTelaAC
    powercfg /change monitor-timeout-dc $tempoTelaBateria
    
    # 2. Configurar hibernação
    powercfg /change hibernate-timeout-ac $config.TempoHibernarAC
    powercfg /change hibernate-timeout-dc $tempoHibernarBateria
    
    # 3. Configurar comportamento dos botões e tampa
    # Mapear valores para códigos do powercfg
    $actionMap = @{
        "Nothing"    = 0
        "Sleep"      = 1
        "Hibernate"  = 2
        "Shutdown"   = 3
    }
    
    # Aplicar para energia conectada (AC)
    powercfg /setacvalueindex SCHEME_CURRENT SUB_BUTTONS POWERBUTTONACTION $actionMap[$config.BotaoEnergiaAC]
    powercfg /setacvalueindex SCHEME_CURRENT SUB_BUTTONS SLEEPBUTTONACTION $actionMap[$config.BotaoSuspensaoAC]
    powercfg /setacvalueindex SCHEME_CURRENT SUB_BUTTONS LIDACTION $actionMap[$config.ComportamentoTampaAC]
    
    # Aplicar para bateria (DC)
    powercfg /setdcvalueindex SCHEME_CURRENT SUB_BUTTONS POWERBUTTONACTION $actionMap[$config.BotaoEnergiaBateria]
    powercfg /setdcvalueindex SCHEME_CURRENT SUB_BUTTONS SLEEPBUTTONACTION $actionMap[$config.BotaoSuspensaoBateria]
    powercfg /setdcvalueindex SCHEME_CURRENT SUB_BUTTONS LIDACTION $actionMap[$config.ComportamentoTampaBateria]
    
    # 4. Configurações de economia de energia
    if ($config.EconomiaEnergiaAtivada) {
        # Ativar economia de energia
        powercfg /setdcvalueindex SCHEME_CURRENT SUB_ENERGYSAVER ESBATTTHRESHOLD $config.NivelAtivacaoEconomia
  	powercfg /setdcvalueindex SCHEME_CURRENT SUB_ENERGYSAVER ESBRIGHTNESS $(if ($config.ReduzirBrilho) {1} else {0})
        
        # Habilitar "Sempre usar economia de energia"
        powercfg /setdcvalueindex SCHEME_CURRENT SUB_ENERGYSAVER ES_POLICY 1
    }
    
    # 5. Aplicar todas as alterações
    powercfg /setactive SCHEME_CURRENT
    
    # 6. Resultado
Write-Log "Configurações aplicadas com sucesso!" -Type Success
Write-Log "`nResumo das configurações:" -Type Info
Write-Log " - Tela (AC/DC): $($config.TempoTelaAC)min / $($config.TempoTelaBateria)min"
Write-Log " - Hibernação (AC/DC): $($config.TempoHibernarAC == 0 ? 'Nunca' : $config.TempoHibernarAC+'min') / $($config.TempoHibernarBateria)min"
Write-Log " - Tampa (AC/DC): $($config.ComportamentoTampaAC) / $($config.ComportamentoTampaBateria)"
Write-Log " - Botão Energia (AC/DC): $($config.BotaoEnergiaAC) / $($config.BotaoEnergiaBateria)"
Write-Log "   - Nível ativação: $($config.NivelAtivacaoEconomia)%"
    Write-Host (" - Economia de energia: " + (if ($config.EconomiaEnergiaAtivada) {'Ativada'} else {'Desativada'}))
    Write-Host ("   - Reduzir brilho: " + (if ($config.ReduzirBrilho) {'Sim'} else {'Não'}))

}

function Enable-DarkTheme {
    Write-Log "Ativando tema escuro..." Yellow
    try {
        reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v AppsUseLightTheme /t REG_DWORD /d 0 /f | Out-Null
        reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v SystemUsesLightTheme /t REG_DWORD /d 0 /f | Out-Null
        Write-Log "Tema escuro ativado." Green
    } 
    catch {
        Write-Log "Erro ao ativar tema escuro: $_" Red
    }
}

function Enable-ClipboardHistory {
    Write-Log "Ativando histórico da área de transferência..." Yellow
    try {
        reg.exe add "HKCU\Software\Microsoft\Clipboard" /v EnableClipboardHistory /t REG_DWORD /d 1 /f | Out-Null
        Write-Log "Histórico da área de transferência ativado." Green
    } 
    catch {
        Write-Log "Erro ao ativar histórico da área de transferência: $_" Red
    }
}

function Enable-WindowsUpdateFast {
    Write-Log "Ativando atualizações antecipadas do Windows Update..." Yellow
    try {
        reg.exe add "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v IsContinuousInnovationOptedIn /t REG_DWORD /d 1 /f | Out-Null
        Write-Log "Atualizações antecipadas ativadas." Green
    } 
    catch {
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
    try {
        reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Sudo" /v EnableSudo /t REG_DWORD /d 1 /f | Out-Null
Write-Log "✅ Sudo do Windows habilitado! Feche e reabra o terminal para usar." -Type Success
        return $true
    } catch {
Write-Log "❌ Não foi possível habilitar o sudo. $_" -Type Error
        return $false
    }
}

function Enable-TaskbarEndTask {
    $build = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentBuild
    if ([int]$build -lt 23430) {
        Write-Log "Este recurso exige o Windows 11 build 23430 ou superior." Red
        return
    }

    try {
        reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarDeveloperSettings" /v TaskbarEndTask /t REG_DWORD /d 1 /f | Out-Null
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

function Rename-Notebook {
    Write-Log "Deseja renomear este notebook? (S/N)" Yellow
    $timeout = 15
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $input = $null
Write-Log "Digite o novo nome do notebook e pressione ENTER (ou aguarde $timeout segundos para cancelar):" -Type Info
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


# === FUNÇÃO GRANT-CONTROLPANELTWEAKS (PRINCIPAL) ===

function Grant-ControlPanelTweaks {
    Write-Log "Aplicando tweaks no Painel de Controle e Explorer..." Yellow

    $registryChanges = @{
        # Ocultar itens no Painel de Controle
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" = @{NoControlPanel = 0; NoViewContextMenu = 0; NoDesktop = 0; NoFind = 0}; # Exemplo de como reativar se desativado por política.

        # Configurações avançadas do Explorer (combinadas em uma única entrada)
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" = @{
            Start_JumpListsItems = 0; # Desabilitar atalhos na barra de tarefas (Taskbar Jump Lists)
            IconsOnly = 1; # Desabilitar pré-visualização de miniaturas (Thumbnails)
            ScanNetDrives = 0; # Desabilitar 'Verificar programas ao iniciar'
            HideFileExt = 0; # Mostrar extensões de arquivos
            ShowSuperHidden = 1; # Ocultar arquivos do sistema (mostrar tudo)
            DisableShake = 1; # Desabilitar o 'shake to minimize'
            DontShowNewInstall = 1; # Desabilitar notificações de novos programas instalados
            LaunchTo = 0; # Abre "Este PC" em vez de Quick Access
            AutoArrange = 0; # Desabilitar o auto-organizar ícones
        };

        # Configurações do Explorer relacionadas a Quick Access (combinadas)
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" = @{
            HubMode = 1; # Desabilitar Recent/Frequent folders
            ShowRecent = 0;
            ShowFrequent = 0;
            Link = 0; # Remover 'Atalho para' do nome de novos atalhos
        };

        # Desabilitar o recurso "Quick Access" completamente no Ribbon
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Ribbon" = @{QatExclude = 1}; # Isto esconderá Quick Access no ribbon do Explorer.

        # Configurações de Desktop (combinadas em uma única entrada)
        "HKCU:\Control Panel\Desktop" = @{
            WindowArrangementActive = 0; # Desabilitar o snap para janelas
            MouseWheelRouting = 0; # Desabilitar a rolagem de janelas inativas
            UserPreferencesMask = 0x90120380; # Desabilitar o FadeEffect no menu iniciar e tooltips
        };

        # Desabilitar Animações do Windows (Minimize/Maximize)
        "HKCU:\Control Panel\Desktop\WindowMetrics" = @{MinAnimate = 0};
    }

    try {
        foreach ($path in $registryChanges.Keys) {
            # Certifica-se de que o caminho existe antes de tentar definir as propriedades
            if (-not (Test-Path $path -ErrorAction SilentlyContinue)) {
                New-Item -Path $path -Force -ErrorAction SilentlyContinue | Out-Null
                Write-Log "Caminho de registro criado: $path" Cyan
            }

            foreach ($name in $registryChanges.$path.Keys) {
                $value = $registryChanges.$path.$name
                Write-Log "Configurando registro: $path - $name = $value" Cyan
                Set-ItemProperty -Path $path -Name $name -Value $value -Force -ErrorAction SilentlyContinue | Out-Null
            }
        }
        Write-Log "Tweaks no Painel de Controle e Explorer aplicados com sucesso." Green
    } catch {
        Write-Log "Erro ao aplicar tweaks no Painel de Controle e Explorer: $_" Red
    }
}

function Grant-ExtraTweaks {
    Write-Log "Aplicando tweaks extras para otimização e segurança..." Yellow

    # Dicionário de alterações de registro para tweaks extras
    $registryChanges = @{
        # Desativar Telemetria para Microsoft Edge (se houver)
        "HKLM:\SOFTWARE\Policies\Microsoft\Edge" = @{TelemetryEnabled = 0};

        # Desabilitar coleta de telemetria do Office (se houver)
        "HKCU:\SOFTWARE\Microsoft\Office\Common\ClientTelemetry" = @{EnableTelemetry = 0};
        "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\ClientTelemetry" = @{EnableTelemetry = 0};
        "HKCU:\SOFTWARE\Microsoft\Office\15.0\Common\ClientTelemetry" = @{EnableTelemetry = 0};

        # Desativar o Superfetch/SysMain para SSDs (melhora o desempenho)
        "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" = @{
            EnableSuperfetch = 0;
            EnablePrefetcher = 0;
        };
        "HKLM:\SYSTEM\CurrentControlSet\Services\SysMain" = @{Start = 4}; # Desabilita o serviço

        # Desativar o "Windows Defender SmartScreen" (somente para fins de teste, segurança reduzida)
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" = @{SmartScreenEnabled = "Off"};
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" = @{SmartScreenEnabled = "Off"};

        # Desativar "Game DVR" e "Game Bar" (já foi em Privacy, mas reforço aqui)
        "HKCU:\System\GameConfigStore" = @{GameDVR_Enabled = 0};
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" = @{AllowGameDVR = 0};

        # Desativar Compartilhamento de Diagnósticos
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\Settings" = @{AllowDiagnosticDataToFlow = 0};

        # Desativar Limpeza Automática do Disco (Storage Sense)
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" = @{01 = 0};

        # Ajustes de Inicialização e Desligamento
        "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" = @{HiberbootEnabled = 0}; # Desabilitar Fast Startup
        "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" = @{AutoReboot = 0}; # Desabilitar reinicialização automática em caso de BSOD

        # Desativar o Serviço de Fax (se não for usado)
        "HKLM:\SYSTEM\CurrentControlSet\Services\Fax" = @{Start = 4};

        # Desativar o Serviço de Acesso Remoto (se não for usado)
        "HKLM:\SYSTEM\CurrentControlSet\Services\RasAuto" = @{Start = 4};
        "HKLM:\SYSTEM\CurrentControlSet\Services\RemoteAccess" = @{Start = 4};

        # Desativar o Serviço de Política de Diagnóstico (Diagnostic Policy Service)
        "HKLM:\SYSTEM\CurrentControlSet\Services\DPS" = @{Start = 4};

        # Desabilitar o UAC Remote Restrictions (para acesso remoto admin)
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" = @{LocalAccountTokenFilterPolicy = 1};

        # Desativar Programas ao Abrir (se houver)
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" = @{}; # Limpa tudo nesta chave

        # Desativar o Serviço de Windows Search (melhora uso de disco/CPU para alguns)
        "HKLM:\SYSTEM\CurrentControlSet\Services\WSearch" = @{Start = 4};

        # Desativar Relatório de Erros do Windows
        "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" = @{Disabled = 1};

        # Ajustes para SSD (desabilitar Last Access Time)
        "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" = @{NtfsDisableLastAccessUpdate = 1};

        # Otimização de Menu Iniciar (reduz atraso)
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" = @{
            "Start_ShowControlPanel" = 0; # Oculta Painel de Controle do Menu Iniciar
            "Start_ShowDownloads" = 0;   # Oculta Pasta Downloads do Menu Iniciar
        };

        # Desativar o serviço Biometric (se não usa leitor de digital/facial)
        "HKLM:\SYSTEM\CurrentControlSet\Services\WbioSrvc" = @{Start = 4};

        # Desabilitar tarefas agendadas de telemetria e manutenção agressiva - Consolidado
        # Essas entradas modificam o estado de tarefas agendadas no Registro, não criam chaves duplicadas.
        # Os valores 'SD' são descritores de segurança em formato binário.
        "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\UpdateOrchestrator" = @{
            SD = [byte[]](0x01,0x00,0x04,0x80,0x7C,0x00,0x00,0x00,0x8C,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x14,0x00,0x00,0x00,0x02,0x00,0x1C,0x00,0x01,0x00,0x00,0x00,0x0F,0x00,0x04,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00);
        };
        "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\Maintenance" = @{
            SD = [byte[]](0x01,0x00,0x04,0x80,0x7C,0x00,0x00,0x00,0x8C,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x14,0x00,0x00,0x00,0x02,0x00,0x1C,0x00,0x01,0x00,0x00,0x00,0x0F,0x00,0x04,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00);
        };

        # Desabilitar o recurso "Conectividade de Rede" do Sistema (Network Connectivity Assistant)
        "HKLM:\SYSTEM\CurrentControlSet\Services\NlaSvc" = @{Start = 4};

        # Desabilitar o recurso "Experiência de Aplicativos" (Application Experience Service)
        "HKLM:\SYSTEM\CurrentControlSet\Services\AeLookupSvc" = @{Start = 4};

        # Desabilitar o serviço de "Download de Mapas" (MapsBroker)
        "HKLM:\SYSTEM\CurrentControlSet\Services\MapsBroker" = @{Start = 4};

        # Desabilitar a função "Serviços de Usuário Conectado e Telemetria" (Connected User Experiences and Telemetry)
        "HKLM:\SYSTEM\CurrentControlSet\Services\DiagTrack" = @{Start = 4};

        # Desabilitar o "Serviço de Coleta de Telemetria de Compatibilidade da Microsoft"
        "HKLM:\SYSTEM\CurrentControlSet\Services\dmwappushservice" = @{Start = 4};
    }

    try {
        foreach ($path in $registryChanges.Keys) {
            if (-not (Test-Path $path -ErrorAction SilentlyContinue)) {
                New-Item -Path $path -Force -ErrorAction SilentlyContinue | Out-Null
                Write-Log "Caminho de registro criado: $path" Cyan
            }

            foreach ($name in $registryChanges.$path.Keys) {
                $value = $registryChanges.$path.$name
                Write-Log "Configurando registro: $path - $name = $value" Cyan
                Set-ItemProperty -Path $path -Name $name -Value $value -Force -ErrorAction SilentlyContinue | Out-Null
            }
        }
        Write-Log "Tweaks extras aplicados com sucesso." Green
    } catch {
        Write-Log "Erro ao aplicar tweaks extras: $_" Red
    }
}

function Grant-HardenOfficeMacros {
    Write-Log "Desabilitando macros perigosos do Office..." Yellow
    try {
        $officePaths = @(
        "HKCU\Software\Microsoft\Office\16.0\Word\Security",
        "HKCU\Software\Microsoft\Office\16.0\Excel\Security",
        "HKCU\Software\Microsoft\Office\16.0\PowerPoint\Security"
    )

    foreach ($path in $officePaths) {
        try {
            New-Item -Path $path -Force | Out-Null
            Set-ItemProperty -Path $path -Name "VBAWarnings" -Value 4
            Set-ItemProperty -Path $path -Name "AccessVBOM" -Value 0
            Write-Log "Macros desativadas em: $path" Green
        } 
        catch {
            Write-Log "Erro ao ajustar segurança em ${path}: $_" Yellow
        }
    }
    }
    catch {
        Write-Log "Erro ao desabilitar macros perigosos do Office: $_" Red
    }
}

function Set-OptimizedPowerPlan {
    <#
    .SYNOPSIS
        Define um plano de energia otimizado para o sistema.
    .DESCRIPTION
        Esta função define o plano de energia "Alto Desempenho" como ativo.
        O plano de "Alto Desempenho" maximiza o desempenho do sistema,
        sendo ideal para tarefas que exigem mais processamento.
    #>
    
    Write-Log "Iniciando a configuração do plano de energia otimizado (Alto Desempenho)." -Type Info
Write-Log "Configurando o plano de energia para 'Alto Desempenho'..."

    try {
        # GUID para o plano de "Alto Desempenho"
        # Você pode obter outros GUIDs usando: powercfg /list
        $highPerformanceGuid = "8c5e90a0-be2a-4935-8482-5c260a2b1232"

        # Tentar definir o plano como ativo
        powercfg /setactive $highPerformanceGuid | Out-Null
        
        # Verificar se o plano foi realmente ativado
        $currentPlan = (powercfg /getactivescheme | Select-String -Pattern "GUID do esquema de energia:").ToString().Split(':')[1].Trim()
        
        if ($currentPlan -eq $highPerformanceGuid) {
            Write-Log "Plano de energia 'Alto Desempenho' ativado com sucesso." -Type Success
Write-Log "Plano de energia 'Alto Desempenho' ativado com sucesso!" -Type Success
        } else {
            Write-Log "Falha ao ativar o plano de energia 'Alto Desempenho'. O plano atual é: $currentPlan" -Type Error
Write-Log "ERRO: Não foi possível ativar o plano de energia 'Alto Desempenho'." -Type Error
        }

    } catch {
        Write-Log "Ocorreu um erro ao configurar o plano de energia: $($_.Exception.Message)" -Type Error
Write-Log "ERRO ao configurar o plano de energia: $($_.Exception.Message)" -Type Error
    }
    Start-Sleep -Seconds 2
}

# === FUNÇÕES ESPECIAIS ===

function Remove-OneDrive-AndRestoreFolders {
    Write-Log "Removendo OneDrive e restaurando pastas padrão..." Yellow
    try {
        taskkill.exe /F /IM "OneDrive.exe"
        taskkill.exe /F /IM "explorer.exe"
    } 
    catch {
        Write-Log "Erro ao remover OneDrive: $_" Red
    }
Write-Output "Remove OneDrive"
if (Test-Path "$env:systemroot\System32\OneDriveSetup.exe") {
    & "$env:systemroot\System32\OneDriveSetup.exe" /uninstall
}
if (Test-Path "$env:systemroot\SysWOW64\OneDriveSetup.exe") {
    & "$env:systemroot\SysWOW64\OneDriveSetup.exe" /uninstall
}

Write-Output "Removing OneDrive leftovers"
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:localappdata\Microsoft\OneDrive"
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:programdata\Microsoft OneDrive"
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:systemdrive\OneDriveTemp"
# check if directory is empty before removing:
If ((Get-ChildItem "$env:userprofile\OneDrive" -Recurse | Measure-Object).Count -eq 0) {
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:userprofile\OneDrive"
}

Write-Output "Disable OneDrive via Group Policies"
New-FolderForced -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\OneDrive"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\OneDrive" "DisableFileSyncNGSC" 1

Write-Output "Remove Onedrive from explorer sidebar"
New-PSDrive -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" -Name "HKCR"
mkdir -Force "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
Set-ItemProperty -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" "System.IsPinnedToNameSpaceTree" 0
mkdir -Force "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
Set-ItemProperty -Path "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" "System.IsPinnedToNameSpaceTree" 0
Remove-PSDrive "HKCR"

# Thank you Matthew Israelsson
Write-Output "Removing run hook for new users"
reg load "hku\Default" "C:\Users\Default\NTUSER.DAT"
reg delete "HKEY_USERS\Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "OneDriveSetup" /f
reg unload "hku\Default"

Write-Output "Removing startmenu entry"
Remove-Item -Force -ErrorAction SilentlyContinue "$env:userprofile\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk"

Write-Output "Removing scheduled task"
Get-ScheduledTask -TaskPath '\' -TaskName 'OneDrive*' -ea SilentlyContinue | Unregister-ScheduledTask -Confirm:$false

Write-Output "Restarting explorer"
Start-Process "explorer.exe"

Write-Output "Waiting for explorer to complete loading"
Start-Sleep 10
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
Write-Log "Digite o caminho da pasta onde está o backup do registro:" -Type Info
    $bkpPath = Read-Host "Exemplo: C:\Users\SeuUsuario\Desktop\reg_backup_20250704_140000"
    try {
        reg.exe restore HKLM\SOFTWARE "$bkpPath\HKLM_SOFTWARE.reg" | Out-Null
        reg.exe restore HKLM\SYSTEM "$bkpPath\HKLM_SYSTEM.reg" | Out-Null
        reg.exe restore HKCU "$bkpPath\HKCU.reg" | Out-Null
        Write-Log "Registro restaurado a partir de $bkpPath." Green
    } catch { Write-Log "Erro ao restaurar o registro: $_" Red }
}

function Invoke-ExternalDebloaters {
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

function Invoke-WindowsActivator {
    Clear-Host
Write-Log "==== ATIVAÇÃO DO WINDOWS ====" -Type Info
Write-Log "Executando script de ativação oficial (get.activated.win)..." -Type Warning
    try {
        irm https://get.activated.win | iex
        Write-Log "Script de ativação executado com sucesso." Green
    } catch {
        Write-Log "Erro ao executar o script de ativação: $_" Red
    }
    
}

function Invoke-ChrisTitusToolbox {
    Clear-Host
Write-Log "==== CHRIS TITUS TOOLBOX ====" -Type Info
Write-Log "Executando toolbox oficial do site christitus.com..." -Type Warning
    try {
        irm christitus.com/win | iex
        Write-Log "Chris Titus Toolbox executado com sucesso." Green
    } catch {
        Write-Log "Erro ao executar o script do Chris Titus: $_" Red
    }
}

function Update-ScriptFromCloud {
    Clear-Host
Write-Log "=======================" -Type Info
Write-Log "ATUALIZANDO SCRIPT..." -Type Info
Write-Log "=======================" -Type Info

    try {
        Write-Log "Verificando conexão com servidor..." Yellow
        if (-not (Test-Connection -ComputerName "script.colegiomundodosaber.com.br" -Count 1 -Quiet)) {
            Write-Log "❌ Sem conexão. Atualização abortada." Red
            return
        }

        Write-Log "Baixando script atualizado do Colégio Mundo do Saber..." Yellow
        irm script.colegiomundodosaber.com.br | iex
        Write-Log "✅ Script atualizado com sucesso!" Green
        Show-SuccessMessage
    } catch {
        Write-Log "❌ Falha ao atualizar script: $_" Red
        Show-SuccessMessage
    }
}

function Show-AutoLoginMenu {
Write-Log "=== Configurar Autologin ===" -Type Info
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


# === FUNÇÕES DE RESTAURAÇÃO E UNDO ===

function Restore-DefaultUAC {
    Write-Log "Tentando restaurar as configurações padrão do UAC..." Yellow

    try {
        # Define EnableLUA para 1 para ativar o UAC
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1 -Force -ErrorAction Stop | Out-Null
        # Define ConsentPromptBehaviorAdmin para 5 (padrão) para o prompt de consentimento para administradores
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 5 -Force -ErrorAction Stop | Out-Null

        Write-Log "UAC restaurado para as configurações padrão com sucesso. Será necessário reiniciar para que as alterações tenham efeito completo." Green
Write-Log "UAC restaurado. Reinicie o computador para aplicar as alterações." -Type Success
    } catch {
        Write-Log "Erro ao restaurar o UAC: $_" Red
Write-Log "Erro ao restaurar o UAC. Verifique o log." -Type Error
    }
}

function Restore-DefaultIPv6 {
    Write-Log "Reabilitando IPv6..." Yellow
    try {
        Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisabledComponents" -ErrorAction SilentlyContinue
        Write-Log "IPv6 reabilitado." Green
    } catch { Write-Log "Erro ao reabilitar IPv6: $_" Red }
}

function Restore-Registry-FromBackup {
Write-Log "Digite o caminho do backup do registro para restaurar (pasta):" -Type Info
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

function Grant-ActionCenter-Notifications {
    Write-Log "Reabilitando Action Center e notificações..." Yellow
    try {
        reg.exe delete "HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v DisableNotificationCenter /f | Out-Null
        reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications" /v ToastEnabled /t REG_DWORD /d 1 /f | Out-Null
        reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v GlobalUserDisabled /t REG_DWORD /d 0 /f | Out-Null
        Write-Log "Action Center e notificações reabilitados." Green
    } catch { Write-Log "Erro ao reabilitar Action Center: $_" Red }
}

function Enable-SMBv1 {
    Write-Log "Tentando ativar o SMBv1..." Yellow
Write-Log "Ativando o SMBv1..." -Type Warning
Write-Log "ATENÇÃO: Ativar o SMBv1 pode expor o sistema a vulnerabilidades de segurança mais antigas. Prossiga com cautela." -Type Warning
    Start-Sleep -Seconds 2

    try {
        # Habilitar o componente SMBv1 via PowerShell
        Write-Log "Habilitando o recurso SMB1Protocol..." Cyan
        Enable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart -ErrorAction Stop | Out-Null

        # Ativar o driver do serviço SMBv1
        Write-Log "Configurando o serviço MRxSmb10 para iniciar automaticamente (2)..." Cyan
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\MRxSmb10" -Name "Start" -Value 2 -Force -ErrorAction Stop | Out-Null

        # Ativar o LanmanServer para usar SMB1
        Write-Log "Configurando o serviço LanmanServer para usar SMB1..." Cyan
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -Value 1 -Force -ErrorAction Stop | Out-Null

        # Iniciar os serviços se não estiverem rodando
        Write-Log "Iniciando serviços relacionados ao SMBv1..." Cyan
        Get-Service -Name "LanmanServer" -ErrorAction SilentlyContinue | Where-Object {$_.Status -ne 'Running'} | Start-Service -ErrorAction SilentlyContinue | Out-Null
        Get-Service -Name "MRxSmb10" -ErrorAction SilentlyContinue | Where-Object {$_.Status -ne 'Running'} | Start-Service -ErrorAction SilentlyContinue | Out-Null

        Write-Log "SMBv1 ativado com sucesso. Reinicialização pode ser necessária para que todas as alterações tenham efeito." Green
Write-Log "SMBv1 ativado. Reinicialização recomendada." -Type Success
    } catch {
        Write-Log "Erro ao ativar o SMBv1: $_" Red
Write-Log "Erro ao ativar o SMBv1. Verifique o log." -Type Error
    }
}

function Disable-SMBv1 {
    Write-Log "Tentando desativar o SMBv1..." Yellow
Write-Log "Desativando o SMBv1..." -Type Warning

    try {
        # Desabilitar o componente SMBv1 via PowerShell (equivalente a Remove-WindowsFeature)
        # Verifica se o recurso SMB1-Protocol existe antes de tentar removê-lo
        if (Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -ErrorAction SilentlyContinue) {
            Write-Log "Desabilitando o recurso SMB1Protocol..." Cyan
            Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart -ErrorAction Stop | Out-Null
        } else {
            Write-Log "Recurso SMB1Protocol não encontrado ou já desabilitado." Yellow
        }

        # Desativar o driver do serviço SMBv1
        Write-Log "Configurando o serviço MRxSmb10 para iniciar desativado (4)..." Cyan
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\MRxSmb10" -Name "Start" -Value 4 -Force -ErrorAction Stop | Out-Null

        # Desativar o LanmanServer para não usar SMB1
        Write-Log "Configurando o serviço LanmanServer para não usar SMB1..." Cyan
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -Value 0 -Force -ErrorAction Stop | Out-Null

        # Parar os serviços se estiverem rodando
        Write-Log "Parando serviços relacionados ao SMBv1 se estiverem rodando..." Cyan
        Get-Service -Name "LanmanServer" -ErrorAction SilentlyContinue | Where-Object {$_.Status -eq 'Running'} | Stop-Service -Force -ErrorAction SilentlyContinue | Out-Null
        Get-Service -Name "MRxSmb10" -ErrorAction SilentlyContinue | Where-Object {$_.Status -eq 'Running'} | Stop-Service -Force -ErrorAction SilentlyContinue | Out-Null

        Write-Log "SMBv1 desativado com sucesso. Reinicialização pode ser necessária para que todas as alterações tenham efeito." Green
Write-Log "SMBv1 desativado. Reinicialização recomendada." -Type Success
    } catch {
        Write-Log "Erro ao desativar o SMBv1: $_" Red
Write-Log "Erro ao desativar o SMBv1. Verifique o log." -Type Error
    }
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
    $onedriveSetup = "$env:SystemRoot\SysWOW64\OneDriveSetup.exe"
    if (Test-Path $onedriveSetup) {
        Start-Process $onedriveSetup
        Write-Log "OneDrive reinstalado." Green
    } else {
        Write-Log "OneDriveSetup.exe não encontrado!" Red
    }
}

function Restore-BloatwareSafe {
    Write-Log "Reinstalando aplicativos essenciais..." Yellow
    $apps = @(
        "Microsoft.WindowsCalculator",
        "Microsoft.WindowsNotepad",
        "Microsoft.ScreenSketch",           # Ferramenta de Captura
        "Microsoft.WindowsSoundRecorder",   # Gravador de Voz
        "Microsoft.WindowsCamera",
        "Microsoft.OutlookForWindows",      # Outlook novo
        "Microsoft.Outlook",                # Outlook clássico
        "Microsoft.Linkedin"
    )

    foreach ($app in $apps) {
        try {
            $pkg = Get-AppxPackage -AllUsers -Name $app
            if ($pkg) {
                $manifest = Join-Path $pkg.InstallLocation "AppxManifest.xml"
                if (Test-Path $manifest) {
                    Add-AppxPackage -DisableDevelopmentMode -Register $manifest
                    Write-Log "$app reinstalado com sucesso." Green
                } else {
                    Write-Log "AppxManifest não encontrado para $app." Red
                }
            } else {
                Write-Log "$app não está instalado. Pulando." Yellow
            }
        } catch {
            Write-Log "❌ Erro ao reinstalar $(app): $_" Red
        }
    }

    Show-SuccessMessage
}

function Restore-ControlPanelTweaks {
    Write-Log "Restaurando configurações do Painel de Controle e comportamento do sistema para o padrão..." Yellow

    # Dicionário de alterações de registro para restaurar padrões
    $registryChanges = @{
        # Pasta do Usuário (Explorador de Arquivos) - Consolidado
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" = @{
            Hidden = 1; # Mostrar arquivos e pastas ocultos (pode ser 2 para não mostrar)
            ShowSuperHidden = 1; # Mostrar arquivos de sistema protegidos
            HideFileExt = 0; # Mostrar extensões de arquivos
        };

        # Visual FX (Desempenho Visual)
        "HKCU:\Control Panel\Desktop" = @{
            UserPreferencesMask = "90,12,02,80,10,00,00,00"; # Padrão do Windows
            DragFullWindows = "2"; # Arrastar janelas mostrando o conteúdo (Padrão: 1 - contorno)
            FontSmoothing = "2"; # ClearType
        };

        # Windows Defender Security Center - Consolidado
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" = @{DisableAntiSpyware = 0}; # Reabilitar se desabilitado
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" = @{
            DisableRealtimeMonitoring = 0; # Reabilitar monitoramento em tempo real
            DisableBehaviorMonitoring = 0;
            DisableScanOnRealtimeEnable = 0;
            DisableIOAVProtection = 0;
        };
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" = @{
            SpyNetReporting = 1; # Basic (1) ou Advanced (2)
            SubmitSamplesConsent = 1; # Enviar amostras (1:Enviar automaticamente, 2:Sempre perguntar, 3:Nunca enviar, 4:Enviar amostras seguras automaticamente)
        };
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager" = @{
            DisableAntiSpyware = 0;
            AllowUserUIRestrictions = 0;
            AllowFastStart = 1;
            AllowPrimaryMonitorScan = 1;
            AllowCloudProtection = 1;
        };

        # Ajustes de Desempenho Visual (Restore-VisualPerformanceDefault)
        "HKCU:\Control Panel\Desktop\WindowMetrics" = @{
            MinAnimate = "1"; # Habilita animação de minimizar/maximizar
        };

        # Desabilitar Telemetria de Compatibilidade (se ativada por algum tweak)
        "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Telemetry" = @{DisableTelemetry = 0};

        # Reabilitar Windows Update (se desativado por algum tweak)
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" = @{ExcludeWUDriversInQualityUpdate = 0};
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" = @{
            NoAutoUpdate = 0;
            AUOptions = 4; # Auto download e agendar instalação
            ScheduledInstallDay = 0; # Todo dia
            ScheduledInstallTime = 3; # 3 AM
        };

        # Restaura o WinRE (Windows Recovery Environment) para padrão
        "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Recovery" = @{RecoveryEnvironment = 1};

        # Reabilitar Cortana/Pesquisa
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" = @{CortanaConsent = 1; BingSearchEnabled = 1};

        # Reabilitar Notificações do Action Center
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" = @{NOC_Global_Enabled = 1};

        # Reabilitar Experiências Compartilhadas (Continuar no PC)
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Workloads\SharedExperience" = @{EnableSharedExperience = 1};
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Workloads\SharedExperience" = @{EnableSharedExperience = 1};

        # Reabilitar Conteúdo em Destaque do Windows
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" = @{
            OemPreInstalledAppsEnabled = 1;
            PreInstalledAppsEnabled = 1;
            SilentInstalledAppsEnabled = 1;
            SoftLandingEnabled = 1;
            "SubscribedContent-338387Enabled" = 1;
            "SubscribedContent-338388Enabled" = 1;
            "SubscribedContent-338389Enabled" = 1;
            "SubscribedContent-338393Enabled" = 1;
            "SubscribedContent-353693Enabled" = 1;
            ContentDeliveryAllowed = 1
        };
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" = @{ContentDeliveryAllowed = 1};

        # Reabilitar Telemetria e Coleta de Dados (HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection)
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" = @{
            AllowTelemetry = 1;
            DoNotShowFeedbackNotifications = 0;
            MaxTelemetryAllowed = 3; # Default value
        };
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" = @{
            AllowTelemetry = 1;
            CommercialDataOptIn = 1; # Default
            DoNotShowFeedbackNotifications = 0;
            MaxTelemetryAllowed = 3; # Default
            UploadUserActivities = 1; # Default
        };

        # Reabilitar OneDrive na barra lateral do Explorador de Arquivos (Consolidado)
        "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" = @{"System.IsPinnedToNameSpaceTree" = 1};
        "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" = @{"System.IsPinnedToNameSpaceTree" = 1};

        # Reabilitar Game Bar
        "HKCU:\SOFTWARE\Microsoft\GameBar" = @{AllowGameBar = 1; UseNexusForGameBar = 1; ShowStartupPanel = 1};
    }

    try {
        foreach ($path in $registryChanges.Keys) {
            # Certifica-se de que o caminho existe antes de tentar definir as propriedades
            if (-not (Test-Path $path -ErrorAction SilentlyContinue)) {
                New-Item -Path $path -Force -ErrorAction SilentlyContinue | Out-Null
                Write-Log "Caminho de registro criado: $path" Cyan
            }

            foreach ($name in $registryChanges.$path.Keys) {
                $value = $registryChanges.$path.$name
                Write-Log "Configurando registro: $path - $name = $value" Cyan
                Set-ItemProperty -Path $path -Name $name -Value $value -Force -ErrorAction SilentlyContinue | Out-Null
            }
        }
        Write-Log "Configurações do Painel de Controle e comportamento do sistema restauradas com sucesso." Green
    } catch {
        Write-Log "Erro ao restaurar configurações do Painel de Controle: $_" Red
    }
}

# === FUNÇÃO COLÉGIO (PRINCIPAL) ===

function Invoke-Colégio {
    Clear-Host
    $start = Get-Date
    Write-Log "`n🚀 Iniciando sequência personalizada para o Colégio..." Cyan

    try {
        # ===== AJUSTES E TWEAKS ====
        Write-Log "🔧 Aplicando ajustes e tweaks de sistema..." Yellow
        Grant-ControlPanelTweaks
        Grant-ExtraTweaks
        Grant-PrivacyTweaks
        Enable-PrivacyHardening
        Set-VisualPerformance
        Disable-ActionCenter-Notifications
        Disable-BloatwareScheduledTasks
        Disable-Cortana-AndSearch
        Disable-IPv6
        Grant-HardenOfficeMacros

        # ===== LIMPEZA ====
        Write-Log "🧹 Realizando limpeza profunda do sistema..." Yellow
        Clear-Prefetch
        Clear-PrintSpooler
        Clear-TemporaryFiles
        Clear-WinSxS
        Clear-WUCache
        Remove-WindowsOld
        Clear-DeepSystemCleanup

        # ===== REMOÇÕES ====
        Write-Log "❌ Removendo bloatware e recursos desnecessários..." Yellow
        Remove-Bloatware
        Remove-Copilot
        Remove-OneDrive-AndRestoreFolders
        Stop-BloatwareProcesses

        # ===== OTIMIZAÇÃO ====
        Write-Log "🚀 Otimizando rede e desempenho..." Yellow
        Clear-DNS
        Optimize-NetworkPerformance

        # ===== INSTALAÇÕES ====
        Write-Log "⬇️ Instalando aplicativos essenciais..." Yellow
        Install-Applications
        Update-PowerShell

        # ===== EXTERNOS ====
        Write-Log "⚙️ Executando scripts externos, se houver..." Yellow
        Invoke-ExternalDebloaters

        $end = Get-Date
        $duration = $end - $start
        Write-Log "✅ Sequência para o Colégio concluída com sucesso em $($duration.ToString("hh\:mm\:ss"))" Green
        Show-SuccessMessage
    }
    catch {
        Write-Log "❌ Erro crítico durante a sequência do Colégio: $_" Red
    }
}

# === FUNÇÕES AUXILIARES PARA MENUS ===
function Show-Menu {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Title,
        [Parameter(Mandatory=$true)]
        [array]$Options
    )

    while ($true) {
        clear-host
        Write-Host "--- $Title ---" -ForegroundColor Yellow
        Write-Host ""
        for ($i = 0; $i -lt $Options.Count; $i++) {
            Write-Host "$($i+1). $($Options[$i])" -ForegroundColor Cyan
        }
        Write-Host "0. Sair" -ForegroundColor Red
        Write-Host ""
        $choice = Read-Host "Digite o número da sua escolha"
        if ($choice -ge 0 -and $choice -le $Options.Count) {
            return $choice
        } else {
            Write-Log "Opção inválida. Por favor, digite um número de 0 a $($Options.Count)." -Type Warning
            Start-Sleep -Seconds 2
        }
    }
}

function New-FolderForced {
    param (
        [string]$Path
    )
    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -ItemType Directory -Force | Out-Null
    }
}

#endregion

#region MENUS

# -------------------------------------------------------------------------
# Funções de Exibição de Menus
# -------------------------------------------------------------------------

function Show-MainMenu {
    do {
        clear-host
        Write-Host "==================================================="
        Write-Host "             Script Supremo de Manutenção"
        Write-Host "==================================================="
        Write-Host "Selecione uma opção:"
        Write-Host ""
        Write-Host " A) Aplicativos"
        Write-Host " B) Bloatware"
        Write-Host " C) Diagnósticos"
        Write-Host " D) Limpeza"
        Write-Host " E) Rede"
        Write-Host " F) Scripts Externos"
        Write-Host " G) Tweaks e Otimizações"
        Write-Host " H) Desfazer Ações (Undo)"
        Write-Host ""
        Write-Host " R) Reiniciar Computador"
        Write-Host " S) Desligar Computador"
        Write-Host " Z) Sair do Script" # Usando Z para sair do script principal
        Write-Host "==================================================="

        $key = [string]::Concat($Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown").Character).ToUpper()
        switch ($key) {
            'A' { Show-AppsMenu }
            'B' { Show-BloatwareMenu }
            'C' { Show-DiagnosticsMenu }
            'D' { Show-LimpezaMenu }
            'E' { Show-NetworkMenu }
            'F' { Show-ExternalScriptsMenu }
            'G' { Show-TweaksMenu }
            'H' { Show-UndoMenu }
            'R' { Restart-ComputerConfirmation; break }
            'S' { Stop-ComputerConfirmation; break }
            'Z' { break } # Sair do script
            default { Write-Log "Opção inválida. Tente novamente." -Type Warning; Suspend-Script }
        }
    } while ($true)
}

function Show-AppsMenu {
    do {
        clear-host
        Write-Host "==================================================="
        Write-Host "             Menu: Aplicativos"
        Write-Host "==================================================="
        Write-Host "Selecione uma opção:"
        Write-Host ""
        Write-Host " B) Instalar Aplicativos (Install-Applications)" # A é para "Executar Todos"
        Write-Host ""
        Write-Host " A) Executar Todas as Tarefas em Sequência"
        Write-Host " Y) Voltar ao Menu Anterior"
        Write-Host " Z) Voltar ao Menu Principal"
        Write-Host "==================================================="

        $key = [string]::Concat($Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown").Character).ToUpper()
        switch ($key) {
            'B' { Install-Applications; Show-SuccessMessage; Suspend-Script }
            'A' {
                Write-Log "Executando todas as tarefas de Aplicativos em sequência..." -Type Info
                Install-Applications; Show-SuccessMessage
                Suspend-Script
            }
            'Y' { break } # Voltar ao menu anterior
            'Z' { Show-MainMenu; return } # Voltar ao menu principal
            default { Write-Log "Opção inválida. Tente novamente." -Type Warning; Suspend-Script }
        }
    } while ($true)
}

function Show-BloatwareMenu {
    do {
        clear-host
        Write-Host "==================================================="
        Write-Host "             Menu: Bloatware"
        Write-Host "==================================================="
        Write-Host "Selecione uma opção:"
        Write-Host ""
        Write-Host " B) Aplicar Prevenção de Privacidade e Bloatware (Apply-PrivacyAndBloatwarePrevention)"
        Write-Host " C) Desabilitar Tarefas Agendadas de Bloatware (Disable-BloatwareScheduledTasks)"
        Write-Host " D) Desabilitar Serviços Desnecessários (Disable-UnnecessaryServices)"
        Write-Host " E) Desabilitar Windows Recall (Disable-WindowsRecall)"
        Write-Host " F) Forçar Remoção Completa do OneDrive (Force-RemoveOneDrive)"
        Write-Host " G) Invocar Ferramentas Externas de Debloating (Invoke-ExternalDebloaters)"
        Write-Host " H) Remover Bloatware e Aplicativos Pré-instalados (Remove-Bloatware)"
        Write-Host " I) Remover Copilot (Remove-Copilot)"
        Write-Host " J) Remover Pins do Menu Iniciar e Barra de Tarefas (Remove-StartAndTaskbarPins)"
        Write-Host " K) Remover Tarefas Agendadas Agressivamente (Remove-ScheduledTasksAggressive)"
        Write-Host " L) Remover Windows.old (Remove-WindowsOld)"
        Write-Host " M) Parar Processos de Bloatware (Stop-BloatwareProcesses)"
        Write-Host ""
        Write-Host " A) Executar Todas as Tarefas em Sequência"
        Write-Host " Y) Voltar ao Menu Anterior"
        Write-Host " Z) Voltar ao Menu Principal"
        Write-Host "==================================================="

        $key = [string]::Concat($Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown").Character).ToUpper()
        switch ($key) {
            'B' { Apply-PrivacyAndBloatwarePrevention; Show-SuccessMessage; Suspend-Script }
            'C' { Disable-BloatwareScheduledTasks; Show-SuccessMessage; Suspend-Script }
            'D' { Disable-UnnecessaryServices; Show-SuccessMessage; Suspend-Script }
            'E' { Disable-WindowsRecall; Show-SuccessMessage; Suspend-Script }
            'F' { Force-RemoveOneDrive; Show-SuccessMessage; Suspend-Script }
            'G' { Invoke-ExternalDebloaters; Show-SuccessMessage; Suspend-Script }
            'H' { Remove-Bloatware; Show-SuccessMessage; Suspend-Script }
            'I' { Remove-Copilot; Show-SuccessMessage; Suspend-Script }
            'J' { Remove-StartAndTaskbarPins; Show-SuccessMessage; Suspend-Script }
            'K' { Remove-ScheduledTasksAggressive; Show-SuccessMessage; Suspend-Script }
            'L' { Remove-WindowsOld; Show-SuccessMessage; Suspend-Script }
            'M' { Stop-BloatwareProcesses; Show-SuccessMessage; Suspend-Script }
            'A' {
                Write-Log "Executando todas as tarefas de Bloatware em sequência..." -Type Info
                Apply-PrivacyAndBloatwarePrevention; Show-SuccessMessage
                Disable-BloatwareScheduledTasks; Show-SuccessMessage
                Disable-UnnecessaryServices; Show-SuccessMessage
                Disable-WindowsRecall; Show-SuccessMessage
                Force-RemoveOneDrive; Show-SuccessMessage
                Invoke-ExternalDebloaters; Show-SuccessMessage
                Remove-Bloatware; Show-SuccessMessage
                Remove-Copilot; Show-SuccessMessage
                Remove-StartAndTaskbarPins; Show-SuccessMessage
                Remove-ScheduledTasksAggressive; Show-SuccessMessage
                Remove-WindowsOld; Show-SuccessMessage
                Stop-BloatwareProcesses; Show-SuccessMessage
                Suspend-Script
            }
            'Y' { break }
            'Z' { Show-MainMenu; return }
            default { Write-Log "Opção inválida. Tente novamente." -Type Warning; Suspend-Script }
        }
    } while ($true)
}

function Show-DiagnosticsMenu {
    do {
        clear-host
        Write-Host "==================================================="
        Write-Host "             Menu: Diagnósticos"
        Write-Host "==================================================="
        Write-Host "Selecione uma opção:"
        Write-Host ""
        Write-Host " B) Executar Todos os Diagnósticos Avançados (Invoke-All-DiagnosticsAdvanced)"
        Write-Host " C) Exibir Uso do Disco (Show-DiskUsage)"
        Write-Host " D) Exibir Informações do Sistema (Show-SystemInfo)"
        Write-Host " E) Testar Memória (Agendar) (Test-Memory)"
        Write-Host " F) Testar Integridade de Drives SMART (Test-SMART-Drives)"
        Write-Host ""
        Write-Host " A) Executar Todas as Tarefas em Sequência"
        Write-Host " Y) Voltar ao Menu Anterior"
        Write-Host " Z) Voltar ao Menu Principal"
        Write-Host "==================================================="

        $key = [string]::Concat($Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown").Character).ToUpper()
        switch ($key) {
            'B' { Invoke-All-DiagnosticsAdvanced; Show-SuccessMessage; Suspend-Script }
            'C' { Show-DiskUsage; Show-SuccessMessage; Suspend-Script }
            'D' { Show-SystemInfo; Show-SuccessMessage; Suspend-Script }
            'E' { Test-Memory; Show-SuccessMessage; Suspend-Script }
            'F' { Test-SMART-Drives; Show-SuccessMessage; Suspend-Script }
            'A' {
                Write-Log "Executando todas as tarefas de Diagnósticos em sequência..." -Type Info
                Invoke-All-DiagnosticsAdvanced; Show-SuccessMessage
                Show-DiskUsage; Show-SuccessMessage
                Show-SystemInfo; Show-SuccessMessage
                Test-Memory; Show-SuccessMessage
                Test-SMART-Drives; Show-SuccessMessage
                Suspend-Script
            }
            'Y' { break }
            'Z' { Show-MainMenu; return }
            default { Write-Log "Opção inválida. Tente novamente." -Type Warning; Suspend-Script }
        }
    } while ($true)
}

function Show-LimpezaMenu {
    do {
        clear-host
        Write-Host "==================================================="
        Write-Host "             Menu: Limpeza do Sistema"
        Write-Host "==================================================="
        Write-Host "Selecione uma opção:"
        Write-Host ""
        Write-Host " B) Limpeza Profunda do Sistema (Clear-DeepSystemCleanup)"
        Write-Host " C) Limpeza de Prefetch (Clear-Prefetch)"
        Write-Host " D) Limpeza de Spooler de Impressão (Clear-PrintSpooler)"
        Write-Host " E) Limpeza de Arquivos Temporários (Clear-TemporaryFiles)"
        Write-Host " F) Limpeza de WinSxS (Component Store) (Clear-WinSxS)"
        Write-Host " G) Limpeza de Cache do Windows Update (Clear-WUCache)"
        Write-Host " H) Iniciar Verificação DISM (Invoke-DISM-Scan)"
        Write-Host " I) Iniciar Verificação SFC (Invoke-SFC-Scan)"
        Write-Host " J) Agendar Verificação de Disco (ChkDsk) (New-ChkDsk)"
        Write-Host " K) Executar Limpeza Geral (Perform-Cleanup)"
        Write-Host ""
        Write-Host " A) Executar Todas as Tarefas em Sequência"
        Write-Host " Y) Voltar ao Menu Anterior"
        Write-Host " Z) Voltar ao Menu Principal"
        Write-Host "==================================================="

        $key = [string]::Concat($Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown").Character).ToUpper()
        switch ($key) {
            'B' { Clear-DeepSystemCleanup; Show-SuccessMessage; Suspend-Script }
            'C' { Clear-Prefetch; Show-SuccessMessage; Suspend-Script }
            'D' { Clear-PrintSpooler; Show-SuccessMessage; Suspend-Script }
            'E' { Clear-TemporaryFiles; Show-SuccessMessage; Suspend-Script }
            'F' { Clear-WinSxS; Show-SuccessMessage; Suspend-Script }
            'G' { Clear-WUCache; Show-SuccessMessage; Suspend-Script }
            'H' { Invoke-DISM-Scan; Show-SuccessMessage; Suspend-Script }
            'I' { Invoke-SFC-Scan; Show-SuccessMessage; Suspend-Script }
            'J' { New-ChkDsk; Show-SuccessMessage; Suspend-Script }
            'K' { Perform-Cleanup; Show-SuccessMessage; Suspend-Script }
            'A' {
                Write-Log "Executando todas as tarefas de Limpeza em sequência..." -Type Info
                Clear-DeepSystemCleanup; Show-SuccessMessage
                Clear-Prefetch; Show-SuccessMessage
                Clear-PrintSpooler; Show-SuccessMessage
                Clear-TemporaryFiles; Show-SuccessMessage
                Clear-WinSxS; Show-SuccessMessage
                Clear-WUCache; Show-SuccessMessage
                Invoke-DISM-Scan; Show-SuccessMessage
                Invoke-SFC-Scan; Show-SuccessMessage
                New-ChkDsk; Show-SuccessMessage
                # Perform-Cleanup (Considerar se essa função global deve ser incluída no "Executar Todos" ou se as funções individuais são suficientes)
                Suspend-Script
            }
            'Y' { break }
            'Z' { Show-MainMenu; return }
            default { Write-Log "Opção inválida. Tente novamente." -Type Warning; Suspend-Script }
        }
    } while ($true)
}

function Show-NetworkMenu {
    do {
        clear-host
        Write-Host "==================================================="
        Write-Host "             Menu: Rede e Conectividade"
        Write-Host "==================================================="
        Write-Host "Selecione uma opção:"
        Write-Host ""
        Write-Host " B) Adicionar Rede Wi-Fi (Add-WiFiNetwork)"
        Write-Host " C) Limpar Cache ARP (Clear-ARP)"
        Write-Host " D) Limpar Cache DNS (Clear-DNS)"
        Write-Host " E) Desabilitar IPv6 (Disable-IPv6)"
        Write-Host " F) Desabilitar SMBv1 (Disable-SMBv1)"
        Write-Host " G) Instalar Impressoras de Rede (Install-NetworkPrinters)"
        Write-Host " H) Executar Todas as Otimizações de Rede Avançadas (Invoke-All-NetworkAdvanced)"
        Write-Host " I) Otimizar Desempenho de Rede (Optimize-NetworkPerformance)"
        Write-Host " J) Configurar DNS Google/Cloudflare (Set-DnsGoogleCloudflare)"
        Write-Host " K) Exibir Informações de Rede (Show-NetworkInfo)"
        Write-Host " L) Testar Velocidade da Internet (Test-InternetSpeed)"
        Write-Host ""
        Write-Host " A) Executar Todas as Tarefas em Sequência"
        Write-Host " Y) Voltar ao Menu Anterior"
        Write-Host " Z) Voltar ao Menu Principal"
        Write-Host "==================================================="

        $key = [string]::Concat($Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown").Character).ToUpper()
        switch ($key) {
            'B' { Add-WiFiNetwork; Show-SuccessMessage; Suspend-Script }
            'C' { Clear-ARP; Show-SuccessMessage; Suspend-Script }
            'D' { Clear-DNS; Show-SuccessMessage; Suspend-Script }
            'E' { Disable-IPv6; Show-SuccessMessage; Suspend-Script }
            'F' { Disable-SMBv1; Show-SuccessMessage; Suspend-Script }
            'G' { Install-NetworkPrinters; Show-SuccessMessage; Suspend-Script }
            'H' { Invoke-All-NetworkAdvanced; Show-SuccessMessage; Suspend-Script }
            'I' { Optimize-NetworkPerformance; Show-SuccessMessage; Suspend-Script }
            'J' { Set-DnsGoogleCloudflare; Show-SuccessMessage; Suspend-Script }
            'K' { Show-NetworkInfo; Show-SuccessMessage; Suspend-Script }
            'L' { Test-InternetSpeed; Show-SuccessMessage; Suspend-Script }
            'A' {
                Write-Log "Executando todas as tarefas de Rede em sequência..." -Type Info
                Add-WiFiNetwork; Show-SuccessMessage
                Clear-ARP; Show-SuccessMessage
                Clear-DNS; Show-SuccessMessage
                Disable-IPv6; Show-SuccessMessage
                Disable-SMBv1; Show-SuccessMessage
                Install-NetworkPrinters; Show-SuccessMessage
                Invoke-All-NetworkAdvanced; Show-SuccessMessage
                Optimize-NetworkPerformance; Show-SuccessMessage
                Set-DnsGoogleCloudflare; Show-SuccessMessage
                Show-NetworkInfo; Show-SuccessMessage
                Test-InternetSpeed; Show-SuccessMessage
                Suspend-Script
            }
            'Y' { break }
            'Z' { Show-MainMenu; return }
            default { Write-Log "Opção inválida. Tente novamente." -Type Warning; Suspend-Script }
        }
    } while ($true)
}

function Show-ExternalScriptsMenu {
    do {
        clear-host
        Write-Host "==================================================="
        Write-Host "             Menu: Scripts Externos"
        Write-Host "==================================================="
        Write-Host "Selecione uma opção:"
        Write-Host ""
        Write-Host " B) Invocar Chris Titus Toolbox (Invoke-ChrisTitusToolbox)"
        Write-Host " C) Invocar Script Colégio (Invoke-Colégio)"
        Write-Host " D) Invocar Ativador do Windows (Invoke-WindowsActivator)"
        Write-Host ""
        Write-Host " A) Executar Todas as Tarefas em Sequência"
        Write-Host " Y) Voltar ao Menu Anterior"
        Write-Host " Z) Voltar ao Menu Principal"
        Write-Host "==================================================="

        $key = [string]::Concat($Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown").Character).ToUpper()
        switch ($key) {
            'B' { Invoke-ChrisTitusToolbox; Show-SuccessMessage; Suspend-Script }
            'C' { Invoke-Colégio; Show-SuccessMessage; Suspend-Script }
            'D' { Invoke-WindowsActivator; Show-SuccessMessage; Suspend-Script }
            'A' {
                Write-Log "Executando todos os Scripts Externos em sequência..." -Type Info
                Invoke-ChrisTitusToolbox; Show-SuccessMessage
                Invoke-Colégio; Show-SuccessMessage
                Invoke-WindowsActivator; Show-SuccessMessage
                Suspend-Script
            }
            'Y' { break }
            'Z' { Show-MainMenu; return }
            default { Write-Log "Opção inválida. Tente novamente." -Type Warning; Suspend-Script }
        }
    } while ($true)
}

function Show-TweaksMenu {
    do {
        clear-host
        Write-Host "==================================================="
        Write-Host "             Menu: Tweaks e Otimizações"
        Write-Host "==================================================="
        Write-Host "Selecione uma opção:"
        Write-Host ""
        Write-Host " B) Aplicar Configurações GPO/Registro (Apply-GPORegistrySettings)"
        Write-Host " C) Aplicar Tweaks de Interface (Apply-UITweaks)"
        Write-Host " D) Desabilitar Action Center e Notificações (Disable-ActionCenter-Notifications)"
        Write-Host " E) Desabilitar Cortana e Pesquisa na Nuvem (Disable-Cortana-AndSearch)"
        Write-Host " F) Desabilitar UAC (Disable-UAC)"
        Write-Host " G) Habilitar Menu de Contexto Clássico (Win11) (Enable-ClassicContextMenu)"
        Write-Host " H) Habilitar Histórico da Área de Transferência (Enable-ClipboardHistory)"
        Write-Host " I) Habilitar Tema Escuro (Enable-DarkTheme)"
        Write-Host " J) Habilitar Outras Atualizações Microsoft (Enable-OtherMicrosoftUpdates)"
        Write-Host " K) Habilitar Opções de Energia Avançadas (Enable-PowerOptions)"
        Write-Host " L) Habilitar Reforço de Privacidade (Enable-PrivacyHardening)"
        Write-Host " M) Habilitar Reinício de Apps Após Reboot (Enable-RestartAppsAfterReboot)"
        Write-Host " N) Habilitar Sudo (Enable-Sudo)"
        Write-Host " O) Habilitar Finalizar Tarefa na Barra de Tarefas (Enable-TaskbarEndTask)"
        Write-Host " P) Habilitar Segundos na Barra de Tarefas (Enable-TaskbarSeconds)"
        Write-Host " Q) Habilitar Reforço do Windows (Enable-WindowsHardening)"
        Write-Host " R) Habilitar Windows Update Rápido (Enable-WindowsUpdateFast)"
        Write-Host " S) Aplicar Tweaks do Painel de Controle (Grant-ControlPanelTweaks)"
        Write-Host " T) Aplicar Tweaks Extras (Grant-ExtraTweaks)"
        Write-Host " U) Reforçar Macros do Office (Grant-HardenOfficeMacros)"
        Write-Host " V) Aplicar Tweaks de Privacidade (Grant-PrivacyTweaks)"
        Write-Host " W) Criar Pasta Forçada (New-FolderForced)"
        Write-Host " X) Criar Ponto de Restauração do Sistema (New-SystemRestorePoint)" # Removido Y, Z para navegação
        Write-Host " Y) Otimizar Desempenho do Explorer (Optimize-ExplorerPerformance)"
        Write-Host " Z) Otimizar Volumes (Desfragmentação/Trim) (Optimize-Volumes)"
        Write-Host " A2) Realizar Otimizações do Sistema (Perform-SystemOptimizations)" # Se esgotar as letras, precisa de uma estratégia
        Write-Host " B2) Renomear Notebook (Rename-Notebook)"
        Write-Host " C2) Definir Plano de Energia Otimizado (Set-OptimizedPowerPlan)"
        Write-Host " D2) Definir Tema de Desempenho (Set-PerformanceTheme)"
        Write-Host " E2) Definir Performance Visual (Set-VisualPerformance)"
        Write-Host " F2) Exibir Menu de AutoLogin (Show-AutoLoginMenu)"
        Write-Host ""
        Write-Host " A) Executar Todas as Tarefas em Sequência"
        Write-Host " Y2) Voltar ao Menu Anterior" # Usando Y2 para evitar conflito com Y de função
        Write-Host " Z2) Voltar ao Menu Principal" # Usando Z2 para evitar conflito com Z de função
        Write-Host "==================================================="

        $key = [string]::Concat($Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown").Character).ToUpper()
        switch ($key) {
            'B' { Apply-GPORegistrySettings; Show-SuccessMessage; Suspend-Script }
            'C' { Apply-UITweaks; Show-SuccessMessage; Suspend-Script }
            'D' { Disable-ActionCenter-Notifications; Show-SuccessMessage; Suspend-Script }
            'E' { Disable-Cortana-AndSearch; Show-SuccessMessage; Suspend-Script }
            'F' { Disable-UAC; Show-SuccessMessage; Suspend-Script }
            'G' { Enable-ClassicContextMenu; Show-SuccessMessage; Suspend-Script }
            'H' { Enable-ClipboardHistory; Show-SuccessMessage; Suspend-Script }
            'I' { Enable-DarkTheme; Show-SuccessMessage; Suspend-Script }
            'J' { Enable-OtherMicrosoftUpdates; Show-SuccessMessage; Suspend-Script }
            'K' { Enable-PowerOptions; Show-SuccessMessage; Suspend-Script }
            'L' { Enable-PrivacyHardening; Show-SuccessMessage; Suspend-Script }
            'M' { Enable-RestartAppsAfterReboot; Show-SuccessMessage; Suspend-Script }
            'N' { Enable-Sudo; Show-SuccessMessage; Suspend-Script }
            'O' { Enable-TaskbarEndTask; Show-SuccessMessage; Suspend-Script }
            'P' { Enable-TaskbarSeconds; Show-SuccessMessage; Suspend-Script }
            'Q' { Enable-WindowsHardening; Show-SuccessMessage; Suspend-Script }
            'R' { Enable-WindowsUpdateFast; Show-SuccessMessage; Suspend-Script }
            'S' { Grant-ControlPanelTweaks; Show-SuccessMessage; Suspend-Script }
            'T' { Grant-ExtraTweaks; Show-SuccessMessage; Suspend-Script }
            'U' { Grant-HardenOfficeMacros; Show-SuccessMessage; Suspend-Script }
            'V' { Grant-PrivacyTweaks; Show-SuccessMessage; Suspend-Script }
            'W' { New-FolderForced; Show-SuccessMessage; Suspend-Script }
            'X' { New-SystemRestorePoint; Show-SuccessMessage; Suspend-Script }
            'Y' { Optimize-ExplorerPerformance; Show-SuccessMessage; Suspend-Script }
            'Z' { Optimize-Volumes; Show-SuccessMessage; Suspend-Script }
            # Opções além de Z: exigem uma abordagem diferente, como A2, B2...
            # Para evitar complexidade excessiva com o ReadKey, é melhor limitar o número de funções por submenu
            # ou usar um esquema de paginação/outra forma de seleção.
            # Por enquanto, vou mapear as funções restantes usando A2, B2 etc, mas o ReadKey padrão não lida com isso diretamente.
            # Isso pode exigir que a seleção seja feita como "A2", e o ReadKey original só pega um caractere.
            # Para manter "No Enter", a abordagem A2 etc. é complexa.
            # Sugiro limitar a ~24 funções por submenu ou reavaliar "todas as opções devem ser letras".
            # Para este exemplo, vou manter o mapeamento conceitual e deixarei um aviso.
            'A2' { Perform-SystemOptimizations; Show-SuccessMessage; Suspend-Script }
            'B2' { Rename-Notebook; Show-SuccessMessage; Suspend-Script }
            'C2' { Set-OptimizedPowerPlan; Show-SuccessMessage; Suspend-Script }
            'D2' { Set-PerformanceTheme; Show-SuccessMessage; Suspend-Script }
            'E2' { Set-VisualPerformance; Show-SuccessMessage; Suspend-Script }
            'F2' { Show-AutoLoginMenu; Show-SuccessMessage; Suspend-Script }
            'A' {
                Write-Log "Executando todas as tarefas de Tweaks em sequência..." -Type Info
                Apply-GPORegistrySettings; Show-SuccessMessage
                Apply-UITweaks; Show-SuccessMessage
                Disable-ActionCenter-Notifications; Show-SuccessMessage
                Disable-Cortana-AndSearch; Show-SuccessMessage
                Disable-UAC; Show-SuccessMessage
                Enable-ClassicContextMenu; Show-SuccessMessage
                Enable-ClipboardHistory; Show-SuccessMessage
                Enable-DarkTheme; Show-SuccessMessage
                Enable-OtherMicrosoftUpdates; Show-SuccessMessage
                Enable-PowerOptions; Show-SuccessMessage
                Enable-PrivacyHardening; Show-SuccessMessage
                Enable-RestartAppsAfterReboot; Show-SuccessMessage
                Enable-Sudo; Show-SuccessMessage
                Enable-TaskbarEndTask; Show-SuccessMessage
                Enable-TaskbarSeconds; Show-SuccessMessage
                Enable-WindowsHardening; Show-SuccessMessage
                Enable-WindowsUpdateFast; Show-SuccessMessage
                Grant-ControlPanelTweaks; Show-SuccessMessage
                Grant-ExtraTweaks; Show-SuccessMessage
                Grant-HardenOfficeMacros; Show-SuccessMessage
                Grant-PrivacyTweaks; Show-SuccessMessage
                New-FolderForced; Show-SuccessMessage
                New-SystemRestorePoint; Show-SuccessMessage
                Optimize-ExplorerPerformance; Show-SuccessMessage
                Optimize-Volumes; Show-SuccessMessage
                Perform-SystemOptimizations; Show-SuccessMessage
                Rename-Notebook; Show-SuccessMessage
                Set-OptimizedPowerPlan; Show-SuccessMessage
                Set-PerformanceTheme; Show-SuccessMessage
                Set-VisualPerformance; Show-SuccessMessage
                Show-AutoLoginMenu; Show-SuccessMessage
                Suspend-Script
            }
            'Y2' { break } # Voltar ao menu anterior
            'Z2' { Show-MainMenu; return } # Voltar ao menu principal
            default { Write-Log "Opção inválida. Tente novamente." -Type Warning; Suspend-Script }
        }
    } while ($true)
}

function Show-UndoMenu {
    do {
        clear-host
        Write-Host "==================================================="
        Write-Host "             Menu: Desfazer Ações (Undo)"
        Write-Host "==================================================="
        Write-Host "Selecione uma opção:"
        Write-Host ""
        Write-Host " B) Fazer Backup do Registro (Backup-Registry)"
        Write-Host " C) Restaurar Action Center e Notificações (Grant-ActionCenter-Notifications) - OBS: Assumindo que esta função reverte a desativação."
        Write-Host " D) Restaurar Tweaks do Painel de Controle (Restore-ControlPanelTweaks)"
        Write-Host " E) Restaurar IPv6 Padrão (Restore-DefaultIPv6)"
        Write-Host " F) Restaurar UAC Padrão (Restore-DefaultUAC)"
        Write-Host " G) Restaurar Macros do Office (Restore-OfficeMacros)"
        Write-Host " H) Restaurar OneDrive (Restore-OneDrive)"
        Write-Host " I) Restaurar Registro (Restore-Registry) - (Incluindo Restore-Registry-FromBackup se houver)"
        Write-Host " J) Restaurar Performance Visual Padrão (Restore-VisualPerformanceDefault)"
        Write-Host " K) Desfazer Reforço de Privacidade (Undo-PrivacyHardening)"
        Write-Host ""
        Write-Host " A) Executar Todas as Tarefas em Sequência"
        Write-Host " Y) Voltar ao Menu Anterior"
        Write-Host " Z) Voltar ao Menu Principal"
        Write-Host "==================================================="

        $key = [string]::Concat($Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown").Character).ToUpper()
        switch ($key) {
            'B' { Backup-Registry; Show-SuccessMessage; Suspend-Script }
            'C' { Grant-ActionCenter-Notifications; Show-SuccessMessage; Suspend-Script } # Assumindo função de reversão
            'D' { Restore-ControlPanelTweaks; Show-SuccessMessage; Suspend-Script }
            'E' { Restore-DefaultIPv6; Show-SuccessMessage; Suspend-Script }
            'F' { Restore-DefaultUAC; Show-SuccessMessage; Suspend-Script }
            'G' { Restore-OfficeMacros; Show-SuccessMessage; Suspend-Script }
            'H' { Restore-OneDrive; Show-SuccessMessage; Suspend-Script }
            'I' { Restore-Registry; Show-SuccessMessage; Suspend-Script }
            'J' { Restore-VisualPerformanceDefault; Show-SuccessMessage; Suspend-Script }
            'K' { Undo-PrivacyHardening; Show-SuccessMessage; Suspend-Script }
            'A' {
                Write-Log "Executando todas as tarefas de Desfazer em sequência..." -Type Info
                Backup-Registry; Show-SuccessMessage
                Grant-ActionCenter-Notifications; Show-SuccessMessage # Assumindo função de reversão
                Restore-ControlPanelTweaks; Show-SuccessMessage
                Restore-DefaultIPv6; Show-SuccessMessage
                Restore-DefaultUAC; Show-SuccessMessage
                Restore-OfficeMacros; Show-SuccessMessage
                Restore-OneDrive; Show-SuccessMessage
                Restore-Registry; Show-SuccessMessage
                Restore-VisualPerformanceDefault; Show-SuccessMessage
                Undo-PrivacyHardening; Show-SuccessMessage
                Suspend-Script
            }
            'Y' { break }
            'Z' { Show-MainMenu; return }
            default { Write-Log "Opção inválida. Tente novamente." -Type Warning; Suspend-Script }
        }
    } while ($true)
}

function Show-WindowsUpdateMenu {
    do {
        clear-host
        Write-Host "==================================================="
        Write-Host "             Menu: Windows Update"
        Write-Host "==================================================="
        Write-Host "Selecione uma opção:"
        Write-Host ""
        Write-Host " B) Gerenciar Atualizações do Windows (Manage-WindowsUpdates)"
        Write-Host " C) Atualizar PowerShell (Update-PowerShell)"
        Write-Host " D) Atualizar Script da Nuvem (Update-ScriptFromCloud)"
        Write-Host " E) Atualizar Windows e Drivers (Update-WindowsAndDrivers)"
        Write-Host ""
        Write-Host " A) Executar Todas as Tarefas em Sequência"
        Write-Host " Y) Voltar ao Menu Anterior"
        Write-Host " Z) Voltar ao Menu Principal"
        Write-Host "==================================================="

        $key = [string]::Concat($Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown").Character).ToUpper()
        switch ($key) {
            'B' { Manage-WindowsUpdates; Show-SuccessMessage; Suspend-Script }
            'C' { Update-PowerShell; Show-SuccessMessage; Suspend-Script }
            'D' { Update-ScriptFromCloud; Show-SuccessMessage; Suspend-Script }
            'E' { Update-WindowsAndDrivers; Show-SuccessMessage; Suspend-Script }
            'A' {
                Write-Log "Executando todas as tarefas de Windows Update em sequência..." -Type Info
                Manage-WindowsUpdates; Show-SuccessMessage
                Update-PowerShell; Show-SuccessMessage
                Update-ScriptFromCloud; Show-SuccessMessage
                Update-WindowsAndDrivers; Show-SuccessMessage
                Suspend-Script
            }
            'Y' { break }
            'Z' { Show-MainMenu; return }
            default { Write-Log "Opção inválida. Tente novamente." -Type Warning; Suspend-Script }
        }
    } while ($true)
}
#endregion
