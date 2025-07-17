# ===============================
# SCRIPT SUPREMO DE MANUTENÇÃO 🛠️
# ===============================
# Iniciado em: $(Get-Date)
# Desenvolvido com sangue, café e PowerShell 💪

# clear-host
Write-Host "-------------------------------------------------------------------------"
Write-Host "| Script pra ajustes de notebooks do ambiente do Colégio Mundo do Saber |"
Write-Host "-------------------------------------------------------------------------"

#region → PARÂMETROS DE EXECUÇÃO (Adicionado)
[CmdletBinding()]
param (
    [Parameter(HelpMessage="Executa todas as rotinas de limpeza.")]
    [bool]$RunAllCleanup = $false,

    [Parameter(HelpMessage="Executa a remoção de Bloatware.")]
    [bool]$RunBloatwareRemoval = $false,

    [Parameter(HelpMessage="Aplica os ajustes de privacidade e registro.")]
    [bool]$RunPrivacyTweaks = $false,

    [Parameter(HelpMessage="Otimiza o desempenho de rede.")]
    [bool]$RunNetworkOptimization = $false,

    [Parameter(HelpMessage="Instala os aplicativos definidos.")]
    [bool]$RunAppInstallation = $false,

    [Parameter(HelpMessage="Executa diagnósticos do sistema.")]
    [bool]$RunDiagnostics = $false,

    [Parameter(HelpMessage="Cria um ponto de restauração do sistema antes de iniciar.")]
    [bool]$CreateRestorePoint = $false,

    [Parameter(HelpMessage="Força a remoção completa do OneDrive.")]
    [bool]$ForceOneDriveRemoval = $false,

    [Parameter(HelpMessage="Remove e desativa o Windows Copilot.")]
    [bool]$RemoveCopilot = $false,

    [Parameter(HelpMessage="Desativa o recurso Windows Recall.")]
    [bool]$DisableRecall = $false,

    [Parameter(HelpMessage="Executa o processo de atualização do Windows via PSWindowsUpdate.")]
    [bool]$RunWindowsUpdate = $false,

    [Parameter(HelpMessage="Aplica a configuração de plano de energia otimizado.")]
    [bool]$ApplyOptimizedPowerPlan = $false
)
#endregion

# ===============================
# CONFIGURAÇÕES GLOBAIS DO SCRIPT
# ===============================

$ScriptConfig = @{
    # Configurações Gerais
    LogFilePath = "C:\Logs\ScriptSupremo.log" # Onde os logs serão salvos
    CreateRestorePoint = $false # Define se um ponto de restauração deve ser criado na automação
    ConfirmationRequired = $true # Define se prompts de confirmação são exibidos (true/false)

    # Gerenciamento de Limpeza e Otimização
    Cleanup = @{
        CleanTemporaryFiles = $true
        CleanWUCache = $true
        OptimizeVolumes = $true
        PerformDeepSystemCleanup = $true
        ClearDNSCache = $true
        DisableMemoryDumps = $true
    }

    # Remoção de Bloatware e Componentes
    BloatwareRemoval = @{
        RemovePreinstalledApps = $true # Remova apps pré-instalados (e.g., Xbox, Solitaire)
        RemoveCopilot = $false # Remover/Desativar Windows Copilot
        DisableRecall = $false # Desativar Windows Recall
        ForceOneDriveRemoval = $false # Forçar remoção completa do OneDrive
    }

    # Ajustes de Privacidade e Registro
    PrivacyTweaks = @{
        DisableTelemetry = $true
        DisableDiagnosticData = $true
        BlockTelemetryHosts = $true
        DisableLocationServices = $true
        DisableActivityHistory = $true
        DisableAdvertisingID = $true
        DisableCortana = $true
        DisableBiometrics = $false # Desativar biometria (se não usar)
        DisableFeedbackRequests = $true
        DisableSuggestedContent = $true
        DisableAutoUpdatesStoreApps = $true
        DisableWidgets = $true # Desativar widgets do Windows 11
        DisableNewsAndInterests = $true # Desativar notícias e interesses na barra de tarefas (Windows 10)
    }

    # Otimização de Rede
    NetworkOptimization = @{
        DisableNetworkThrottling = $true
        OptimizeDNSSettings = $true
        DisableLargeSendOffload = $true
    }

    # Instalação de Aplicativos
    AppInstallation = @{
        InstallApps = $true
        # Sua lista de IDs de aplicativos pode ser movida para cá ou permanecer na função,
        # dependendo da sua preferência de flexibilidade. Por enquanto, a lista pode ficar na função.
        # PackageManager = 'Winget' # 'Winget', 'Chocolatey', 'Prompt'
    }

    # Configurações de GPO via Registro
    GPORegistrySettings = @{
        EnableUpdateManagement = $true
        DisableAutoReboot = $true
        SetScheduledUpdateTime = $true
        DisableDriverUpdates = $false # Desativar drivers via WU (true/false)
        ConfigureEdge = $true
        ConfigureChrome = $true
        DisableWindowsTips = $true # <<<< ADICIONE ESTA LINHA AQUI
    }

    # Plano de Energia Otimizado
    PowerPlan = @{
        ApplyOptimizedPlan = $true
        PlanName = "Plano de Energia Supremacy" # Nome do plano a ser criado
        GUID = "" # Preenchido automaticamente ou pode ser um GUID específico
    }
	
	# Configurações de Interface do Usuário (UI Tweaks) <<<< NOVA SEÇÃO
    UITweaks = @{
        EnableDarkMode = $true
        DisableTransparency = $true
        DisableAnimations = $true
        TaskbarAlignLeft = $false # $true para alinhar à esquerda, $false para centro (Win 11)
        HideSearchBox = $true # Ocultar caixa de pesquisa da barra de tarefas (Win 10/11)
        ShowDesktopIcons = $true # Exibir ícones padrão da área de trabalho (Computador, Lixeira, etc.)
        HideDupliDrive = $true # Ocultar entradas de drives duplicadas no Explorer (Win 10/11)
        Hide3dObjects = $true # Ocultar pasta Objetos 3D do Explorer
        HideOneDriveFolder = $false # Ocultar pasta OneDrive do Explorer (se não for removê-lo completamente)
    }

    # Outras Utilitades
    EnableDeveloperMode = $false # Ativar modo desenvolvedor para side-loading de apps
    HideSearchBox = $true # Ocultar caixa de pesquisa da barra de tarefas
    ShowDesktopIcons = $true # Exibir ícones padrão da área de trabalho (Computador, Lixeira, etc.)
    # ... Adicione mais configurações conforme necessário ...
}

# Você pode usar a hashtable $ScriptConfig agora. Exemplo:
# $ScriptConfig.LogFilePath
# $ScriptConfig.Cleanup.CleanTemporaryFiles$global:ConfirmPreference = "None"
$global:ProgressPreference = 'Continue'
$global:ErrorActionPreference = "SilentlyContinue"
$VerbosePreference = "SilentlyContinue"
$IsWindows11 = (Get-CimInstance Win32_OperatingSystem).Caption -like "*Windows 11*"

$logFile = "$PSScriptRoot\log.txt"
$startTime = Get-Date

#region → Configurações Iniciais
$Host.UI.RawUI.WindowTitle = "MANUTENÇÃO WINDOWS - NÃO FECHE ESTA JANELA"
#Clear-Host

# Verifica se é administrador
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Este script precisa ser executado como Administrador." -ForegroundColor Red
    Write-Host "Por favor, feche e execute novamente como Administrador." -ForegroundColor Yellow
    pause
    exit
}

#endregion

# === CONFIGURAÇÕES GLOBAIS ===
$global:ConfirmPreference = "None"
$global:ProgressPreference = 'Continue'  
$global:ErrorActionPreference = "SilentlyContinue"
$VerbosePreference = "SilentlyContinue" 

$logFile = "$PSScriptRoot\log.txt"
$startTime = Get-Date

#region → Configurações Iniciais
$Host.UI.RawUI.WindowTitle = "MANUTENÇÃO WINDOWS - NÃO FECHE ESTA JANELA"
#Clear-Host

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

#endregion

#region → FUNÇÕES

# === FUNÇÕES DE UTILIDADE ===
function Write-Log {
    param([string]$message, [string]$color = "White")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] $message"
    Add-Content -Path $logFile -Value $logMessage
    Write-Host $logMessage -ForegroundColor $color
}

function Suspend-Script {
    Write-Host "`nPressione ENTER para continuar..." -ForegroundColor Cyan
    do {
        $key = [System.Console]::ReadKey($true)
    } until ($key.Key -eq 'Enter')
}

function Test-RequiredFunctions {
    param (
        [string[]]$FunctionList
    )

    Write-Host "🔎 Verificando funções exigidas pelo script..." -ForegroundColor Cyan
    $allGood = $true

    foreach ($func in $FunctionList) {
        if (Get-Command $func -ErrorAction SilentlyContinue) {
            Write-Host "✅ $func" -ForegroundColor Green
        } else {
            Write-Host "❌ $func (não encontrada)" -ForegroundColor Red
            $allGood = $false
        }
    }

    if (-not $allGood) {
        Write-Host "`n❗ Algumas funções estão faltando. O script pode falhar!" -ForegroundColor Yellow
        # Você pode descomentar para abortar:
        # throw "Funções ausentes detectadas. Corrija antes de continuar."
    } else {
        Write-Host "`n✔️ Todas as funções estão disponíveis. Continuando execução..." -ForegroundColor Cyan
    }
}

function Show-SuccessMessage {
    Write-Host "`n✅ Tarefa concluída com sucesso!" -ForegroundColor Green
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
    [CmdletBinding()]
    param()

    Write-Log "Iniciando reinício do Windows Explorer..." -Type Info
    Write-Host "Reiniciando o Windows Explorer..." -ForegroundColor Magenta

    try {
        Write-Host "Encerrando processo Explorer..." -ForegroundColor Cyan
        taskkill.exe /F /IM "explorer.exe" /T | Out-Null
        Write-Log "Processo Explorer encerrado." -Type Success

        Write-Host "Iniciando Explorer..." -ForegroundColor Cyan
        Start-Process "explorer.exe"
        Write-Log "Processo Explorer iniciado." -Type Success

        Write-Host "Aguardando Explorer carregar..." -ForegroundColor Yellow
        Start-Sleep -Seconds 5 # Dê um tempo para o Explorer carregar completamente
        Write-Log "Explorer carregado com sucesso." -Type Success

        Write-Log "Reinício do Windows Explorer concluído com sucesso." -Type Success
        Write-Host "Windows Explorer reiniciado!" -ForegroundColor Green

    } catch {
        Write-Log "Ocorreu um erro ao reiniciar o Windows Explorer: $($_.Exception.Message)" -Type Error
        Write-Host "ERRO ao reiniciar o Windows Explorer: $($_.Exception.Message)" -ForegroundColor Red
    }
    Start-Sleep -Seconds 2
}
Write-Log "Iniciando script de manutenção..." Cyan



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
    [CmdletBinding()]
    param()

    Write-Log "Iniciando o gerenciamento de atualizações do Windows." -Type Info
    Write-Host "Iniciando o gerenciamento de atualizações do Windows..." -ForegroundColor Magenta

    try {
        # 1. Verificar e instalar o módulo PSWindowsUpdate
        if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
            Write-Log "Módulo PSWindowsUpdate não encontrado. Tentando instalar..." -Type Warning
            Write-Host "Módulo PSWindowsUpdate não encontrado. Tentando instalar do PowerShell Gallery..." -ForegroundColor Yellow
            try {
                Install-Module -Name PSWindowsUpdate -Force -AllowClobber -Scope AllUsers -ErrorAction Stop
                Write-Log "Módulo PSWindowsUpdate instalado com sucesso." -Type Success
                Write-Host "Módulo PSWindowsUpdate instalado com sucesso!" -ForegroundColor Green
            } catch {
                Write-Log "Falha ao instalar o módulo PSWindowsUpdate: $($_.Exception.Message)" -Type Error
                Write-Host "ERRO: Não foi possível instalar o módulo PSWindowsUpdate. As atualizações não poderão ser gerenciadas automaticamente. $($_.Exception.Message)" -ForegroundColor Red
                Start-Sleep -Seconds 5
                return # Sai da função se a instalação falhar
            }
        } else {
            Write-Log "Módulo PSWindowsUpdate já está instalado." -Type Info
            Write-Host "Módulo PSWindowsUpdate já está instalado." -ForegroundColor Green
        }

        # Importar o módulo (garantir que está carregado)
        Import-Module PSWindowsUpdate -ErrorAction SilentlyContinue

        # 2. Oferecer opções de atualização
        Write-Host "Opções de Atualização:" -ForegroundColor Cyan
        Write-Host "1) Buscar e Instalar TODAS as atualizações (incluindo opcionais/drivers)" -ForegroundColor Green
        Write-Host "2) Buscar e Instalar apenas atualizações CRÍTICAS e de SEGURANÇA" -ForegroundColor Green
        Write-Host "3) Apenas buscar atualizações (não instalar)" -ForegroundColor Green
        Write-Host "0) Voltar ao Menu Principal" -ForegroundColor Red
        $updateChoice = Read-Host "Escolha uma opção de atualização"

        switch ($updateChoice) {
            "1" {
                Write-Log "Buscando e instalando TODAS as atualizações (incluindo opcionais/drivers)..." -Type Info
                Write-Host "Buscando e instalando TODAS as atualizações..." -ForegroundColor Yellow
                Get-WindowsUpdate -Install -AcceptAll -AutoReboot | Out-Null # -Install e -AcceptAll para instalar tudo
                Write-Log "Processo de atualização completo (todas as atualizações)." -Type Success
            }
            "2" {
                Write-Log "Buscando e instalando atualizações CRÍTICAS e de SEGURANÇA..." -Type Info
                Write-Host "Buscando e instalando atualizações CRÍTICAS e de SEGURANÇA..." -ForegroundColor Yellow
                Get-WindowsUpdate -Install -AcceptAll -CriticalUpdate -SecurityUpdate -AutoReboot | Out-Null
                Write-Log "Processo de atualização completo (críticas/segurança)." -Type Success
            }
            "3" {
                Write-Log "Apenas buscando atualizações disponíveis..." -Type Info
                Write-Host "Buscando atualizações disponíveis (não será instalado nada)..." -ForegroundColor Yellow
                Get-WindowsUpdate | Format-Table -AutoSize
                Write-Log "Busca de atualizações concluída." -Type Info
                Write-Host "Busca de atualizações concluída. Verifique a lista acima." -ForegroundColor Green
                pause
            }
            "0" {
                Write-Log "Retornando ao menu principal de atualizações." -Type Info
                return
            }
            default {
                Write-Host "Opção inválida. Retornando ao menu principal." -ForegroundColor Red
                Start-Sleep -Seconds 2
            }
        }

        Write-Host "Processo de gerenciamento de atualizações concluído." -ForegroundColor Green

    } catch {
        Write-Log "Ocorreu um erro durante o gerenciamento de atualizações: $($_.Exception.Message)" -Type Error
        Write-Host "ERRO durante o gerenciamento de atualizações: $($_.Exception.Message)" -ForegroundColor Red
    }
    Start-Sleep -Seconds 2
}

# === FUNÇÕES DE REMOÇÃO DE BLOATWARE ===

function Remove-Bloatware {
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
    [CmdletBinding()]
    param()

    if (-not (Test-Path Variable:ScriptConfig)) {
        Write-Log "ERRO: \$ScriptConfig não encontrada. Certifique-se de que foi definida no topo do script." -Type Error
        Write-Host "ERRO: Configurações globais (\$ScriptConfig) não encontradas. Abortando remoção do OneDrive." -ForegroundColor Red
        return
    }

    Write-Log "Iniciando remoção completa do OneDrive..." -Type Info
    Write-Host "Iniciando Remoção Completa do OneDrive..." -ForegroundColor Red

    # === NOVO CÓDIGO AQUI ===
    if ($ScriptConfig.ConfirmationRequired) {
        $confirm = Read-Host "AVISO: A remoção do OneDrive é irreversível e pode afetar a sincronização de arquivos. Tem certeza que deseja prosseguir? (s/n)"
        if ($confirm -ne 's') {
            Write-Log "Remoção do OneDrive cancelada pelo usuário." -Type Info
            Write-Host "Remoção do OneDrive cancelada." -ForegroundColor Yellow
            Start-Sleep -Seconds 2
            return # Sai da função se o usuário cancelar
        }
    }
    # === FIM DO NOVO CÓDIGO ===

    try {
        # Encerra processos do OneDrive
        Get-Process -Name "OneDrive*" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue | Out-Null
        Write-Host "  -> Processos do OneDrive encerrados." -ForegroundColor DarkCyan
        Write-Log "Processos do OneDrive encerrados." -Type Success

        # Desinstala o OneDrive para todas as arquiteturas
        $onedriveSetupPath_x64 = "$env:SystemRoot\SysWOW64\OneDriveSetup.exe"
        $onedriveSetupPath_x86 = "$env:SystemRoot\System32\OneDriveSetup.exe"

        if (Test-Path $onedriveSetupPath_x64) {
            Write-Host "  -> Desinstalando OneDrive (x64)..." -ForegroundColor DarkCyan
            Start-Process -FilePath $onedriveSetupPath_x64 -ArgumentList "/uninstall" -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue | Out-Null
            Write-Log "OneDrive x64 desinstalado." -Type Success
        } elseif (Test-Path $onedriveSetupPath_x86) {
            Write-Host "  -> Desinstalando OneDrive (x86)..." -ForegroundColor DarkCyan
            Start-Process -FilePath $onedriveSetupPath_x86 -ArgumentList "/uninstall" -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue | Out-Null
            Write-Log "OneDrive x86 desinstalado." -Type Success
        } else {
            Write-Host "  -> Instalador do OneDrive não encontrado. Pulando desinstalação via setup." -ForegroundColor Yellow
            Write-Log "Instalador do OneDrive não encontrado. Pulando desinstalação via setup." -Type Warning
        }

        # Remove pastas de dados e vestígios
        $userProfiles = Get-ChildItem -Path "$env:SystemDrive\Users" -Directory -ErrorAction SilentlyContinue
        foreach ($profile in $userProfiles) {
            $onedriveUserPath = Join-Path -Path $profile.FullName -ChildPath "OneDrive"
            if (Test-Path $onedriveUserPath) {
                Remove-Item -Path $onedriveUserPath -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
                Write-Host "  -> Removido pasta OneDrive de $($profile.BaseName)." -ForegroundColor DarkCyan
            }
            $onedriveLocalAppData = Join-Path -Path $profile.FullName -ChildPath "AppData\Local\Microsoft\OneDrive"
            if (Test-Path $onedriveLocalAppData) {
                Remove-Item -Path $onedriveLocalAppData -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
                Write-Host "  -> Removido AppData de OneDrive de $($profile.BaseName)." -ForegroundColor DarkCyan
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
                    Write-Host "  -> Limpado registro: $path" -ForegroundColor DarkCyan
                }
            } catch {
                Write-Log "Falha ao limpar registro do OneDrive ($path): $($_.Exception.Message)" -Type Warning
            }
        }

        # Desativa o início automático do OneDrive via registro (se ainda houver entradas)
        try {
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "OneDrive" -Value "" -ErrorAction SilentlyContinue | Out-Null
            Write-Host "  -> Desativado início automático do OneDrive." -ForegroundColor DarkCyan
        } catch { Write-Log "Falha ao desativar início automático do OneDrive: $($_.Exception.Message)" -Type Warning }


        Write-Log "Remoção completa do OneDrive concluída." -Type Success
        Write-Host "Remoção Completa do OneDrive Concluída!" -ForegroundColor Green

    } catch {
        Write-Log "Ocorreu um erro crítico durante a remoção do OneDrive: $($_.Exception.Message)" -Type Error
        Write-Host "ERRO: Ocorreu um erro crítico durante a remoção do OneDrive: $($_.Exception.Message)" -ForegroundColor Red
    }
    Start-Sleep -Seconds 2
}

    # Função auxiliar para verificar se um pacote deve ser removido
    function Test-ShouldRemovePackage {
        param (
            [Parameter(Mandatory=$true)]
            [string]$PackageName
        )
        if ($whitelist -contains $PackageName) {
            return $false
        }
        foreach ($item in $bloatwareToRemove) {
            if ($PackageName -like $item) {
                return $true
            }
        }
        return $false
    }

    try {
        # Passo 1: Remover pacotes provisionados (para novos usuários)
        Write-Log "Removendo pacotes provisionados para novos usuários..." Cyan
        Get-AppxProvisionedPackage -ErrorAction SilentlyContinue | ForEach-Object {
            if (Test-ShouldRemovePackage -PackageName $_.PackageName) {
                Write-Log "Removendo provisionamento de $($_.PackageName)..." Cyan
                Remove-AppxProvisionedPackage -PackageName $_.PackageName -ErrorAction SilentlyContinue
            }
        }

        # Passo 2: Remover do usuário atual
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
    [CmdletBinding()]
    param()

    Write-Log "Iniciando remoção e desativação do Windows Copilot." -Type Info
    Write-Host "Iniciando remoção e desativação do Windows Copilot..." -ForegroundColor Magenta

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
        Write-Host "Windows Copilot removido/desativado com sucesso!" -ForegroundColor Green

        # Reiniciar o Explorer para que as mudanças na barra de tarefas sejam aplicadas imediatamente
        Write-Host "Reiniciando Explorer para aplicar as alterações na barra de tarefas..." -ForegroundColor Yellow
        Stop-Process -Name "explorer" -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        Start-Process -FilePath "explorer.exe" -ErrorAction SilentlyContinue

    } catch {
        Write-Log "Ocorreu um erro durante a remoção/desativação do Windows Copilot: $($_.Exception.Message)" -Type Error
        Write-Host "Erro durante a remoção/desativação do Windows Copilot: $($_.Exception.Message)" -ForegroundColor Red
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
    [CmdletBinding()]
    param()

    Write-Log "Iniciando desativação do Windows Recall." -Type Info
    Write-Host "Iniciando desativação do Windows Recall..." -ForegroundColor Magenta

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
        Write-Host "Windows Recall desativado com sucesso!" -ForegroundColor Green

    } catch {
        Write-Log "Ocorreu um erro durante a desativação do Windows Recall: $($_.Exception.Message)" -Type Error
        Write-Host "Erro durante a desativação do Windows Recall: $($_.Exception.Message)" -ForegroundColor Red
    }
    Start-Sleep -Seconds 2
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
            Write-Host "Removendo a impressora 'OneNote (Desktop)'..." -ForegroundColor Yellow
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
            
            Write-Host "Impressora 'OneNote (Desktop)' removida com sucesso!" -ForegroundColor Green
            return $true
        }
        catch {
            Write-Host "Falha ao remover a impressora: $_" -ForegroundColor Red
            return $false
        }
    }
    else {
        Write-Host "A impressora 'OneNote (Desktop)' não está instalada." -ForegroundColor Cyan
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
    Write-Host "Aplicando otimizações de rede..." -ForegroundColor Yellow

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
    Write-Host "Otimizações de rede aplicadas. Um reinício pode ser necessário para algumas alterações." -ForegroundColor Green
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
    Write-Host "ATENÇÃO: Desativar o UAC reduz a segurança do sistema. Prossiga com cautela." -ForegroundColor Yellow
    Start-Sleep -Seconds 2

    try {
        # Define EnableLUA para 0 para desativar o UAC
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 0 -Force -ErrorAction Stop | Out-Null
        # Define ConsentPromptBehaviorAdmin para 0 para desabilitar o prompt de consentimento para administradores
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 0 -Force -ErrorAction Stop | Out-Null

        Write-Log "UAC desativado com sucesso. Será necessário reiniciar para que as alterações tenham efeito completo." Green
        Write-Host "UAC desativado. Reinicie o computador para aplicar as alterações." -ForegroundColor Green
    } catch {
        Write-Log "Erro ao desativar o UAC: $_" Red
        Write-Host "Erro ao desativar o UAC. Verifique o log." -ForegroundColor Red
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
    [CmdletBinding()]
    param()

    # Certifique-se de que a hashtable de configuração existe
    if (-not (Test-Path Variable:ScriptConfig)) {
        Write-Log "ERRO: \$ScriptConfig não encontrada. Certifique-se de que foi definida no topo do script." -Type Error
        Write-Host "ERRO: Configurações globais (\$ScriptConfig) não encontradas. Abortando otimizações." -ForegroundColor Red
        return
    }

    Write-Log "Iniciando rotinas de otimização do sistema..." -Type Info
    Write-Host "Iniciando Rotinas de Limpeza e Otimização do Sistema..." -ForegroundColor Cyan

    # Chamada condicional das funções de limpeza com base em $ScriptConfig
    if ($ScriptConfig.Cleanup.CleanTemporaryFiles) {
        Write-Log "Executando limpeza de arquivos temporários..." -Type Info
        Write-Host "  -> Limpando arquivos temporários..." -ForegroundColor DarkCyan
        # Você precisaria de uma função como: Clear-TemporaryFiles
        try { Clear-TemporaryFiles } catch { Write-Log "Falha ao limpar arquivos temporários: $($_.Exception.Message)" -Type Warning }
    }

    if ($ScriptConfig.Cleanup.CleanWUCache) {
        Write-Log "Limpando cache do Windows Update..." -Type Info
        Write-Host "  -> Limpando cache do Windows Update..." -ForegroundColor DarkCyan
        # Você precisaria de uma função como: Clear-WUCache
        try { Clear-WUCache } catch { Write-Log "Falha ao limpar cache WU: $($_.Exception.Message)" -Type Warning }
    }

    if ($ScriptConfig.Cleanup.OptimizeVolumes) {
        Write-Log "Otimizando volumes de disco..." -Type Info
        Write-Host "  -> Otimizando volumes de disco (Desfragmentação/Trim)..." -ForegroundColor DarkCyan
        # Você precisaria de uma função como: Optimize-Volumes
        try { Optimize-Volumes } catch { Write-Log "Falha ao otimizar volumes: $($_.Exception.Message)" -Type Warning }
    }

    if ($ScriptConfig.Cleanup.PerformDeepSystemCleanup) {
        Write-Log "Executando limpeza profunda do sistema..." -Type Info
        Write-Host "  -> Realizando limpeza profunda do sistema (Disk Cleanup)..." -ForegroundColor DarkCyan
        # Você precisaria de uma função como: Clear-DeepSystemCleanup
        try { Clear-DeepSystemCleanup } catch { Write-Log "Falha na limpeza profunda: $($_.Exception.Message)" -Type Warning }
    }

    if ($ScriptConfig.Cleanup.ClearDNSCache) {
        Write-Log "Limpando cache DNS..." -Type Info
        Write-Host "  -> Limpando cache DNS..." -ForegroundColor DarkCyan
        # Função simples para limpar DNS: ipconfig /flushdns
        try { ipconfig /flushdns | Out-Null; Write-Host "     DNS cache limpo." -ForegroundColor Green } catch { Write-Log "Falha ao limpar cache DNS: $($_.Exception.Message)" -Type Warning }
    }

    if ($ScriptConfig.Cleanup.DisableMemoryDumps) {
        Write-Log "Desativando despejos de memória..." -Type Info
        Write-Host "  -> Desativando criação de despejos de memória..." -ForegroundColor DarkCyan
        # Exemplo de como desativar despejos de memória via registro
        try {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -Name "CrashDumpEnabled" -Value 0 -Force -ErrorAction Stop
            Write-Host "     Despejos de memória desativados." -ForegroundColor Green
        } catch { Write-Log "Falha ao desativar despejos de memória: $($_.Exception.Message)" -Type Warning }
    }

    Write-Log "Rotinas de otimização do sistema concluídas." -Type Success
    Write-Host "Rotinas de Limpeza e Otimização do Sistema Concluídas!" -ForegroundColor Green
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
    [CmdletBinding()]
    param()

    # Certifique-se de que a hashtable de configuração existe
    if (-not (Test-Path Variable:ScriptConfig)) {
        Write-Log "ERRO: \$ScriptConfig não encontrada. Certifique-se de que foi definida no topo do script." -Type Error
        Write-Host "ERRO: Configurações globais (\$ScriptConfig) não encontradas. Abortando ajustes de privacidade." -ForegroundColor Red
        return
    }

    Write-Log "Iniciando aplicação de ajustes de privacidade e prevenção de bloatware..." -Type Info
    Write-Host "Iniciando Ajustes de Privacidade e Prevenção de Bloatware..." -ForegroundColor Cyan

    # Chamada condicional das ações de privacidade com base em $ScriptConfig
    if ($ScriptConfig.PrivacyTweaks.DisableTelemetry) {
        Write-Log "Desativando telemetria..." -Type Info
        Write-Host "  -> Desativando telemetria..." -ForegroundColor DarkCyan
        try {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0 -Force -ErrorAction Stop
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Value 0 -Force -ErrorAction Stop
            Write-Host "     Telemetria desativada." -ForegroundColor Green
        } catch { Write-Log "Falha ao desativar telemetria: $($_.Exception.Message)" -Type Warning }
    }

    if ($ScriptConfig.PrivacyTweaks.DisableDiagnosticData) {
        Write-Log "Desativando dados de diagnóstico..." -Type Info
        Write-Host "  -> Desativando dados de diagnóstico..." -ForegroundColor DarkCyan
        try {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" -Name "DiagTrack" -Value 0 -Force -ErrorAction Stop
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\Settings" -Name "SQMConsent" -Value 0 -Force -ErrorAction Stop
            Write-Host "     Dados de diagnóstico desativados." -ForegroundColor Green
        } catch { Write-Log "Falha ao desativar dados de diagnóstico: $($_.Exception.Message)" -Type Warning }
    }

    if ($ScriptConfig.PrivacyTweaks.BlockTelemetryHosts) {
        Write-Log "Bloqueando hosts de telemetria no arquivo hosts..." -Type Info
        Write-Host "  -> Bloqueando hosts de telemetria..." -ForegroundColor DarkCyan
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
            Write-Host "     Hosts de telemetria bloqueados." -ForegroundColor Green
        } catch { Write-Log "Falha ao bloquear hosts de telemetria: $($_.Exception.Message)" -Type Warning }
    }

    if ($ScriptConfig.PrivacyTweaks.DisableLocationServices) {
        Write-Log "Desativando serviços de localização..." -Type Info
        Write-Host "  -> Desativando serviços de localização..." -ForegroundColor DarkCyan
        try {
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Value "Deny" -Force -ErrorAction Stop
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -Value 1 -Force -ErrorAction Stop
            Write-Host "     Serviços de localização desativados." -ForegroundColor Green
        } catch { Write-Log "Falha ao desativar serviços de localização: $($_.Exception.Message)" -Type Warning }
    }

    if ($ScriptConfig.PrivacyTweaks.DisableActivityHistory) {
        Write-Log "Desativando histórico de atividades..." -Type Info
        Write-Host "  -> Desativando histórico de atividades..." -ForegroundColor DarkCyan
        try {
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" -Name "ActivityData" -Value 0 -Force -ErrorAction Stop
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Value 0 -Force -ErrorAction Stop
            Write-Host "     Histórico de atividades desativado." -ForegroundColor Green
        } catch { Write-Log "Falha ao desativar histórico de atividades: $($_.Exception.Message)" -Type Warning }
    }

    if ($ScriptConfig.PrivacyTweaks.DisableAdvertisingID) {
        Write-Log "Desativando ID de publicidade..." -Type Info
        Write-Host "  -> Desativando ID de publicidade..." -ForegroundColor DarkCyan
        try {
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Value 0 -Force -ErrorAction Stop
            Write-Host "     ID de publicidade desativado." -ForegroundColor Green
        } catch { Write-Log "Falha ao desativar ID de publicidade: $($_.Exception.Message)" -Type Warning }
    }

    if ($ScriptConfig.PrivacyTweaks.DisableCortana) {
        Write-Log "Desativando Cortana..." -Type Info
        Write-Host "  -> Desativando Cortana..." -ForegroundColor DarkCyan
        try {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Value 0 -Force -ErrorAction Stop
            Write-Host "     Cortana desativada." -ForegroundColor Green
        } catch { Write-Log "Falha ao desativar Cortana: $($_.Exception.Message)" -Type Warning }
    }

    if ($ScriptConfig.PrivacyTweaks.DisableBiometrics) {
        Write-Log "Desativando biometria (se não utilizada)..." -Type Info
        Write-Host "  -> Desativando biometria..." -ForegroundColor DarkCyan
        try {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics" -Name "Enabled" -Value 0 -Force -ErrorAction Stop
            Write-Host "     Biometria desativada." -ForegroundColor Green
        } catch { Write-Log "Falha ao desativar biometria: $($_.Exception.Message)" -Type Warning }
    }

    if ($ScriptConfig.PrivacyTweaks.DisableFeedbackRequests) {
        Write-Log "Desativando solicitações de feedback..." -Type Info
        Write-Host "  -> Desativando solicitações de feedback..." -ForegroundColor DarkCyan
        try {
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "Period" -Value 0 -Force -ErrorAction Stop
            Write-Host "     Solicitações de feedback desativadas." -ForegroundColor Green
        } catch { Write-Log "Falha ao desativar solicitações de feedback: $($_.Exception.Message)" -Type Warning }
    }

    if ($ScriptConfig.PrivacyTweaks.DisableSuggestedContent) {
        Write-Log "Desativando conteúdo sugerido..." -Type Info
        Write-Host "  -> Desativando conteúdo sugerido..." -ForegroundColor DarkCyan
        try {
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Value 0 -Force -ErrorAction Stop
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Value 0 -Force -ErrorAction Stop
            Write-Host "     Conteúdo sugerido desativado." -ForegroundColor Green
        } catch { Write-Log "Falha ao desativar conteúdo sugerido: $($_.Exception.Message)" -Type Warning }
    }

    if ($ScriptConfig.PrivacyTweaks.DisableAutoUpdatesStoreApps) {
        Write-Log "Desativando atualizações automáticas de apps da Loja..." -Type Info
        Write-Host "  -> Desativando atualizações automáticas da Loja..." -ForegroundColor DarkCyan
        try {
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Auto Update\Store" -Name "AutoDownload" -Value 2 -Force -ErrorAction Stop # 2 = desativado
            Write-Host "     Atualizações automáticas da Loja desativadas." -ForegroundColor Green
        } catch { Write-Log "Falha ao desativar atualizações automáticas da Loja: $($_.Exception.Message)" -Type Warning }
    }

    if ($ScriptConfig.PrivacyTweaks.DisableWidgets) {
        Write-Log "Desativando Widgets do Windows 11..." -Type Info
        Write-Host "  -> Desativando Widgets..." -ForegroundColor DarkCyan
        try {
            # Desativar da barra de tarefas
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarDa" -Value 0 -Force -ErrorAction Stop
            # Ocultar o painel de widgets
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Hidden\Widgets" -Name "Enabled" -Value 0 -Force -ErrorAction Stop
            Write-Host "     Widgets desativados." -ForegroundColor Green
        } catch { Write-Log "Falha ao desativar Widgets: $($_.Exception.Message)" -Type Warning }
    }

    if ($ScriptConfig.PrivacyTweaks.DisableNewsAndInterests) {
        Write-Log "Desativando Notícias e Interesses (Windows 10)..." -Type Info
        Write-Host "  -> Desativando Notícias e Interesses..." -ForegroundColor DarkCyan
        try {
            # Desativar da barra de tarefas
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds" -Name "ShellFeedsTaskbarViewMode" -Value 2 -Force -ErrorAction Stop # 2 = Desativado
            Write-Host "     Notícias e Interesses desativados." -ForegroundColor Green
        } catch { Write-Log "Falha ao desativar Notícias e Interesses: $($_.Exception.Message)" -Type Warning }
    }

    Write-Log "Ajustes de privacidade e prevenção de bloatware concluídos." -Type Success
    Write-Host "Ajustes de Privacidade e Prevenção de Bloatware Concluídos!" -ForegroundColor Green
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
    [CmdletBinding()]
    param()

    # Certifique-se de que a hashtable de configuração existe
    if (-not (Test-Path Variable:ScriptConfig)) {
        Write-Log "ERRO: \$ScriptConfig não encontrada. Certifique-se de que foi definida no topo do script." -Type Error
        Write-Host "ERRO: Configurações globais (\$ScriptConfig) não encontradas. Abortando aplicação de GPO via Registro." -ForegroundColor Red
        return
    }

    Write-Log "Iniciando aplicação de configurações de GPO via Registro..." -Type Info
    Write-Host "Iniciando Aplicação de Configurações de GPO via Registro..." -ForegroundColor Cyan

    # ===============================
    # Configurações de Windows Update
    # ===============================

    if ($ScriptConfig.GPORegistrySettings.EnableUpdateManagement) {
        Write-Log "Configurando gerenciamento de Windows Update..." -Type Info
        Write-Host "  -> Configurando gerenciamento de Windows Update..." -ForegroundColor DarkCyan
        try {
            # Desativa o acesso à interface de usuário de updates para usuários padrão
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DoNotAllowWindowsUpdate" -Value 1 -Force -ErrorAction Stop
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Value 1 -Force -ErrorAction Stop # Desativar atualização automática para controlar manualmente
            # Define o comportamento para download e notificação
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -Value 2 -Force -ErrorAction Stop # 2 = Notificar para download e instalação
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoRebootWithLoggedOnUsers" -Value 1 -Force -ErrorAction Stop # Evita reinício com usuário logado
            Write-Host "     Gerenciamento de Windows Update configurado." -ForegroundColor Green
        } catch { Write-Log "Falha ao configurar gerenciamento de Windows Update: $($_.Exception.Message)" -Type Warning }
    }

    if ($ScriptConfig.GPORegistrySettings.DisableAutoReboot) {
        Write-Log "Desativando reinício automático após updates..." -Type Info
        Write-Host "  -> Desativando reinício automático após updates..." -ForegroundColor DarkCyan
        try {
            # Já coberto parcialmente por NoAutoRebootWithLoggedOnUsers acima, mas garante mais
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoRebootWithLoggedOnUsers" -Value 1 -Force -ErrorAction Stop
            # Adicional: Remove a tarefa de reinício forçado (pode ser recriada pelo sistema)
            SchTasks /Change /TN "\Microsoft\Windows\UpdateOrchestrator\Reboot" /Disable | Out-Null
            Write-Host "     Reinício automático após updates desativado." -ForegroundColor Green
        } catch { Write-Log "Falha ao desativar reinício automático: $($_.Exception.Message)" -Type Warning }
    }

    if ($ScriptConfig.GPORegistrySettings.SetScheduledUpdateTime) {
        Write-Log "Definindo horário de instalação de updates agendados..." -Type Info
        Write-Host "  -> Definindo horário de instalação de updates agendados (3 AM)..." -ForegroundColor DarkCyan
        try {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "ScheduledInstallDay" -Value 0 -Force -ErrorAction Stop # 0 = Todos os dias
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "ScheduledInstallTime" -Value 3 -Force -ErrorAction Stop # 3 = 03:00 AM
            Write-Host "     Horário de atualização agendado para 03:00 AM." -ForegroundColor Green
        } catch { Write-Log "Falha ao definir horário de updates: $($_.Exception.Message)" -Type Warning }
    }

    if ($ScriptConfig.GPORegistrySettings.DisableDriverUpdates) {
        Write-Log "Desativando updates de drivers via Windows Update..." -Type Info
        Write-Host "  -> Desativando updates de drivers via Windows Update..." -ForegroundColor DarkCyan
        try {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontSearchWindowsUpdate" -Value 1 -Force -ErrorAction Stop
            Write-Host "     Updates de drivers via WU desativados." -ForegroundColor Green
        } catch { Write-Log "Falha ao desativar updates de drivers: $($_.Exception.Message)" -Type Warning }
    }

    # =========================
    # Configurações de Navegadores
    # =========================

    if ($ScriptConfig.GPORegistrySettings.ConfigureEdge) {
        Write-Log "Configurando Microsoft Edge..." -Type Info
        Write-Host "  -> Configurando Microsoft Edge (bloqueando Edge Copilot, etc.)..." -ForegroundColor DarkCyan
        try {
            # Desativa o Edge Copilot
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Edge" -Name "EdgeCopilotEnabled" -Value 0 -Force -ErrorAction Stop
            # Outras configurações do Edge podem ser adicionadas aqui
            # Ex: Desativar página de nova aba do Bing
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Edge" -Name "NewTabPageUrl" -Value "about:blank" -Force -ErrorAction Stop
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Edge" -Name "NewTabPageLocation" -Value 1 -Force -ErrorAction Stop # 1=blank page
            Write-Host "     Microsoft Edge configurado." -ForegroundColor Green
        } catch { Write-Log "Falha ao configurar Edge: $($_.Exception.Message)" -Type Warning }
    }

    if ($ScriptConfig.GPORegistrySettings.ConfigureChrome) {
        Write-Log "Configurando Google Chrome..." -Type Info
        Write-Host "  -> Configurando Google Chrome (desativando algumas integrações)..." -ForegroundColor DarkCyan
        try {
            # Exemplo: Desativar Safe Browse (use com cautela)
            # Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "SafeBrowseEnabled" -Value 0 -Force -ErrorAction Stop
            # Exemplo: Prevenir a instalação de extensões de fora da Chrome Web Store
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "ExtensionInstallForcelist" -Value 0 -Force -ErrorAction Stop
            Write-Host "     Google Chrome configurado." -ForegroundColor Green
        } catch { Write-Log "Falha ao configurar Chrome: $($_.Exception.Message)" -Type Warning }
    }

    # =========================
    # Outras configurações de GPO (Exemplos)
    # =========================

    if ($ScriptConfig.GPORegistrySettings.DisableWindowsTips) { # Exemplo de uma nova flag a ser adicionada no $ScriptConfig.GPORegistrySettings se desejar
        Write-Log "Desativando dicas e sugestões do Windows..." -Type Info
        Write-Host "  -> Desativando dicas e sugestões do Windows..." -ForegroundColor DarkCyan
        try {
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Value 0 -Force -ErrorAction Stop
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353694Enabled" -Value 0 -Force -ErrorAction Stop
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353696Enabled" -Value 0 -Force -ErrorAction Stop
            Write-Host "     Dicas e sugestões desativadas." -ForegroundColor Green
        } catch { Write-Log "Falha ao desativar dicas: $($_.Exception.Message)" -Type Warning }
    }
    # ... adicione mais configurações aqui, baseadas em novas flags no $ScriptConfig.GPORegistrySettings

    Write-Log "Aplicação de configurações de GPO via Registro concluída." -Type Success
    Write-Host "Configurações de GPO via Registro Concluídas!" -ForegroundColor Green
    Start-Sleep -Seconds 2
}

function Apply-UITweaks {
    <#
    .SYNOPSIS
        Aplica diversos ajustes na interface do usuário do Windows baseados nas configurações globais.
    .DESCRIPTION
        Esta função modifica configurações visuais e de usabilidade do sistema operacional,
        como tema, transparência, animações, e itens da barra de tarefas/Explorer,
        controladas pela hashtable global $ScriptConfig.UITweaks.
    #>
    [CmdletBinding()]
    param()

    if (-not (Test-Path Variable:ScriptConfig)) {
        Write-Log "ERRO: \$ScriptConfig não encontrada. Certifique-se de que foi definida no topo do script." -Type Error
        Write-Host "ERRO: Configurações globais (\$ScriptConfig) não encontradas. Abortando ajustes de UI." -ForegroundColor Red
        return
    }

    Write-Log "Iniciando aplicação de ajustes de interface do usuário (UI Tweaks)..." -Type Info
    Write-Host "Iniciando Ajustes de Interface do Usuário (UI Tweaks)..." -ForegroundColor Cyan

    # Tema Escuro/Claro
    if ($ScriptConfig.UITweaks.EnableDarkMode) {
        Write-Log "Ativando Modo Escuro..." -Type Info
        Write-Host "  -> Ativando Modo Escuro..." -ForegroundColor DarkCyan
        try {
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Value 0 -Force -ErrorAction Stop
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Value 0 -Force -ErrorAction Stop
            Write-Host "     Modo Escuro ativado." -ForegroundColor Green
        } catch { Write-Log "Falha ao ativar Modo Escuro: $($_.Exception.Message)" -Type Warning }
    } else { # Opcional: para garantir o modo claro se a flag for $false
        Write-Log "Garantindo Modo Claro (se ativado nas configs)..." -Type Info
        Write-Host "  -> Garantindo Modo Claro..." -ForegroundColor DarkCyan
        try {
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Value 1 -Force -ErrorAction Stop
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Value 1 -Force -ErrorAction Stop
            Write-Host "     Modo Claro configurado." -ForegroundColor Green
        } catch { Write-Log "Falha ao configurar Modo Claro: $($_.Exception.Message)" -Type Warning }
    }

    # Transparência
    if ($ScriptConfig.UITweaks.DisableTransparency) {
        Write-Log "Desativando Efeitos de Transparência..." -Type Info
        Write-Host "  -> Desativando Efeitos de Transparência..." -ForegroundColor DarkCyan
        try {
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "EnableTransparency" -Value 0 -Force -ErrorAction Stop
            Write-Host "     Efeitos de transparência desativados." -ForegroundColor Green
        } catch { Write-Log "Falha ao desativar transparência: $($_.Exception.Message)" -Type Warning }
    } else {
        Write-Log "Ativando Efeitos de Transparência (se ativado nas configs)..." -Type Info
        Write-Host "  -> Ativando Efeitos de Transparência..." -ForegroundColor DarkCyan
        try {
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "EnableTransparency" -Value 1 -Force -ErrorAction Stop
            Write-Host "     Efeitos de transparência ativados." -ForegroundColor Green
        } catch { Write-Log "Falha ao ativar transparência: $($_.Exception.Message)" -Type Warning }
    }

    # Animações
    if ($ScriptConfig.UITweaks.DisableAnimations) {
        Write-Log "Desativando Animações do Windows..." -Type Info
        Write-Host "  -> Desativando Animações do Windows..." -ForegroundColor DarkCyan
        try {
            Set-ItemProperty -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -Value 0 -Force -ErrorAction Stop
            Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "UserPreferenceMask" -Value ([byte[]]([System.Convert]::FromBase64String("AAAAAQAAAAIAAAADAAAAQA=="))) -Force -ErrorAction Stop # Desabilita várias animações
            Write-Host "     Animações do Windows desativadas." -ForegroundColor Green
        } catch { Write-Log "Falha ao desativar animações: $($_.Exception.Message)" -Type Warning }
    } else {
        Write-Log "Ativando Animações do Windows (se ativado nas configs)..." -Type Info
        Write-Host "  -> Ativando Animações do Windows..." -ForegroundColor DarkCyan
        try {
            Set-ItemProperty -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -Value 1 -Force -ErrorAction Stop
            Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "UserPreferenceMask" -Value ([byte[]]([System.Convert]::FromBase64String("BwAAAAEAIAAIAAAADAAAAQA="))) -Force -ErrorAction Stop # Habilita animações padrão
            Write-Host "     Animações do Windows ativadas." -ForegroundColor Green
        } catch { Write-Log "Falha ao ativar animações: $($_.Exception.Message)" -Type Warning }
    }

    # Alinhamento da Barra de Tarefas (Windows 11)
    if ($IsWindows11) { # Variável $IsWindows11 deve ser definida no topo do script ou dentro da função
        if ($ScriptConfig.UITweaks.TaskbarAlignLeft) {
            Write-Log "Alinhando itens da barra de tarefas à esquerda (Windows 11)..." -Type Info
            Write-Host "  -> Alinhando barra de tarefas à esquerda (Windows 11)..." -ForegroundColor DarkCyan
            try {
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAl" -Value 0 -Force -ErrorAction Stop # 0 = Esquerda, 1 = Centro
                Write-Host "     Barra de tarefas alinhada à esquerda." -ForegroundColor Green
            } catch { Write-Log "Falha ao alinhar barra de tarefas: $($_.Exception.Message)" -Type Warning }
        } else {
            Write-Log "Alinhando itens da barra de tarefas ao centro (Windows 11)..." -Type Info
            Write-Host "  -> Alinhando barra de tarefas ao centro (Windows 11)..." -ForegroundColor DarkCyan
            try {
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAl" -Value 1 -Force -ErrorAction Stop # 0 = Esquerda, 1 = Centro
                Write-Host "     Barra de tarefas alinhada ao centro." -ForegroundColor Green
            } catch { Write-Log "Falha ao alinhar barra de tarefas: $($_.Exception.Message)" -Type Warning }
        }
    } else {
        Write-Log "Ignorando alinhamento da barra de tarefas: Não é Windows 11." -Type Info
    }

    # Ocultar Caixa de Pesquisa da Barra de Tarefas (Windows 10/11)
    if ($ScriptConfig.UITweaks.HideSearchBox) {
        Write-Log "Ocultando caixa de pesquisa da barra de tarefas..." -Type Info
        Write-Host "  -> Ocultando caixa de pesquisa..." -ForegroundColor DarkCyan
        try {
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Value 0 -Force -ErrorAction Stop # 0=Hidden, 1=Icon, 2=Box
            Write-Host "     Caixa de pesquisa oculta." -ForegroundColor Green
        } catch { Write-Log "Falha ao ocultar caixa de pesquisa: $($_.Exception.Message)" -Type Warning }
    } else {
        Write-Log "Exibindo caixa de pesquisa da barra de tarefas (se ativado nas configs)..." -Type Info
        Write-Host "  -> Exibindo caixa de pesquisa (ícone)..." -ForegroundColor DarkCyan
        try {
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Value 1 -Force -ErrorAction Stop # 0=Hidden, 1=Icon, 2=Box
            Write-Host "     Caixa de pesquisa exibida (apenas ícone)." -ForegroundColor Green
        } catch { Write-Log "Falha ao exibir caixa de pesquisa: $($_.Exception.Message)" -Type Warning }
    }

    # Exibir Ícones Padrão da Área de Trabalho (Computador, Lixeira, Rede)
    if ($ScriptConfig.UITweaks.ShowDesktopIcons) {
        Write-Log "Exibindo ícones padrão da área de trabalho..." -Type Info
        Write-Host "  -> Exibindo ícones padrão da área de trabalho (Computador, Lixeira, Rede)..." -ForegroundColor DarkCyan
        try {
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Value 0 -Force -ErrorAction Stop # Meu Computador
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{645FF040-5081-101B-9F08-00AA002F954E}" -Value 0 -Force -ErrorAction Stop # Lixeira
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{F02B4C93-C4F5-4039-86A7-772D932FCA9A}" -Value 0 -Force -ErrorAction Stop # Rede
            Write-Host "     Ícones padrão da área de trabalho exibidos." -ForegroundColor Green
        } catch { Write-Log "Falha ao exibir ícones da área de trabalho: $($_.Exception.Message)" -Type Warning }
    } else {
        Write-Log "Ocultando ícones padrão da área de trabalho (se desativado nas configs)..." -Type Info
        Write-Host "  -> Ocultando ícones padrão da área de trabalho..." -ForegroundColor DarkCyan
        try {
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Value 1 -Force -ErrorAction Stop
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{645FF040-5081-101B-9F08-00AA002F954E}" -Value 1 -Force -ErrorAction Stop
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{F02B4C93-C4F5-4039-86A7-772D932FCA9A}" -Value 1 -Force -ErrorAction Stop
            Write-Host "     Ícones padrão da área de trabalho ocultos." -ForegroundColor Green
        } catch { Write-Log "Falha ao ocultar ícones da área de trabalho: $($_.Exception.Message)" -Type Warning }
    }

    # Ocultar Entradas de Drives Duplicadas no Explorer
    if ($ScriptConfig.UITweaks.HideDupliDrive) {
        Write-Log "Ocultando entradas de drives duplicadas no Explorer..." -Type Info
        Write-Host "  -> Ocultando entradas de drives duplicadas..." -ForegroundColor DarkCyan
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
            Write-Host "     Entradas de drives duplicadas ocultas (se aplicável)." -ForegroundColor Green
        } catch { Write-Log "Falha ao ocultar entradas de drives duplicadas: $($_.Exception.Message)" -Type Warning }
    }

    # Ocultar pasta Objetos 3D do Explorer
    if ($ScriptConfig.UITweaks.Hide3dObjects) {
        Write-Log "Ocultando pasta Objetos 3D do Explorer..." -Type Info
        Write-Host "  -> Ocultando pasta 'Objetos 3D'..." -ForegroundColor DarkCyan
        try {
            # Remover do User Shell Folders
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "{0F214138-B1D3-4A90-BBA9-F7A6A09C2E47}" -Value "" -Force -ErrorAction Stop
            # Remover do NameSpace
            Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{0F214138-B1D3-4A90-BBA9-F7A6A09C2E47}" -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
            Remove-Item -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{0F214138-B1D3-4A90-BBA9-F7A6A09C2E47}" -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
            Write-Host "     Pasta 'Objetos 3D' oculta." -ForegroundColor Green
        } catch { Write-Log "Falha ao ocultar pasta Objetos 3D: $($_.Exception.Message)" -Type Warning }
    }

    # Ocultar pasta OneDrive do Explorer (se não for removê-lo completamente)
    if ($ScriptConfig.UITweaks.HideOneDriveFolder) {
        Write-Log "Ocultando pasta OneDrive do painel de navegação do Explorer..." -Type Info
        Write-Host "  -> Ocultando pasta 'OneDrive' do Explorer (se ainda existir)..." -ForegroundColor DarkCyan
        try {
            # Este é o mesmo CLSID que o OneDrive usa para aparecer nos drives duplicados.
            # Se você usa Force-RemoveOneDrive, esta etapa é redundante e pode causar erros se o OneDrive já foi totalmente removido.
            # Use esta opção apenas se você *não* pretende remover o OneDrive, mas apenas ocultá-lo do painel de navegação.
            Set-ItemProperty -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-2ad65C87B14B}" -Name "System.IsPinnedToNameSpaceTree" -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
            Set-ItemProperty -Path "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-2ad65C87B14B}" -Name "System.IsPinnedToNameSpaceTree" -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
            Write-Host "     Pasta 'OneDrive' oculta do painel de navegação." -ForegroundColor Green
        } catch { Write-Log "Falha ao ocultar pasta OneDrive: $($_.Exception.Message)" -Type Warning }
    }

    Write-Log "Ajustes de interface do usuário (UI Tweaks) concluídos." -Type Success
    Write-Host "Ajustes de Interface do Usuário (UI Tweaks) Concluídos!" -ForegroundColor Green
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
    Write-Host "Configurações aplicadas com sucesso!" -ForegroundColor Green
    Write-Host "`nResumo das configurações:" -ForegroundColor Cyan
    Write-Host " - Tela (AC/DC): $($config.TempoTelaAC)min / $($config.TempoTelaBateria)min"
    Write-Host " - Hibernação (AC/DC): $($config.TempoHibernarAC == 0 ? 'Nunca' : $config.TempoHibernarAC+'min') / $($config.TempoHibernarBateria)min"
    Write-Host " - Tampa (AC/DC): $($config.ComportamentoTampaAC) / $($config.ComportamentoTampaBateria)"
    Write-Host " - Botão Energia (AC/DC): $($config.BotaoEnergiaAC) / $($config.BotaoEnergiaBateria)"
    Write-Host "   - Nível ativação: $($config.NivelAtivacaoEconomia)%"
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
        Write-Host "✅ Sudo do Windows habilitado! Feche e reabra o terminal para usar." -ForegroundColor Green
        return $true
    } catch {
        Write-Host "❌ Não foi possível habilitar o sudo. $_" -ForegroundColor Red
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
    [CmdletBinding()]
    param()

    Write-Log "Iniciando a configuração do plano de energia otimizado (Alto Desempenho)." -Type Info
    Write-Host "Configurando o plano de energia para 'Alto Desempenho'..." -ForegroundColor Magenta

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
            Write-Host "Plano de energia 'Alto Desempenho' ativado com sucesso!" -ForegroundColor Green
        } else {
            Write-Log "Falha ao ativar o plano de energia 'Alto Desempenho'. O plano atual é: $currentPlan" -Type Error
            Write-Host "ERRO: Não foi possível ativar o plano de energia 'Alto Desempenho'." -ForegroundColor Red
        }

    } catch {
        Write-Log "Ocorreu um erro ao configurar o plano de energia: $($_.Exception.Message)" -Type Error
        Write-Host "ERRO ao configurar o plano de energia: $($_.Exception.Message)" -ForegroundColor Red
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
    Write-Host "Digite o caminho da pasta onde está o backup do registro:" -ForegroundColor Cyan
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
    Write-Host "==== ATIVAÇÃO DO WINDOWS ====" -ForegroundColor Cyan
    Write-Host "Executando script de ativação oficial (get.activated.win)..." -ForegroundColor Yellow
    try {
        irm https://get.activated.win | iex
        Write-Log "Script de ativação executado com sucesso." Green
    } catch {
        Write-Log "Erro ao executar o script de ativação: $_" Red
    }
    
}

function Invoke-ChrisTitusToolbox {
    Clear-Host
    Write-Host "==== CHRIS TITUS TOOLBOX ====" -ForegroundColor Cyan
    Write-Host "Executando toolbox oficial do site christitus.com..." -ForegroundColor Yellow
    try {
        irm christitus.com/win | iex
        Write-Log "Chris Titus Toolbox executado com sucesso." Green
    } catch {
        Write-Log "Erro ao executar o script do Chris Titus: $_" Red
    }
}

function Update-ScriptFromCloud {
    Clear-Host
    Write-Host "=======================" -ForegroundColor Cyan
    Write-Host "ATUALIZANDO SCRIPT..." -ForegroundColor Cyan
    Write-Host "=======================" -ForegroundColor Cyan

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


# === FUNÇÕES DE RESTAURAÇÃO E UNDO ===

function Restore-DefaultUAC {
    Write-Log "Tentando restaurar as configurações padrão do UAC..." Yellow

    try {
        # Define EnableLUA para 1 para ativar o UAC
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1 -Force -ErrorAction Stop | Out-Null
        # Define ConsentPromptBehaviorAdmin para 5 (padrão) para o prompt de consentimento para administradores
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 5 -Force -ErrorAction Stop | Out-Null

        Write-Log "UAC restaurado para as configurações padrão com sucesso. Será necessário reiniciar para que as alterações tenham efeito completo." Green
        Write-Host "UAC restaurado. Reinicie o computador para aplicar as alterações." -ForegroundColor Green
    } catch {
        Write-Log "Erro ao restaurar o UAC: $_" Red
        Write-Host "Erro ao restaurar o UAC. Verifique o log." -ForegroundColor Red
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
    Write-Host "Ativando o SMBv1..." -ForegroundColor Yellow
    Write-Host "ATENÇÃO: Ativar o SMBv1 pode expor o sistema a vulnerabilidades de segurança mais antigas. Prossiga com cautela." -ForegroundColor Yellow
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
        Write-Host "SMBv1 ativado. Reinicialização recomendada." -ForegroundColor Green
    } catch {
        Write-Log "Erro ao ativar o SMBv1: $_" Red
        Write-Host "Erro ao ativar o SMBv1. Verifique o log." -ForegroundColor Red
    }
}

function Disable-SMBv1 {
    Write-Log "Tentando desativar o SMBv1..." Yellow
    Write-Host "Desativando o SMBv1..." -ForegroundColor Yellow

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
        Write-Host "SMBv1 desativado. Reinicialização recomendada." -ForegroundColor Green
    } catch {
        Write-Log "Erro ao desativar o SMBv1: $_" Red
        Write-Host "Erro ao desativar o SMBv1. Verifique o log." -ForegroundColor Red
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

function New-FolderForced {
    param (
        [string]$Path
    )
    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -ItemType Directory -Force | Out-Null
    }
}

#endregion

#region → MENUS

# === FUNÇÕES DE MENU ===


function Show-FullMaintenance {
    Clear-Host
    Write-Host "=============================================" -ForegroundColor Cyan
    Write-Host "        INICIANDO MANUTENÇÃO COMPLETA        " -ForegroundColor Cyan
    Write-Host "=============================================" -ForegroundColor Cyan
    Write-Log "Iniciando Manutenção Completa..." Yellow

    # Sequência lógica de chamadas aos novos menus e funções
    # A maioria dos menus já tem sua própria opção de "Executar Todos" (Opção 1)
    # Então, vamos simular a seleção da Opção 1 dentro de cada submenu
    # Nota: Show-MainMenu não tem "Executar Todos", suas opções são os submenus em si.

    Write-Host "Executando: Menu de Instalação de Programas (Opção 1 - Todas as Ferramentas)..." -ForegroundColor Green
    # Chamando a função Install-Applications que está dentro de Show-InstallationMenu opção 1
    Install-Applications
    # Se Show-InstallationMenu tivesse outras funções que não estivessem em Install-Applications,
    # ou uma opção de "Executar Todas" mais abrangente, chamaria essa opção aqui.
    Start-Sleep 2

    Write-Host "Executando: Menu de Rede e Impressoras (Opção 1 - Todas as Configurações de Rede)..." -ForegroundColor Green
    # Chamando as funções que estão dentro de Show-NetworkMenu opção 1
    Install-NetworkPrinters
    Optimize-NetworkPerformance
    Start-Sleep 2

    Write-Host "Executando: Menu de Configurações Avançadas (Opção 1 - Todas as Configurações)..." -ForegroundColor Green
    # Chamando as funções que estão dentro de Show-AdvancedSettingsMenu opção 1
    Disable-UAC
    Disable-SMBv1
    Grant-HardenOfficeMacros
    Start-Sleep 2

    Write-Host "Executando: Menu de Utilitários do Sistema (Opção 1 - Todas as Tarefas de Otimização)..." -ForegroundColor Green
    # Chamando as funções que estão dentro de Show-UtilitiesMenu opção 1
    Remove-Bloatware
    Remove-OneDrive-AndRestoreFolders
    Cleanup-System
    Optimize-Drives
    Grant-PrivacyTweaks
    Grant-ControlPanelTweaks
    Grant-ExtraTweaks
    Disable-Cortana-AndSearch
    Start-Sleep 2

    Write-Host "Executando: Menu de Diagnóstico e Informações (Opção 1 - Todas as Verificações)..." -ForegroundColor Green
    # Chamando as funções que estão dentro de Show-DiagnosticsMenu opção 1
    sfc /scannow
    Dism /Online /Cleanup-Image /RestoreHealth
    # Chkdsk é omitido aqui por requerer reboot
    Start-Sleep 2

    Write-Host "Executando: Menu de Scripts Externos e Ativadores (Opção 1 - Todos os Scripts)..." -ForegroundColor Green
    # Chame aqui as funções ou comandos para seus scripts externos,
    # como você os configurou na opção 1 de Show-ExternalScriptsMenu
    # Exemplo: & "$PSScriptRoot\ExternalScripts\ScriptExterno1.ps1"
    # Exemplo: Start-Process "C:\Caminho\Para\SeuAtivador.exe" -Wait
    Start-Sleep 2


    Write-Host "=============================================" -ForegroundColor Cyan
    Write-Host "        MANUTENÇÃO COMPLETA CONCLUÍDA!       " -ForegroundColor Cyan
    Write-Host "=============================================" -ForegroundColor Cyan
    Write-Log "Manutenção Completa Concluída." Green
    Show-SuccessMessage
    [Console]::ReadKey($true) | Out-Null
}

function Show-PersonalizationTweaksMenu {
    do {
        Clear-Host
        Write-Host "=============================================" -ForegroundColor Cyan
        Write-Host "   MENU DE PERSONALIZAÇÃO E NOVOS RECURSOS   " -ForegroundColor Cyan
        Write-Host "=============================================" -ForegroundColor Cyan
        Write-Log "Exibindo menu de Personalização e Novos Recursos..." Blue

        Write-Host " A. Executar Todos os Ajustes de Personalização (Sequência)" -ForegroundColor Green
        Write-Host " B. Ativar 'Finalizar tarefa' na barra de tarefas"
        Write-Host " C. Ativar atualizações antecipadas do Windows Update"
        Write-Host " D. Ativar modo escuro"
        Write-Host " E. Ativar histórico da área de transferência"
        Write-Host " F. Restauração de apps após reinício"
        Write-Host " G. Mostrar segundos no relógio"
        Write-Host " H. Updates para outros produtos Microsoft"
        Write-Host " I. Habilitar sudo embutido (Windows 11 24H2+)"
        Write-Host "`n X. Voltar ao Menu Anterior" -ForegroundColor Magenta
        Write-Host "=============================================" -ForegroundColor Cyan

        $key = [Console]::ReadKey($true).Key
        Write-Log "Opção escolhida no menu de Personalização: $key" Blue

        switch ($key) {
            'A' {
                Write-Host "Executando: Todos os Ajustes de Personalização..." -ForegroundColor Yellow
                Enable-TaskbarEndTask
                Enable-WindowsUpdateFast
                Enable-DarkTheme
                Enable-ClipboardHistory
                Enable-RestartAppsAfterReboot
                Enable-TaskbarSeconds
                Enable-OtherMicrosoftUpdates
                Enable-Sudo
                Write-Host "Todos os Ajustes de Personalização Concluídos!" -ForegroundColor Green
                [Console]::ReadKey($true) | Out-Null
            }
            'B' { Enable-TaskbarEndTask; Show-SuccessMessage }
            'C' { Enable-WindowsUpdateFast; Show-SuccessMessage }
            'D' { Enable-DarkTheme; Show-SuccessMessage }
            'E' { Enable-ClipboardHistory; Show-SuccessMessage }
            'F' { Enable-RestartAppsAfterReboot; Show-SuccessMessage }
            'G' { Enable-TaskbarSeconds; Show-SuccessMessage }
            'H' { Enable-OtherMicrosoftUpdates; Show-SuccessMessage }
            'I' { Enable-Sudo; Show-SuccessMessage }
            'x' { return }
            'X' { return }
            default {
                Write-Host "`nOpção inválida! Pressione qualquer tecla para continuar." -ForegroundColor Red
                [Console]::ReadKey($true) | Out-Null
            }
        }
    } while ($true)
}

function Show-AdvancedSettingsMenu {
    do {
        Clear-Host
        Write-Host "=============================================" -ForegroundColor Cyan
        Write-Host "       MENU DE CONFIGURAÇÕES AVANÇADAS      " -ForegroundColor Cyan
        Write-Host "=============================================" -ForegroundColor Cyan
        Write-Log "Exibindo menu de Configurações Avançadas..." Blue

        Write-Host " A. Executar Todas as Configurações Avançadas (Sequência)" -ForegroundColor Green
        Write-Host " B. Desabilitar Controle de Conta de Usuário (UAC)"
        Write-Host " C. Desabilitar SMBv1 (RECOMENDADO PARA SEGURANÇA)"
        Write-Host " D. Proteger Office contra Macros Maliciosas"
        Write-Host "`n X. Voltar ao Menu Principal" -ForegroundColor Magenta
        Write-Host "=============================================" -ForegroundColor Cyan

        $key = [Console]::ReadKey($true).Key
        Write-Log "Opção escolhida no menu de Configurações Avançadas: $key" Blue

        switch ($key) {
            'A' {
                Write-Host "Executando: Todas as Configurações Avançadas..." -ForegroundColor Yellow
                Disable-UAC
                Disable-SMBv1
                Grant-HardenOfficeMacros
                Write-Host "Todas as Configurações Avançadas Concluídas!" -ForegroundColor Green
                [Console]::ReadKey($true) | Out-Null
            }
            'B' { Disable-UAC; Show-SuccessMessage }
            'C' { Disable-SMBv1; Show-SuccessMessage }
            'D' { Grant-HardenOfficeMacros; Show-SuccessMessage }
            'x' { return }
            'X' { return }
            default {
                Write-Host "`nOpção inválida! Pressione qualquer tecla para continuar." -ForegroundColor Red
                [Console]::ReadKey($true) | Out-Null
            }
        }
    } while ($true)
}

function Show-DiagnosticsMenu {
    do {
        Clear-Host
        Write-Host "=============================================" -ForegroundColor Cyan
        Write-Host "      MENU DE DIAGNÓSTICO E INFORMAÇÕES     " -ForegroundColor Cyan
        Write-Host "=============================================" -ForegroundColor Cyan
        Write-Log "Exibindo menu de Diagnóstico e Informações..." Blue

        Write-Host " A. Executar Todas as Verificações de Diagnóstico (Sequência)" -ForegroundColor Green
        Write-Host " B. Verificar Integridade dos Arquivos do Sistema (SFC)"
        Write-Host " C. Reparar Imagem do Windows (DISM)"
        Write-Host " D. Verificar Disco (Chkdsk)"
        Write-Host " E. Abrir Visualizador de Eventos"
        Write-Host " F. Gerar Relatório de Informações do Sistema"
        Write-Host "`n X. Voltar ao Menu Principal" -ForegroundColor Magenta
        Write-Host "=============================================" -ForegroundColor Cyan

        $key = [Console]::ReadKey($true).Key
        Write-Log "Opção escolhida no menu de Diagnóstico: $key" Blue

        switch ($key) {
            'A' {
                Write-Host "Executando: Todas as Verificações de Diagnóstico..." -ForegroundColor Yellow
                Write-Log "Iniciando verificação SFC..." Yellow
                sfc /scannow | Write-Log -Color White
                Write-Log "Verificação SFC concluída." Green
                Start-Sleep 2

                Write-Log "Iniciando reparo de imagem DISM..." Yellow
                Dism /Online /Cleanup-Image /RestoreHealth | Write-Log -Color White
                Write-Log "Reparo de imagem DISM concluído." Green
                Start-Sleep 2

                Write-Host "Todas as Verificações de Diagnóstico Concluídas (excluindo Chkdsk automático)!" -ForegroundColor Green
                [Console]::ReadKey($true) | Out-Null
            }
            'B' {
                Write-Log "Iniciando verificação SFC..." Yellow
                sfc /scannow | Write-Log -Color White
                Write-Log "Verificação SFC concluída." Green
                [Console]::ReadKey($true) | Out-Null
            }
            'C' {
                Write-Log "Iniciando reparo de imagem DISM..." Yellow
                Dism /Online /Cleanup-Image /RestoreHealth | Write-Log -Color White
                Write-Log "Reparo de imagem DISM concluído." Green
                [Console]::ReadKey($true) | Out-Null
            }
            'D' {
                Write-Host "Aviso: Chkdsk C: /f /r pode exigir reinicialização do sistema." -ForegroundColor Yellow
                Write-Host "Deseja agendar a verificação de disco na próxima reinicialização? (S/N)" -ForegroundColor White
                $confirmChkdsk = [Console]::ReadKey($true).KeyChar
                if ($confirmChkdsk -eq 's' -or $confirmChkdsk -eq 'S') {
                    Write-Log "Agendando Chkdsk na próxima reinicialização..." Yellow
                    chkdsk C: /f /r
                    Write-Log "Chkdsk agendado. Reinicie o PC para executar." Green
                } else {
                    Write-Log "Chkdsk não agendado." Red
                }
                [Console]::ReadKey($true) | Out-Null
            }
            'E' {
                Write-Log "Abrindo Visualizador de Eventos..." Yellow
                Start-Process eventvwr.msc
                [Console]::ReadKey($true) | Out-Null
            }
            'F' {
                Write-Log "Gerando relatório de informações do sistema..." Yellow
                msinfo32.exe
                Write-Log "Relatório de informações do sistema gerado/aberto." Green
                [Console]::ReadKey($true) | Out-Null
            }
            'x' { return }
            'X' { return }
            default {
                Write-Host "`nOpção inválida! Pressione qualquer tecla para continuar." -ForegroundColor Red
                [Console]::ReadKey($true) | Out-Null
            }
        }
    } while ($true)
}

function Show-InstallationMenu {
    do {
        Clear-Host
        Write-Host "==== MENU: INSTALAÇÃO DE PROGRAMAS ====" -ForegroundColor Cyan
        Write-Host " A. Instalar todos os programas listados" -ForegroundColor Green
        Write-Host " B. 7-Zip"
        Write-Host " C. AnyDesk"
        Write-Host " D. AutoHotKey"
        Write-Host " E. Google Chrome"
        Write-Host " F. Google Drive"
        Write-Host " G. Microsoft Office"
        Write-Host " H. Microsoft PowerToys"
        Write-Host " I. Notepad++"
        Write-Host " J. VLC Media Player"
        Write-Host " K. Instalar/Atualizar PowerShell"
        Write-Host " X. Voltar ao menu principal" -ForegroundColor Green

        $key = [Console]::ReadKey($true).Key
        switch ($key) {
            'A' { Install-Applications; Show-SuccessMessage }
            'B' { winget install --id 7zip.7zip -e --accept-package-agreements --accept-source-agreements; Show-SuccessMessage }
            'C' { winget install --id AnyDesk.AnyDesk -e --accept-package-agreements --accept-source-agreements; Show-SuccessMessage }
            'D' { winget install --id AutoHotkey.AutoHotkey -e --accept-package-agreements --accept-source-agreements; Show-SuccessMessage }
            'E' { winget install --id Google.Chrome -e --accept-package-agreements --accept-source-agreements; Show-SuccessMessage }
            'F' { winget install --id Google.GoogleDrive -e --accept-package-agreements --accept-source-agreements; Show-SuccessMessage }
            'G' { winget install --id Microsoft.Office -e --accept-package-agreements --accept-source-agreements; Show-SuccessMessage }
            'H' { winget install --id Microsoft.PowerToys -e --accept-package-agreements --accept-source-agreements; Show-SuccessMessage }
            'I' { winget install --id Notepad++.Notepad++ -e --accept-package-agreements --accept-source-agreements; Show-SuccessMessage }
            'J' { winget install --id VideoLAN.VLC -e --accept-package-agreements --accept-source-agreements; Show-SuccessMessage }
            'K' { Update-PowerShell; Show-SuccessMessage 
            # ✅ Após a última instalação, copia o atalho pro Startup
$atalhoOrigem = "G:\Drives compartilhados\MundoCOC\Tecnologia\AutoHotKey\Colegio - Atalho.lnk"
$atalhoDestino = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\" + "\Colegio - Atalho.lnk"
Copy-Item -Path $atalhoOrigem -Destination $atalhoDestino -Force
            }
            'X' { return }
            default { Write-Host "`nOpção inválida!" -ForegroundColor Red; Start-Sleep 1 }
        }
    } while ($true)
}

function Show-NetworkMenu {
    do {
        Clear-Host
        Write-Host "=============================================" -ForegroundColor Cyan
        Write-Host "           MENU DE REDE E IMPRESSORAS        " -ForegroundColor Cyan
        Write-Host "=============================================" -ForegroundColor Cyan
        Write-Log "Exibindo menu de Rede e Impressoras..." Blue

        Write-Host " A. Executar Todas as Configurações de Rede (Sequência)" -ForegroundColor Green
        Write-Host " B. Instalar Impressoras de Rede"
        Write-Host " C. Otimizar Desempenho de Rede"
        Write-Host " D. Restaurar Padrões de IPv6"
        Write-Host "`n X. Voltar ao Menu Principal" -ForegroundColor Magenta
        Write-Host "=============================================" -ForegroundColor Cyan

        $key = [Console]::ReadKey($true).Key
        Write-Log "Opção escolhida no menu de Rede e Impressoras: $key" Blue

        switch ($key) {
            'A' {
                Write-Host "Executando: Todas as Configurações de Rede..." -ForegroundColor Yellow
                Install-NetworkPrinters
                Optimize-NetworkPerformance
                Restore-DefaultIPv6
                Write-Host "Todas as Configurações de Rede Concluídas!" -ForegroundColor Green
                [Console]::ReadKey($true) | Out-Null
            }
            'B' { Install-NetworkPrinters; Show-SuccessMessage }
            'C' { Optimize-NetworkPerformance; Show-SuccessMessage }
            'D' { Restore-DefaultIPv6; Show-SuccessMessage }
            'x' { return }
            'X' { return }
            default {
                Write-Host "`nOpção inválida! Pressione qualquer tecla para continuar." -ForegroundColor Red
                [Console]::ReadKey($true) | Out-Null
            }
        }
    } while ($true)
}

function Show-ExternalScriptsMenu {
    do {
        Clear-Host
        Write-Host "==== MENU: SCRIPTS EXTERNOS E ATIVADORES ====" -ForegroundColor Cyan
        Write-Host " A. Executar todos os scripts deste menu" -ForegroundColor Green
        Write-Host " B. Ativar Windows (get.activated.win)"
        Write-Host " C. Toolbox Chris Titus (christitus.com)"
        Write-Host " D. Atualizar Script Supremo"
        Write-Host " X. Voltar ao menu principal" -ForegroundColor Green

        $key = [Console]::ReadKey($true).Key
        switch ($key) {
            'A' {
                Invoke-WindowsActivator
                Invoke-ChrisTitusToolbox
                Update-ScriptFromCloud
                Show-SuccessMessage
            }
            'B' { Invoke-WindowsActivator; Show-SuccessMessage }
            'C' { Invoke-ChrisTitusToolbox; Show-SuccessMessage }
            'D' { Update-ScriptFromCloud; Show-SuccessMessage }
            'X' { return }
            default {
                Write-Host "`nOpção inválida!" -ForegroundColor Red
                Start-Sleep -Seconds 1
            }
        }
    } while ($true)
}

function Show-RestoreUndoMenu {
    do {
        Clear-Host
        Write-Host "=============================================" -ForegroundColor Cyan
        Write-Host "  MENU DE RESTAURAÇÃO E SEGURANÇA (UNDO)   " -ForegroundColor Cyan
        Write-Host "=============================================" -ForegroundColor Cyan
        Write-Log "Exibindo menu de Restauração e Segurança (Undo)..." Blue

        Write-Host " A. Executar todas as tarefas deste menu" -ForegroundColor Green
        Write-Host " B. Bloquear macros Office (segurança)"
        Write-Host " C. Desabilitar SMBv1 (RECOMENDADO)"
        Write-Host " D. Desfazer privacidade agressiva"
        Write-Host " E. Habilitar SMBv1 (NÃO RECOMENDADO)"
        Write-Host " F. Reabilitar Action Center/Notificações"
        Write-Host " G. Reabilitar IPv6"
        Write-Host " H. Reinstalar aplicativos essenciais"
        Write-Host " I. Reinstalar o OneDrive"
        Write-Host " J. Restaurar backup do registro"
        Write-Host " K. Restaurar backup do registro (alternativo)"
        Write-Host " L. Restaurar macros Office (padrão)"
        Write-Host " M. Restaurar menu de contexto clássico"
        Write-Host " N. Restaurar UAC para padrão"
        Write-Host " O. Restaurar visual padrão"
        Write-Host " X. Voltar ao menu principal" -ForegroundColor Green

        $key = [Console]::ReadKey($true).Key
        switch ($key) {
            'A' {
                Grant-HardenOfficeMacros
                Disable-SMBv1
                Undo-PrivacyHardening
                Enable-SMBv1
                Grant-ActionCenter-Notifications
                Restore-DefaultIPv6
                Restore-BloatwareSafe
                Restore-OneDrive
                Restore-Registry-FromBackup
                Restore-Registry
                Restore-OfficeMacros
                Enable-ClassicContextMenu
                Restore-DefaultUAC
                Restore-VisualPerformanceDefault
                Show-SuccessMessage
            }
            'B' { Grant-HardenOfficeMacros; Show-SuccessMessage }
            'C' { Disable-SMBv1; Show-SuccessMessage }
            'D' { Undo-PrivacyHardening; Show-SuccessMessage }
            'E' { Enable-SMBv1; Show-SuccessMessage }
            'F' { Grant-ActionCenter-Notifications; Show-SuccessMessage }
            'G' { Restore-DefaultIPv6; Show-SuccessMessage }
            'H' { Restore-BloatwareSafe; Show-SuccessMessage }
            'I' { Restore-OneDrive; Show-SuccessMessage }
            'J' { Restore-Registry-FromBackup; Show-SuccessMessage }
            'K' { Restore-Registry; Show-SuccessMessage }
            'L' { Restore-OfficeMacros; Show-SuccessMessage }
            'M' { Enable-ClassicContextMenu; Show-SuccessMessage }
            'N' { Restore-DefaultUAC; Show-SuccessMessage }
            'O' { Restore-VisualPerformanceDefault; Show-SuccessMessage }
            'X' { return }
            default {
                Write-Host "`nOpção inválida!" -ForegroundColor Red
                Start-Sleep 1
            }
        }
    } while ($true)
}

function Show-UtilitiesMenu {
    do {
        Clear-Host
        Write-Host "=============================================" -ForegroundColor Cyan
        Write-Host "       MENU DE UTILITÁRIOS DO SISTEMA        " -ForegroundColor Cyan
        Write-Host "=============================================" -ForegroundColor Cyan
        Write-Log "Exibindo menu de Utilitários do Sistema..." Blue

        Write-Host " A. Executar Todas as Tarefas de Otimização (Sequência)" -ForegroundColor Green
        Write-Host " B. Gerenciar Bloatware"
        Write-Host " C. Limpeza e Otimização de Disco"
        Write-Host " D. Aplicar Otimizações de Desempenho e Privacidade"
        Write-Host " E. Desativar Cortana e Pesquisa Online"
        Write-Host "`n X. Voltar ao Menu Principal" -ForegroundColor Magenta
        Write-Host "=============================================" -ForegroundColor Cyan

        $key = [Console]::ReadKey($true).Key
        Write-Log "Opção escolhida no menu de Utilitários: $key" Blue

        switch ($key) {
            'A' {
                Write-Host "Executando: Todas as Tarefas de Otimização..." -ForegroundColor Yellow
                Remove-Bloatware
                Remove-OneDrive-AndRestoreFolders
                Cleanup-System
                Optimize-Drives
                Grant-PrivacyTweaks
                Grant-ControlPanelTweaks
                Grant-ExtraTweaks
                Disable-Cortana-AndSearch
                Show-PersonalizationTweaksMenu # NOVO: CHAMA O MENU DE PERSONALIZAÇÃO COMPLETO
                Write-Host "Todas as Tarefas de Otimização Concluídas!" -ForegroundColor Green
                [Console]::ReadKey($true) | Out-Null
            }
            'B' {
                do {
                    Clear-Host
                    Write-Host "=============================================" -ForegroundColor Cyan
                    Write-Host "       SUBMENU DE GERENCIAMENTO DE BLOATWARE        " -ForegroundColor Cyan
                    Write-Host "=============================================" -ForegroundColor Cyan
                    Write-Log "Exibindo submenu de Bloatware..." Blue

                    Write-Host " A. Remover Bloatware (Todos em sequência)"
                    Write-Host " B. Remover Aplicativos Pré-instalados (Bloatware)"
                    Write-Host " C. Remover OneDrive e Restaurar Pastas"
                    Write-Host "`n X. Voltar ao Menu Anterior" -ForegroundColor Magenta
                    Write-Host "=============================================" -ForegroundColor Cyan

                    $subChoice = [Console]::ReadKey($true).Key
                    Write-Log "Opção escolhida no submenu de Bloatware: $subChoice" Blue

                    switch ($subChoice) {
                        'A' {
                            Write-Host "Executando: Remover Bloatware (Todos em sequência)..." -ForegroundColor Yellow
                            Remove-Bloatware
                            Remove-OneDrive-AndRestoreFolders
                            Write-Host "Remoção de Bloatware Concluída!" -ForegroundColor Green
                            [Console]::ReadKey($true) | Out-Null
                        }
                        'B' { Remove-Bloatware; Show-SuccessMessage }
                        'C' { Remove-OneDrive-AndRestoreFolders; Show-SuccessMessage }
                        'x' { return }
                        'X' { return }
                        default {
                            Write-Host "`nOpção inválida! Pressione qualquer tecla para continuar." -ForegroundColor Red
                            [Console]::ReadKey($true) | Out-Null
                        }
                    }
                } while ($true)
            }
            'C' {
                do {
                    Clear-Host
                    Write-Host "=============================================" -ForegroundColor Cyan
                    Write-Host "      SUBMENU DE LIMPEZA E OTIMIZAÇÃO DE DISCO      " -ForegroundColor Cyan
                    Write-Host "=============================================" -ForegroundColor Cyan
                    Write-Log "Exibindo submenu de Limpeza e Otimização..." Blue

                    Write-Host " A. Executar Todas as Tarefas de Limpeza e Otimização"
                    Write-Host " B. Limpeza de Arquivos Temporários"
                    Write-Host " C. Desfragmentar/Otimizar Drives"
                    Write-Host "`n X. Voltar ao Menu Anterior" -ForegroundColor Magenta
                    Write-Host "=============================================" -ForegroundColor Cyan

                    $subChoice = [Console]::ReadKey($true).Key
                    Write-Log "Opção escolhida no submenu de Limpeza: $subChoice" Blue

                    switch ($subChoice) {
                        'A' {
                            Write-Host "Executando: Todas as Tarefas de Limpeza e Otimização..." -ForegroundColor Yellow
                            Cleanup-System
                            Optimize-Drives
                            Write-Host "Limpeza e Otimização Concluídas!" -ForegroundColor Green
                            [Console]::ReadKey($true) | Out-Null
                        }
                        'B' { Cleanup-System; Show-SuccessMessage }
                        'C' { Optimize-Drives; Show-SuccessMessage }
                        'x' { return }
                        'X' { return }
                        default {
                            Write-Host "`nOpção inválida! Pressione qualquer tecla para continuar." -ForegroundColor Red
                            [Console]::ReadKey($true) | Out-Null
                        }
                    }
                } while ($true)
            }
            'D' { # Otimizações de Desempenho e Privacidade
                do {
                    Clear-Host
                    Write-Host "=============================================" -ForegroundColor Cyan
                    Write-Host "    SUBMENU DE OTIMIZAÇÕES DE DESEMPENHO E PRIVACIDADE    " -ForegroundColor Cyan
                    Write-Host "=============================================" -ForegroundColor Cyan
                    Write-Log "Exibindo submenu de Otimizações de Desempenho e Privacidade..." Blue

                    Write-Host " A. Aplicar Todas as Otimizações de Desempenho e Privacidade"
                    Write-Host " B. Aplicar Tweaks de Privacidade"
                    Write-Host " C. Ajustar Painel de Controle e Explorer"
                    Write-Host " D. Aplicar Tweaks Extras"
                    Write-Host " E. Outros Ajustes e Personalização" -ForegroundColor Green
                    Write-Host "`n X. Voltar ao Menu Anterior" -ForegroundColor Magenta
                    Write-Host "=============================================" -ForegroundColor Cyan

                    $subChoice = [Console]::ReadKey($true).Key
                    Write-Log "Opção escolhida no submenu de Desempenho e Privacidade: $subChoice" Blue

                    switch ($subChoice) {
                        'A' {
                            Write-Host "Executando: Todas as Otimizações de Desempenho e Privacidade..." -ForegroundColor Yellow
                            Grant-PrivacyTweaks
                            Grant-ControlPanelTweaks
                            Grant-ExtraTweaks
                            Show-PersonalizationTweaksMenu # NOVO: CHAMA O MENU DE PERSONALIZAÇÃO COMPLETO
                            Write-Host "Otimizações de Desempenho e Privacidade Concluídas!" -ForegroundColor Green
                            [Console]::ReadKey($true) | Out-Null
                        }
                        'B' { Grant-PrivacyTweaks; Show-SuccessMessage }
                        'C' { Grant-ControlPanelTweaks; Show-SuccessMessage }
                        'D' { Grant-ExtraTweaks; Show-SuccessMessage }
                        'E' { Show-PersonalizationTweaksMenu }
                        'x' { return }
                        'X' { return }
                        default {
                            Write-Host "`nOpção inválida! Pressione qualquer tecla para continuar." -ForegroundColor Red
                            [Console]::ReadKey($true) | Out-Null
                        }
                    }
                } while ($true)
            }
            'E' { Disable-Cortana-AndSearch; Show-SuccessMessage }
            'x' { return }
            'X' { return }
            default {
                Write-Host "`nOpção inválida! Pressione qualquer tecla para continuar." -ForegroundColor Red
                [Console]::ReadKey($true) | Out-Null
            }
        }
    } while ($true)
}

function Show-CleanupMenu {
    do {
        Clear-Host
        Write-Host "==== MENU: LIMPEZA E OTIMIZAÇÃO ====" -ForegroundColor Cyan
        Write-Host " A. Executar todas as limpezas" -ForegroundColor Green
        Write-Host " B. Limpar arquivos temporários"
        Write-Host " C. Limpar cache do Windows Update"
        Write-Host " D. Limpar cache DNS"
        Write-Host " E. Limpar Prefetch"
        Write-Host " F. Limpar spooler de impressão"
        Write-Host " G. Limpeza profunda do sistema"
        Write-Host " H. Limpar WinSxS"
        Write-Host " I. Remover Windows.old"
        Write-Host " J. Otimizar volumes"
        Write-Host " X. Voltar ao menu anterior" -ForegroundColor Green

        $key = [Console]::ReadKey($true).Key
        switch ($key) {
            'A' {
                Clear-TemporaryFiles
                Clear-WUCache
                Clear-DNS
                Clear-Prefetch
                Clear-PrintSpooler
                Clear-DeepSystemCleanup
                Clear-WinSxS
                Remove-WindowsOld
                Optimize-Volumes
                Show-SuccessMessage
            }
            'B' { Clear-TemporaryFiles; Show-SuccessMessage }
            'C' { Clear-WUCache; Show-SuccessMessage }
            'D' { Clear-DNS; Show-SuccessMessage }
            'E' { Clear-Prefetch; Show-SuccessMessage }
            'F' { Clear-PrintSpooler; Show-SuccessMessage }
            'G' { Clear-DeepSystemCleanup; Show-SuccessMessage }
            'H' { Clear-WinSxS; Show-SuccessMessage }
            'I' { Remove-WindowsOld; Show-SuccessMessage }
            'J' { Optimize-Volumes; Show-SuccessMessage }
            'X' { return }
            default {
                Write-Host "`nOpção inválida!" -ForegroundColor Red
                Start-Sleep 1
            }
        }
    } while ($true)
}

function Show-BloatwareMenu {
    do {
        Clear-Host
        Write-Host "==== MENU: REMOÇÃO DE BLOATWARE ====" -ForegroundColor Cyan
        Write-Host " A. Executar todas as remoções" -ForegroundColor Green
        Write-Host " B. Remover bloatware (LinkedIn, Xbox, etc.)"
        Write-Host " C. Remover Copilot"
        Write-Host " D. Remover OneDrive"
        Write-Host " E. Encerrar processos dispensáveis"
        Write-Host " F. Desativar tarefas agendadas de bloatware"
        Write-Host " G. Remover pins do Menu Iniciar"
        Write-Host " X. Voltar ao menu anterior" -ForegroundColor Green

        $key = [Console]::ReadKey($true).Key
        switch ($key) {
            'A' {
                Remove-Bloatware
                Remove-Copilot
                Remove-OneDrive-AndRestoreFolders
                Stop-BloatwareProcesses
                Disable-BloatwareScheduledTasks
                Remove-StartAndTaskbarPins
                Show-SuccessMessage
            }
            'B' { Remove-Bloatware; Show-SuccessMessage }
            'C' { Remove-Copilot; Show-SuccessMessage }
            'D' { Remove-OneDrive-AndRestoreFolders; Show-SuccessMessage }
            'E' { Stop-BloatwareProcesses; Show-SuccessMessage }
            'F' { Disable-BloatwareScheduledTasks; Show-SuccessMessage }
            'G' { Remove-StartAndTaskbarPins; Show-SuccessMessage }
            'X' { return }
            default {
                Write-Host "`nOpção inválida!" -ForegroundColor Red
                Start-Sleep 1
            }
        }
    } while ($true)
}

function Show-SystemPerformanceMenu {
    do {
        Clear-Host
        Write-Host "==== MENU: DESEMPENHO DO SISTEMA ====" -ForegroundColor Cyan
        Write-Host " A. Executar todas as otimizações" -ForegroundColor Green
        Write-Host " B. Aplicar tema de desempenho"
        Write-Host " C. Otimizar Windows Explorer"
        Write-Host " D. Desativar serviços desnecessários"
        Write-Host " E. Ajustar visual para performance"
        Write-Host " F. Criar ponto de restauração"
        Write-Host " G. Aplicar hardening de segurança"
        Write-Host " X. Voltar ao menu anterior" -ForegroundColor Green

        $key = [Console]::ReadKey($true).Key
        switch ($key) {
            'A' {
                Set-PerformanceTheme
                Optimize-ExplorerPerformance
                Disable-UnnecessaryServices
                Set-VisualPerformance
                New-SystemRestorePoint
                Enable-WindowsHardening
                Show-SuccessMessage
            }
            'B' { Set-PerformanceTheme; Show-SuccessMessage }
            'C' { Optimize-ExplorerPerformance; Show-SuccessMessage }
            'D' { Disable-UnnecessaryServices; Show-SuccessMessage }
            'E' { Set-VisualPerformance; Show-SuccessMessage }
            'F' { New-SystemRestorePoint; Show-SuccessMessage }
            'G' { Enable-WindowsHardening; Show-SuccessMessage }
            'X' { return }
            default {
                Write-Host "`nOpção inválida!" -ForegroundColor Red
                Start-Sleep 1
            }
        }
    } while ($true)
}


# === MENU PRINCIPAL ===

function Show-MainMenu {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [bool]$RunFullAutomation = $false, # Mantém este, mas a lógica de automação principal usa os outros parâmetros
        [Parameter(Mandatory=$false)]
        [bool]$RunAllCleanup = $false,
        [Parameter(Mandatory=$false)]
        [bool]$RunBloatwareRemoval = $false,
        [Parameter(Mandatory=$false)]
        [bool]$RunPrivacyTweaks = $false,
        [Parameter(Mandatory=$false)]
        [bool]$InstallEssentialApps = $false, # Parâmetro correto para instalação de apps
        [Parameter(Mandatory=$false)]
        [bool]$RunWindowsUpdate = $false,
        [Parameter(Mandatory=$false)]
        [bool]$RemoveCopilot = $false,
        [Parameter(Mandatory=$false)]
        [bool]$DisableRecall = $false,
        [Parameter(Mandatory=$false)]
        [bool]$ApplyOptimizedPowerPlan = $false,
        [Parameter(Mandatory=$false)]
        [bool]$ApplyGPOSettings = $false, # NOVO PARÂMETRO
        [Parameter(Mandatory=$false)]
        [bool]$CreateRestorePoint = $false, # Adicionado aqui para consistência nos parâmetros
        [Parameter(Mandatory=$false)]
        [bool]$RunNetworkOptimization = $false, # Adicionado aqui para consistência nos parâmetros
        [Parameter(Mandatory=$false)]
        [bool]$RunDiagnostics = $false, # Adicionado aqui para consistência nos parâmetros
        [Parameter(Mandatory=$false)]
        [bool]$ForceOneDriveRemoval = $false # Adicionado aqui para consistência nos parâmetros
    )

    # Definindo as opções do menu principal com numeração explícita
    $mainMenuOptions = @(
        "1) Executar Rotinas de Limpeza e Otimização",
        "2) Remover Bloatware",
        "3) Aplicar Ajustes de Privacidade e Registro",
        "4) Otimizar Desempenho de Rede",
        "5) Instalar Aplicativos Essenciais",
        "6) Executar Diagnósticos do Sistema",
        "7) Gerenciar Atualizações do Windows (PSWindowsUpdate)",
        "8) Configurar Plano de Energia Otimizado",
        "9) Remover OneDrive Completamente",
        "10) Aplicar Configurações de GPO (Atualizações, Navegadores)", # NOVA OPÇÃO
		"11) Reiniciar Explorer", # NOVA OPÇÃO
	    "12) Aplicar Ajustes de Interface do Usuário (UI Tweaks)", # NOVA OPÇÃO
		"0) Sair"
    )

    # Lógica que decide se o script roda automaticamente ou exibe o menu
    # Usando $RunFullAutomation ou qualquer outro parâmetro de execução específica
    if ($RunFullAutomation -or $RunAllCleanup -or $RunBloatwareRemoval -or $RunPrivacyTweaks -or $RunNetworkOptimization -or `
        $InstallEssentialApps -or $RunDiagnostics -or $CreateRestorePoint -or $ForceOneDriveRemoval -or `
        $RemoveCopilot -or $DisableRecall -or $RunWindowsUpdate -or $ApplyOptimizedPowerPlan -or $ApplyGPOSettings) # Adicionado $ApplyGPOSettings aqui
    {
        Write-Log "Modo de execução automática ativado via parâmetros." -Type Info
        Write-Host "Iniciando execução automática de acordo com os parâmetros fornecidos..." -ForegroundColor Green

        # Cria o ponto de restauração se o parâmetro for true
        if ($CreateRestorePoint) {
            Write-Log "Criando ponto de restauração..." -Type Info
            Write-Host "Criando ponto de restauração. Aguarde..." -ForegroundColor Cyan
            try {
                Checkpoint-Computer -Description "Manutenção Suprema Automatizada" -ErrorAction Stop
                Write-Log "Ponto de restauração criado com sucesso." -Type Success
                Write-Host "Ponto de restauração criado com sucesso!" -ForegroundColor Green
            } catch {
                Write-Log "Falha ao criar ponto de restauração: $($_.Exception.Message)" -Type Error
                Write-Host "Falha ao criar ponto de restauração: $($_.Exception.Message)" -ForegroundColor Red
            }
        }

        # Executa as ações baseadas nos parâmetros
        if ($RunAllCleanup) {
            Write-Log "Executando todas as rotinas de limpeza e otimização..." -Type Info
            Write-Host "Executando Rotinas de Limpeza e Otimização..." -ForegroundColor Cyan
            Perform-SystemOptimizations # CHAMA A FUNÇÃO
            Write-Host "--> Limpeza e Otimização concluídas." -ForegroundColor Green
        }
        if ($RunBloatwareRemoval) {
            Write-Log "Executando remoção de Bloatware..." -Type Info
            Write-Host "Executando Remoção de Bloatware..." -ForegroundColor Cyan
            Remove-Bloatware # Sua função de remoção de bloatware existente
            if ($RemoveCopilot) {
                Write-Log "Removendo e desativando Windows Copilot..." -Type Info
                Remove-WindowsCopilot # CHAMA A FUNÇÃO
            }
            if ($DisableRecall) {
                Write-Log "Desativando Windows Recall..." -Type Info
                Disable-WindowsRecall # CHAMA A FUNÇÃO
            }
            if ($ForceOneDriveRemoval) {
                Write-Log "Forçando remoção completa do OneDrive..." -Type Info
                Force-RemoveOneDrive # CHAMA A FUNÇÃO
            }
            Write-Host "--> Remoção de Bloatware concluída." -ForegroundColor Green
        }
        if ($RunPrivacyTweaks) {
            Write-Log "Aplicando ajustes de privacidade e registro..." -Type Info
            Write-Host "Aplicando Ajustes de Privacidade e Registro..." -ForegroundColor Cyan
            Enable-PrivacyHardening # Sua função de privacidade existente
            Apply-PrivacyAndBloatwarePrevention # CHAMA A FUNÇÃO
            Write-Host "--> Ajustes de Privacidade concluídos." -ForegroundColor Green
        }
        if ($RunNetworkOptimization) {
            Write-Log "Otimizando desempenho de rede..." -Type Info
            Write-Host "Otimizando Desempenho de Rede..." -ForegroundColor Cyan
            Optimize-NetworkPerformance # Sua função de otimização de rede existente
            Write-Host "--> Otimização de Rede concluída." -ForegroundColor Green
        }
        if ($InstallEssentialApps) { # Parâmetro corrigido para InstallEssentialApps
            Write-Log "Instalando aplicativos essenciais..." -Type Info
            Write-Host "Instalando Aplicativos Essenciais..." -ForegroundColor Cyan
            Install-Applications # Sua função de instalação de apps existente
            Write-Host "--> Instalação de Aplicativos concluída." -ForegroundColor Green
        }
        if ($RunDiagnostics) {
            Write-Log "Executando diagnósticos do sistema..." -Type Info
            Write-Host "Executando Diagnósticos do Sistema..." -ForegroundColor Cyan
            # Suas funções de diagnóstico aqui.
            Write-Host "--> Diagnósticos do Sistema concluídos." -ForegroundColor Green
        }

        if ($RunWindowsUpdate) {
            Write-Log "Gerenciando atualizações do Windows via PSWindowsUpdate..." -Type Info
            Manage-WindowsUpdates # CHAMA A FUNÇÃO
        }
        if ($ApplyOptimizedPowerPlan) {
            Write-Log "Aplicando plano de energia otimizado..." -Type Info
            Write-Host "Aplicando Plano de Energia Otimizado..." -ForegroundColor Cyan
            Set-OptimizedPowerPlan # Esta será uma das próximas edições
            Write-Host "--> Plano de Energia Otimizado aplicado." -ForegroundColor Green
        }
        if ($ApplyGPOSettings) { # NOVO BLOCO DE EXECUÇÃO AUTOMÁTICA
            Write-Log "Aplicando configurações de GPO via Registro (modo automático)..." -Type Info
            Apply-GPORegistrySettings # CHAMA A NOVA FUNÇÃO
        }

        Write-Log "Execução automática concluída." -Type Success
        Write-Host "Todas as tarefas automáticas foram concluídas. Pressione Enter para sair." -ForegroundColor Green
        pause
        exit # Sai do script após a execução automática
    }
    else {
        # Se nenhum parâmetro de automação for passado, exibe o menu interativo
        do {
            clear-host # Limpa a tela antes de exibir o menu
            $choice = Show-Menu -Title "MENU PRINCIPAL - MANUTENÇÃO SUPREMA" -Options $mainMenuOptions
            switch ($choice) {
                "1" {
                    Write-Log "Executando Rotinas de Limpeza e Otimização via menu..." -Type Info
                    Write-Host "Executando Rotinas de Limpeza e Otimização..." -ForegroundColor Cyan
                    Perform-SystemOptimizations # CHAMA A FUNÇÃO
                    Write-Host "--> Concluído. Pressione Enter para continuar." -ForegroundColor Green
                    pause
                }
                "2" {
                    Write-Log "Executando Remoção de Bloatware via menu..." -Type Info
                    Write-Host "Executando Remoção de Bloatware..." -ForegroundColor Cyan
                    Remove-Bloatware
                    # Opcional: Adicionar Copilot/Recall/OneDrive como sub-opções do menu "Remover Bloatware"
                    # ou como opções separadas no menu principal, se desejar um controle mais granular.
                    Write-Host "--> Concluído. Pressione Enter para continuar." -ForegroundColor Green
                    pause
                }
                "3" {
                    Write-Log "Aplicando Ajustes de Privacidade e Registro via menu..." -Type Info
                    Write-Host "Aplicando Ajustes de Privacidade e Registro..." -ForegroundColor Cyan
                    Enable-PrivacyHardening
                    Apply-PrivacyAndBloatwarePrevention # CHAMA A FUNÇÃO
                    Write-Host "--> Concluído. Pressione Enter para continuar." -ForegroundColor Green
                    pause
                }
                "4" {
                    Write-Log "Otimizando Desempenho de Rede via menu..." -Type Info
                    Write-Host "Otimizando Desempenho de Rede..." -ForegroundColor Cyan
                    Optimize-NetworkPerformance
                    Write-Host "--> Concluído. Pressione Enter para continuar." -ForegroundColor Green
                    pause
                }
                "5" {
                    Write-Log "Instalando Aplicativos Essenciais via menu..." -Type Info
                    Write-Host "Instalando Aplicativos Essenciais..." -ForegroundColor Cyan
                    Install-Applications
                    Write-Host "--> Concluído. Pressione Enter para continuar." -ForegroundColor Green
                    pause
                }
                "6" {
                    Write-Log "Executando Diagnósticos do Sistema via menu..." -Type Info
                    Write-Host "Executando Diagnósticos do Sistema..." -ForegroundColor Cyan
                    # Suas funções de diagnóstico aqui
                    Write-Host "--> Concluído. Pressione Enter para continuar." -ForegroundColor Green
                    pause
                }
                "7" {
                    Write-Log "Gerenciando Atualizações do Windows via menu..." -Type Info
                    Manage-WindowsUpdates # CHAMA A FUNÇÃO
                    Write-Host "--> Concluído. Pressione Enter para continuar." -ForegroundColor Green
                    pause
                }
                "8" {
                    Write-Log "Configurando Plano de Energia Otimizado via menu..." -Type Info
                    Write-Host "Configurando Plano de Energia Otimizado..." -ForegroundColor Cyan
                    Set-OptimizedPowerPlan # Esta será uma das próximas edições
                    Write-Host "--> Concluído. Pressione Enter para continuar." -ForegroundColor Green
                    pause
                }
                "9" { # Opção para Remover OneDrive Completamente
                    Write-Log "Removendo OneDrive Completamente via menu..." -Type Info
                    Force-RemoveOneDrive
                    Write-Host "--> Concluído. Pressione Enter para continuar." -ForegroundColor Green
                    pause
                }
                "10" { # NOVO CASE para GPO
                    Write-Log "Aplicando Configurações de GPO via menu..." -Type Info
                    Apply-GPORegistrySettings # CHAMA A NOVA FUNÇÃO AQUI
                    Write-Host "--> Concluído. Pressione Enter para continuar." -ForegroundColor Green
                    pause
                }
				"11" { # NOVO CASE
					Write-Log "Reiniciando Explorer via menu..." -Type Info
					Restart-Explorer # CHAMA A NOVA FUNÇÃO AQUI
					Write-Host "--> Concluído. Pressione Enter para continuar." -ForegroundColor Green
					pause
				}
				"12" { # NOVO CASE
					Write-Log "Aplicando Ajustes de Interface do Usuário via menu..." -Type Info
					Apply-UITweaks # CHAMA A NOVA FUNÇÃO AQUI
					Write-Host "--> Concluído. Pressione Enter para continuar." -ForegroundColor Green
					pause
				}
                "0" { # Sair
                    Write-Log "Saindo do script. Até mais!" -Type Info
                    exit
                }
                default {
                    Write-Host "Opção inválida. Tente novamente." -ForegroundColor Red
                    Start-Sleep -Seconds 1
                }
            }
        } while ($choice -ne "0")
    }
}
#endregion

# === VERIFICAÇÃO DE FUNÇÕES CRÍTICAS ===
$FuncoesCriticas = @(
    'Disable-Cortana-AndSearch',
    'Disable-SMBv1',
    'Disable-UAC',
    'Enable-PrivacyHardening',
    'Enable-SMBv1',
    'Grant-ActionCenter-Notifications',
    'Grant-ControlPanelTweaks',
    'Grant-ExtraTweaks',
    'Grant-HardenOfficeMacros',
    'Optimize-NetworkPerformance',
    'Remove-Bloatware',
    'Remove-OneDrive-AndRestoreFolders',
    'Restore-ControlPanelTweaks',
    'Restore-DefaultIPv6',
    'Restore-DefaultUAC',
    'Restore-Registry-FromBackup',
    'Restore-VisualPerformanceDefault',
    'Show-AutoLoginMenu',
    'Show-DiagnosticsMenu',
    'Show-ExternalScriptsMenu',
    'Show-SuccessMessage',
    'Show-PersonalizationTweaksMenu', # NOVO: O menu que acabamos de criar
    'Enable-TaskbarEndTask', # NOVO
    'Enable-WindowsUpdateFast', # NOVO
    'Enable-DarkTheme', # NOVO
    'Enable-ClipboardHistory', # NOVO
    'Enable-RestartAppsAfterReboot', # NOVO
    'Enable-TaskbarSeconds', # NOVO
    'Enable-OtherMicrosoftUpdates', # NOVO
    'Enable-Sudo', # NOVO
    'Undo-PrivacyHardening'
    # 'Show-BloatwareMenu', # Removido anteriormente
    # 'Show-CleanupMenu', # Removido anteriormente
    # 'Show-SystemPerformanceMenu' # Removido anteriormente
)

Test-RequiredFunctions -FunctionList $FuncoesCriticas

# === EXECUÇÃO PRINCIPAL ===

# Inicia a função principal.
# Ela agora decide se roda automaticamente (se parâmetros forem passados)
# ou exibe o menu interativo.
Show-MainMenu
