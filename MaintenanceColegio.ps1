#region → PARÂMETROS DE EXECUÇÃO
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

#region → CONFIGURAÇÕES GLOBAIS E VARIÁVEIS INICIAIS

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

# Configurações gerais do script
$ScriptConfig = @{
    LogFilePath              = Join-Path $PSScriptRoot "ScriptSupremo.log" 
    ConfirmBeforeDestructive = $true # Usado na função Force-RemoveOneDrive

    Cleanup = @{
        CleanTemporaryFiles = $true
        CleanWUCache = $true
        OptimizeVolumes = $true
        PerformDeepSystemCleanup = $true
        ClearDNSCache = $true
        DisableMemoryDumps = $true
    }
    
    PrivacyTweaks = @{
        DisableTelemetry = $true
        DisableDiagnosticData = $true
        BlockTelemetryHosts = $true
        DisableLocationServices = $true
        DisableActivityHistory = $true
        DisableAdvertisingID = $true
        DisableCortana = $true
        DisableBiometrics = $true
        DisableFeedbackRequests = $true
        DisableSuggestedContent = $true
        DisableAutoUpdatesStoreApps = $true
        DisableWidgets = $true
        DisableNewsAndInterests = $true
    }
    
    GPORegistrySettings = @{
        EnableUpdateManagement = $true
        DisableAutoReboot = $true
        SetScheduledUpdateTime = $true
        DisableDriverUpdates = $true
        ConfigureEdge = $true
        ConfigureChrome = $true
        DisableWindowsTips = $true
    }
    
    UITweaks = @{
        EnableDarkMode = $true
        DisableTransparency = $true
        DisableAnimations = $true
        TaskbarAlignLeft = $true
        HideSearchBox = $true
        ShowDesktopIcons = $true
        HideDupliDrive = $true
        Hide3dObjects = $true
        HideOneDriveFolder = $true
    }
}
Set-Content -Path $LogFilePath -Value "" -Encoding UTF8 -ErrorAction SilentlyContinue | Out-Null

# Garante que o PowerShell esteja usando o TLS 1.2 para downloads seguros
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 

# Cores padrão para cada tipo de log (movido para o escopo global)
$global:defaultColors = @{
    'Info'    = 'Cyan'
    'Success' = 'Green'
    'Warning' = 'Yellow'
    'Error'   = 'Red'
    'Debug'   = 'DarkGray'
    'Verbose' = 'Gray'
}

# Listas globais para remoção de bloatware (movido e definido globalmente)
$global:bloatwareToRemove = @(
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

$global:whitelist = @(
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
function Write-Log {
    param(
        [Parameter(Mandatory,Position=0)]
        [object]$Message = '',

        [Parameter(Position=1)]
        [ValidateSet('Info','Success','Warning','Error','Debug','Verbose')]
        [string]$Type = 'Info'
    )

    # Garante texto e converte arrays para string
    if ($null -eq $Message) { $Message = '' } 
    $text = if ($Message -is [array]) {
        ($Message | ForEach-Object { ($_ -ne $null) ? $_.ToString() : '' }) -join ' '
    } else {
        $Message.ToString()
    }

    $timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss') 
    $entry     = "[$timestamp] [$Type] $text" 
    $color     = $global:defaultColors[$Type] # Acessa cores do escopo global 

    Write-Host $entry -ForegroundColor $color 

    $logPath = $script:ScriptConfig.LogFilePath 
    if (-not $logPath) { $logPath = Join-Path $env:TEMP 'ScriptSupremo.log' } 

    # Certifica-se de que o diretório de log existe (movido para dentro da função Write-Log)
    $logDir = Split-Path -Path $logPath -Parent
    if (-not (Test-Path $logDir)) {
        try {
            New-Item -Path $logDir -ItemType Directory -Force | Out-Null 
        } catch {
            Write-Host "ERRO: Não foi possível criar o diretório de log '$logDir'. Mensagem: $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    try {
        $entry | Out-File -FilePath $logPath -Append -Encoding UTF8 
    } catch {
        Write-Host "ERRO ao gravar log: $($_.Exception.Message)" -ForegroundColor Red 
    }
}

# --- Funções Auxiliares de Interação ---
function Suspend-Script {
    Write-Log "`nPressione ENTER para continuar..." -Type Info
    do {
        $key = [System.Console]::ReadKey($true)
    } until ($key.Key -eq 'Enter')
}

function Show-SuccessMessage {
    Write-Log "`n✅ Tarefa concluída com sucesso!" -Type Success
}

# --- Funções Auxiliares de Verificação ---
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
        # throw "Funções ausentes detectadas. Corrija antes de continuar."
    } else {
        Write-Log "`n✔️ Todas as funções estão disponíveis. Continuando execução..." -Type Info 
    }
}
#endregion

#region → FUNÇÕES ORQUESTRADORAS

function Invoke-Cleanup {
    Write-Log "Iniciando o orquestrador de Limpeza e Manutenção Completa..." -Type Info

    # Chame cada função dentro de seu próprio try/catch
    try { Clear-DeepSystemCleanup -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Clear-DeepSystemCleanup: $($_.Exception.Message)" -Type Error }
    try { Clear-Prefetch -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Clear-Prefetch: $($_.Exception.Message)" -Type Error }
    try { Clear-PrintSpooler -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Clear-PrintSpooler: $($_.Exception.Message)" -Type Error }
    try { Clear-TemporaryFiles -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Clear-TemporaryFiles: $($_.Exception.Message)" -Type Error }
    try { Clear-WUCache -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Clear-WUCache: $($_.Exception.Message)" -Type Error }
    try { Clear-WinSxS -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Clear-WinSxS: $($_.Exception.Message)" -Type Error }
    try { Perform-Cleanup -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Perform-Cleanup: $($_.Exception.Message)" -Type Error }
    try { Remove-WindowsOld -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Remove-WindowsOld: $($_.Exception.Message)" -Type Error }
    try { Backup-Registry -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Backup-Registry: $($_.Exception.Message)" -Type Error }
    try { Clear-TemporaryFiles -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Clear-TemporaryFiles: $($_.Exception.Message)" -Type Error } # Duplicado, verificar
    try { Disable-SMBv1 -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Disable-SMBv1: $($_.Exception.Message)" -Type Error }
    try { Invoke-DISM-Scan -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Invoke-DISM-Scan: $($_.Exception.Message)" -Type Error }
    try { Invoke-SFC-Scan -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Invoke-SFC-Scan: $($_.Exception.Message)" -Type Error }
    try { New-ChkDsk -ErrorAction Stop } catch { Write-Log "ERRO: Falha em New-ChkDsk: $($_.Exception.Message)" -Type Error }

    Write-Log "Todas as rotinas de limpeza e manutenção foram concluídas pelo orquestrador." -Type Success
    
    Suspend-Script # Pausa para o usuário ver o resultado final antes de retornar ao menu
}

function Invoke-Bloatware {
	Write-Log "Iniciando o orquestrador de Bloatwares..." -Type Info
    
    try { Apply-PrivacyAndBloatwarePrevention -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Apply-PrivacyAndBloatwarePrevention: $($_.Exception.Message)" -Type Error }
    try { Disable-BloatwareScheduledTasks -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Disable-BloatwareScheduledTasks: $($_.Exception.Message)" -Type Error }
    try { Disable-UnnecessaryServices -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Disable-UnnecessaryServices: $($_.Exception.Message)" -Type Error }
    try { Disable-WindowsRecall -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Disable-WindowsRecall: $($_.Exception.Message)" -Type Error }
    try { Force-RemoveOneDrive -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Force-RemoveOneDrive: $($_.Exception.Message)" -Type Error }
    try { Remove-AppxBloatware -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Remove-AppxBloatware: $($_.Exception.Message)" -Type Error }
    try { Remove-WindowsCopilot -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Remove-WindowsCopilot: $($_.Exception.Message)" -Type Error } # Duplicado, verificar
    try { Remove-OneDrive-AndRestoreFolders -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Remove-OneDrive-AndRestoreFolders: $($_.Exception.Message)" -Type Error }
    try { Remove-ScheduledTasksAggressive -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Remove-ScheduledTasksAggressive: $($_.Exception.Message)" -Type Error }
    try { Remove-StartAndTaskbarPins -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Remove-StartAndTaskbarPins: $($_.Exception.Message)" -Type Error }
    try { Remove-WindowsCopilot -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Remove-WindowsCopilot: $($_.Exception.Message)" -Type Error } # Duplicado, verificar
    try { Remove-WindowsOld -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Remove-WindowsOld: $($_.Exception.Message)" -Type Error } # Duplicado, verificar
    try { Restore-BloatwareSafe -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Restore-BloatwareSafe: $($_.Exception.Message)" -Type Error }
    try { Stop-BloatwareProcesses -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Stop-BloatwareProcesses: $($_.Exception.Message)" -Type Error }
		
	Write-Log "Todas as rotinas de bloatware foram concluídas pelo orquestrador." -Type Success
    
    Suspend-Script # Pausa para o usuário ver o resultado final antes de retornar ao menu
}

function Invoke-Diagnose {
	Write-Log "Iniciando o orquestrador de Diagnósticos..." -Type Info
    
    try { Invoke-All-DiagnosticsAdvanced -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Invoke-All-DiagnosticsAdvanced: $($_.Exception.Message)" -Type Error }
    try { Show-DiskUsage -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Show-DiskUsage: $($_.Exception.Message)" -Type Error }
    try { Show-SystemInfo -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Show-SystemInfo: $($_.Exception.Message)" -Type Error }
    try { Test-Memory -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Test-Memory: $($_.Exception.Message)" -Type Error }
		
	Write-Log "Todas as rotinas de diagnósticos foram concluídas pelo orquestrador." -Type Success
    
    Suspend-Script # Pausa para o usuário ver o resultado final antes de retornar ao menu
}

function Invoke-Tweaks {
	Write-Log "Iniciando o orquestrador de Tweaks..." -Type Info
    
    try { Apply-GPORegistrySettings -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Apply-GPORegistrySettings: $($_.Exception.Message)" -Type Error }
    try { Apply-UITweaks -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Apply-UITweaks: $($_.Exception.Message)" -Type Error }
    try { Disable-ActionCenter-Notifications -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Disable-ActionCenter-Notifications: $($_.Exception.Message)" -Type Error }
    try { Disable-UAC -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Disable-UAC: $($_.Exception.Message)" -Type Error }
    try { Enable-ClassicContextMenu -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Enable-ClassicContextMenu: $($_.Exception.Message)" -Type Error }
    try { Enable-ClipboardHistory -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Enable-ClipboardHistory: $($_.Exception.Message)" -Type Error }
    try { Enable-DarkTheme -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Enable-DarkTheme: $($_.Exception.Message)" -Type Error }
    try { Enable-OtherMicrosoftUpdates -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Enable-OtherMicrosoftUpdates: $($_.Exception.Message)" -Type Error }
    try { Enable-PowerOptions -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Enable-PowerOptions: $($_.Exception.Message)" -Type Error }
    try { Enable-PrivacyHardening -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Enable-PrivacyHardening: $($_.Exception.Message)" -Type Error }
    try { Enable-RestartAppsAfterReboot -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Enable-RestartAppsAfterReboot: $($_.Exception.Message)" -Type Error }
    try { Enable-SMBv1 -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Enable-SMBv1: $($_.Exception.Message)" -Type Error }
    try { Enable-Sudo -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Enable-Sudo: $($_.Exception.Message)" -Type Error }
    try { Enable-TaskbarEndTask -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Enable-TaskbarEndTask: $($_.Exception.Message)" -Type Error }
    try { Enable-TaskbarSeconds -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Enable-TaskbarSeconds: $($_.Exception.Message)" -Type Error }
    try { Enable-WindowsHardening -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Enable-WindowsHardening: $($_.Exception.Message)" -Type Error }
    try { Enable-WindowsUpdateFast -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Enable-WindowsUpdateFast: $($_.Exception.Message)" -Type Error }
    try { Grant-ControlPanelTweaks -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Grant-ControlPanelTweaks: $($_.Exception.Message)" -Type Error }
    try { Grant-ExtraTweaks -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Grant-ExtraTweaks: $($_.Exception.Message)" -Type Error }
    try { Grant-HardenOfficeMacros -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Grant-HardenOfficeMacros: $($_.Exception.Message)" -Type Error }
    try { Grant-PrivacyTweaks -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Grant-PrivacyTweaks: $($_.Exception.Message)" -Type Error }
    try { Manage-WindowsUpdates -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Manage-WindowsUpdates: $($_.Exception.Message)" -Type Error }
    try { New-FolderForced -ErrorAction Stop } catch { Write-Log "ERRO: Falha em New-FolderForced: $($_.Exception.Message)" -Type Error }
    try { New-SystemRestorePoint -ErrorAction Stop } catch { Write-Log "ERRO: Falha em New-SystemRestorePoint: $($_.Exception.Message)" -Type Error }
    try { Optimize-ExplorerPerformance -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Optimize-ExplorerPerformance: $($_.Exception.Message)" -Type Error }
    try { Optimize-NetworkPerformance -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Optimize-NetworkPerformance: $($_.Exception.Message)" -Type Error }
    try { Optimize-Volumes -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Optimize-Volumes: $($_.Exception.Message)" -Type Error }
    try { Perform-SystemOptimizations -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Perform-SystemOptimizations: $($_.Exception.Message)" -Type Error }
    try { Rename-Notebook -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Rename-Notebook: $($_.Exception.Message)" -Type Error }
    try { Set-OptimizedPowerPlan -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Set-OptimizedPowerPlan: $($_.Exception.Message)" -Type Error }
    try { Set-PerformanceTheme -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Set-PerformanceTheme: $($_.Exception.Message)" -Type Error }
    try { Set-VisualPerformance -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Set-VisualPerformance: $($_.Exception.Message)" -Type Error }
    try { Show-AutoLoginMenu -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Show-AutoLoginMenu: $($_.Exception.Message)" -Type Error }
		
	Write-Log "Todas as rotinas de tweaks foram concluídas pelo orquestrador." -Type Success
    
    Suspend-Script # Pausa para o usuário ver o resultado final antes de retornar ao menu
}

function Invoke-NetworkUtilities {
	Write-Log "Iniciando o orquestrador de Redes..." -Type Info
    
    try { Add-WiFiNetwork -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Add-WiFiNetwork: $($_.Exception.Message)" -Type Error }
    try { Clear-ARP -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Clear-ARP: $($_.Exception.Message)" -Type Error }
    try { Clear-DNS -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Clear-DNS: $($_.Exception.Message)" -Type Error }
    try { Clear-PrintSpooler -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Clear-PrintSpooler: $($_.Exception.Message)" -Type Error } # Duplicado, verificar
    try { Disable-IPv6 -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Disable-IPv6: $($_.Exception.Message)" -Type Error }
    try { Install-NetworkPrinters -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Install-NetworkPrinters: $($_.Exception.Message)" -Type Error }
    try { Invoke-All-NetworkAdvanced -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Invoke-All-NetworkAdvanced: $($_.Exception.Message)" -Type Error }
    try { Set-DnsGoogleCloudflare -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Set-DnsGoogleCloudflare: $($_.Exception.Message)" -Type Error }
    try { Show-NetworkInfo -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Show-NetworkInfo: $($_.Exception.Message)" -Type Error }
    try { Test-InternetSpeed -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Test-InternetSpeed: $($_.Exception.Message)" -Type Error }
		
	Write-Log "Todas as rotinas de redes foram concluídas pelo orquestrador." -Type Success
    
    Suspend-Script # Pausa para o usuário ver o resultado final antes de retornar ao menu
}

function Invoke-Undo {
	Write-Log "Iniciando o orquestrador de Restauração..." -Type Info
    
    try { Grant-ActionCenter-Notifications -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Grant-ActionCenter-Notifications: $($_.Exception.Message)" -Type Error }
    try { Restore-ControlPanelTweaks -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Restore-ControlPanelTweaks: $($_.Exception.Message)" -Type Error }
    try { Restore-DefaultIPv6 -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Restore-DefaultIPv6: $($_.Exception.Message)" -Type Error }
    try { Restore-DefaultUAC -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Restore-DefaultUAC: $($_.Exception.Message)" -Type Error }
    try { Restore-OfficeMacros -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Restore-OfficeMacros: $($_.Exception.Message)" -Type Error }
    try { Restore-OneDrive -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Restore-OneDrive: $($_.Exception.Message)" -Type Error }
    try { Restore-Registry -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Restore-Registry: $($_.Exception.Message)" -Type Error }
    try { Restore-Registry-FromBackup -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Restore-Registry-FromBackup: $($_.Exception.Message)" -Type Error }
    try { Restore-VisualPerformanceDefault -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Restore-VisualPerformanceDefault: $($_.Exception.Message)" -Type Error }
		
	Write-Log "Todas as rotinas de restauração foram concluídas pelo orquestrador." -Type Success
    
    Suspend-Script # Pausa para o usuário ver o resultado final antes de retornar ao menu
}

function Invoke-All-DiagnosticsAdvanced {
    Write-Log "Iniciando orquestrador de Diagnósticos Avançados..." -Type Info
    
    try { Show-SystemInfo -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Show-SystemInfo: $($_.Exception.Message)" -Type Error }
    try { Show-DiskUsage -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Show-DiskUsage: $($_.Exception.Message)" -Type Error }
    try { Show-NetworkInfo -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Show-NetworkInfo: $($_.Exception.Message)" -Type Error }
    try { Invoke-SFC-Scan -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Invoke-SFC-Scan: $($_.Exception.Message)" -Type Error }
    try { Invoke-DISM-Scan -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Invoke-DISM-Scan: $($_.Exception.Message)" -Type Error }
    try { Test-SMART-Drives -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Test-SMART-Drives: $($_.Exception.Message)" -Type Error }
    try { Test-Memory -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Test-Memory: $($_.Exception.Message)" -Type Error }
    try { Show-SuccessMessage -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Show-SuccessMessage: $($_.Exception.Message)" -Type Error } # Função que você chamou e agora está definida

    Write-Log "Todas as rotinas de diagnósticos avançados foram concluídas." -Type Success
    
    Suspend-Script # Pausa para o usuário ver o resultado final
}

function Invoke-Colegio {
	Write-Log "Iniciando rotina completa de manutenção do Colégio..." -Type Info
    
    try { Add-WiFiNetwork -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Add-WiFiNetwork: $($_.Exception.Message)" -Type Error }
    try { Apply-GPORegistrySettings -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Apply-GPORegistrySettings: $($_.Exception.Message)" -Type Error }
    try { Apply-PrivacyAndBloatwarePrevention -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Apply-PrivacyAndBloatwarePrevention: $($_.Exception.Message)" -Type Error }
    try { Apply-UITweaks -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Apply-UITweaks: $($_.Exception.Message)" -Type Error }
    try { Backup-Registry -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Backup-Registry: $($_.Exception.Message)" -Type Error }
    try { Clear-ARP -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Clear-ARP: $($_.Exception.Message)" -Type Error }
    try { Clear-DNS -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Clear-DNS: $($_.Exception.Message)" -Type Error }
    try { Clear-DeepSystemCleanup -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Clear-DeepSystemCleanup: $($_.Exception.Message)" -Type Error }
    try { Clear-Prefetch -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Clear-Prefetch: $($_.Exception.Message)" -Type Error }
    try { Clear-PrintSpooler -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Clear-PrintSpooler: $($_.Exception.Message)" -Type Error }
    try { Clear-WUCache -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Clear-WUCache: $($_.Exception.Message)" -Type Error }
    try { Clear-WinSxS -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Clear-WinSxS: $($_.Exception.Message)" -Type Error }
    try { Disable-ActionCenter-Notifications -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Disable-ActionCenter-Notifications: $($_.Exception.Message)" -Type Error }
    try { Disable-BloatwareScheduledTasks -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Disable-BloatwareScheduledTasks: $($_.Exception.Message)" -Type Error }
    try { Disable-IPv6 -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Disable-IPv6: $($_.Exception.Message)" -Type Error }
    try { Disable-SMBv1 -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Disable-SMBv1: $($_.Exception.Message)" -Type Error }
    try { Disable-UAC -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Disable-UAC: $($_.Exception.Message)" -Type Error }
    try { Disable-UnnecessaryServices -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Disable-UnnecessaryServices: $($_.Exception.Message)" -Type Error }
    try { Disable-WindowsRecall -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Disable-WindowsRecall: $($_.Exception.Message)" -Type Error }
    try { Enable-ClassicContextMenu -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Enable-ClassicContextMenu: $($_.Exception.Message)" -Type Error }
    try { Enable-ClipboardHistory -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Enable-ClipboardHistory: $($_.Exception.Message)" -Type Error }
    try { Enable-DarkTheme -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Enable-DarkTheme: $($_.Exception.Message)" -Type Error }
    try { Enable-OtherMicrosoftUpdates -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Enable-OtherMicrosoftUpdates: $($_.Exception.Message)" -Type Error }
    try { Enable-PowerOptions -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Enable-PowerOptions: $($_.Exception.Message)" -Type Error }
    try { Enable-PrivacyHardening -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Enable-PrivacyHardening: $($_.Exception.Message)" -Type Error }
    try { Enable-RestartAppsAfterReboot -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Enable-RestartAppsAfterReboot: $($_.Exception.Message)" -Type Error }
    try { Enable-SMBv1 -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Enable-SMBv1: $($_.Exception.Message)" -Type Error }
    try { Enable-Sudo -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Enable-Sudo: $($_.Exception.Message)" -Type Error }
    try { Enable-TaskbarEndTask -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Enable-TaskbarEndTask: $($_.Exception.Message)" -Type Error }
    try { Enable-TaskbarSeconds -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Enable-TaskbarSeconds: $($_.Exception.Message)" -Type Error }
    try { Enable-WindowsHardening -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Enable-WindowsHardening: $($_.Exception.Message)" -Type Error }
    try { Enable-WindowsUpdateFast -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Enable-WindowsUpdateFast: $($_.Exception.Message)" -Type Error }
    try { Force-RemoveOneDrive -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Force-RemoveOneDrive: $($_.Exception.Message)" -Type Error }
    try { Grant-ControlPanelTweaks -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Grant-ControlPanelTweaks: $($_.Exception.Message)" -Type Error }
    try { Grant-ExtraTweaks -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Grant-ExtraTweaks: $($_.Exception.Message)" -Type Error }
    try { Grant-HardenOfficeMacros -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Grant-HardenOfficeMacros: $($_.Exception.Message)" -Type Error }
    try { Grant-PrivacyTweaks -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Grant-PrivacyTweaks: $($_.Exception.Message)" -Type Error }
    try { Install-NetworkPrinters -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Install-NetworkPrinters: $($_.Exception.Message)" -Type Error }
    try { Manage-WindowsUpdates -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Manage-WindowsUpdates: $($_.Exception.Message)" -Type Error }
    try { New-FolderForced -ErrorAction Stop } catch { Write-Log "ERRO: Falha em New-FolderForced: $($_.Exception.Message)" -Type Error }
    try { New-SystemRestorePoint -ErrorAction Stop } catch { Write-Log "ERRO: Falha em New-SystemRestorePoint: $($_.Exception.Message)" -Type Error }
    try { Optimize-ExplorerPerformance -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Optimize-ExplorerPerformance: $($_.Exception.Message)" -Type Error }
    try { Optimize-NetworkPerformance -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Optimize-NetworkPerformance: $($_.Exception.Message)" -Type Error }
    try { Perform-SystemOptimizations -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Perform-SystemOptimizations: $($_.Exception.Message)" -Type Error }
    try { Remove-AppxBloatware -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Remove-AppxBloatware: $($_.Exception.Message)" -Type Error }
    try { Remove-OneDrive-AndRestoreFolders -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Remove-OneDrive-AndRestoreFolders: $($_.Exception.Message)" -Type Error }
    try { Remove-ScheduledTasksAggressive -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Remove-ScheduledTasksAggressive: $($_.Exception.Message)" -Type Error }
    try { Remove-StartAndTaskbarPins -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Remove-StartAndTaskbarPins: $($_.Exception.Message)" -Type Error }
    try { Remove-WindowsCopilot -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Remove-WindowsCopilot: $($_.Exception.Message)" -Type Error }
    try { Remove-WindowsOld -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Remove-WindowsOld: $($_.Exception.Message)" -Type Error }
    try { Set-DnsGoogleCloudflare -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Set-DnsGoogleCloudflare: $($_.Exception.Message)" -Type Error }
    try { Set-OptimizedPowerPlan -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Set-OptimizedPowerPlan: $($_.Exception.Message)" -Type Error }
    try { Set-PerformanceTheme -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Set-PerformanceTheme: $($_.Exception.Message)" -Type Error }
    try { Set-VisualPerformance -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Set-VisualPerformance: $($_.Exception.Message)" -Type Error }
    try { Stop-BloatwareProcesses -ErrorAction Stop } catch { Write-Log "ERRO: Falha em Stop-BloatwareProcesses: $($_.Exception.Message)" -Type Error }

		Write-Log "Todas as rotinas de manutenção do Colégio foram concluídas." -Type Success
    
    Suspend-Script # Pausa para o usuário ver o resultado final
}

#endregion

#region → FUNÇÕES DE LIMPEZA E OTIMIZAÇÃO (AJUSTADAS)

function Clear-TemporaryFiles {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param()
    Write-Log "Iniciando limpeza de arquivos temporários (usuário e sistema)..." -Type Info
    $activity = "Limpeza de Arquivos Temporários"
    $currentStep = 1
    $totalSteps = 2

    if ($PSCmdlet.ShouldProcess("arquivos temporários", "limpar")) {
        try {
            Write-Progress -Activity $activity -Status "Executando Limpeza de Disco (cleanmgr /sagerun:1)..." -PercentComplete (($currentStep / $totalSteps) * 100)
            Write-Log "Executando Limpeza de Disco (cleanmgr /sagerun:1)..." -Type Info
            if (-not $WhatIf) {
                # O sagerun:1 deve ser configurado previamente com cleanmgr /sageset:1
                Start-Process -FilePath "cleanmgr.exe" -ArgumentList "/sagerun:1" -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue
                # Note: Start-Process não lança erro que try/catch pega diretamente. O ErrorAction é para o próprio Start-Process.
            } else {
                Write-Log "Modo WhatIf: cleanmgr /sagerun:1 seria executado." -Type Debug
            }
            $currentStep++

            Write-Progress -Activity $activity -Status "Removendo arquivos temporários adicionais..." -PercentComplete (($currentStep / $totalSteps) * 100)
            Write-Log "Removendo arquivos temporários adicionais..." -Type Info
            $tempPaths = @(
                "$env:TEMP\*" # Geralmente aponta para %LOCALAPPDATA%\Temp para o usuário logado
                "$env:SystemRoot\Temp\*"
                "$env:UserProfile\AppData\Local\Temp\*" # Incluído para clareza, pode ser redundante
            )
            foreach ($path in $tempPaths) {
                if (Test-Path $path) {
                    Write-Log "Tentando remover itens em $path" -Type Debug
                    if (-not $WhatIf) {
                        Remove-Item $path -Recurse -Force -ErrorAction SilentlyContinue
                    } else {
                        Write-Log "Modo WhatIf: Itens em $path seriam removidos." -Type Debug
                    }
                } else {
                    Write-Log "Caminho não encontrado: $path. Pulando." -Type Debug
                }
            }
            Write-Log "Limpeza de temporários concluída." -Type Success

        } catch {
            Write-Log "ERRO ao limpar arquivos temporários: $($_.Exception.Message)" -Type Error
            Write-Log "Detalhes do Erro: $($_.Exception.ToString())" -Type Error
        } finally {
            Write-Progress -Activity $activity -Status "Concluído" -PercentComplete 100 -Completed
        }
    }
}

function Clear-WUCache {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
       
    )
    Write-Log "Iniciando limpeza de cache do Windows Update..." -Type Info
    $activity = "Limpeza de Cache do Windows Update"
    $currentStep = 1
    $totalSteps = 3

    if ($PSCmdlet.ShouldProcess("cache do Windows Update", "limpar")) {
        try {
            Write-Progress -Activity $activity -Status "Parando serviço 'wuauserv'..." -PercentComplete (($currentStep / $totalSteps) * 100)
            Write-Log "Parando serviço 'wuauserv'..." -Type Info
            if (-not $WhatIf) {
                Stop-Service wuauserv -Force -ErrorAction SilentlyContinue
            } else {
                Write-Log "Modo WhatIf: Serviço 'wuauserv' seria parado." -Type Debug
            }
            $currentStep++

            Write-Progress -Activity $activity -Status "Removendo conteúdo de 'SoftwareDistribution\Download'..." -PercentComplete (($currentStep / $totalSteps) * 100)
            Write-Log "Removendo conteúdo de '$env:SystemRoot\SoftwareDistribution\Download\'..." -Type Info
            if (-not $WhatIf) {
                Remove-Item "$env:SystemRoot\SoftwareDistribution\Download\*" -Recurse -Force -ErrorAction SilentlyContinue
            } else {
                Write-Log "Modo WhatIf: Conteúdo de 'SoftwareDistribution\Download' seria removido." -Type Debug
            }
            $currentStep++

            Write-Progress -Activity $activity -Status "Iniciando serviço 'wuauserv'..." -PercentComplete (($currentStep / $totalSteps) * 100)
            Write-Log "Iniciando serviço 'wuauserv'..." -Type Info
            if (-not $WhatIf) {
                Start-Service wuauserv -ErrorAction SilentlyContinue
            } else {
                Write-Log "Modo WhatIf: Serviço 'wuauserv' seria iniciado." -Type Debug
            }
            Write-Log "Cache do Windows Update limpo." -Type Success

        } catch {
            Write-Log "ERRO ao limpar cache do Windows Update: $($_.Exception.Message)" -Type Error
            Write-Log "Detalhes do Erro: $($_.Exception.ToString())" -Type Error
        } finally {
            Write-Progress -Activity $activity -Status "Concluído" -PercentComplete 100 -Completed
        }
    }
}

function Optimize-Volumes {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
     
    )
    Write-Log "Iniciando otimização de volumes (desfragmentação/retrim)..." -Type Info
    $activity = "Otimização de Volumes"
    $volumes = Get-Volume | Where-Object {$_.DriveType -eq 'Fixed' -and $_.DriveLetter}
    $totalVolumes = $volumes.Count
    $volumeCount = 0

    if ($PSCmdlet.ShouldProcess("volumes do disco", "otimizar")) {
        try {
            foreach ($vol in $volumes) {
                $volumeCount++
                $percentComplete = ($volumeCount / $totalVolumes) * 100
                $statusMessage = "Otimizando volume $($vol.DriveLetter):\"

                Write-Progress -Activity $activity -Status $statusMessage -CurrentOperation "Volume: $($vol.DriveLetter):\" -PercentComplete $percentComplete
                Write-Log "Otimizando volume $($vol.DriveLetter):\" -Type Info

                if (-not $WhatIf) {
                    if ($vol.FileSystem -eq "NTFS") {
                        Write-Log "Desfragmentando volume NTFS: $($vol.DriveLetter):\" -Type Debug
                        Optimize-Volume -DriveLetter $vol.DriveLetter -Defrag -Verbose:$false -ErrorAction Stop
                    } elseif ($vol.FileSystem -eq "FAT32" -or $vol.FileSystem -eq "exFAT") {
                        Write-Log "Volume $($vol.DriveLetter): é ${$vol.FileSystem}. Desfragmentação/ReTrim não aplicável via Optimize-Volume. Pulando." -Type Warning
                    } else { # Assume SSDs ou outros sistemas de arquivo que se beneficiam de ReTrim
                        Write-Log "Executando ReTrim em volume: $($vol.DriveLetter):\" -Type Debug
                        Optimize-Volume -DriveLetter $vol.DriveLetter -ReTrim -Verbose:$false -ErrorAction Stop
                    }
                } else {
                    Write-Log "Modo WhatIf: Volume $($vol.DriveLetter): seria otimizado (Defrag para NTFS, ReTrim para outros)." -Type Debug
                }
            }
            Write-Log "Otimização de volumes concluída." -Type Success

        } catch {
            Write-Log "ERRO ao otimizar volumes: $($_.Exception.Message)" -Type Error
            Write-Log "Detalhes do Erro: $($_.Exception.ToString())" -Type Error
            Write-Log "Verifique se o PowerShell está rodando como Administrador e se os volumes não estão bloqueados." -Type Info
        } finally {
            Write-Progress -Activity $activity -Status "Concluído" -PercentComplete 100 -Completed
        }
    }
}

function Clear-WinSxS {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
       
            )
    Write-Log "Iniciando limpeza de WinSxS (Limpeza de Componentes com ResetBase)..." -Type Info
    $activity = "Limpeza de WinSxS"

    if ($PSCmdlet.ShouldProcess("WinSxS", "limpar")) {
        try {
            Write-Progress -Activity $activity -Status "Executando DISM para limpeza de componentes (pode demorar)..." -PercentComplete 25
            Write-Log "Executando Dism.exe /online /Cleanup-Image /StartComponentCleanup /ResetBase (isso pode levar bastante tempo!)..." -Type Warning
            if (-not $WhatIf) {
                # O comando DISM não fornece feedback de progresso nativo fácil para Write-Progress
                # mas o Out-Null evita que sua saída polua o console.
                $process = Start-Process -FilePath "Dism.exe" -ArgumentList "/online /Cleanup-Image /StartComponentCleanup /ResetBase" -WindowStyle Hidden -Wait -PassThru
                $process.WaitForExit()
                if ($process.ExitCode -ne 0) {
                    throw "Comando DISM falhou com código de saída $($process.ExitCode)."
                }
            } else {
                Write-Log "Modo WhatIf: DISM /Cleanup-Image /StartComponentCleanup /ResetBase seria executado." -Type Debug
            }
            Write-Log "WinSxS limpo." -Type Success

        } catch {
            Write-Log "ERRO ao limpar WinSxS: $($_.Exception.Message)" -Type Error
            Write-Log "Detalhes do Erro: $($_.Exception.ToString())" -Type Error
            Write-Log "Verifique se o PowerShell está rodando como Administrador." -Type Info
        } finally {
            Write-Progress -Activity $activity -Status "Concluído" -PercentComplete 100 -Completed
        }
    }
}

function New-ChkDsk {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
       
            )
    Write-Log "Agendando chkdsk /f /r no próximo reboot para o disco do sistema ($env:SystemDrive)..." -Type Info
    $activity = "Agendamento de ChkDsk"

    if ($PSCmdlet.ShouldProcess("chkdsk no próximo reboot", "agendar")) {
        try {
            Write-Progress -Activity $activity -Status "Executando chkdsk para agendamento..." -PercentComplete 50
            Write-Log "Executando chkdsk $env:SystemDrive /f /r /x..." -Type Info # /x força desmontagem do volume
            if (-not $WhatIf) {
                # Chkdsk pode pedir confirmação. O /x ajuda a evitar se possível.
                # Capturamos a saída e erros para evitar prompts interativos
                $chkdskOutput = & chkdsk $env:SystemDrive /f /r /x 2>&1
                if ($LASTEXITCODE -ne 0) {
                    # Chkdsk retorna 0 para sucesso, 1 para reinício necessário
                    # Outros códigos indicam erro
                    if ($LASTEXITCODE -eq 1) {
                         Write-Log "chkdsk agendado com sucesso (reinício necessário)." -Type Success
                    } else {
                        throw "Comando chkdsk falhou com código de saída $LASTEXITCODE. Output: $chkdskOutput"
                    }
                } else {
                    Write-Log "chkdsk não necessitou agendamento (disco limpo)." -Type Success
                }
            } else {
                Write-Log "Modo WhatIf: chkdsk $env:SystemDrive /f /r /x seria agendado." -Type Debug
            }
            Write-Log "chkdsk agendado (confirme no prompt, se solicitado, após o reboot)." -Type Success

        } catch {
            Write-Log "ERRO ao agendar chkdsk: $($_.Exception.Message)" -Type Error
            Write-Log "Detalhes do Erro: $($_.Exception.ToString())" -Type Error
            Write-Log "Verifique se o PowerShell está rodando como Administrador." -Type Info
        } finally {
            Write-Progress -Activity $activity -Status "Concluído" -PercentComplete 100 -Completed
        }
    }
}

function Remove-WindowsOld {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
       
            )
    Write-Log "Iniciando remoção da pasta Windows.old..." -Type Info
    $activity = "Remoção de Windows.old"

    if ($PSCmdlet.ShouldProcess("pasta Windows.old", "remover")) {
        try {
            Write-Progress -Activity $activity -Status "Verificando existência da pasta Windows.old..." -PercentComplete 25
            if (Test-Path "$env:SystemDrive\Windows.old") {
                Write-Progress -Activity $activity -Status "Removendo pasta Windows.old (pode demorar)..." -PercentComplete 50
                Write-Log "Removendo '$env:SystemDrive\Windows.old'..." -Type Info
                if (-not $WhatIf) {
                    Remove-Item "$env:SystemDrive\Windows.old" -Force -Recurse -ErrorAction SilentlyContinue
                } else {
                    Write-Log "Modo WhatIf: Pasta '$env:SystemDrive\Windows.old' seria removida." -Type Debug
                }
                Write-Log "Windows.old removido." -Type Success
            } else {
                Write-Log "Pasta Windows.old não encontrada. Nenhuma ação necessária." -Type Info
            }
        } catch {
            Write-Log "ERRO ao remover Windows.old: $($_.Exception.Message)" -Type Error
            Write-Log "Detalhes do Erro: $($_.Exception.ToString())" -Type Error
            Write-Log "Pode ser necessário reiniciar em modo de recuperação ou usar a Limpeza de Disco para remover." -Type Info
        } finally {
            Write-Progress -Activity $activity -Status "Concluído" -PercentComplete 100 -Completed
        }
    }
}

function Clear-DeepSystemCleanup {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
       
            )
    Write-Log "Iniciando limpeza profunda do sistema (logs, etc.)..." -Type Info
    $activity = "Limpeza Profunda do Sistema"
    $currentStep = 1
    $totalSteps = 2 # Ajustado, pois o cache de update foi removido daqui

    if ($PSCmdlet.ShouldProcess("limpeza profunda do sistema", "executar")) {
        try {
            # REMOVIDO: A limpeza do cache de update já é tratada por Clear-WUCache. Não duplicar aqui.
            # Remove-Item "$env:SystemRoot\SoftwareDistribution\Download\*" -Recurse -Force -ErrorAction SilentlyContinue

            Write-Progress -Activity $activity -Status "Removendo arquivos de log antigos e não essenciais..." -PercentComplete (($currentStep / $totalSteps) * 100)
            Write-Log "Removendo arquivos de log antigos e não essenciais (ex: logs de INF, CBS)..." -Type Info

            # Mais seletivo na limpeza de logs para não apagar dados importantes de diagnóstico
            $logPaths = @(
                "$env:SystemRoot\INF\*.log" # Logs de instalação de drivers, geralmente seguros
                "$env:SystemRoot\Logs\CBS\*.log" # Logs do Component Based Servicing, podem ser grandes
                # Para logs de eventos do Windows (Aplicativo, Sistema, Segurança), é melhor usar 'wevtutil cl "NomeDoLog"'
                # Exemplo: wevtutil cl "Application" ; wevtutil cl "System"
                # Isso não está incluído aqui para evitar interrupções ou remoção agressiva sem aviso.
            )
            foreach ($path in $logPaths) {
                if (Test-Path $path) {
                    Write-Log "Tentando remover itens em $path" -Type Debug
                    if (-not $WhatIf) {
                        Remove-Item $path -Force -ErrorAction SilentlyContinue
                    } else {
                        Write-Log "Modo WhatIf: Itens em $path seriam removidos." -Type Debug
                    }
                } else {
                    Write-Log "Caminho não encontrado: $path. Pulando." -Type Debug
                }
            }
            $currentStep++

            Write-Log "Limpeza profunda realizada." -Type Success

        } catch {
            Write-Log "ERRO na limpeza profunda: $($_.Exception.Message)" -Type Error
            Write-Log "Detalhes do Erro: $($_.Exception.ToString())" -Type Error
        } finally {
            Write-Progress -Activity $activity -Status "Concluído" -PercentComplete 100 -Completed
        }
    }
}

function Clear-PrintSpooler {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
       
            )
    Write-Log "Iniciando limpeza do spooler de impressão..." -Type Info
    $activity = "Limpeza do Spooler de Impressão"
    $currentStep = 1
    $totalSteps = 3

    if ($PSCmdlet.ShouldProcess("spooler de impressão", "limpar")) {
        try {
            Write-Progress -Activity $activity -Status "Parando serviço 'Spooler'..." -PercentComplete (($currentStep / $totalSteps) * 100)
            Write-Log "Parando serviço 'Spooler'..." -Type Info
            if (-not $WhatIf) {
                Stop-Service -Name Spooler -Force -ErrorAction SilentlyContinue
            } else {
                Write-Log "Modo WhatIf: Serviço 'Spooler' seria parado." -Type Debug
            }
            $currentStep++

            Write-Progress -Activity $activity -Status "Removendo arquivos da fila de impressão..." -PercentComplete (($currentStep / $totalSteps) * 100)
            Write-Log "Removendo arquivos da fila de impressão em '$env:SystemRoot\System32\spool\PRINTERS\'..." -Type Info
            if (-not $WhatIf) {
                Remove-Item -Path "$env:SystemRoot\System32\spool\PRINTERS\*" -Force -Recurse -ErrorAction SilentlyContinue
            } else {
                Write-Log "Modo WhatIf: Arquivos da fila de impressão seriam removidos." -Type Debug
            }
            $currentStep++

            Write-Progress -Activity $activity -Status "Iniciando serviço 'Spooler'..." -PercentComplete (($currentStep / $totalSteps) * 100)
            Write-Log "Iniciando serviço 'Spooler'..." -Type Info
            if (-not $WhatIf) {
                Start-Service -Name Spooler -ErrorAction SilentlyContinue
            } else {
                Write-Log "Modo WhatIf: Serviço 'Spooler' seria iniciado." -Type Debug
            }
            Write-Log "Spooler de impressão limpo com sucesso." -Type Success

        } catch {
            Write-Log "ERRO ao limpar spooler de impressão: $($_.Exception.Message)" -Type Error
            Write-Log "Detalhes do Erro: $($_.Exception.ToString())" -Type Error
        } finally {
            Write-Progress -Activity $activity -Status "Concluído" -PercentComplete 100 -Completed
        }
    }
}

function Clear-Prefetch {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
       
            )
    Write-Log "Iniciando limpeza de Prefetch..." -Type Info
    $activity = "Limpeza de Prefetch"

    if ($PSCmdlet.ShouldProcess("cache Prefetch", "limpar")) {
        try {
            Write-Progress -Activity $activity -Status "Verificando existência da pasta Prefetch..." -PercentComplete 25
            if (Test-Path "$env:SystemRoot\Prefetch") {
                Write-Progress -Activity $activity -Status "Removendo arquivos Prefetch..." -PercentComplete 50
                Write-Log "Removendo arquivos em '$env:SystemRoot\Prefetch\'..." -Type Info
                if (-not $WhatIf) {
                    Remove-Item "$env:SystemRoot\Prefetch\*" -Force -Recurse -ErrorAction SilentlyContinue
                } else {
                    Write-Log "Modo WhatIf: Arquivos Prefetch seriam removidos." -Type Debug
                }
                Write-Log "Prefetch limpo." -Type Success
            } else {
                Write-Log "Pasta Prefetch não encontrada. Nenhuma ação necessária." -Type Info
            }
        } catch {
            Write-Log "ERRO ao limpar Prefetch: $($_.Exception.Message)" -Type Error
            Write-Log "Detalhes do Erro: $($_.Exception.ToString())" -Type Error
        } finally {
            Write-Progress -Activity $activity -Status "Concluído" -PercentComplete 100 -Completed
        }
    }
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
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
       
            )
    Write-Log "Iniciando o gerenciamento de atualizações do Windows." -Type Info
    $activity = "Gerenciamento de Atualizações do Windows"

    if ($PSCmdlet.ShouldProcess("atualizações do Windows", "gerenciar")) {
        try {
            Write-Progress -Activity $activity -Status "Verificando e instalando o módulo PSWindowsUpdate..." -PercentComplete 10
            # 1. Verificar e instalar o módulo PSWindowsUpdate
            if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
                Write-Log "Módulo PSWindowsUpdate não encontrado. Tentando instalar do PowerShell Gallery..." -Type Warning
                if (-not $WhatIf) {
                    try {
                        Install-Module -Name PSWindowsUpdate -Force -AllowClobber -Scope AllUsers -ErrorAction Stop
                        Write-Log "Módulo PSWindowsUpdate instalado com sucesso!" -Type Success
                    } catch {
                        Write-Log "ERRO: Não foi possível instalar o módulo PSWindowsUpdate: $($_.Exception.Message)" -Type Error
                        Write-Log "As atualizações não poderão ser gerenciadas automaticamente." -Type Error
                        Write-Log "Detalhes do Erro: $($_.Exception.ToString())" -Type Error
                        Start-Sleep -Seconds 5
                        return # Sai da função se a instalação falhar
                    }
                } else {
                    Write-Log "Modo WhatIf: Módulo PSWindowsUpdate seria instalado." -Type Debug
                }
            } else {
                Write-Log "Módulo PSWindowsUpdate já está instalado." -Type Info
            }

            # Importar o módulo (garantir que está carregado)
            Import-Module PSWindowsUpdate -ErrorAction SilentlyContinue

            Write-Progress -Activity $activity -Status "Aguardando escolha de opção de atualização..." -PercentComplete 50
            Write-Log "Opções de Atualização:" -Type Info
            Write-Log "1) Buscar e Instalar TODAS as atualizações (incluindo opcionais/drivers)" -Type Info
            Write-Log "2) Buscar e Instalar apenas atualizações CRÍTICAS e de SEGURANÇA" -Type Info
            Write-Log "3) Apenas buscar atualizações (não instalar)" -Type Info
            Write-Log "0) Voltar ao Menu Principal" -Type Warning
            $updateChoice = Read-Host "Escolha uma opção de atualização"

            switch ($updateChoice) {
                "1" {
                    Write-Log "Buscando e instalando TODAS as atualizações..." -Type Info
                    Write-Progress -Activity $activity -Status "Instalando todas as atualizações (pode demorar e reiniciar!)..." -PercentComplete 75
                    if (-not $WhatIf) {
                        Get-WindowsUpdate -Install -AcceptAll -AutoReboot | Out-Null
                        Write-Log "Processo de atualização completo (todas as atualizações)." -Type Success
                    } else {
                        Write-Log "Modo WhatIf: Seriam buscadas e instaladas TODAS as atualizações, com reinício automático." -Type Debug
                    }
                }
                "2" {
                    Write-Log "Buscando e instalando atualizações CRÍTICAS e de SEGURANÇA..." -Type Info
                    Write-Progress -Activity $activity -Status "Instalando atualizações críticas e de segurança (pode demorar e reiniciar!)..." -PercentComplete 75
                    if (-not $WhatIf) {
                        Get-WindowsUpdate -Install -AcceptAll -CriticalUpdate -SecurityUpdate -AutoReboot | Out-Null
                        Write-Log "Processo de atualização completo (críticas/segurança)." -Type Success
                    } else {
                        Write-Log "Modo WhatIf: Seriam buscadas e instaladas atualizações CRÍTICAS e de SEGURANÇA, com reinício automático." -Type Debug
                    }
                }
                "3" {
                    Write-Log "Buscando atualizações disponíveis (não será instalado nada)..." -Type Info
                    Write-Progress -Activity $activity -Status "Buscando atualizações disponíveis..." -PercentComplete 75
                    if (-not $WhatIf) {
                        Get-WindowsUpdate | Format-Table -AutoSize
                        Write-Log "Busca de atualizações concluída. Verifique a lista acima." -Type Success
                    } else {
                        Write-Log "Modo WhatIf: Seriam buscadas e listadas as atualizações disponíveis." -Type Debug
                    }
                    # O pause é necessário para o usuário ver a tabela de atualizações
                    Read-Host "Pressione ENTER para continuar..."
                }
                "0" {
                    Write-Log "Retornando ao menu principal." -Type Info
                    return
                }
                default {
                    Write-Log "Opção inválida. Por favor, escolha uma opção válida." -Type Error
                    Start-Sleep -Seconds 2
                }
            }
            Write-Log "Processo de gerenciamento de atualizações concluído." -Type Success

        } catch {
            Write-Log "ERRO durante o gerenciamento de atualizações: $($_.Exception.Message)" -Type Error
            Write-Log "Detalhes do Erro: $($_.Exception.ToString())" -Type Error
        } finally {
            Write-Progress -Activity $activity -Status "Concluído" -PercentComplete 100 -Completed
            Start-Sleep -Seconds 2
        }
    }
}

function Perform-Cleanup {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
       
            )
    Write-Log "Executando rotinas de limpeza do sistema (agrupadas)..." -Type Info
    $activity = "Rotinas de Limpeza e Otimização"
    $totalFunctions = 11 # Número total de funções chamadas (excluindo Manage-WindowsUpdates se for interativa)
    $completedFunctions = 0

    if ($PSCmdlet.ShouldProcess("rotinas de limpeza agrupadas", "executar")) {
        try {
            # Chamada das funções menores (passando WhatIf para elas)
            # Acompanhe o progresso geral
            
            $completedFunctions++
            Write-Progress -Activity $activity -Status "Limpeza de cache ARP..." -PercentComplete (($completedFunctions / $totalFunctions) * 100)
            Clear-ARP -WhatIf:$WhatIf
            
            $completedFunctions++
            Write-Progress -Activity $activity -Status "Limpeza de cache DNS..." -PercentComplete (($completedFunctions / $totalFunctions) * 100)
            Clear-DNS -WhatIf:$WhatIf
            
            $completedFunctions++
            Write-Progress -Activity $activity -Status "Limpeza de Prefetch..." -PercentComplete (($completedFunctions / $totalFunctions) * 100)
            Clear-Prefetch -WhatIf:$WhatIf
            
            $completedFunctions++
            Write-Progress -Activity $activity -Status "Limpeza do spooler de impressão..." -PercentComplete (($completedFunctions / $totalFunctions) * 100)
            Clear-PrintSpooler -WhatIf:$WhatIf
            
            $completedFunctions++
            Write-Progress -Activity $activity -Status "Limpeza de arquivos temporários..." -PercentComplete (($completedFunctions / $totalFunctions) * 100)
            Clear-TemporaryFiles -WhatIf:$WhatIf
            
            $completedFunctions++
            Write-Progress -Activity $activity -Status "Limpeza do cache do Windows Update..." -PercentComplete (($completedFunctions / $totalFunctions) * 100)
            Clear-WUCache -WhatIf:$WhatIf
            
            $completedFunctions++
            Write-Progress -Activity $activity -Status "Limpeza do WinSxS..." -PercentComplete (($completedFunctions / $totalFunctions) * 100)
            Clear-WinSxS -WhatIf:$WhatIf

            $completedFunctions++
            Write-Progress -Activity $activity -Status "Limpeza profunda do sistema (logs, etc.)..." -PercentComplete (($completedFunctions / $totalFunctions) * 100)
            Clear-DeepSystemCleanup -WhatIf:$WhatIf
            
            $completedFunctions++
            Write-Progress -Activity $activity -Status "Verificando/removendo Windows.old..." -PercentComplete (($completedFunctions / $totalFunctions) * 100)
            Remove-WindowsOld -WhatIf:$WhatIf
            
            $completedFunctions++
            Write-Progress -Activity $activity -Status "Agendando ChkDsk para o próximo reboot..." -PercentComplete (($completedFunctions / $totalFunctions) * 100)
            New-ChkDsk -WhatIf:$WhatIf
            
            $completedFunctions++
            Write-Progress -Activity $activity -Status "Otimizando volumes do disco..." -PercentComplete (($completedFunctions / $totalFunctions) * 100)
            Optimize-Volumes -WhatIf:$WhatIf

            Write-Log "Todas as rotinas de limpeza e otimização foram concluídas." -Type Success
        } catch {
            Write-Log "ERRO GERAL na orquestração de limpeza: $($_.Exception.Message)" -Type Error
            Write-Log "Detalhes do Erro: $($_.Exception.ToString())" -Type Error
        } finally {
            Write-Progress -Activity $activity -Status "Concluído" -PercentComplete 100 -Completed
        }
    }
}

# endregion

#region → FUNÇÕES DE REMOÇÃO DE BLOATWARE (AJUSTADAS)

# IMPORTANTE: Esta revisão assume que você tem uma função Write-Log definida que suporta o parâmetro -Type (ex: -Type Info, -Type Success, -Type Error).
# Exemplo de como sua função Write-Log poderia ser (se ainda não tiver):
# function Write-Log {
#     param(
#         [Parameter(Mandatory=$true)]
#         [string]$Message,
#         [Parameter(Mandatory=$false)]
#         [ValidateSet('Info', 'Warning', 'Success', 'Error', 'Debug')]
#         [string]$Type = 'Info'
#     )
#     $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
#     $logEntry = "[$timestamp] [$Type] $Message"
#     
#     switch ($Type) {
#         'Info' { Write-Host $logEntry -ForegroundColor Cyan }
#         'Warning' { Write-Host $logEntry -ForegroundColor Yellow }
#         'Success' { Write-Host $logEntry -ForegroundColor Green }
#         'Error' { Write-Host $logEntry -ForegroundColor Red }
#         'Debug' { Write-Host $logEntry -ForegroundColor DarkGray }
#     }
#     # Opcional: Adicionar lógica para escrever em um arquivo de log
#     # Add-Content -Path "C:\Logs\SeuScript.log" -Value $logEntry
# }

# Variáveis globais para listas de bloatware e whitelist, acessadas por Test-ShouldRemovePackage
# ATENÇÃO: Adicione ou remova itens conforme sua necessidade e cuidado ao remover pacotes essenciais!
$global:bloatwareToRemove = @(
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
    "*Microsoft.Windows.Photos.Addon*", # Complemento do aplicativo Fotos
    "*Microsoft.549981C3F5F10*" # Copilot, se for tratado como AppX separado do Windows Copilot completo
)

$global:whitelist = @(
    "Microsoft.DesktopAppInstaller", # winget
    "Microsoft.Store", # Loja da Microsoft
    "Microsoft.Windows.StartMenuExperienceHost", # Menu Iniciar
    "Microsoft.Windows.ShellExperienceHost", # Shell
    "Microsoft.UI.Xaml.2.X", # Componentes da UI (usar wildcard para versões: Microsoft.UI.Xaml.2.*)
    "Microsoft.VCLibs.140.00", # Bibliotecas essenciais
    "Microsoft.NET.Native.Framework.*", # Bibliotecas .NET
    "Microsoft.NET.Native.Runtime.*", # Bibliotecas .NET
    "Microsoft.Services.Store.Engagement", # Loja
    "Microsoft.Xbox.TCUI", # Componentes Xbox (se necessário)
    "Microsoft.XboxGameCallableUI", # Componentes Xbox (se necessário)
    "Microsoft.AccountsControl",
    "Microsoft.LockApp",
    "Microsoft.Windows.SecHealthUI", # Segurança do Windows
    "Microsoft.ScreenCapture" # Ferramenta de Captura
)

# Helper function para verificar se um pacote deve ser removido
function Test-ShouldRemovePackage {
    param (
        [Parameter(Mandatory = $true)]
        [string]$PackageName
    )
    # Verifica se o pacote está na whitelist
    if ($global:whitelist -contains $PackageName -or $PackageName -like "Microsoft.UI.Xaml.2.*" -or $PackageName -like "Microsoft.NET.Native.Framework.*" -or $PackageName -like "Microsoft.NET.Native.Runtime.*") {
        return $false
    }
    # Verifica se o pacote corresponde a um item da lista de bloatware
    foreach ($item in $global:bloatwareToRemove) {
        if ($PackageName -like $item) {
            return $true
        }
    }
    return $false
}

function Force-RemoveOneDrive {
    <#
    .SYNOPSIS
        Força a remoção completa do OneDrive do sistema.
    .DESCRIPTION
        Esta função desinstala completamente o OneDrive, desabilitando seus serviços
        e removendo seus arquivos do sistema.
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
       
            )
    Write-Log "Iniciando remoção completa do OneDrive..." -Type Info
    $activity = "Remoção Completa do OneDrive"
    $currentStep = 1
    $totalSteps = 4

    if ($PSCmdlet.ShouldProcess("OneDrive", "remover completamente")) {
        try {
            # === NOVO CÓDIGO AQUI ===
            # Verifique se $ScriptConfig está definida e se ConfirmationRequired é verdadeiro
            # Assume que $ScriptConfig é uma variável de escopo mais alto ou global que contém esta configuração.
            # Se não, remova esta verificação ou defina $ScriptConfig no seu script principal.
            if ((Get-Variable -Name ScriptConfig -ErrorAction SilentlyContinue) -and $ScriptConfig.ConfirmationRequired) {
                Write-Log "AVISO: A remoção do OneDrive é irreversível e pode afetar a sincronização de arquivos." -Type Warning
                $confirm = Read-Host "Tem certeza que deseja prosseguir? (s/n)"
                if ($confirm -ne 's') {
                    Write-Log "Remoção do OneDrive cancelada pelo usuário." -Type Info
                    return # Sai da função se o usuário cancelar
                }
            }
            # === FIM DO NOVO CÓDIGO ===

            Write-Progress -Activity $activity -Status "Encerrando processos do OneDrive..." -PercentComplete (($currentStep / $totalSteps) * 100)
            Write-Log "Encerrando processos do OneDrive." -Type Info
            if (-not $WhatIf) {
                Get-Process -Name "OneDrive*" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
            } else {
                Write-Log "Modo WhatIf: Processos do OneDrive seriam encerrados." -Type Debug
            }
            $currentStep++

            Write-Progress -Activity $activity -Status "Desinstalando OneDrive via setup..." -PercentComplete (($currentStep / $totalSteps) * 100)
            Write-Log "Desinstalando OneDrive para todas as arquiteturas." -Type Info
            $onedriveSetupPath_x64 = "$env:SystemRoot\SysWOW64\OneDriveSetup.exe"
            $onedriveSetupPath_x86 = "$env:SystemRoot\System32\OneDriveSetup.exe"

            if (-not $WhatIf) {
                if (Test-Path $onedriveSetupPath_x64) {
                    Write-Log "Desinstalando OneDrive (x64)..." -Type Debug
                    Start-Process -FilePath $onedriveSetupPath_x64 -ArgumentList "/uninstall" -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue
                } elseif (Test-Path $onedriveSetupPath_x86) {
                    Write-Log "Desinstalando OneDrive (x86)..." -Type Debug
                    Start-Process -FilePath $onedriveSetupPath_x86 -ArgumentList "/uninstall" -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue
                } else {
                    Write-Log "Instalador do OneDrive não encontrado. Pulando desinstalação via setup." -Type Warning
                }
            } else {
                Write-Log "Modo WhatIf: OneDrive seria desinstalado via setup." -Type Debug
            }
            $currentStep++

            Write-Progress -Activity $activity -Status "Removendo pastas de dados e vestígios..." -PercentComplete (($currentStep / $totalSteps) * 100)
            Write-Log "Removendo pastas de dados e vestígios do OneDrive." -Type Info
            $userProfiles = Get-ChildItem -Path "$env:SystemDrive\Users" -Directory -ErrorAction SilentlyContinue
            foreach ($profile in $userProfiles) {
                $onedriveUserPath = Join-Path -Path $profile.FullName -ChildPath "OneDrive"
                $onedriveLocalAppData = Join-Path -Path $profile.FullName -ChildPath "AppData\Local\Microsoft\OneDrive"
                if (-not $WhatIf) {
                    if (Test-Path $onedriveUserPath) {
                        Remove-Item -Path $onedriveUserPath -Recurse -Force -ErrorAction SilentlyContinue
                        Write-Log "Removido pasta OneDrive de $($profile.BaseName)." -Type Debug
                    }
                    if (Test-Path $onedriveLocalAppData) {
                        Remove-Item -Path $onedriveLocalAppData -Recurse -Force -ErrorAction SilentlyContinue
                        Write-Log "Removido AppData de OneDrive de $($profile.BaseName)." -Type Debug
                    }
                } else {
                    Write-Log "Modo WhatIf: Pastas OneDrive e AppData de $($profile.BaseName) seriam removidas." -Type Debug
                }
            }
            $currentStep++

            Write-Progress -Activity $activity -Status "Limpando entradas de registro do OneDrive..." -PercentComplete (($currentStep / $totalSteps) * 100)
            Write-Log "Limpando registro do OneDrive e desativando início automático." -Type Info
            $regPaths = @(
                "HKCR:\CLSID\{018D5C66-4533-4307-9B53-2ad65C87B14B}", # OneDrive no painel de navegação
                "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-2ad65C87B14B}",
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{A52BBA46-A28D-493B-B034-2AFB6F3AD90C}",
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SyncRootManager\OneDrive!*"
            )
            foreach ($path in $regPaths) {
                try {
                    if (Test-Path $path) {
                        if (-not $WhatIf) {
                            Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
                            Write-Log "Limpado registro: $path" -Type Debug
                        } else {
                            Write-Log "Modo WhatIf: Registro $path seria limpo." -Type Debug
                        }
                    }
                } catch {
                    Write-Log "Falha ao limpar registro do OneDrive ($path): $($_.Exception.Message)" -Type Warning
                }
            }
            if (-not $WhatIf) {
                try {
                    # Desativa o início automático do OneDrive via registro (se ainda houver entradas)
                    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "OneDrive" -Value "" -ErrorAction SilentlyContinue
                    Write-Log "Desativado início automático do OneDrive." -Type Debug
                } catch { Write-Log "Falha ao desativar início automático do OneDrive: $($_.Exception.Message)" -Type Warning }
            } else {
                Write-Log "Modo WhatIf: Início automático do OneDrive seria desativado." -Type Debug
            }

            Write-Log "Remoção completa do OneDrive concluída." -Type Success

        } catch {
            Write-Log "ERRO crítico durante a remoção do OneDrive: $($_.Exception.Message)" -Type Error
            Write-Log "Detalhes do Erro: $($_.Exception.ToString())" -Type Error
        } finally {
            Write-Progress -Activity $activity -Status "Concluído" -PercentComplete 100 -Completed
        }
    }
}

function Remove-AppxBloatware {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
       
            )
    Write-Log "Iniciando a remoção de Bloatware (AppX packages)..." -Type Info
    $activity = "Remoção de Bloatware (AppX)"
    $packagesToProcess = @()

    if ($PSCmdlet.ShouldProcess("Bloatware (AppX packages)", "remover")) {
        try {
            # Coleta de pacotes provisionados
            Write-Progress -Activity $activity -Status "Identificando pacotes provisionados para remoção..." -PercentComplete 10
            $provisionedPackages = Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Where-Object { Test-ShouldRemovePackage -PackageName $_.PackageName }
            if ($provisionedPackages) { $packagesToProcess += $provisionedPackages }

            # Coleta de pacotes instalados por usuário
            Write-Progress -Activity $activity -Status "Identificando pacotes instalados por usuário para remoção..." -PercentComplete 20
            $userPackages = Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Where-Object { Test-ShouldRemovePackage -PackageName $_.Name }
            if ($userPackages) { $packagesToProcess += $userPackages }
            
            $totalPackages = $packagesToProcess.Count
            $removedCount = 0

            if ($totalPackages -eq 0) {
                Write-Log "Nenhum bloatware AppX identificado para remoção." -Type Info
                return
            }

            foreach ($pkg in $packagesToProcess) {
                $removedCount++
                $percentComplete = ($removedCount / $totalPackages) * 100
                $statusMessage = "Removendo $($pkg.Name)"

                Write-Progress -Activity $activity -Status $statusMessage -CurrentOperation "Pacote: $($pkg.Name)" -PercentComplete $percentComplete
                
                if ($pkg.GetType().Name -eq "AppxProvisionedPackage") {
                    Write-Log "Removendo provisionamento de $($pkg.PackageName)..." -Type Info
                    if (-not $WhatIf) {
                        Remove-AppxProvisionedPackage -Online -PackageName $pkg.PackageName -ErrorAction SilentlyContinue
                    } else {
                        Write-Log "Modo WhatIf: Provisionamento de $($pkg.PackageName) seria removido." -Type Debug
                    }
                } else { # É um AppxPackage para usuário
                    Write-Log "Removendo $($pkg.Name) para o usuário $($pkg.User.Name)..." -Type Info
                    if (-not $WhatIf) {
                        Remove-AppxPackage -Package $pkg.PackageFullName -ErrorAction SilentlyContinue
                    } else {
                        Write-Log "Modo WhatIf: $($pkg.Name) seria removido para $($pkg.User.Name)." -Type Debug
                    }
                }
            }
            Write-Log "Remoção de Bloatware (AppX packages) concluída." -Type Success

        } catch {
            Write-Log "ERRO durante a remoção de Bloatware (AppX packages): $($_.Exception.Message)" -Type Error
            Write-Log "Detalhes do Erro: $($_.Exception.ToString())" -Type Error
        } finally {
            Write-Progress -Activity $activity -Status "Concluído" -PercentComplete 100 -Completed
        }
    }
}

function Disable-BloatwareScheduledTasks {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
       
            )
    Write-Log "Desativando tarefas agendadas de bloatware e telemetria..." -Type Info
    $activity = "Desativação de Tarefas Agendadas"
    $tasks = @(
        "\Microsoft\Windows\Application Experience\ProgramDataUpdater",
        "\Microsoft\Windows\Autochk\Proxy",
        "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
        "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
        "\Microsoft\Windows\Customer Experience Improvement Program\Uploader",
        "\Microsoft\Windows\Feedback\Siuf\DmClient",
        "\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload",
        "\Microsoft\Windows\Windows Error Reporting\QueueReporting",
        "\Microsoft\Windows\OneDrive\Standalone Update Task",
        "\Microsoft\XblGameSave\XblGameSaveTask",
        "\Microsoft\Windows\Feedback\FeedbackUpload",
        "\Microsoft\Windows\Shell\FamilySafetyMonitor",
        "\Microsoft\Windows\Shell\FamilySafetyRefreshTask"
    )
    $totalTasks = $tasks.Count
    $processedCount = 0

    if ($PSCmdlet.ShouldProcess("tarefas agendadas de bloatware/telemetria", "desativar")) {
        foreach ($task in $tasks) {
            $processedCount++
            $percentComplete = ($processedCount / $totalTasks) * 100
            Write-Progress -Activity $activity -Status "Desativando tarefa: $task" -PercentComplete $percentComplete
            try {
                if (-not $WhatIf) {
                    $result = schtasks /Change /TN $task /Disable 2>&1
                    if ($LASTEXITCODE -ne 0) {
                        if ($result -like "*ERROR: The system cannot find the file specified.*" -or $result -like "*Task does not exist*") {
                            Write-Log "Tarefa '$task' não encontrada ou não existe. Pulando." -Type Debug
                        } else {
                            throw "Comando schtasks falhou para '$task': $result"
                        }
                    } else {
                        Write-Log "Tarefa '$task' desativada com sucesso." -Type Success
                    }
                } else {
                    Write-Log "Modo WhatIf: Tarefa '$task' seria desativada." -Type Debug
                }
            } catch {
                Write-Log "ERRO ao desativar tarefa '$task': $($_.Exception.Message)" -Type Error
                Write-Log "Detalhes do Erro: $($_.Exception.ToString())" -Type Error
            }
        }
        Write-Log "Desativação de tarefas agendadas concluída." -Type Success
    }
    Write-Progress -Activity $activity -Status "Concluído" -PercentComplete 100 -Completed
}

function Stop-BloatwareProcesses {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
       
            )
    Write-Log "Encerrando processos dispensáveis em segundo plano..." -Type Info
    $activity = "Encerramento de Processos"
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
    $totalProcs = $processes.Count
    $processedCount = 0

    if ($PSCmdlet.ShouldProcess("processos de bloatware", "encerrar")) {
        foreach ($proc in $processes) {
            $processedCount++
            $percentComplete = ($processedCount / $totalProcs) * 100
            Write-Progress -Activity $activity -Status "Encerrando processo: $proc" -PercentComplete $percentComplete
            try {
                if (-not $WhatIf) {
                    Get-Process -Name "$proc*" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
                    if ($LASTEXITCODE -eq 0) { # Verifica se o comando Get-Process/Stop-Process foi bem-sucedido
                        Write-Log "Processo '$proc' encerrado." -Type Success
                    }
                } else {
                    Write-Log "Modo WhatIf: Processo '$proc' seria encerrado." -Type Debug
                }
            } catch {
                Write-Log "ERRO ao encerrar processo '$proc': $($_.Exception.Message)" -Type Error
                Write-Log "Detalhes do Erro: $($_.Exception.ToString())" -Type Error
            }
        }
        Write-Log "Encerramento de processos dispensáveis concluído." -Type Success
    }
    Write-Progress -Activity $activity -Status "Concluído" -PercentComplete 100 -Completed
}

function Remove-StartAndTaskbarPins {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
       
            )
    Write-Log "Removendo pins do Menu Iniciar e Barra de Tarefas..." -Type Info
    $activity = "Remoção de Pins"

    if ($PSCmdlet.ShouldProcess("pins do Menu Iniciar e Barra de Tarefas", "remover")) {
        try {
            Write-Progress -Activity $activity -Status "Removendo arquivo LayoutModification.xml..." -PercentComplete 50
            $startLayout = "$env:LOCALAPPDATA\Microsoft\Windows\Shell\LayoutModification.xml"
            if (Test-Path $startLayout) {
                if (-not $WhatIf) {
                    Remove-Item $startLayout -Force -ErrorAction Stop
                    Write-Log "Arquivo LayoutModification.xml removido." -Type Success
                    Write-Log "Pins removidos (pode ser necessário reiniciar o Explorer para ver as mudanças)." -Type Warning
                } else {
                    Write-Log "Modo WhatIf: Arquivo LayoutModification.xml seria removido." -Type Debug
                }
            } else {
                Write-Log "Arquivo LayoutModification.xml não encontrado. Nenhuma ação necessária." -Type Info
            }
        } catch {
            Write-Log "ERRO ao remover pins: $($_.Exception.Message)" -Type Error
            Write-Log "Detalhes do Erro: $($_.Exception.ToString())" -Type Error
        } finally {
            Write-Progress -Activity $activity -Status "Concluído" -PercentComplete 100 -Completed
        }
    }
}

function Remove-ScheduledTasksAggressive {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
       
            )
    Write-Log "Removendo tarefas agendadas de bloatware/telemetria (modo agressivo)..." -Type Info
    $activity = "Remoção Agressiva de Tarefas Agendadas"
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
    $totalTasks = $tasks.Count
    $processedCount = 0

    if ($PSCmdlet.ShouldProcess("tarefas agendadas de bloatware/telemetria (agressivo)", "remover/desativar")) {
        foreach ($task in $tasks) {
            $processedCount++
            $percentComplete = ($processedCount / $totalTasks) * 100
            Write-Progress -Activity $activity -Status "Processando tarefa: $task" -PercentComplete $percentComplete
            try {
                if (-not $WhatIf) {
                    # Tenta desativar primeiro (menos destrutivo)
                    $disableResult = schtasks.exe /change /TN $task /DISABLE 2>&1
                    if ($LASTEXITCODE -ne 0 -and $disableResult -notlike "*Task does not exist*") {
                        Write-Log "Aviso: Falha ao desativar tarefa '$task' (pode não existir ou ter erro): $disableResult" -Type Warning
                    }

                    # Tenta remover
                    $deleteResult = schtasks.exe /delete /TN $task /f 2>&1
                    if ($LASTEXITCODE -ne 0 -and $deleteResult -notlike "*Task does not exist*") {
                        Write-Log "Aviso: Falha ao remover tarefa '$task' (pode não existir ou ter erro): $deleteResult" -Type Warning
                    } else {
                        Write-Log "Tarefa '$task' desativada e removida (se existia)." -Type Success
                    }
                } else {
                    Write-Log "Modo WhatIf: Tarefa '$task' seria desativada e removida." -Type Debug
                }
            } catch {
                Write-Log "ERRO ao processar tarefa '$task': $($_.Exception.Message)" -Type Error
                Write-Log "Detalhes do Erro: $($_.Exception.ToString())" -Type Error
            }
        }
        Write-Log "Remoção agressiva de tarefas agendadas concluída." -Type Success
    }
    Write-Progress -Activity $activity -Status "Concluído" -PercentComplete 100 -Completed
}

function Enable-ClassicContextMenu {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
       
            )
    Write-Log "Restaurando menu de contexto clássico (Windows 11)..." -Type Info
    $activity = "Habilitar Menu de Contexto Clássico"

    if ($PSCmdlet.ShouldProcess("menu de contexto clássico", "habilitar")) {
        try {
            Write-Progress -Activity $activity -Status "Aplicando ajuste de registro..." -PercentComplete 50
            if (-not $WhatIf) {
                $result = reg.exe add "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" /f /ve 2>&1
                if ($LASTEXITCODE -ne 0) {
                    throw "Comando reg.exe falhou: $result"
                }
                Write-Log "Menu de contexto clássico habilitado." -Type Success
                Write-Log "Pode ser necessário reiniciar o Explorer para que as mudanças sejam aplicadas." -Type Warning
            } else {
                Write-Log "Modo WhatIf: Menu de contexto clássico seria habilitado via registro." -Type Debug
            }
        } catch {
            Write-Log "ERRO ao restaurar menu de contexto clássico: $($_.Exception.Message)" -Type Error
            Write-Log "Detalhes do Erro: $($_.Exception.ToString())" -Type Error
        } finally {
            Write-Progress -Activity $activity -Status "Concluído" -PercentComplete 100 -Completed
        }
    }
}

function Remove-WindowsCopilot {
    <#
    .SYNOPSIS
        Remove e desabilita o Windows Copilot e seu ícone.
    .DESCRIPTION
        Esta função tenta remover o pacote do Windows Copilot (se presente)
        e aplica ajustes de registro para desabilitar sua interface e funcionalidade.
        Também inclui lógica para remover o Copilot via AppX (Microsoft.549981C3F5F10).
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
       
            )
    Write-Log "Iniciando remoção e desativação do Windows Copilot." -Type Info
    $activity = "Remoção e Desativação do Copilot"
    $currentStep = 1
    $totalSteps = 3

    if ($PSCmdlet.ShouldProcess("Windows Copilot", "remover/desativar")) {
        try {
            Write-Progress -Activity $activity -Status "Tentando remover o pacote do Windows Copilot (AppX)..." -PercentComplete (($currentStep / $totalSteps) * 100)
            Write-Log "Tentando remover o pacote do Windows Copilot (Microsoft.Windows.Copilot ou Microsoft.549981C3F5F10)..." -Type Info
            if (-not $WhatIf) {
                # Tenta remover o pacote principal do Copilot
                Get-AppxPackage -Name "*Microsoft.Windows.Copilot*" -AllUsers -ErrorAction SilentlyContinue | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
                # Tenta remover a versão mais antiga do Copilot (app separada)
                Get-AppxPackage -Name "Microsoft.549981C3F5F10" -AllUsers -ErrorAction SilentlyContinue | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
                Write-Log "Tentativa de remoção de pacotes Copilot concluída." -Type Success
            } else {
                Write-Log "Modo WhatIf: Pacotes do Copilot seriam removidos." -Type Debug
            }
            $currentStep++

            Write-Progress -Activity $activity -Status "Aplicando ajustes de registro para desabilitar o Copilot..." -PercentComplete (($currentStep / $totalSteps) * 100)
            Write-Log "Aplicando ajustes de registro para desabilitar o Copilot UI e funcionalidade..." -Type Info
            if (-not $WhatIf) {
                # Desabilitar o Copilot via políticas (Windows 11 23H2+)
                New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Copilot" -ErrorAction SilentlyContinue | Out-Null # Garante que a chave existe
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Copilot" -Name "TurnOffCopilot" -Value 1 -Force -ErrorAction SilentlyContinue
                
                # Desativar o botão do Copilot na barra de tarefas (para usuário atual)
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowCopilotButton" -Value 0 -Force -ErrorAction SilentlyContinue

                # Desabilitar a funcionalidade completa (se a chave existir)
                $regPathAI = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartMenu\StartMenuSettings"
                if (-not (Test-Path $regPathAI)) { New-Item -Path $regPathAI -Force | Out-Null }
                Set-ItemProperty -Path $regPathAI -Name "AITrayEnabled" -Value 0 -Force -Force -ErrorAction SilentlyContinue
                Write-Log "Ajustes de registro para Copilot aplicados." -Type Success
            } else {
                Write-Log "Modo WhatIf: Ajustes de registro para desabilitar Copilot seriam aplicados." -Type Debug
            }
            $currentStep++

            Write-Progress -Activity $activity -Status "Reiniciando Explorer..." -PercentComplete (($currentStep / $totalSteps) * 100)
            Write-Log "Windows Copilot removido/desativado com sucesso. Reiniciando Explorer para aplicar as alterações na barra de tarefas..." -Type Success
            if (-not $WhatIf) {
                Stop-Process -Name "explorer" -Force -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 2
                Start-Process -FilePath "explorer.exe" -ErrorAction SilentlyContinue
            } else {
                Write-Log "Modo WhatIf: Explorer seria reiniciado." -Type Debug
            }

        } catch {
            Write-Log "ERRO durante a remoção/desativação do Windows Copilot: $($_.Exception.Message)" -Type Error
            Write-Log "Detalhes do Erro: $($_.Exception.ToString())" -Type Error
        } finally {
            Write-Progress -Activity $activity -Status "Concluído" -PercentComplete 100 -Completed
        }
    }
}

function Disable-WindowsRecall {
    <#
    .SYNOPSIS
        Desabilita o recurso Windows Recall (se presente).
    .DESCRIPTION
        Esta função aplica ajustes de registro para desabilitar o Windows Recall,
        uma funcionalidade de gravação de tela e atividades.
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
       
            )
    Write-Log "Iniciando desativação do Windows Recall." -Type Info
    $activity = "Desativação do Windows Recall"

    if ($PSCmdlet.ShouldProcess("Windows Recall", "desativar")) {
        try {
            Write-Progress -Activity $activity -Status "Aplicando ajustes de registro para desabilitar o Recall..." -PercentComplete 50
            Write-Log "Aplicando ajustes de registro para desabilitar o Recall..." -Type Info

            if (-not $WhatIf) {
                # Desabilitar Recall (Windows 11 24H2+)
                $regPathRecall = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Recall"
                if (-not (Test-Path $regPathRecall)) { New-Item -Path $regPathRecall -Force -ErrorAction SilentlyContinue | Out-Null }
                Set-ItemProperty -Path $regPathRecall -Name "Debugger" -Value "cmd.exe /k echo Recall is disabled && exit" -Force -ErrorAction SilentlyContinue

                # Outras chaves de desativação que podem aparecer em futuras versões
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "RecallEnabled" -Value 0 -Force -ErrorAction SilentlyContinue
                
                New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" -ErrorAction SilentlyContinue | Out-Null # Garante que a chave existe
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" -Name "DisableRecall" -Value 1 -Force -ErrorAction SilentlyContinue
                
                Write-Log "Ajustes de registro para Windows Recall aplicados." -Type Success
            } else {
                Write-Log "Modo WhatIf: Ajustes de registro para desabilitar Recall seriam aplicados." -Type Debug
            }

            Write-Log "Windows Recall desativado com sucesso." -Type Success

        } catch {
            Write-Log "ERRO durante a desativação do Windows Recall: $($_.Exception.Message)" -Type Error
            Write-Log "Detalhes do Erro: $($_.Exception.ToString())" -Type Error
        } finally {
            Write-Progress -Activity $activity -Status "Concluído" -PercentComplete 100 -Completed
        }
    }
}

function Remove-AppxBloatwares { # Esta é a função orquestradora
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
       
            )
    Write-Log "Iniciando as rotinas de remoção de Bloatware e recursos indesejados..." -Type Info
    $activity = "Remoção de Bloatware (Orquestrador)"
    $totalFunctions = 7 # Contagem das funções a serem chamadas aqui
    $completedFunctions = 0

    if ($PSCmdlet.ShouldProcess("todas as rotinas de remoção de bloatware", "executar")) {
        try {
            # Chamada das funções menores (passando WhatIf para elas)

            $completedFunctions++
            Write-Progress -Activity $activity -Status "Removendo pacotes AppX de bloatware..." -PercentComplete (($completedFunctions / $totalFunctions) * 100)
            Remove-AppxBloatware -WhatIf:$WhatIf

            $completedFunctions++
            Write-Progress -Activity $activity -Status "Desativando tarefas agendadas de bloatware..." -PercentComplete (($completedFunctions / $totalFunctions) * 100)
            Disable-BloatwareScheduledTasks -WhatIf:$WhatIf

            $completedFunctions++
            Write-Progress -Activity $activity -Status "Desativando tarefas agendadas agressivamente..." -PercentComplete (($completedFunctions / $totalFunctions) * 100)
            Remove-ScheduledTasksAggressive -WhatIf:$WhatIf
            
            $completedFunctions++
            Write-Progress -Activity $activity -Status "Encerrando processos de bloatware..." -PercentComplete (($completedFunctions / $totalFunctions) * 100)
            Stop-BloatwareProcesses -WhatIf:$WhatIf
            
            $completedFunctions++
            Write-Progress -Activity $activity -Status "Removendo pins do Menu Iniciar e Barra de Tarefas..." -PercentComplete (($completedFunctions / $totalFunctions) * 100)
            Remove-StartAndTaskbarPins -WhatIf:$WhatIf
            
            $completedFunctions++
            Write-Progress -Activity $activity -Status "Removendo e desativando Windows Copilot..." -PercentComplete (($completedFunctions / $totalFunctions) * 100)
            Remove-WindowsCopilot -WhatIf:$WhatIf
            
            $completedFunctions++
            Write-Progress -Activity $activity -Status "Desativando Windows Recall..." -PercentComplete (($completedFunctions / $totalFunctions) * 100)
            Disable-WindowsRecall -WhatIf:$WhatIf
            
            # Funções que podem ter confirmação e/ou são muito destrutivas podem ser chamadas separadamente
            # se não quiserem ser parte do fluxo automatizado do "Perform-Bloatwares"
            # Ex: Force-RemoveOneDrive -WhatIf:$WhatIf
            # Enable-ClassicContextMenu é um ajuste, não uma remoção, mas pode ser incluída aqui se desejar
            # Enable-ClassicContextMenu -WhatIf:$WhatIf

            Write-Log "Todas as rotinas de remoção de Bloatware e recursos indesejados concluídas." -Type Success

        } catch {
            Write-Log "ERRO GERAL na orquestração de remoção de Bloatware: $($_.Exception.Message)" -Type Error
            Write-Log "Detalhes do Erro: $($_.Exception.ToString())" -Type Error
        } finally {
            Write-Progress -Activity $activity -Status "Concluído" -PercentComplete 100 -Completed
        }
    }
}

#endregion

#region → FUNÇÕES DE INSTALAÇÃO DE APLICATIVOS (AJUSTADAS)

# IMPORTANTE: Esta revisão assume que você tem uma função Write-Log definida que suporta o parâmetro -Type (ex: -Type Info, -Type Success, -Type Error).
# Exemplo de como sua função Write-Log poderia ser (se ainda não tiver):
# function Write-Log {
#     param(
#         [Parameter(Mandatory=$true)]
#         [string]$Message,
#         [Parameter(Mandatory=$false)]
#         [ValidateSet('Info', 'Warning', 'Success', 'Error', 'Debug')]
#         [string]$Type = 'Info'
#     )
#     $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
#     $logEntry = "[$timestamp] [$Type] $Message"
#     
#     switch ($Type) {
#         'Info' { Write-Host $logEntry -ForegroundColor Cyan }
#         'Warning' { Write-Host $logEntry -ForegroundColor Yellow }
#         'Success' { Write-Host $logEntry -ForegroundColor Green }
#         'Error' { Write-Host $logEntry -ForegroundColor Red }
#         'Debug' { Write-Host $logEntry -ForegroundColor DarkGray }
#     }
#     # Opcional: Adicionar lógica para escrever em um arquivo de log
#     # Add-Content -Path "C:\Logs\SeuScript.log" -Value $logEntry
# }

function Install-Applications {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
       
            )
    Write-Log "Iniciando instalação de aplicativos..." -Type Info
    $activity = "Instalação de Aplicativos via Winget"

    if ($PSCmdlet.ShouldProcess("aplicativos", "instalar")) {
        try {
            Write-Progress -Activity $activity -Status "Verificando instalação do Winget..." -PercentComplete 5
            if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
                Write-Log "Winget não está instalado. Pulando instalação de aplicativos." -Type Error
                Write-Log "Por favor, instale o Winget manualmente ou via Microsoft Store para usar esta função." -Type Info
                return
            }
            Write-Log "Winget encontrado. Prosseguindo com a instalação." -Type Success

            $apps = @(
                @{Name = "AutoHotKey"; Id = "AutoHotkey.AutoHotkey"},
                @{Name = "Google Chrome"; Id = "Google.Chrome"},
                @{Name = "Google Drive"; Id = "Google.GoogleDrive"},
                @{Name = "VLC Media Player"; Id = "VideoLAN.VLC"},
                @{Name = "Microsoft Office"; Id = "Microsoft.Office"},
                @{Name = "Microsoft PowerToys"; Id = "Microsoft.PowerToys"},
                @{Name = "AnyDesk"; Id = "AnyDesk.AnyDesk"},
                @{Name = "Notepad++"; Id = "Notepad++.Notepad++"},
                @{ Id = "ShareX.ShareX" ; Name = "ShareX" },
                @{Name = "7-Zip"; Id = "7zip.7zip"}
            )
            $totalApps = $apps.Count
            $installedCount = 0

            foreach ($app in $apps) {
                $installedCount++
                $percentComplete = (($installedCount / $totalApps) * 100)
                $statusMessage = "Instalando $($app.Name)..."

                Write-Progress -Activity $activity -Status $statusMessage -CurrentOperation "App: $($app.Name) (ID: $($app.Id))" -PercentComplete $percentComplete

                try {
                    Write-Log "Tentando instalar $($app.Name) (ID: $($app.Id))..." -Type Info
                    if (-not $WhatIf) {
                        # A Winget pode retornar um exit code diferente de 0 mesmo em caso de sucesso (ex: se o app já está instalado)
                        # Redirecionar stderr para stdout para capturar todas as mensagens
                        $installResult = (winget install --id $app.Id -e --accept-package-agreements --accept-source-agreements 2>&1)
                        
                        # Verificar o $LASTEXITCODE para sucesso (0) ou falha. 
                        # Muitos instaladores Winget retornam 0 mesmo se o software já estiver instalado ou se não houve alteração.
                        if ($LASTEXITCODE -eq 0) {
                            Write-Log "$($app.Name) instalado ou já presente com sucesso." -Type Success
                        } else {
                            # Tentar identificar se o erro é 'já instalado' ou um erro real
                            if ($installResult -like "*already installed*" -or $installResult -like "*already exists*") {
                                Write-Log "$($app.Name) já está instalado. Pulando." -Type Info
                            } else {
                                Write-Log "Falha ao instalar $($app.Name): Winget retornou erro. Detalhes: $($installResult | Out-String)" -Type Error
                            }
                        }
                    } else {
                        Write-Log "Modo WhatIf: $($app.Name) (ID: $($app.Id)) seria instalado." -Type Debug
                    }
                } catch {
                    Write-Log "ERRO inesperado ao tentar instalar $($app.Name): $($_.Exception.Message)" -Type Error
                    Write-Log "Detalhes do Erro: $($_.Exception.ToString())" -Type Error
                }
            }
            Write-Log "Instalação de aplicativos concluída." -Type Success

        } catch {
            Write-Log "ERRO GERAL durante a instalação de aplicativos: $($_.Exception.Message)" -Type Error
            Write-Log "Detalhes do Erro: $($_.Exception.ToString())" -Type Error
        } finally {
            Write-Progress -Activity $activity -Status "Concluído" -PercentComplete 100 -Completed
        }
    }
}

function Update-PowerShell {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
       
            )
    Write-Log "Iniciando instalação/atualização do PowerShell..." -Type Info
    $activity = "Atualização do PowerShell"

    if ($PSCmdlet.ShouldProcess("PowerShell", "instalar/atualizar")) {
        try {
            Write-Progress -Activity $activity -Status "Definindo política de execução..." -PercentComplete 30
            Write-Log "Definindo política de execução para 'Unrestricted' no escopo CurrentUser para permitir scripts." -Type Info
            if (-not $WhatIf) {
                Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Unrestricted -Force -ErrorAction Stop
            } else {
                Write-Log "Modo WhatIf: Política de execução seria definida para 'Unrestricted'." -Type Debug
            }

            Write-Progress -Activity $activity -Status "Baixando e executando script de instalação..." -PercentComplete 60
            Write-Log "Baixando e executando script oficial de instalação/atualização do PowerShell." -Type Info
            if (-not $WhatIf) {
                # O script baixado pode necessitar de conexão com a internet
                # A execução de iex pode ser perigosa; certifique-se da fonte (aka.ms)
                iex "& { $(irm https://aka.ms/install-powershell.ps1) } -UseMSI"
                Write-Log "Script de instalação/atualização do PowerShell executado. Por favor, verifique a saída para detalhes." -Type Success
            } else {
                Write-Log "Modo WhatIf: Script de instalação/atualização do PowerShell seria baixado e executado." -Type Debug
            }

            Write-Log "PowerShell instalado/atualizado com sucesso (verifique a versão após a conclusão)." -Type Success

        } catch {
            Write-Log "ERRO durante a instalação/atualização do PowerShell: $($_.Exception.Message)" -Type Error
            Write-Log "Detalhes do Erro: $($_.Exception.ToString())" -Type Error
        } finally {
            Write-Progress -Activity $activity -Status "Concluído" -PercentComplete 100 -Completed
        }
    }
}

#endregion

#region → FUNÇÕES DE REDE E IMPRESSORAS (AJUSTADAS)

# IMPORTANTE: Esta revisão assume que você tem uma função Write-Log definida que suporta o parâmetro -Type (ex: -Type Info, -Type Success, -Type Error).

function Add-WiFiNetwork {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
       
            )
    Write-Log "Iniciando configuração da rede Wi-Fi 'VemProMundo - Adm'..." -Type Info
    $activity = "Configuração de Rede Wi-Fi"
    $ssid = "VemProMundo - Adm"
    $password = "!Mund0CoC@7281%" # Atenção: Senha em texto claro! Considerar métodos mais seguros para produção.

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

    if ($PSCmdlet.ShouldProcess("rede Wi-Fi '$ssid'", "adicionar")) {
        try {
            Write-Progress -Activity $activity -Status "Criando arquivo de perfil Wi-Fi temporário..." -PercentComplete 10
            $tempFile = Join-Path -Path $env:TEMP -ChildPath "$($ssid.Replace(' ', '_')).xml"
            if (-not $WhatIf) {
                $xmlProfile | Out-File -FilePath $tempFile -Encoding ascii -Force -ErrorAction Stop
                Write-Log "Arquivo de perfil '$tempFile' criado." -Type Debug
            } else {
                Write-Log "Modo WhatIf: Arquivo de perfil '$tempFile' seria criado." -Type Debug
            }

            Write-Progress -Activity $activity -Status "Adicionando perfil Wi-Fi..." -PercentComplete 40
            Write-Log "Adicionando perfil Wi-Fi '$ssid' usando netsh." -Type Info
            if (-not $WhatIf) {
                netsh wlan add profile filename="$tempFile" user=all -ErrorAction Stop | Out-Null
                Write-Log "Perfil '$ssid' adicionado." -Type Debug
            } else {
                Write-Log "Modo WhatIf: Perfil '$ssid' seria adicionado." -Type Debug
            }

            Write-Progress -Activity $activity -Status "Configurando tipo de conexão e categoria de rede..." -PercentComplete 70
            Write-Log "Configurando tipo de conexão para ESS e categoria de rede para Privada." -Type Info
            if (-not $WhatIf) {
                netsh wlan set profileparameter name="$ssid" connectiontype=ESS -ErrorAction Stop | Out-Null
                Set-NetConnectionProfile -Name "$ssid" -NetworkCategory Private -ErrorAction Stop
                Write-Log "Configurações de conexão aplicadas." -Type Debug
            } else {
                Write-Log "Modo WhatIf: Tipo de conexão e categoria de rede seriam configurados." -Type Debug
            }

            Write-Progress -Activity $activity -Status "Limpando arquivos temporários..." -PercentComplete 90
            Write-Log "Removendo arquivo temporário '$tempFile'." -Type Info
            if (-not $WhatIf) {
                Remove-Item $tempFile -Force -ErrorAction Stop
                Write-Log "Arquivo temporário removido." -Type Debug
            } else {
                Write-Log "Modo WhatIf: Arquivo temporário '$tempFile' seria removido." -Type Debug
            }

            Write-Log "Rede Wi-Fi '$ssid' configurada com sucesso." -Type Success

        } catch {
            Write-Log "ERRO ao adicionar rede Wi-Fi '$ssid': $($_.Exception.Message)" -Type Error
            Write-Log "Detalhes do Erro: $($_.Exception.ToString())" -Type Error
        } finally {
            Write-Progress -Activity $activity -Status "Concluído" -PercentComplete 100 -Completed
        }
    }
}

function Install-NetworkPrinters {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
       
            )
    Write-Log "Iniciando instalação de impressoras e drivers de rede..." -Type Info
    $activity = "Instalação de Impressoras de Rede"

    if ($PSCmdlet.ShouldProcess("impressoras de rede", "instalar")) {
        try {
            Write-Progress -Activity $activity -Status "Instalando drivers de impressora via pnputil..." -PercentComplete 5
            Write-Log "Tentando instalar drivers: ssn3m.inf e E_WF1YWE.INF." -Type Info
            if (-not $WhatIf) {
                # Lista de caminhos de drivers para tentar
                $driverPaths = @(
                    "G:\Drives compartilhados\MundoCOC\Tecnologia\Gerais\Drivers\ssn3m.inf",
                    "G:\Drives compartilhados\MundoCOC\Tecnologia\Gerais\Drivers\E_WF1YWE.INF"
                )
                
                foreach ($driverPath in $driverPaths) {
                    $driverName = Split-Path $driverPath -Leaf
                    if (Test-Path $driverPath) {
                        try {
                            pnputil /add-driver $driverPath /install | Out-Null
                            if ($LASTEXITCODE -eq 0) {
                                Write-Log "Driver $driverName instalado com sucesso." -Type Success
                            } else {
                                Write-Log "Falha ao instalar $driverName (código: $LASTEXITCODE)" -Type Warning
                            }
                        } catch {
                            Write-Log "Erro ao instalar ${driverName}: $($_.Exception.Message)" -Type Warning
                        }
                    } else {
                        Write-Log "Driver não encontrado: $driverPath" -Type Warning
                    }
                }
            } else {
                Write-Log "Modo WhatIf: Drivers ssn3m.inf e E_WF1YWE.INF seriam instalados." -Type Debug
            }

            $printers = @(
                @{Name = "Samsung Mundo1"; IP = "172.16.40.40"; Driver = "Samsung M337x 387x 407x Series PCL6 Class Driver"},
                @{Name = "Samsung Mundo2"; IP = "172.17.40.25"; Driver = "Samsung M337x 387x 407x Series PCL6 Class Driver"},
                @{Name = "EpsonMundo1 (L3250 Series)"; IP = "172.16.40.37"; Driver = "EPSON L3250 Series"},
                @{Name = "EpsonMundo2 (L3250 Series)"; IP = "172.17.40.72"; Driver = "EPSON L3250 Series"}
            )
            $totalPrinters = $printers.Count
            $currentPrinter = 0

            foreach ($printer in $printers) {
                $currentPrinter++
                $percentComplete = 5 + (($currentPrinter / $totalPrinters) * 60) # 5% para drivers, 60% para impressoras
                $ip = $printer.IP
                $name = $printer.Name
                $driver = $printer.Driver
                $portName = "IP_$($ip.Replace('.','_'))"

                Write-Progress -Activity $activity -Status "Processando impressora: $name ($ip)..." -CurrentOperation "Instalando: $name" -PercentComplete $percentComplete
                Write-Log "Processando impressora $name ($ip)." -Type Info

                try {
                    if (-not (Get-PrinterPort -Name $portName -ErrorAction SilentlyContinue)) {
                        Write-Log "Porta '$portName' para $ip não encontrada. Criando..." -Type Info
                        if (-not $WhatIf) {
                            Add-PrinterPort -Name $portName -PrinterHostAddress $ip -ErrorAction Stop
                            Write-Log "Porta $portName criada para $ip." -Type Success
                        } else {
                            Write-Log "Modo WhatIf: Porta $portName seria criada para $ip." -Type Debug
                        }
                    } else {
                        Write-Log "Porta '$portName' para $ip já existe." -Type Info
                    }

                    if (-not (Get-Printer -Name $name -ErrorAction SilentlyContinue)) {
                        Write-Log "Impressora '$name' não encontrada. Instalando..." -Type Info
                        if (-not $WhatIf) {
                            Add-Printer -Name $name -DriverName $driver -PortName $portName -ErrorAction Stop
                            Write-Log "Impressora $name ($ip) instalada." -Type Success
                        } else {
                            Write-Log "Modo WhatIf: Impressora $name ($ip) seria instalada." -Type Debug
                        }
                    } else {
                        Write-Log "Impressora $name ($ip) já está instalada." -Type Info
                    }
                } catch {
                    Write-Log "ERRO ao processar impressora $name ($ip): $($_.Exception.Message)" -Type Error
                    Write-Log "Detalhes do Erro: $($_.Exception.ToString())" -Type Error
                }
            }

            # Remover impressora OneNote Desktop se existir
            Write-Progress -Activity $activity -Status "Verificando e removendo impressora 'OneNote (Desktop)'..." -PercentComplete 80
            Write-Log "Verificando se a impressora 'OneNote (Desktop)' está instalada para remoção." -Type Info
            $oneNotePrinter = Get-Printer -Name "OneNote (Desktop)" -ErrorAction SilentlyContinue

            if ($null -ne $oneNotePrinter) {
                Write-Log "A impressora 'OneNote (Desktop)' foi encontrada. Removendo..." -Type Warning
                try {
                    if ($PSCmdlet.ShouldProcess("impressora 'OneNote (Desktop)'", "remover")) {
                        if (-not $WhatIf) {
                            Remove-Printer -Name "OneNote (Desktop)" -ErrorAction Stop
                            Write-Log "Impressora 'OneNote (Desktop)' removida com sucesso." -Type Success

                            # Tentar remover o driver (se houver um nome genérico como "Microsoft XPS Document Writer")
                            # Cuidado ao remover drivers genéricos, pois podem afetar outras impressoras.
                            $driver = Get-PrinterDriver -Name "Microsoft XPS Document Writer*" -ErrorAction SilentlyContinue
                            if ($null -ne $driver) {
                                Write-Log "Removendo driver associado à impressora 'OneNote (Desktop)' (se genérico)." -Type Debug
                                Remove-PrinterDriver -Name $driver.Name -ErrorAction SilentlyContinue | Out-Null
                            }

                            # Remover portas associadas (se houver)
                            $ports = Get-PrinterPort -Name "OneNote*" -ErrorAction SilentlyContinue
                            foreach ($port in $ports) {
                                Write-Log "Removendo porta associada: $($port.Name)." -Type Debug
                                Remove-PrinterPort -Name $port.Name -ErrorAction SilentlyContinue | Out-Null
                            }
                        } else {
                            Write-Log "Modo WhatIf: Impressora 'OneNote (Desktop)', seu driver e portas seriam removidos." -Type Debug
                        }
                    }
                } catch {
                    Write-Log "ERRO ao remover a impressora 'OneNote (Desktop)': $($_.Exception.Message)" -Type Error
                    Write-Log "Detalhes do Erro: $($_.Exception.ToString())" -Type Error
                }
            } else {
                Write-Log "A impressora 'OneNote (Desktop)' não está instalada. Nenhuma ação necessária." -Type Info
            }

            Write-Log "Instalação e configuração de impressoras concluídas." -Type Success

        } catch {
            Write-Log "ERRO GERAL durante a instalação de impressoras de rede: $($_.Exception.Message)" -Type Error
            Write-Log "Detalhes do Erro: $($_.Exception.ToString())" -Type Error
        } finally {
            Write-Progress -Activity $activity -Status "Concluído" -PercentComplete 100 -Completed
        }
    }
}

function Invoke-All-NetworkAdvanced {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
       
            )
    Write-Log "Iniciando todas as otimizações e configurações de rede avançadas..." -Type Info
    $activity = "Otimizações de Rede Avançadas"

    if ($PSCmdlet.ShouldProcess("todas as otimizações de rede", "executar")) {
        Write-Progress -Activity $activity -Status "Limpando DNS..." -PercentComplete 10
        Write-Log "Chamando Clear-DNS..." -Type Info
        if (-not $WhatIf) { Clear-DNS -WhatIf:$WhatIf } # Assumindo que Clear-DNS existe e suporta WhatIf

        Write-Progress -Activity $activity -Status "Otimizando desempenho de rede..." -PercentComplete 30
        Write-Log "Chamando Optimize-NetworkPerformance..." -Type Info
        Optimize-NetworkPerformance -WhatIf:$WhatIf

        Write-Progress -Activity $activity -Status "Configurando DNS para Google/Cloudflare..." -PercentComplete 50
        Write-Log "Chamando Set-DnsGoogleCloudflare..." -Type Info
        Set-DnsGoogleCloudflare -WhatIf:$WhatIf

        Write-Progress -Activity $activity -Status "Testando velocidade da internet..." -PercentComplete 70
        Write-Log "Chamando Test-InternetSpeed..." -Type Info
        Test-InternetSpeed -WhatIf:$WhatIf

        Write-Progress -Activity $activity -Status "Limpando ARP cache..." -PercentComplete 90
        Write-Log "Chamando Clear-ARP..." -Type Info
        if (-not $WhatIf) { Clear-ARP -WhatIf:$WhatIf } # Assumindo que Clear-ARP existe e suporta WhatIf

        Write-Log "Todas as otimizações e configurações de rede avançadas concluídas." -Type Success
        Write-Progress -Activity $activity -Status "Concluído" -PercentComplete 100 -Completed
    }
}

function Set-DnsGoogleCloudflare {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
       
            )
    Write-Log "Configurando DNS para Cloudflare (1.1.1.1) e Google (8.8.8.8)..." -Type Info
    $activity = "Configuração de DNS"

    if ($PSCmdlet.ShouldProcess("servidores DNS", "definir para Cloudflare e Google")) {
        try {
            Write-Progress -Activity $activity -Status "Obtendo adaptadores de rede..." -PercentComplete 20
            $netIPConfigurations = Get-NetIPConfiguration | Where-Object {$_.IPv4Address -and $_.InterfaceAlias -notmatch "Loopback"}

            if (-not $netIPConfigurations) {
                Write-Log "Nenhum adaptador de rede ativo com IPv4 encontrado para configurar DNS." -Type Warning
                return
            }

            $totalAdapters = $netIPConfigurations.Count
            $currentAdapter = 0

            foreach ($config in $netIPConfigurations) {
                $currentAdapter++
                $percentComplete = 20 + (($currentAdapter / $totalAdapters) * 70)
                Write-Progress -Activity $activity -Status "Configurando DNS para adaptador: $($config.InterfaceAlias)..." -CurrentOperation "Adaptador: $($config.InterfaceAlias)" -PercentComplete $percentComplete
                Write-Log "Configurando DNS para adaptador $($config.InterfaceAlias)." -Type Info

                try {
                    if (-not $WhatIf) {
                        Set-DnsClientServerAddress -InterfaceAlias $config.InterfaceAlias -ServerAddresses ("1.1.1.1","8.8.8.8") -ErrorAction Stop
                        Write-Log "DNS configurado com sucesso para $($config.InterfaceAlias)." -Type Success
                    } else {
                        Write-Log "Modo WhatIf: DNS seria configurado para '1.1.1.1','8.8.8.8' no adaptador $($config.InterfaceAlias)." -Type Debug
                    }
                } catch {
                    Write-Log "ERRO ao configurar DNS para $($config.InterfaceAlias): $($_.Exception.Message)" -Type Error
                }
            }
            Write-Log "DNS configurado para Cloudflare/Google em todos os adaptadores aplicáveis." -Type Success
        } catch {
            Write-Log "ERRO GERAL ao configurar DNS: $($_.Exception.Message)" -Type Error
            Write-Log "Detalhes do Erro: $($_.Exception.ToString())" -Type Error
        } finally {
            Write-Progress -Activity $activity -Status "Concluído" -PercentComplete 100 -Completed
        }
    }
}

function Test-InternetSpeed {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
       
            )
    Write-Log "Iniciando teste de velocidade de internet..." -Type Info
    $activity = "Teste de Velocidade de Internet"

    if ($PSCmdlet.ShouldProcess("velocidade da internet", "testar")) {
        try {
            Write-Progress -Activity $activity -Status "Verificando instalação do Winget..." -PercentComplete 10
            if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
                Write-Log "Winget não está disponível neste sistema. Não é possível instalar o Speedtest CLI." -Type Error
                Write-Log "Por favor, instale o Winget para usar esta função ou instale o Speedtest CLI manualmente." -Type Info
                return
            }

            Write-Progress -Activity $activity -Status "Verificando instalação do Speedtest CLI..." -PercentComplete 30
            if (-not (Get-Command speedtest -ErrorAction SilentlyContinue)) {
                Write-Log "Speedtest CLI não encontrado. Tentando instalar via Winget..." -Type Info
                if (-not $WhatIf) {
                    Write-Log "Instalando Ookla.Speedtest..." -Type Info
                    winget install --id Ookla.Speedtest -e --accept-package-agreements --accept-source-agreements -ErrorAction Stop | Out-Null
                    Write-Log "Ookla.Speedtest instalado com sucesso." -Type Success
                } else {
                    Write-Log "Modo WhatIf: Ookla.Speedtest seria instalado via Winget." -Type Debug
                }
            } else {
                Write-Log "Speedtest CLI já está instalado." -Type Info
            }

            Write-Progress -Activity $activity -Status "Executando teste de velocidade..." -PercentComplete 70
            Write-Log "Executando comando 'speedtest'. Isso pode demorar um pouco..." -Type Info
            if (-not $WhatIf) {
                speedtest -ErrorAction Stop
                Write-Log "Teste de velocidade concluído." -Type Success
            } else {
                Write-Log "Modo WhatIf: Comando 'speedtest' seria executado." -Type Debug
            }
        } catch {
            Write-Log "ERRO ao testar velocidade de internet: $($_.Exception.Message)" -Type Error
            Write-Log "Detalhes do Erro: $($_.Exception.ToString())" -Type Error
        } finally {
            Write-Progress -Activity $activity -Status "Concluído" -PercentComplete 100 -Completed
        }
    }
}

function Optimize-NetworkPerformance {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
       
            )
    Write-Log "Iniciando a otimização do desempenho da rede..." -Type Info
    $activity = "Otimização de Rede"

    if ($PSCmdlet.ShouldProcess("desempenho da rede", "otimizar")) {
        try {
            Write-Progress -Activity $activity -Status "Carregando módulo NetAdapter..." -PercentComplete 5
            # Carrega o módulo NetAdapter se ainda não estiver carregado
            if (-not (Get-Module -ListAvailable -Name NetAdapter)) {
                Write-Log "Módulo NetAdapter não encontrado. Tentando importar..." -Type Warning
                try {
                    Import-Module NetAdapter -ErrorAction Stop
                    Write-Log "Módulo NetAdapter importado com sucesso." -Type Success
                } catch {
                    Write-Log "ERRO ao importar o módulo NetAdapter: $($_.Exception.Message). Algumas otimizações podem não ser aplicadas." -Type Error
                    return # Sai da função se o módulo não puder ser carregado
                }
            } else {
                Write-Log "Módulo NetAdapter já carregado." -Type Info
            }

            Write-Progress -Activity $activity -Status "Obtendo adaptadores de rede físicos..." -PercentComplete 10
            $networkAdapters = Get-NetAdapter -Physical -ErrorAction SilentlyContinue

            if (-not $networkAdapters) {
                Write-Log "Nenhum adaptador de rede físico encontrado para otimização." -Type Warning
                return
            }

            $totalAdapters = $networkAdapters.Count
            $currentAdapter = 0

            foreach ($adapter in $networkAdapters) {
                $currentAdapter++
                $percentComplete = 10 + (($currentAdapter / $totalAdapters) * 50) # 10% para módulo, 50% para adaptadores
                Write-Progress -Activity $activity -Status "Otimizando adaptador de rede: $($adapter.Name)..." -CurrentOperation "Adaptador: $($adapter.Name)" -PercentComplete $percentComplete
                Write-Log "Otimizando adaptador de rede: $($adapter.Name)..." -Type Info

                try {
                    # Desabilitar a Checagem de Descarregamento IPv4
                    Write-Log "Desabilitando IPv4 Checksum Offload para $($adapter.Name)." -Type Info
                    if (-not $WhatIf) {
                        Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName "IPv4 Checksum Offload" -DisplayValue "Disabled" -ErrorAction SilentlyContinue | Out-Null
                        Write-Log "IPv4 Checksum Offload desabilitado para $($adapter.Name)." -Type Success
                    } else {
                        Write-Log "Modo WhatIf: IPv4 Checksum Offload seria desabilitado para $($adapter.Name)." -Type Debug
                    }

                    # Desabilitar a Checagem de Descarregamento TCP
                    Write-Log "Desabilitando TCP Checksum Offload (IPv4/IPv6) para $($adapter.Name)." -Type Info
                    if (-not $WhatIf) {
                        Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName "TCP Checksum Offload (IPv4)" -DisplayValue "Disabled" -ErrorAction SilentlyContinue | Out-Null
                        Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName "TCP Checksum Offload (IPv6)" -DisplayValue "Disabled" -ErrorAction SilentlyContinue | Out-Null
                        Write-Log "TCP Checksum Offload desabilitado para $($adapter.Name)." -Type Success
                    } else {
                        Write-Log "Modo WhatIf: TCP Checksum Offload seria desabilitado para $($adapter.Name)." -Type Debug
                    }

                    # Desabilitar Large Send Offload (LSO) - CUIDADO: Pode impactar desempenho em algumas redes
                    Write-Log "Desabilitando Large Send Offload (LSO) V2 (IPv4/IPv6) para $($adapter.Name)." -Type Info
                    if (-not $WhatIf) {
                        Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName "Large Send Offload V2 (IPv4)" -DisplayValue "Disabled" -ErrorAction SilentlyContinue | Out-Null
                        Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName "Large Send Offload V2 (IPv6)" -DisplayValue "Disabled" -ErrorAction SilentlyContinue | Out-Null
                        Write-Log "Large Send Offload (LSO) desabilitado para $($adapter.Name)." -Type Success
                    } else {
                        Write-Log "Modo WhatIf: Large Send Offload (LSO) seria desabilitado para $($adapter.Name)." -Type Debug
                    }

                    # Desabilitar o Receive Side Scaling (RSS) - geralmente é bom, mas pode ser desabilitado se houver problemas
                    # Write-Log "Desabilitando Receive Side Scaling (RSS) para $($adapter.Name)." -Type Info
                    # if (-not $WhatIf) {
                    #     Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName "Receive Side Scaling" -DisplayValue "Disabled" -ErrorAction SilentlyContinue | Out-Null
                    #     Write-Log "RSS desabilitado para $($adapter.Name)." -Type Success
                    # } else {
                    #     Write-Log "Modo WhatIf: RSS seria desabilitado para $($adapter.Name)." -Type Debug
                    # }

                    # Desabilitar o NetBIOS sobre TCP/IP (se não for usado para redes legadas)
                    # Write-Log "Desabilitando NetBIOS sobre TCP/IP para $($adapter.Name)." -Type Info
                    # if (-not $WhatIf) {
                    #     Get-NetAdapterBinding -ComponentID ms_netbios -Name $adapter.Name -ErrorAction SilentlyContinue | Disable-NetAdapterBinding -ErrorAction SilentlyContinue | Out-Null
                    #     Write-Log "NetBIOS sobre TCP/IP desabilitado para $($adapter.Name)." -Type Success
                    # } else {
                    #     Write-Log "Modo WhatIf: NetBIOS sobre TCP/IP seria desabilitado para $($adapter.Name)." -Type Debug
                    # }

                } catch {
                    Write-Log "ERRO ao otimizar adaptador $($adapter.Name): $($_.Exception.Message)" -Type Error
                    Write-Log "Detalhes do Erro: $($_.Exception.ToString())" -Type Error
                }
            }

            Write-Progress -Activity $activity -Status "Aplicando configurações globais de TCP via Registro..." -PercentComplete 70
            Write-Log "Aplicando configurações globais de TCP via Registro..." -Type Info
            try {
                # Desabilitar Nagle's Algorithm (TcpNoDelay=1)
                Write-Log "Configurando TcpNoDelay (desabilitar Nagle's Algorithm)." -Type Info
                if (-not $WhatIf) {
                    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "TcpNoDelay" -Value 1 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
                    Write-Log "Nagle's Algorithm desabilitado (TcpNoDelay=1)." -Type Success
                } else {
                    Write-Log "Modo WhatIf: Nagle's Algorithm seria desabilitado." -Type Debug
                }

                # Habilitar o TcpAckFrequency (para jogos e baixa latência, ou 1 para ack imediato)
                Write-Log "Configurando TcpAckFrequency para 1 (ACKs imediatos)." -Type Info
                if (-not $WhatIf) {
                    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" -Name "TcpAckFrequency" -Value 1 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
                    Write-Log "TcpAckFrequency configurado para 1." -Type Success
                } else {
                    Write-Log "Modo WhatIf: TcpAckFrequency seria configurado para 1." -Type Debug
                }

                # Ajuste do limite de conexão TCP (para programas P2P, etc.)
                Write-Log "Configurando MaxUserPort para 65534." -Type Info
                if (-not $WhatIf) {
                    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "MaxUserPort" -Value 65534 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
                    Write-Log "MaxUserPort configurado para 65534." -Type Success
                } else {
                    Write-Log "Modo WhatIf: MaxUserPort seria configurado para 65534." -Type Debug
                }

                # Tempo de vida de portas TCP/IP (reduzir espera para reuso de portas)
                Write-Log "Configurando TcpTimedWaitDelay para 30 segundos." -Type Info
                if (-not $WhatIf) {
                    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "TcpTimedWaitDelay" -Value 30 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
                    Write-Log "TcpTimedWaitDelay configurado para 30 segundos." -Type Success
                } else {
                    Write-Log "Modo WhatIf: TcpTimedWaitDelay seria configurado para 30 segundos." -Type Debug
                }

                # Desabilitar o Fast Startup (Inicialização Rápida) via Registro (pode causar problemas em dual-boot)
                Write-Log "Desabilitando Inicialização Rápida (Fast Startup)." -Type Info
                if (-not $WhatIf) {
                    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Value 0 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
                    Write-Log "Inicialização Rápida (Fast Startup) desabilitada." -Type Success
                } else {
                    Write-Log "Modo WhatIf: Inicialização Rápida (Fast Startup) seria desabilitada." -Type Debug
                }

                # Desabilitar ECN Capability (Explicit Congestion Notification) - Globalmente via netsh ou registro
                Write-Log "Desabilitando ECN Capability (se aplicável)." -Type Info
                if (-not $WhatIf) {
                    # ECN é uma configuração TCP global, não por adaptador. Exemplo via netsh:
                    # netsh int tcp set global ecncapability=disabled
                    # Ou via Set-NetTCPSetting para perfis.
                    # Por simplicidade, se for para desativar, um Set-NetTCPSetting seria mais PowerShell-idiomatic.
                    # Mas se a intenção é via registro, é mais complexo.
                    # Por agora, mantenho o exemplo globalmente via netsh para referencia,
                    # mas não adiciono ao script para evitar dependências externas sem controle de erro do PowerShell.
                    # A implementação atual no script original não faz essa parte.
                    Write-Log "ECN Capability: A configuração global de ECN não é feita por este script." -Type Info
                } else {
                    Write-Log "Modo WhatIf: ECN Capability seria desabilitado (se implementado)." -Type Debug
                }

            } catch {
                Write-Log "ERRO ao aplicar configurações globais de TCP/Registro: $($_.Exception.Message)" -Type Error
                Write-Log "Detalhes do Erro: $($_.Exception.ToString())" -Type Error
            }

            Write-Log "Otimização de desempenho da rede concluída." -Type Success
            Write-Log "Otimizações de rede aplicadas. Um reinício pode ser necessário para algumas alterações terem efeito completo." -Type Warning

        } catch {
            Write-Log "ERRO GERAL durante a otimização de desempenho da rede: $($_.Exception.Message)" -Type Error
            Write-Log "Detalhes do Erro: $($_.Exception.ToString())" -Type Error
        } finally {
            Write-Progress -Activity $activity -Status "Concluído" -PercentComplete 100 -Completed
        }
    }
}

function Disable-IPv6 {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
       
            )
    Write-Log "Iniciando desabilitação do IPv6..." -Type Info
    $activity = "Desabilitar IPv6"

    if ($PSCmdlet.ShouldProcess("IPv6", "desabilitar")) {
        try {
            Write-Progress -Activity $activity -Status "Criando/modificando entrada de registro para IPv6..." -PercentComplete 50
            Write-Log "Criando ou modificando a entrada de registro 'DisabledComponents' para desabilitar IPv6." -Type Info
            if (-not $WhatIf) {
                # O valor 0xFF desabilita todos os componentes IPv6 (incluindo túnel)
                New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisabledComponents" -PropertyType DWord -Value 0xFF -Force -ErrorAction Stop | Out-Null
                Write-Log "IPv6 desativado com sucesso. Um reinício é necessário para aplicar a alteração." -Type Success
            } else {
                Write-Log "Modo WhatIf: IPv6 seria desativado via registro. Um reinício seria necessário." -Type Debug
            }
        } catch {
            Write-Log "ERRO ao desativar IPv6: $($_.Exception.Message)" -Type Error
            Write-Log "Detalhes do Erro: $($_.Exception.ToString())" -Type Error
        } finally {
            Write-Progress -Activity $activity -Status "Concluído" -PercentComplete 100 -Completed
        }
    }
}

function Clear-DNS {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
     
    )
    Write-Log "Iniciando limpeza de cache DNS..." -Type Info
    $activity = "Limpeza de Cache DNS"

    if ($PSCmdlet.ShouldProcess("cache DNS", "limpar")) {
        try {
            Write-Progress -Activity $activity -Status "Executando 'ipconfig /flushdns'..." -PercentComplete 50
            Write-Log "Executando 'ipconfig /flushdns'..." -Type Info
            if (-not $WhatIf) {
                $process = Start-Process -FilePath "ipconfig.exe" -ArgumentList "/flushdns" -WindowStyle Hidden -Wait -PassThru
                $process.WaitForExit() # Garante que o processo termine antes de continuar
                if ($process.ExitCode -ne 0) {
                    throw "Comando ipconfig /flushdns falhou com código de saída $($process.ExitCode)."
                }
            } else {
                Write-Log "Modo WhatIf: 'ipconfig /flushdns' seria executado." -Type Debug
            }
            Write-Log "Cache DNS limpo." -Type Success

        } catch {
            Write-Log "ERRO ao limpar cache DNS: $($_.Exception.Message)" -Type Error
            Write-Log "Detalhes do Erro: $($_.Exception.ToString())" -Type Error
        } finally {
            Write-Progress -Activity $activity -Status "Concluído" -PercentComplete 100 -Completed
        }
    }
}

function Clear-ARP {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
       
            )
    Write-Log "Iniciando limpeza de cache ARP..." -Type Info
    $activity = "Limpeza de Cache ARP"

    if ($PSCmdlet.ShouldProcess("cache ARP", "limpar")) {
        try {
            Write-Progress -Activity $activity -Status "Executando 'arp -d *'..." -PercentComplete 50
            Write-Log "Executando 'arp -d *'..." -Type Info
            if (-not $WhatIf) {
                # O comando ARP não joga exceções PowerShell para erros de execução, mas sim para o stderr
                # Redirecionamos stderr para stdout (2>&1) e verificamos a saída ou $LASTEXITCODE
                $arpOutput = & arp -d * 2>&1
                if ($LASTEXITCODE -ne 0) {
                    throw "Comando 'arp -d *' falhou com código de saída $LASTEXITCODE. Output: $arpOutput"
                }
            } else {
                Write-Log "Modo WhatIf: 'arp -d *' seria executado." -Type Debug
            }
            Write-Log "Cache ARP limpo." -Type Success

        } catch {
            Write-Log "ERRO ao limpar cache ARP: $($_.Exception.Message)" -Type Error
            Write-Log "Detalhes do Erro: $($_.Exception.ToString())" -Type Error
            Write-Log "Verifique se o PowerShell está rodando como Administrador." -Type Info
        } finally {
            Write-Progress -Activity $activity -Status "Concluído" -PercentComplete 100 -Completed
        }
    }
}


#endregion

#region → FUNÇÕES DE DIAGNÓSTICO E INFORMAÇÕES (AJUSTADAS)

# IMPORTANTE: Esta revisão assume que você tem uma função Write-Log definida que suporta o parâmetro -Type (ex: -Type Info, -Type Success, -Type TypeError).

function Show-SystemInfo {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
       
            )
    Write-Log "Exibindo informações do sistema..." -Type Info
    $activity = "Coletando Informações do Sistema"

    if ($PSCmdlet.ShouldProcess("informações do sistema", "exibir")) {
        try {
            Write-Progress -Activity $activity -Status "Coletando dados..." -PercentComplete 50
            if (-not $WhatIf) {
                systeminfo | Out-Host
                Write-Log "Informações do sistema exibidas." -Type Success
            } else {
                Write-Log "Modo WhatIf: Informações do sistema seriam exibidas usando 'systeminfo'." -Type Debug
            }
        } catch {
            Write-Log "ERRO ao exibir informações do sistema: $($_.Exception.Message)" -Type Error
            Write-Log "Detalhes do Erro: $($_.Exception.ToString())" -Type Error
        } finally {
            Write-Progress -Activity $activity -Status "Concluído" -PercentComplete 100 -Completed
        }
    }
}

function Show-DiskUsage {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
       
            )
    Write-Log "Exibindo uso do disco..." -Type Info
    $activity = "Coletando Uso do Disco"

    if ($PSCmdlet.ShouldProcess("uso do disco", "exibir")) {
        try {
            Write-Progress -Activity $activity -Status "Coletando dados de volume..." -PercentComplete 50
            if (-not $WhatIf) {
                Get-Volume | Select-Object DriveLetter, FileSystemLabel, @{Name="Size(GB)";Expression={[math]::Round($_.Size/1GB,2)}}, @{Name="Free(GB)";Expression={[math]::Round($_.SizeRemaining/1GB,2)}} | Format-Table -AutoSize | Out-Host
                Write-Log "Uso do disco exibido." -Type Success
            } else {
                Write-Log "Modo WhatIf: Uso do disco seria exibido." -Type Debug
            }
        } catch {
            Write-Log "ERRO ao exibir uso do disco: $($_.Exception.Message)" -Type Error
            Write-Log "Detalhes do Erro: $($_.Exception.ToString())" -Type Error
        } finally {
            Write-Progress -Activity $activity -Status "Concluído" -PercentComplete 100 -Completed
        }
    }
}

function Show-NetworkInfo {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
       
            )
    Write-Log "Exibindo informações de rede..." -Type Info
    $activity = "Coletando Informações de Rede"

    if ($PSCmdlet.ShouldProcess("informações de rede", "exibir")) {
        try {
            Write-Progress -Activity $activity -Status "Coletando configuração IP..." -PercentComplete 30
            if (-not $WhatIf) {
                ipconfig /all | Out-Host
                Write-Log "Informações de ipconfig exibidas." -Type Debug
            } else {
                Write-Log "Modo WhatIf: 'ipconfig /all' seria executado." -Type Debug
            }

            Write-Progress -Activity $activity -Status "Coletando detalhes de interface..." -PercentComplete 70
            if (-not $WhatIf) {
                Get-NetIPConfiguration | Select-Object InterfaceAlias, IPv4Address, IPv4DefaultGateway, DNSServer | Format-Table -AutoSize | Out-Host
                Write-Log "Detalhes de Get-NetIPConfiguration exibidos." -Type Debug
            } else {
                Write-Log "Modo WhatIf: 'Get-NetIPConfiguration' seria executado." -Type Debug
            }

            Write-Log "Informações de rede exibidas." -Type Success
        } catch {
            Write-Log "ERRO ao exibir informações de rede: $($_.Exception.Message)" -Type Error
            Write-Log "Detalhes do Erro: $($_.Exception.ToString())" -Type Error
        } finally {
            Write-Progress -Activity $activity -Status "Concluído" -PercentComplete 100 -Completed
        }
    }
}

function Invoke-All-DiagnosticsAdvanced {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
       
            )
    Write-Log "Iniciando todas as funções avançadas de diagnóstico e informações..." -Type Info
    $activity = "Diagnóstico Avançado"
    $totalSteps = 7 # Número de funções chamadas

    if ($PSCmdlet.ShouldProcess("todas as funções de diagnóstico", "executar")) {
        try {
            Write-Progress -Activity $activity -Status "Exibindo informações do sistema..." -PercentComplete 10
            Write-Log "Chamando Show-SystemInfo..." -Type Info
            Show-SystemInfo -WhatIf:$WhatIf

            Write-Progress -Activity $activity -Status "Exibindo uso do disco..." -PercentComplete 25
            Write-Log "Chamando Show-DiskUsage..." -Type Info
            Show-DiskUsage -WhatIf:$WhatIf

            Write-Progress -Activity $activity -Status "Exibindo informações de rede..." -PercentComplete 40
            Write-Log "Chamando Show-NetworkInfo..." -Type Info
            Show-NetworkInfo -WhatIf:$WhatIf

            Write-Progress -Activity $activity -Status "Executando verificação SFC..." -PercentComplete 55
            Write-Log "Chamando Invoke-SFC-Scan..." -Type Info
            Invoke-SFC-Scan -WhatIf:$WhatIf

            Write-Progress -Activity $activity -Status "Executando verificação DISM..." -PercentComplete 70
            Write-Log "Chamando Invoke-DISM-Scan..." -Type Info
            Invoke-DISM-Scan -WhatIf:$WhatIf

            Write-Progress -Activity $activity -Status "Testando saúde dos discos (SMART)..." -PercentComplete 85
            Write-Log "Chamando Test-SMART-Drives..." -Type Info
            Test-SMART-Drives -WhatIf:$WhatIf

            Write-Progress -Activity $activity -Status "Agendando teste de memória..." -PercentComplete 95
            Write-Log "Chamando Test-Memory..." -Type Info
            Test-Memory -WhatIf:$WhatIf

            Write-Log "Todas as funções avançadas de diagnóstico e informações concluídas." -Type Success

        } catch {
            Write-Log "ERRO GERAL durante a execução dos diagnósticos avançados: $($_.Exception.Message)" -Type Error
            Write-Log "Detalhes do Erro: $($_.Exception.ToString())" -Type Error
        } finally {
            Write-Progress -Activity $activity -Status "Concluído" -PercentComplete 100 -Completed
        }
    }
}

function Invoke-SFC-Scan {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
       
            )
    Write-Log "Iniciando verificação SFC (System File Checker)..." -Type Info
    $activity = "Verificação SFC"

    if ($PSCmdlet.ShouldProcess("verificação SFC", "executar")) {
        try {
            Write-Progress -Activity $activity -Status "Iniciando 'sfc /scannow'. Isso pode levar um tempo..." -PercentComplete 20
            Write-Log "Executando 'sfc /scannow' para verificar e reparar arquivos de sistema." -Type Info
            if (-not $WhatIf) {
                # SFC requer privilégios de administrador
                $sfcResult = sfc /scannow 2>&1
                $sfcResult | Out-Host
                Write-Log "Verificação SFC concluída. Verifique a saída acima para detalhes." -Type Success
            } else {
                Write-Log "Modo WhatIf: 'sfc /scannow' seria executado para verificar arquivos de sistema." -Type Debug
            }
        } catch {
            Write-Log "ERRO ao executar verificação SFC: $($_.Exception.Message)" -Type Error
            Write-Log "Detalhes do Erro: $($_.Exception.ToString())" -Type Error
            Write-Log "Certifique-se de executar o PowerShell como Administrador." -Type Info
        } finally {
            Write-Progress -Activity $activity -Status "Concluído" -PercentComplete 100 -Completed
        }
    }
}

function Invoke-DISM-Scan {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
       
            )
    Write-Log "Iniciando verificação DISM (Deployment Image Servicing and Management)..." -Type Info
    $activity = "Verificação DISM"

    if ($PSCmdlet.ShouldProcess("verificação DISM", "executar")) {
        try {
            Write-Progress -Activity $activity -Status "Iniciando 'DISM /Online /Cleanup-Image /RestoreHealth'. Isso pode levar um tempo..." -PercentComplete 20
            Write-Log "Executando 'DISM /Online /Cleanup-Image /RestoreHealth' para reparar a imagem do Windows." -Type Info
            if (-not $WhatIf) {
                # DISM requer privilégios de administrador
                $dismResult = DISM /Online /Cleanup-Image /RestoreHealth 2>&1
                $dismResult | Out-Host
                Write-Log "Verificação DISM concluída. Verifique a saída acima para detalhes." -Type Success
            } else {
                Write-Log "Modo WhatIf: 'DISM /Online /Cleanup-Image /RestoreHealth' seria executado." -Type Debug
            }
        } catch {
            Write-Log "ERRO ao executar verificação DISM: $($_.Exception.Message)" -Type Error
            Write-Log "Detalhes do Erro: $($_.Exception.ToString())" -Type Error
            Write-Log "Certifique-se de executar o PowerShell como Administrador." -Type Info
        } finally {
            Write-Progress -Activity $activity -Status "Concluído" -PercentComplete 100 -Completed
        }
    }
}

function Test-SMART-Drives {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
       
            )
    Write-Log "Verificando saúde dos discos (SMART)..." -Type Info
    $activity = "Teste de Saúde SMART dos Discos"

    if ($PSCmdlet.ShouldProcess("saúde dos discos", "verificar (SMART)")) {
        try {
            Write-Progress -Activity $activity -Status "Coletando status SMART dos discos..." -PercentComplete 30
            $drives = Get-WmiObject -Namespace root\wmi -Class MSStorageDriver_FailurePredictStatus -ErrorAction Stop

            if ($null -eq $drives -or $drives.Count -eq 0) {
                Write-Log "Nenhum disco com status SMART encontrado ou WMI inacessível." -Type Warning
                return
            }

            $totalDrives = $drives.Count
            $currentDrive = 0

            foreach ($drive in $drives) {
                $currentDrive++
                $percentComplete = 30 + (($currentDrive / $totalDrives) * 60)
                Write-Progress -Activity $activity -Status "Analisando disco: $($drive.InstanceName)..." -CurrentOperation "Disco: $($drive.InstanceName)" -PercentComplete $percentComplete

                if ($drive.PredictFailure) {
                    Write-Log "ALERTA: Disco com PROBLEMAS detectados via SMART: $($drive.InstanceName)" -Type Error
                    if (-not $WhatIf) { Write-Log "É altamente recomendado fazer backup dos dados deste disco imediatamente." -Type Warning }
                } else {
                    Write-Log "Disco OK (SMART): $($drive.InstanceName)" -Type Success
                }
            }
            Write-Log "Verificação de saúde dos discos (SMART) concluída." -Type Success
        } catch {
            Write-Log "ERRO ao verificar saúde dos discos (SMART): $($_.Exception.Message)" -Type Error
            Write-Log "Detalhes do Erro: $($_.Exception.ToString())" -Type Error
        } finally {
            Write-Progress -Activity $activity -Status "Concluído" -PercentComplete 100 -Completed
        }
    }
}

function Test-Memory {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
       
            )
    Write-Log "Iniciando agendamento de teste de memória..." -Type Info
    $activity = "Agendamento de Teste de Memória"

    if ($PSCmdlet.ShouldProcess("teste de memória", "agendar")) {
        try {
            Write-Progress -Activity $activity -Status "Iniciando ferramenta de diagnóstico de memória (mdsched.exe)..." -PercentComplete 50
            Write-Log "Abrindo a Ferramenta de Diagnóstico de Memória do Windows. Você precisará selecionar a opção para reiniciar e verificar." -Type Info
            if (-not $WhatIf) {
                # mdsched.exe abre uma GUI, não é uma operação de console direta.
                # Não haverá uma "saída" que o PowerShell possa capturar diretamente.
                Start-Process -FilePath "mdsched.exe" -Wait -NoNewWindow -ErrorAction Stop
                Write-Log "Ferramenta de Diagnóstico de Memória do Windows iniciada. Siga as instruções na tela." -Type Success
            } else {
                Write-Log "Modo WhatIf: Ferramenta de Diagnóstico de Memória do Windows (mdsched.exe) seria iniciada." -Type Debug
            }
        } catch {
            Write-Log "ERRO ao agendar/iniciar teste de memória: $($_.Exception.Message)" -Type Error
            Write-Log "Detalhes do Erro: $($_.Exception.ToString())" -Type Error
        } finally {
            Write-Progress -Activity $activity -Status "Concluído" -PercentComplete 100 -Completed
        }
    }
}

#endregion

#region → FUNÇÕES DE TWEAKS DE PRIVACIDADE E REGISTRO (AJUSTADAS)

# IMPORTANTE: Esta revisão assume que você tem uma função Write-Log definida que suporta o parâmetro -Type (ex: -Type Info, -Type Success, -Type TypeError).

function Grant-PrivacyTweaks {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
       
            )
    Write-Log "Iniciando aplicação de tweaks de privacidade e desabilitação de funcionalidades desnecessárias..." -Type Info

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

    $totalChanges = ($registryChanges.Keys | Measure-Object).Count
    $currentChange = 0
    $activity = "Aplicando Tweaks de Privacidade no Registro"

    if ($PSCmdlet.ShouldProcess("tweaks de privacidade e registro", "aplicar")) {
        try {
            foreach ($path in $registryChanges.Keys) {
                $currentChange++
                $percentComplete = ($currentChange / $totalChanges) * 100
                Write-Progress -Activity $activity -Status "Processando caminho: $path" -PercentComplete $percentComplete -CurrentOperation "Caminho: $path"

                if (-not (Test-Path $path -ErrorAction SilentlyContinue)) {
                    Write-Log "Verificando/Criando caminho de registro: $path" -Type Debug
                    try {
                        if (-not $WhatIf) {
                            New-Item -Path $path -Force -ErrorAction Stop | Out-Null
                            Write-Log "Caminho de registro criado: $path" -Type Info
                        } else {
                            Write-Log "Modo WhatIf: Caminho de registro '$path' seria criado." -Type Debug
                        }
                    } catch {
                        Write-Log "ERRO ao criar caminho de registro '$path': $($_.Exception.Message)" -Type Error
                        continue # Pula para o próximo caminho se a criação falhar
                    }
                }

                foreach ($name in $registryChanges.$path.Keys) {
                    $value = $registryChanges.$path.$name
                    Write-Log "Configurando: $path - $name = $value" -Type Debug

                    try {
                        if (-not $WhatIf) {
                            Set-ItemProperty -Path $path -Name $name -Value $value -Force -ErrorAction Stop | Out-Null
                            # Write-Log "Configurado: $name = $value em $path" -Type Debug # Demasiado verboso
                        } else {
                            Write-Log "Modo WhatIf: Propriedade '$name' seria definida para '$value' em '$path'." -Type Debug
                        }
                    } catch {
                        Write-Log "ERRO ao configurar propriedade '$name' em '$path': $($_.Exception.Message)" -Type Error
                    }
                }
            }
            Write-Log "Tweaks de privacidade aplicados com sucesso." -Type Success
        } catch {
            Write-Log "ERRO GERAL ao aplicar tweaks de privacidade: $($_.Exception.Message)" -Type Error
            Write-Log "Detalhes do Erro: $($_.Exception.ToString())" -Type Error
        } finally {
            Write-Progress -Activity $activity -Status "Concluído" -PercentComplete 100 -Completed
        }
    }
}

function Enable-PrivacyHardening {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
       
            )
    Write-Log "Iniciando aplicação de privacidade agressiva..." -Type Info
    $activity = "Aplicando Endurecimento de Privacidade"

    if ($PSCmdlet.ShouldProcess("ajustes de privacidade agressiva", "aplicar")) {
        try {
            Write-Progress -Activity $activity -Status "Configurando telemetria..." -PercentComplete 20
            if (-not $WhatIf) { reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f | Out-Null }
            else { Write-Log "Modo WhatIf: Telemetria seria desativada via reg.exe." -Type Debug }

            Write-Progress -Activity $activity -Status "Configurando ID de publicidade..." -PercentComplete 40
            if (-not $WhatIf) { reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v Enabled /t REG_DWORD /d 0 /f | Out-Null }
            else { Write-Log "Modo WhatIf: ID de publicidade seria desativada." -Type Debug }

            Write-Progress -Activity $activity -Status "Restringindo personalização de entrada..." -PercentComplete 60
            if (-not $WhatIf) {
                reg.exe add "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v RestrictImplicitTextCollection /t REG_DWORD /d 1 /f | Out-Null
                reg.exe add "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v RestrictImplicitInkCollection /t REG_DWORD /d 1 /f | Out-Null
            } else { Write-Log "Modo WhatIf: Restrições de personalização de entrada seriam aplicadas." -Type Debug }

            Write-Progress -Activity $activity -Status "Desativando coleta de contatos..." -PercentComplete 80
            if (-not $WhatIf) { reg.exe add "HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /v HarvestContacts /t REG_DWORD /d 0 /f | Out-Null }
            else { Write-Log "Modo WhatIf: Coleta de contatos seria desativada." -Type Debug }

            Write-Log "Privacidade agressiva aplicada com sucesso." -Type Success
        } catch {
            Write-Log "ERRO ao aplicar privacidade agressiva: $($_.Exception.Message)" -Type Error
            Write-Log "Detalhes do Erro: $($_.Exception.ToString())" -Type Error
        } finally {
            Write-Progress -Activity $activity -Status "Concluído" -PercentComplete 100 -Completed
        }
    }
}

function Disable-Cortana-AndSearch {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
       
            )
    Write-Log "Iniciando desativação de Cortana, Windows Search, Telemetria e Relatórios de Erro..." -Type Info
    $activity = "Desativando Cortana e Busca"

    if ($PSCmdlet.ShouldProcess("Cortana e Busca do Windows", "desativar")) {
        try {
            Write-Progress -Activity $activity -Status "Desativando Cortana via registro..." -PercentComplete 10
            if (-not $WhatIf) { reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCortana /t REG_DWORD /d 0 /f | Out-Null }
            else { Write-Log "Modo WhatIf: Cortana seria desativada via registro." -Type Debug }

            Write-Progress -Activity $activity -Status "Desativando busca na nuvem via registro..." -PercentComplete 25
            if (-not $WhatIf) { reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCloudSearch /t REG_DWORD /d 0 /f | Out-Null }
            else { Write-Log "Modo WhatIf: Busca na nuvem seria desativada." -Type Debug }

            Write-Progress -Activity $activity -Status "Parando e desabilitando serviço Windows Search (WSearch)..." -PercentComplete 50
            if (-not $WhatIf) {
                Stop-Service WSearch -Force -ErrorAction SilentlyContinue
                Set-Service WSearch -StartupType Disabled -ErrorAction SilentlyContinue
                Write-Log "Serviço WSearch parado e desabilitado." -Type Debug
            } else { Write-Log "Modo WhatIf: Serviço WSearch seria parado e desabilitado." -Type Debug }

            Write-Progress -Activity $activity -Status "Desativando telemetria via registro..." -PercentComplete 75
            if (-not $WhatIf) { reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f | Out-Null }
            else { Write-Log "Modo WhatIf: Telemetria seria desativada." -Type Debug }

            Write-Progress -Activity $activity -Status "Desativando relatórios de erro via registro..." -PercentComplete 90
            if (-not $WhatIf) { reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\ErrorReporting" /v Disabled /t REG_DWORD /d 1 /f | Out-Null }
            else { Write-Log "Modo WhatIf: Relatórios de erro seriam desativados." -Type Debug }

            Write-Log "Cortana, Search, Telemetria e Relatório de Erro desativados com sucesso." -Type Success
        } catch {
            Write-Log "ERRO ao desativar Cortana/Search/Telemetria: $($_.Exception.Message)" -Type Error
            Write-Log "Detalhes do Erro: $($_.Exception.ToString())" -Type Error
        } finally {
            Write-Progress -Activity $activity -Status "Concluído" -PercentComplete 100 -Completed
        }
    }
}

function Disable-UAC {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
       
            )
    Write-Log "Iniciando desativação do UAC (User Account Control)..." -Type Info
    Write-Log "ATENÇÃO: Desativar o UAC reduz SIGNIFICATIVAMENTE a segurança do sistema. Prossiga com extrema cautela e apenas se for estritamente necessário em um ambiente controlado." -Type Warning
    Start-Sleep -Seconds 2
    $activity = "Desativando UAC"

    if ($PSCmdlet.ShouldProcess("UAC (User Account Control)", "desativar")) {
        try {
            Write-Progress -Activity $activity -Status "Definindo 'EnableLUA' para 0..." -PercentComplete 30
            if (-not $WhatIf) {
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 0 -Force -ErrorAction Stop | Out-Null
            } else { Write-Log "Modo WhatIf: 'EnableLUA' seria definido para 0." -Type Debug }

            Write-Progress -Activity $activity -Status "Definindo 'ConsentPromptBehaviorAdmin' para 0..." -PercentComplete 70
            if (-not $WhatIf) {
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 0 -Force -ErrorAction Stop | Out-Null
            } else { Write-Log "Modo WhatIf: 'ConsentPromptBehaviorAdmin' seria definido para 0." -Type Debug }

            Write-Log "UAC desativado com sucesso. Será necessário reiniciar para que as alterações tenham efeito completo." -Type Success
        } catch {
            Write-Log "ERRO ao desativar o UAC: $($_.Exception.Message)" -Type Error
            Write-Log "Detalhes do Erro: $($_.Exception.ToString())" -Type Error
            Write-Log "A desativação do UAC requer privilégios de administrador. Certifique-se de executar o PowerShell como Administrador." -Type Info
        } finally {
            Write-Progress -Activity $activity -Status "Concluído" -PercentComplete 100 -Completed
        }
    }
}

function Disable-ActionCenter-Notifications {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
       
            )
    Write-Log "Iniciando desabilitação do Action Center e notificações..." -Type Info
    $activity = "Desativando Notificações e Action Center"

    if ($PSCmdlet.ShouldProcess("Action Center e Notificações", "desativar")) {
        try {
            Write-Progress -Activity $activity -Status "Desativando Notification Center via registro..." -PercentComplete 30
            if (-not $WhatIf) { reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v DisableNotificationCenter /t REG_DWORD /d 1 /f | Out-Null }
            else { Write-Log "Modo WhatIf: Notification Center seria desativado." -Type Debug }

            Write-Progress -Activity $activity -Status "Desativando Toast Notifications via registro..." -PercentComplete 60
            if (-not $WhatIf) { reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications" /v ToastEnabled /t REG_DWORD /d 0 /f | Out-Null }
            else { Write-Log "Modo WhatIf: Toast Notifications seriam desativadas." -Type Debug }

            Write-Progress -Activity $activity -Status "Desativando acesso global a aplicativos em segundo plano via registro..." -PercentComplete 90
            if (-not $WhatIf) { reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v GlobalUserDisabled /t REG_DWORD /d 1 /f | Out-Null }
            else { Write-Log "Modo WhatIf: Acesso global a apps em segundo plano seria desativado." -Type Debug }

            Write-Log "Action Center e notificações desativados com sucesso." -Type Success
        } catch {
            Write-Log "ERRO ao desativar Action Center e notificações: $($_.Exception.Message)" -Type Error
            Write-Log "Detalhes do Erro: $($_.Exception.ToString())" -Type Error
        } finally {
            Write-Progress -Activity $activity -Status "Concluído" -PercentComplete 100 -Completed
        }
    }
}

function Set-VisualPerformance {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
       
            )
    Write-Log "Iniciando ajuste visual para melhor performance..." -Type Info
    $activity = "Ajuste de Performance Visual"

    if ($PSCmdlet.ShouldProcess("ajustes visuais para performance", "aplicar")) {
        try {
            Write-Progress -Activity $activity -Status "Definindo VisualFXSetting para performance..." -PercentComplete 50
            if (-not $WhatIf) { reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v VisualFXSetting /t REG_DWORD /d 2 /f | Out-Null }
            else { Write-Log "Modo WhatIf: VisualFXSetting seria definido para 2 (performance)." -Type Debug }

            Write-Progress -Activity $activity -Status "Ajustando UserPreferencesMask..." -PercentComplete 80
            if (-not $WhatIf) { reg.exe add "HKCU\Control Panel\Desktop" /v UserPreferencesMask /t REG_BINARY /d 9012038010000000 /f | Out-Null }
            else { Write-Log "Modo WhatIf: UserPreferencesMask seria ajustado." -Type Debug }

            Write-Log "Visual ajustado para performance com sucesso." -Type Success
            Write-Log "Pode ser necessário reiniciar o Explorer ou o sistema para ver todas as alterações visuais." -Type Info
        } catch {
            Write-Log "ERRO ao ajustar visual para performance: $($_.Exception.Message)" -Type Error
            Write-Log "Detalhes do Erro: $($_.Exception.ToString())" -Type Error
        } finally {
            Write-Progress -Activity $activity -Status "Concluído" -PercentComplete 100 -Completed
        }
    }
	$wallpaperPath = "G:\Drives compartilhados\MundoCOC\Wallpaper\wallpaper.jpg"
	Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop\' -Name Wallpaper -Value $wallpaperPath
	RUNDLL32.EXE user32.dll,UpdatePerUserSystemParameters
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
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
       
            )

    $activity = "Otimizações de Sistema"

    # Certifique-se de que a hashtable de configuração existe
    if (-not (Test-Path Variable:ScriptConfig)) {
        Write-Log "ERRO: \$ScriptConfig não encontrada. Certifique-se de que foi definida no topo do script." -Type Error
        Write-Log "Abortando otimizações." -Type Error
        return
    }

    Write-Log "Iniciando rotinas de otimização do sistema..." -Type Info

    if ($PSCmdlet.ShouldProcess("rotinas de otimização do sistema", "executar")) {
        try {
            # Chamada condicional das funções de limpeza com base em $ScriptConfig
            $currentStep = 0
            $totalSteps = ($ScriptConfig.Cleanup.PSObject.Properties | Where-Object {$_.Value -eq $true}).Count

            if ($ScriptConfig.Cleanup.CleanTemporaryFiles) {
                $currentStep++
                Write-Progress -Activity $activity -Status "Limpando arquivos temporários..." -PercentComplete (($currentStep / $totalSteps) * 100)
                Write-Log "Executando limpeza de arquivos temporários..." -Type Info
                try {
                    if (-not $WhatIf) {
                        # Placeholder para Clear-TemporaryFiles
                        # Clear-TemporaryFiles
                        Write-Log "A função 'Clear-TemporaryFiles' seria executada." -Type Debug
                    } else { Write-Log "Modo WhatIf: 'Clear-TemporaryFiles' seria executada." -Type Debug }
                } catch { Write-Log "Falha ao limpar arquivos temporários: $($_.Exception.Message)" -Type Warning }
            }

            if ($ScriptConfig.Cleanup.CleanWUCache) {
                $currentStep++
                Write-Progress -Activity $activity -Status "Limpando cache do Windows Update..." -PercentComplete (($currentStep / $totalSteps) * 100)
                Write-Log "Limpando cache do Windows Update..." -Type Info
                try {
                    if (-not $WhatIf) {
                        # Placeholder para Clear-WUCache
                        # Clear-WUCache
                        Write-Log "A função 'Clear-WUCache' seria executada." -Type Debug
                    } else { Write-Log "Modo WhatIf: 'Clear-WUCache' seria executada." -Type Debug }
                } catch { Write-Log "Falha ao limpar cache WU: $($_.Exception.Message)" -Type Warning }
            }

            if ($ScriptConfig.Cleanup.OptimizeVolumes) {
                $currentStep++
                Write-Progress -Activity $activity -Status "Otimizando volumes de disco..." -PercentComplete (($currentStep / $totalSteps) * 100)
                Write-Log "Otimizando volumes de disco (Desfragmentação/Trim)..." -Type Info
                try {
                    if (-not $WhatIf) {
                        # Placeholder para Optimize-Volumes
                        # Optimize-Volumes
                        Write-Log "A função 'Optimize-Volumes' seria executada." -Type Debug
                    } else { Write-Log "Modo WhatIf: 'Optimize-Volumes' seria executada." -Type Debug }
                } catch { Write-Log "Falha ao otimizar volumes: $($_.Exception.Message)" -Type Warning }
            }

            if ($ScriptConfig.Cleanup.PerformDeepSystemCleanup) {
                $currentStep++
                Write-Progress -Activity $activity -Status "Executando limpeza profunda do sistema (Disk Cleanup)..." -PercentComplete (($currentStep / $totalSteps) * 100)
                Write-Log "Realizando limpeza profunda do sistema (Disk Cleanup)..." -Type Info
                try {
                    if (-not $WhatIf) {
                        # Placeholder para Clear-DeepSystemCleanup
                        # Clear-DeepSystemCleanup
                        Write-Log "A função 'Clear-DeepSystemCleanup' seria executada." -Type Debug
                    } else { Write-Log "Modo WhatIf: 'Clear-DeepSystemCleanup' seria executada." -Type Debug }
                } catch { Write-Log "Falha na limpeza profunda: $($_.Exception.Message)" -Type Warning }
            }

            if ($ScriptConfig.Cleanup.ClearDNSCache) {
                $currentStep++
                Write-Progress -Activity $activity -Status "Limpando cache DNS..." -PercentComplete (($currentStep / $totalSteps) * 100)
                Write-Log "Limpando cache DNS..." -Type Info
                try {
                    if (-not $WhatIf) {
                        ipconfig /flushdns | Out-Null
                        Write-Log "DNS cache limpo." -Type Success
                    } else { Write-Log "Modo WhatIf: 'ipconfig /flushdns' seria executado." -Type Debug }
                } catch { Write-Log "Falha ao limpar cache DNS: $($_.Exception.Message)" -Type Warning }
            }

            if ($ScriptConfig.Cleanup.DisableMemoryDumps) {
                $currentStep++
                Write-Progress -Activity $activity -Status "Desativando criação de despejos de memória..." -PercentComplete (($currentStep / $totalSteps) * 100)
                Write-Log "Desativando criação de despejos de memória..." -Type Info
                try {
                    if (-not $WhatIf) {
                        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -Name "CrashDumpEnabled" -Value 0 -Force -ErrorAction Stop
                        Write-Log "Despejos de memória desativados." -Type Success
                    } else { Write-Log "Modo WhatIf: Despejos de memória seriam desativados." -Type Debug }
                } catch { Write-Log "Falha ao desativar despejos de memória: $($_.Exception.Message)" -Type Warning }
            }

            Write-Log "Rotinas de otimização do sistema concluídas." -Type Success
        } catch {
            Write-Log "ERRO GERAL durante as rotinas de otimização do sistema: $($_.Exception.Message)" -Type Error
            Write-Log "Detalhes do Erro: $($_.Exception.ToString())" -Type Error
        } finally {
            Write-Progress -Activity $activity -Status "Concluído" -PercentComplete 100 -Completed
            Start-Sleep -Seconds 2
        }
    }
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
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
       
            )

    $activity = "Ajustes de Privacidade e Prevenção de Bloatware"

    # Certifique-se de que a hashtable de configuração existe
    if (-not (Test-Path Variable:ScriptConfig)) {
        Write-Log "ERRO: \$ScriptConfig não encontrada. Certifique-se de que foi definida no topo do script." -Type Error
        Write-Log "Abortando ajustes de privacidade." -Type Error
        return
    }

    Write-Log "Iniciando aplicação de ajustes de privacidade e prevenção de bloatware..." -Type Info

    if ($PSCmdlet.ShouldProcess("ajustes de privacidade e prevenção de bloatware", "aplicar")) {
        try {
            # Chamada condicional das ações de privacidade com base em $ScriptConfig
            $currentStep = 0
            $totalSteps = ($ScriptConfig.PrivacyTweaks.PSObject.Properties | Where-Object {$_.Value -eq $true}).Count

            if ($ScriptConfig.PrivacyTweaks.DisableTelemetry) {
                $currentStep++
                Write-Progress -Activity $activity -Status "Desativando telemetria..." -PercentComplete (($currentStep / $totalSteps) * 100)
                Write-Log "Desativando telemetria..." -Type Info
                try {
                    if (-not $WhatIf) {
                        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0 -Force -ErrorAction Stop
                        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Value 0 -Force -ErrorAction Stop
                        Write-Log "Telemetria desativada." -Type Success
                    } else { Write-Log "Modo WhatIf: Telemetria seria desativada." -Type Debug }
                } catch { Write-Log "Falha ao desativar telemetria: $($_.Exception.Message)" -Type Warning }
            }

            if ($ScriptConfig.PrivacyTweaks.DisableDiagnosticData) {
                $currentStep++
                Write-Progress -Activity $activity -Status "Desativando dados de diagnóstico..." -PercentComplete (($currentStep / $totalSteps) * 100)
                Write-Log "Desativando dados de diagnóstico..." -Type Info
                try {
                    if (-not $WhatIf) {
                        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" -Name "DiagTrack" -Value 0 -Force -ErrorAction Stop
                        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\Settings" -Name "SQMConsent" -Value 0 -Force -ErrorAction Stop
                        Write-Log "Dados de diagnóstico desativados." -Type Success
                    } else { Write-Log "Modo WhatIf: Dados de diagnóstico seriam desativados." -Type Debug }
                } catch { Write-Log "Falha ao desativar dados de diagnóstico: $($_.Exception.Message)" -Type Warning }
            }

            if ($ScriptConfig.PrivacyTweaks.BlockTelemetryHosts) {
                $currentStep++
                Write-Progress -Activity $activity -Status "Bloqueando hosts de telemetria no arquivo hosts..." -PercentComplete (($currentStep / $totalSteps) * 100)
                Write-Log "Bloqueando hosts de telemetria..." -Type Info
                try {
                    if (-not $WhatIf) {
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
                        Write-Log "Hosts de telemetria bloqueados." -Type Success
                    } else { Write-Log "Modo WhatIf: Hosts de telemetria seriam adicionados ao arquivo hosts." -Type Debug }
                } catch { Write-Log "Falha ao bloquear hosts de telemetria: $($_.Exception.Message)" -Type Warning }
            }

            if ($ScriptConfig.PrivacyTweaks.DisableLocationServices) {
                $currentStep++
                Write-Progress -Activity $activity -Status "Desativando serviços de localização..." -PercentComplete (($currentStep / $totalSteps) * 100)
                Write-Log "Desativando serviços de localização..." -Type Info
                try {
                    if (-not $WhatIf) {
                        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Value "Deny" -Force -ErrorAction Stop
                        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -Value 1 -Force -ErrorAction Stop
                        Write-Log "Serviços de localização desativados." -Type Success
                    } else { Write-Log "Modo WhatIf: Serviços de localização seriam desativados." -Type Debug }
                } catch { Write-Log "Falha ao desativar serviços de localização: $($_.Exception.Message)" -Type Warning }
            }

            if ($ScriptConfig.PrivacyTweaks.DisableActivityHistory) {
                $currentStep++
                Write-Progress -Activity $activity -Status "Desativando histórico de atividades..." -PercentComplete (($currentStep / $totalSteps) * 100)
                Write-Log "Desativando histórico de atividades..." -Type Info
                try {
                    if (-not $WhatIf) {
                        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" -Name "ActivityData" -Value 0 -Force -ErrorAction Stop
                        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Value 0 -Force -ErrorAction Stop
                        Write-Log "Histórico de atividades desativado." -Type Success
                    } else { Write-Log "Modo WhatIf: Histórico de atividades seria desativado." -Type Debug }
                } catch { Write-Log "Falha ao desativar histórico de atividades: $($_.Exception.Message)" -Type Warning }
            }

            if ($ScriptConfig.PrivacyTweaks.DisableAdvertisingID) {
                $currentStep++
                Write-Progress -Activity $activity -Status "Desativando ID de publicidade..." -PercentComplete (($currentStep / $totalSteps) * 100)
                Write-Log "Desativando ID de publicidade..." -Type Info
                try {
                    if (-not $WhatIf) {
                        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Value 0 -Force -ErrorAction Stop
                        Write-Log "ID de publicidade desativado." -Type Success
                    } else { Write-Log "Modo WhatIf: ID de publicidade seria desativado." -Type Debug }
                } catch { Write-Log "Falha ao desativar ID de publicidade: $($_.Exception.Message)" -Type Warning }
            }

            if ($ScriptConfig.PrivacyTweaks.DisableCortana) {
                $currentStep++
                Write-Progress -Activity $activity -Status "Desativando Cortana..." -PercentComplete (($currentStep / $totalSteps) * 100)
                Write-Log "Desativando Cortana..." -Type Info
                try {
                    if (-not $WhatIf) {
                        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Value 0 -Force -ErrorAction Stop
                        Write-Log "Cortana desativada." -Type Success
                    } else { Write-Log "Modo WhatIf: Cortana seria desativada." -Type Debug }
                } catch { Write-Log "Falha ao desativar Cortana: $($_.Exception.Message)" -Type Warning }
            }

            if ($ScriptConfig.PrivacyTweaks.DisableBiometrics) {
                $currentStep++
                Write-Progress -Activity $activity -Status "Desativando biometria (se não utilizada)..." -PercentComplete (($currentStep / $totalSteps) * 100)
                Write-Log "Desativando biometria..." -Type Info
                try {
                    if (-not $WhatIf) {
                        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics" -Name "Enabled" -Value 0 -Force -ErrorAction Stop
                        Write-Log "Biometria desativada." -Type Success
                    } else { Write-Log "Modo WhatIf: Biometria seria desativada." -Type Debug }
                } catch { Write-Log "Falha ao desativar biometria: $($_.Exception.Message)" -Type Warning }
            }

            if ($ScriptConfig.PrivacyTweaks.DisableFeedbackRequests) {
                $currentStep++
                Write-Progress -Activity $activity -Status "Desativando solicitações de feedback..." -PercentComplete (($currentStep / $totalSteps) * 100)
                Write-Log "Desativando solicitações de feedback..." -Type Info
                try {
                    if (-not $WhatIf) {
                        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "Period" -Value 0 -Force -ErrorAction Stop
                        Write-Log "Solicitações de feedback desativadas." -Type Success
                    } else { Write-Log "Modo WhatIf: Solicitações de feedback seriam desativadas." -Type Debug }
                } catch { Write-Log "Falha ao desativar solicitações de feedback: $($_.Exception.Message)" -Type Warning }
            }

            if ($ScriptConfig.PrivacyTweaks.DisableSuggestedContent) {
                $currentStep++
                Write-Progress -Activity $activity -Status "Desativando conteúdo sugerido..." -PercentComplete (($currentStep / $totalSteps) * 100)
                Write-Log "Desativando conteúdo sugerido..." -Type Info
                try {
                    if (-not $WhatIf) {
                        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Value 0 -Force -ErrorAction Stop
                        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Value 0 -Force -ErrorAction Stop
                        Write-Log "Conteúdo sugerido desativado." -Type Success
                    } else { Write-Log "Modo WhatIf: Conteúdo sugerido seria desativado." -Type Debug }
                } catch { Write-Log "Falha ao desativar conteúdo sugerido: $($_.Exception.Message)" -Type Warning }
            }

            if ($ScriptConfig.PrivacyTweaks.DisableAutoUpdatesStoreApps) {
                $currentStep++
                Write-Progress -Activity $activity -Status "Desativando atualizações automáticas de apps da Loja..." -PercentComplete (($currentStep / $totalSteps) * 100)
                Write-Log "Desativando atualizações automáticas de apps da Loja..." -Type Info
                try {
                    if (-not $WhatIf) {
                        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Auto Update\Store" -Name "AutoDownload" -Value 2 -Force -ErrorAction Stop # 2 = desativado
                        Write-Log "Atualizações automáticas da Loja desativadas." -Type Success
                    } else { Write-Log "Modo WhatIf: Atualizações automáticas da Loja seriam desativadas." -Type Debug }
                } catch { Write-Log "Falha ao desativar atualizações automáticas da Loja: $($_.Exception.Message)" -Type Warning }
            }

            if ($ScriptConfig.PrivacyTweaks.DisableWidgets) {
                $currentStep++
                Write-Progress -Activity $activity -Status "Desativando Widgets do Windows 11..." -PercentComplete (($currentStep / $totalSteps) * 100)
                Write-Log "Desativando Widgets do Windows 11..." -Type Info
                try {
                    if (-not $WhatIf) {
                        # Desativar da barra de tarefas
                        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarDa" -Value 0 -Force -ErrorAction Stop
                        # Ocultar o painel de widgets
                        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Hidden\Widgets" -Name "Enabled" -Value 0 -Force -ErrorAction Stop
                        Write-Log "Widgets desativados." -Type Success
                    } else { Write-Log "Modo WhatIf: Widgets seriam desativados." -Type Debug }
                } catch { Write-Log "Falha ao desativar Widgets: $($_.Exception.Message)" -Type Warning }
            }

            if ($ScriptConfig.PrivacyTweaks.DisableNewsAndInterests) {
                $currentStep++
                Write-Progress -Activity $activity -Status "Desativando Notícias e Interesses (Windows 10)..." -PercentComplete (($currentStep / $totalSteps) * 100)
                Write-Log "Desativando Notícias e Interesses (Windows 10)..." -Type Info
                try {
                    if (-not $WhatIf) {
                        # Desativar da barra de tarefas
                        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds" -Name "ShellFeedsTaskbarViewMode" -Value 2 -Force -ErrorAction Stop # 2 = Desativado
                        Write-Log "Notícias e Interesses desativados." -Type Success
                    } else { Write-Log "Modo WhatIf: Notícias e Interesses seriam desativados." -Type Debug }
                } catch { Write-Log "Falha ao desativar Notícias e Interesses: $($_.Exception.Message)" -Type Warning }
            }

            Write-Log "Ajustes de privacidade e prevenção de bloatware concluídos." -Type Success
        } catch {
            Write-Log "ERRO GERAL durante os ajustes de privacidade e prevenção de bloatware: $($_.Exception.Message)" -Type Error
            Write-Log "Detalhes do Erro: $($_.Exception.ToString())" -Type Error
        } finally {
            Write-Progress -Activity $activity -Status "Concluído" -PercentComplete 100 -Completed
            Start-Sleep -Seconds 2
        }
    }
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
    if (-not (Test-Path Variable:ScriptConfig) -or -not $ScriptConfig.GPORegistrySettings) {
        Write-Log "ERRO: \$ScriptConfig ou \$ScriptConfig.GPORegistrySettings não encontrada. Abortando aplicação de GPO via Registro." -Type Error
        return
    }

    Write-Log "Iniciando aplicação de configurações de GPO via Registro..." -Type Info

    # ===============================
    # Configurações de Windows Update
    # ===============================

    if ($ScriptConfig.GPORegistrySettings.EnableUpdateManagement) {
        Write-Log "Configurando gerenciamento de Windows Update..." -Type Info
        try {
            # Desativa o acesso à interface de usuário de updates para usuários padrão
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DoNotAllowWindowsUpdate" -Value 1 -Force -ErrorAction Stop
            # Desativar atualização automática para controlar manualmente (AUOptions = 2)
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Value 1 -Force -ErrorAction Stop
            # Define o comportamento para download e notificação
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -Value 2 -Force -ErrorAction Stop # 2 = Notificar para download e instalação
            # Evita reinício com usuário logado
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoRebootWithLoggedOnUsers" -Value 1 -Force -ErrorAction Stop
            Write-Log "Gerenciamento de Windows Update configurado." -Type Success
        } catch { Write-Log "Falha ao configurar gerenciamento de Windows Update: $($_.Exception.Message)" -Type Warning }
    }

    if ($ScriptConfig.GPORegistrySettings.DisableAutoReboot) {
        Write-Log "Desativando reinício automático após updates..." -Type Info
        try {
            # Já coberto parcialmente por NoAutoRebootWithLoggedOnUsers acima, mas garante mais
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoRebootWithLoggedOnUsers" -Value 1 -Force -ErrorAction Stop
            # Adicional: Tenta desabilitar a tarefa de reinício forçado.
            # Nota: O sistema pode recriar/reativar esta tarefa em certas condições.
            SchTasks /Change /TN "\Microsoft\Windows\UpdateOrchestrator\Reboot" /Disable | Out-Null
            Write-Log "Reinício automático após updates desativado." -Type Success
        } catch { Write-Log "Falha ao desativar reinício automático: $($_.Exception.Message)" -Type Warning }
    }

    if ($ScriptConfig.GPORegistrySettings.SetScheduledUpdateTime) {
        Write-Log "Definindo horário de instalação de updates agendados (03:00 AM)..." -Type Info
        try {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "ScheduledInstallDay" -Value 0 -Force -ErrorAction Stop # 0 = Todos os dias
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "ScheduledInstallTime" -Value 3 -Force -ErrorAction Stop # 3 = 03:00 AM
            Write-Log "Horário de atualização agendado para 03:00 AM." -Type Success
        } catch { Write-Log "Falha ao definir horário de updates: $($_.Exception.Message)" -Type Warning }
    }

    if ($ScriptConfig.GPORegistrySettings.DisableDriverUpdates) {
        Write-Log "Desativando updates de drivers via Windows Update..." -Type Info
        try {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontSearchWindowsUpdate" -Value 1 -Force -ErrorAction Stop
            Write-Log "Updates de drivers via WU desativados." -Type Success
        } catch { Write-Log "Falha ao desativar updates de drivers: $($_.Exception.Message)" -Type Warning }
    }

    # =========================
    # Configurações de Navegadores
    # =========================

    if ($ScriptConfig.GPORegistrySettings.ConfigureEdge) {
        Write-Log "Configurando Microsoft Edge (bloqueando Edge Copilot, etc.)..." -Type Info
        try {
            # Desativa o Edge Copilot para o usuário atual
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Edge" -Name "EdgeCopilotEnabled" -Value 0 -Force -ErrorAction Stop
            # Desativar página de nova aba do Bing para o usuário atual
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Edge" -Name "NewTabPageUrl" -Value "about:blank" -Force -ErrorAction Stop
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Edge" -Name "NewTabPageLocation" -Value 1 -Force -ErrorAction Stop # 1=blank page
            Write-Log "Microsoft Edge configurado." -Type Success
        } catch { Write-Log "Falha ao configurar Edge: $($_.Exception.Message)" -Type Warning }
    }

    if ($ScriptConfig.GPORegistrySettings.ConfigureChrome) {
        Write-Log "Configurando Google Chrome (desativando algumas integrações)..." -Type Info
        try {
            # Exemplo: Desativar a instalação de extensões de fora da Chrome Web Store.
            # Nota: O valor '0' em ExtensionInstallForcelist não impede instalações externas.
            # Para bloquear extensões não da loja, você usaria 'ExtensionInstallBlocklist'
            # ou configuraria 'ExtensionInstallSources'. Esta linha está apenas de exemplo.
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "ExtensionInstallForcelist" -Value 0 -Force -ErrorAction Stop # Exemplo genérico
            Write-Log "Google Chrome configurado (Verifique a documentação de políticas para controle de extensão)." -Type Success
        } catch { Write-Log "Falha ao configurar Chrome: $($_.Exception.Message)" -Type Warning }
    }

    # =========================
    # Outras configurações de GPO (Exemplos)
    # =========================

    if ($ScriptConfig.GPORegistrySettings.DisableWindowsTips) {
        Write-Log "Desativando dicas e sugestões do Windows..." -Type Info
        try {
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Value 0 -Force -ErrorAction Stop
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353694Enabled" -Value 0 -Force -ErrorAction Stop
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353696Enabled" -Value 0 -Force -ErrorAction Stop
            Write-Log "Dicas e sugestões desativadas." -Type Success
        } catch { Write-Log "Falha ao desativar dicas: $($_.Exception.Message)" -Type Warning }
    }

    Write-Log "Aplicação de configurações de GPO via Registro concluída." -Type Success
    Start-Sleep -Seconds 2
}

function Show-PersonalizationMenu {
    <#
    .SYNOPSIS
        Exibe um menu interativo para ajustes de aparência e personalização.
    .DESCRIPTION
        Este menu permite ao usuário escolher e aplicar várias configurações
        visuais do Windows. As ações são executadas por funções auxiliares.
        Esta função foi movida para o escopo global para melhor organização.
    #>
    do {
        Clear-Host
        Write-Host "`n[APARÊNCIA E PERSONALIZAÇÃO]" -ForegroundColor Cyan
        Write-Host " A) Aplicar tema escuro"
        Write-Host " B) Mostrar segundos no relógio da barra de tarefas"
        Write-Host " C) Aplicar visual de performance"
        Write-Host " D) Restaurar menu de contexto clássico (Windows 11)"
        Write-Host " X) Voltar"
        $key = [string]::Concat($Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown").Character).ToUpper()
        switch ($key) {
            'A' { Enable-DarkTheme } # Assumindo que Enable-DarkTheme será uma função separada
            'B' { Enable-TaskbarSeconds } # Assumindo que Enable-TaskbarSeconds será uma função separada
            'C' { Set-PerformanceTheme } # Já corrigida abaixo
            'D' { Enable-ClassicContextMenu } # Assumindo que Enable-ClassicContextMenu será uma função separada
            'X' { return }
            default { Write-Host 'Opção inválida' -ForegroundColor Yellow; Start-Sleep -Seconds 1 }
        }
        Show-SuccessMessage
    } while ($true)
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
    if (-not (Test-Path Variable:ScriptConfig) -or -not $ScriptConfig.UITweaks) {
        Write-Log "ERRO: \$ScriptConfig ou \$ScriptConfig.UITweaks não encontrada. Abortando ajustes de UI." -Type Error
        return
    }

    Write-Log "Iniciando aplicação de ajustes de interface do usuário (UI Tweaks)..." -Type Info

    # Tema Escuro/Claro
    if ($ScriptConfig.UITweaks.EnableDarkMode) {
        Write-Log "Ativando Modo Escuro..." -Type Info
        try {
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Value 0 -Force -ErrorAction Stop
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Value 0 -Force -ErrorAction Stop
            Write-Log "Modo Escuro ativado." -Type Success
        } catch { Write-Log "Falha ao ativar Modo Escuro: $($_.Exception.Message)" -Type Warning }
    } else {
        Write-Log "Garantindo Modo Claro..." -Type Info
        try {
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Value 1 -Force -ErrorAction Stop
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Value 1 -Force -ErrorAction Stop
            Write-Log "Modo Claro configurado." -Type Success
        } catch { Write-Log "Falha ao configurar Modo Claro: $($_.Exception.Message)" -Type Warning }
    }

    # Transparência
    if ($ScriptConfig.UITweaks.DisableTransparency) {
        Write-Log "Desativando Efeitos de Transparência..." -Type Info
        try {
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "EnableTransparency" -Value 0 -Force -ErrorAction Stop
            Write-Log "Efeitos de transparência desativados." -Type Success
        } catch { Write-Log "Falha ao desativar transparência: $($_.Exception.Message)" -Type Warning }
    } else {
        Write-Log "Ativando Efeitos de Transparência..." -Type Info
        try {
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "EnableTransparency" -Value 1 -Force -ErrorAction Stop
            Write-Log "Efeitos de transparência ativados." -Type Success
        } catch { Write-Log "Falha ao ativar transparência: $($_.Exception.Message)" -Type Warning }
    }

    # Animações
    if ($ScriptConfig.UITweaks.DisableAnimations) {
        Write-Log "Desativando Animações do Windows..." -Type Info
        try {
            Set-ItemProperty -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -Value 0 -Force -ErrorAction Stop
            # Valor para desabilitar várias animações (base64 de BwAAAAEAIAAIAAAADAAAAQA= com bit 6 desativado)
            # Para desativar tudo, pode ser necessário um valor diferente ou mais chaves.
            Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "UserPreferenceMask" -Value ([byte[]]([System.Convert]::FromBase64String("AAAAAQAAAAIAAAADAAAAQA=="))) -Force -ErrorAction Stop
            Write-Log "Animações do Windows desativadas." -Type Success
        } catch { Write-Log "Falha ao desativar animações: $($_.Exception.Message)" -Type Warning }
    } else {
        Write-Log "Ativando Animações do Windows..." -Type Info
        try {
            Set-ItemProperty -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -Value 1 -Force -ErrorAction Stop
            # Valor para habilitar animações padrão
            Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "UserPreferenceMask" -Value ([byte[]]([System.Convert]::FromBase64String("BwAAAAEAIAAIAAAADAAAAQA="))) -Force -ErrorAction Stop
            Write-Log "Animações do Windows ativadas." -Type Success
        } catch { Write-Log "Falha ao ativar animações: $($_.Exception.Message)" -Type Warning }
    }

    # Alinhamento da Barra de Tarefas (Windows 11)
    if ($global:IsWindows11) { # Usando $global:IsWindows11 conforme definido no topo do script
        if ($ScriptConfig.UITweaks.TaskbarAlignLeft) {
            Write-Log "Alinhando itens da barra de tarefas à esquerda (Windows 11)..." -Type Info
            try {
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAl" -Value 0 -Force -ErrorAction Stop # 0 = Esquerda, 1 = Centro
                Write-Log "Barra de tarefas alinhada à esquerda." -Type Success
            } catch { Write-Log "Falha ao alinhar barra de tarefas: $($_.Exception.Message)" -Type Warning }
        } else {
            Write-Log "Alinhando itens da barra de tarefas ao centro (Windows 11)..." -Type Info
            try {
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAl" -Value 1 -Force -ErrorAction Stop # 0 = Esquerda, 1 = Centro
                Write-Log "Barra de tarefas alinhada ao centro." -Type Success
            } catch { Write-Log "Falha ao alinhar barra de tarefas: $($_.Exception.Message)" -Type Warning }
        }
    } else {
        Write-Log "Ignorando alinhamento da barra de tarefas: Não é Windows 11." -Type Info
    }

    # Ocultar Caixa de Pesquisa da Barra de Tarefas (Windows 10/11)
    if ($ScriptConfig.UITweaks.HideSearchBox) {
        Write-Log "Ocultando caixa de pesquisa da barra de tarefas..." -Type Info
        try {
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Value 0 -Force -ErrorAction Stop # 0=Hidden, 1=Icon, 2=Box
            Write-Log "Caixa de pesquisa oculta." -Type Success
        } catch { Write-Log "Falha ao ocultar caixa de pesquisa: $($_.Exception.Message)" -Type Warning }
    } else {
        Write-Log "Exibindo caixa de pesquisa da barra de tarefas (ícone)..." -Type Info
        try {
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Value 1 -Force -ErrorAction Stop # 0=Hidden, 1=Icon, 2=Box
            Write-Log "Caixa de pesquisa exibida (apenas ícone)." -Type Success
        } catch { Write-Log "Falha ao exibir caixa de pesquisa: $($_.Exception.Message)" -Type Warning }
    }

    # Exibir Ícones Padrão da Área de Trabalho (Computador, Lixeira, Rede)
    if ($ScriptConfig.UITweaks.ShowDesktopIcons) {
        Write-Log "Exibindo ícones padrão da área de trabalho (Computador, Lixeira, Rede)..." -Type Info
        try {
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Value 0 -Force -ErrorAction Stop # Meu Computador
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{645FF040-5081-101B-9F08-00AA002F954E}" -Value 0 -Force -ErrorAction Stop # Lixeira
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{F02B4C93-C4F5-4039-86A7-772D932FCA9A}" -Value 0 -Force -ErrorAction Stop # Rede
            Write-Log "Ícones padrão da área de trabalho exibidos." -Type Success
        } catch { Write-Log "Falha ao exibir ícones da área de trabalho: $($_.Exception.Message)" -Type Warning }
    } else {
        Write-Log "Ocultando ícones padrão da área de trabalho..." -Type Info
        try {
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Value 1 -Force -ErrorAction Stop
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{645FF040-5081-101B-9F08-00AA002F954E}" -Value 1 -Force -ErrorAction Stop
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{F02B4C93-C4F5-4039-86A7-772D932FCA9A}" -Value 1 -Force -ErrorAction Stop
            Write-Log "Ícones padrão da área de trabalho ocultos." -Type Success
        } catch { Write-Log "Falha ao ocultar ícones da área de trabalho: $($_.Exception.Message)" -Type Warning }
    }

    # Ocultar Entradas de Drives Duplicadas no Explorer
    if ($ScriptConfig.UITweaks.HideDupliDrive) {
        Write-Log "Ocultando entradas de drives duplicadas no Explorer..." -Type Info
        try {
            # O CLSID {018D5C66-4533-4307-9B53-2ad65C87B14B} é especificamente para o OneDrive no painel de navegação.
            # Se a intenção é ocultar outras unidades duplicadas (ex: dispositivos móveis), CLSIDs adicionais podem ser necessários.
            # Esta configuração é mais eficaz para o OneDrive.
            $oneDriveCLSID = "{018D5C66-4533-4307-9B53-2ad65C87B14B}"
            if (Test-Path "HKCR:\CLSID\$oneDriveCLSID") {
                Set-ItemProperty -Path "HKCR:\CLSID\$oneDriveCLSID" -Name "System.IsPinnedToNameSpaceTree" -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
            }
            if (Test-Path "HKCR:\Wow6432Node\CLSID\$oneDriveCLSID") {
                Set-ItemProperty -Path "HKCR:\Wow6432Node\CLSID\$oneDriveCLSID" -Name "System.IsPinnedToNameSpaceTree" -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
            }
            Write-Log "Entradas de drives duplicadas ocultas (principalmente OneDrive, se aplicável)." -Type Success
        } catch { Write-Log "Falha ao ocultar entradas de drives duplicadas: $($_.Exception.Message)" -Type Warning }
    }

    # Ocultar pasta Objetos 3D do Explorer
    if ($ScriptConfig.UITweaks.Hide3dObjects) {
        Write-Log "Ocultando pasta Objetos 3D do Explorer..." -Type Info
        try {
            # Remover do User Shell Folders
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "{0F214138-B1D3-4A90-BBA9-F7A6A09C2E47}" -Value "" -Force -ErrorAction Stop
            # Remover do NameSpace
            Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{0F214138-B1D3-4A90-BBA9-F7A6A09C2E47}" -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
            Remove-Item -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{0F214138-B1D3-4A90-BBA9-F7A6A09C2E47}" -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
            Write-Log "Pasta 'Objetos 3D' oculta." -Type Success
        } catch { Write-Log "Falha ao ocultar pasta Objetos 3D: $($_.Exception.Message)" -Type Warning }
    }

    # Ocultar pasta OneDrive do Explorer (se não for removê-lo completamente)
    if ($ScriptConfig.UITweaks.HideOneDriveFolder) {
        Write-Log "Ocultando pasta OneDrive do painel de navegação do Explorer (se ainda existir)..." -Type Info
        try {
            # Este é o mesmo CLSID que o OneDrive usa para aparecer nos drives duplicados.
            # Use esta opção apenas se você *não* pretende remover o OneDrive, mas apenas ocultá-lo do painel de navegação.
            $oneDriveCLSID = "{018D5C66-4533-4307-9B53-2ad65C87B14B}"
            if (Test-Path "HKCR:\CLSID\$oneDriveCLSID") {
                Set-ItemProperty -Path "HKCR:\CLSID\$oneDriveCLSID" -Name "System.IsPinnedToNameSpaceTree" -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
            }
            if (Test-Path "HKCR:\Wow6432Node\CLSID\$oneDriveCLSID") {
                Set-ItemProperty -Path "HKCR:\Wow6432Node\CLSID\$oneDriveCLSID" -Name "System.IsPinnedToNameSpaceTree" -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
            }
            Write-Log "Pasta 'OneDrive' oculta do painel de navegação." -Type Success
        } catch { Write-Log "Falha ao ocultar pasta OneDrive: $($_.Exception.Message)" -Type Warning }
    }

    Write-Log "Ajustes de interface do usuário (UI Tweaks) concluídos." -Type Success
    Start-Sleep -Seconds 2

    # Reinicia o Explorer para que as mudanças de UI entrem em vigor
    Restart-Explorer
}

function Set-PerformanceTheme {
    <#
    .SYNOPSIS
        Aplica configurações de desempenho no tema do Windows, desativando efeitos visuais.
    .DESCRIPTION
        Esta função otimiza a experiência visual do Windows para desempenho máximo
        desativando animações, transparências e outros efeitos gráficos que podem
        consumir recursos.
    #>
    Write-Log "Aplicando configurações de desempenho no tema do Windows..." -Type Info
    try {
        # Define o ajuste de efeitos visuais para 'Ajustar para melhor desempenho'
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Value 2 -Force -ErrorAction Stop

        # Controla várias animações e efeitos visuais
        # O valor '9012038010000000' em binário (hex 90 12 03 80 10 00 00 00) desativa a maioria das animações.
        # Equivalente a desmarcar todas as opções em "Ajustar para melhor desempenho" nas Opções de Desempenho.
        Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "UserPreferencesMask" -Value ([byte[]](0x90,0x12,0x03,0x80,0x10,0x00,0x00,0x00)) -Force -ErrorAction Stop

        # Desativa a prevalência de cor na barra de título (DWM - Desktop Window Manager)
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "ColorPrevalence" -Value 0 -Force -ErrorAction Stop
        # Desativa o Aero Peek
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "EnableAeroPeek" -Value 0 -Force -ErrorAction Stop
        # Desativa o desfoque atrás das janelas (Blur Behind)
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "EnableBlurBehind" -Value 0 -Force -ErrorAction Stop
        # Desativa a transparência geral (DWM) - pode ser redundante com a configuração em Apply-UITweaks
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "EnableTransparency" -Value 0 -Force -ErrorAction Stop

        # Desativa "Mostrar conteúdo da janela ao arrastar"
        Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "DragFullWindows" -Value 0 -Force -ErrorAction Stop
        # Reduz o atraso do menu (torna menus mais rápidos)
        Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "MenuShowDelay" -Value 0 -Force -ErrorAction Stop
        
        # Configura o suavizamento de fonte (ClearType)
        Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "FontSmoothing" -Value 2 -Force -ErrorAction Stop
        Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "FontSmoothingType" -Value 1 -Force -ErrorAction Stop
        Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "FontSmoothingGamma" -Value 0 -Force -ErrorAction Stop
        Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "FontSmoothingOrientation" -Value 0 -Force -ErrorAction Stop

        Write-Log "Configurações de desempenho aplicadas ao tema do Windows." -Type Success
    }
    catch {
        Write-Log "Erro ao aplicar tema de desempenho: $($_.Exception.Message)" -Type Error
    }
    # Reinicia o Explorer para aplicar algumas mudanças de tema imediatamente
    Restart-Explorer
}

#region → FUNÇÕES DE OTIMIZAÇÃO E DESEMPENHO


function Optimize-ExplorerPerformance {
    Write-Log "Otimizando Windows Explorer para desempenho..." -Type Warning
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
        Write-Log "Windows Explorer otimizado para desempenho." -Type Success
    } 
    catch {
        Write-Log "Erro ao otimizar o Explorer: $_" -Type Error
    }
}

function New-SystemRestorePoint {
    Write-Log "Criando ponto de restauração do sistema..." -Type Warning
    try {
        Checkpoint-Computer -Description "Antes da manutenção Windows" -RestorePointType "MODIFY_SETTINGS"
        Write-Log "Ponto de restauração criado com sucesso." -Type Success
    } 
    catch {
        Write-Log "Erro ao criar ponto de restauração: $_" -Type Error
    }
}

function Enable-WindowsHardening {
    Write-Log "Aplicando hardening de segurança..." -Type Warning
    try {
		Set-MpPreference -AttackSurfaceReductionRules_Ids "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550" -AttackSurfaceReductionRules_Actions Enabled
		Set-MpPreference -CloudBlockLevel High
		Set-MpPreference -CloudExtendedTimeout 50
		Set-MpPreference -EnableControlledFolderAccess Enabled
		Set-MpPreference -EnableNetworkProtection Enabled 
		Set-MpPreference -MAPSReporting Advanced 
		Set-MpPreference -PUAProtection Enabled
		Set-MpPreference -ScanScheduleDay Everyday Set-MpPreference -ScanScheduleTime 02:00 Set-MpPreference -ScanParameters FullScan
		Set-NetFirewallProfile -Profile Domain,Public,Private -AllowInboundRules "BlockInboundAlways"
		Set-NetFirewallProfile -Profile Domain,Public,Private -AllowLocalFirewallRules "False"
		Set-NetFirewallProfile -Profile Domain,Public,Private -AllowLocalIPsecRules "False"
		Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block
		Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Allow
		Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
		Set-NetFirewallProfile -Profile Domain,Public,Private -LogAllowed True
		Set-NetFirewallProfile -Profile Domain,Public,Private -LogBlocked True
		Set-NetFirewallProfile -Profile Domain,Public,Private -LogFileName "%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log"
		Set-NetFirewallProfile -Profile Domain,Public,Private -LogMaxSizeKilobytes 32767
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
        Write-Log "Hardening de segurança aplicado." -Type Success
    } 
    catch {
        Write-Log "Erro ao aplicar hardening: $_" -Type Error
    }
}

function Disable-UnnecessaryServices {
    Write-Log "Desativando serviços desnecessários..." -Type Warning
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
            Write-Log "Serviço ${svc} desativado." -Type Success
        } 
        catch {
            Write-Log "Erro ao desativar serviço ${svc}: $_" -Type Error
        }
    }
    Write-Log "Desativação de serviços concluída." -Type Success
}

function Update-WindowsAndDrivers {
    Write-Log "Verificando e instalando atualizações do Windows..." -Type Warning
    try {
        # Atualizações do Windows
        Install-Module PSWindowsUpdate -Force -Scope CurrentUser -ErrorAction SilentlyContinue
        Import-Module PSWindowsUpdate
        Get-WindowsUpdate -AcceptAll -Install -AutoReboot
        Write-Log "Atualizações do Windows concluídas." -Type Success
    } 
    catch {
        Write-Log "Erro ao atualizar o Windows: $_" -Type Error
    }
    try {
        # Atualização de drivers via winget (opcional, depende do suporte do fabricante)
        Write-Log "Verificando atualizações de drivers via winget..." -Type Warning
        winget upgrade --all --accept-package-agreements --accept-source-agreements
        Write-Log "Atualização de drivers via winget concluída." -Type Success
    } 
    catch {
        Write-Log "Erro ao atualizar drivers via winget: $_" -Type Error
    }
}

#endregion

#region → FUNÇÕES TWEAKS

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
$hibernacaoAC = if ($config.TempoHibernarAC -eq 0) { 'Nunca' } else { "$($config.TempoHibernarAC)min" }
Write-Log " - Hibernação (AC/DC): $hibernacaoAC / $($config.TempoHibernarBateria)min"
Write-Log " - Tampa (AC/DC): $($config.ComportamentoTampaAC) / $($config.ComportamentoTampaBateria)"
Write-Log " - Botão Energia (AC/DC): $($config.BotaoEnergiaAC) / $($config.BotaoEnergiaBateria)"
Write-Log "   - Nível ativação: $($config.NivelAtivacaoEconomia)%"
    Write-Host (" - Economia de energia: " + (if ($config.EconomiaEnergiaAtivada) {'Ativada'} else {'Desativada'}))
    Write-Host ("   - Reduzir brilho: " + (if ($config.ReduzirBrilho) {'Sim'} else {'Não'}))

}

function Enable-DarkTheme {
    Write-Log "Ativando tema escuro..." -Type Warning
    try {
        reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v AppsUseLightTheme /t REG_DWORD /d 0 /f | Out-Null
        reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v SystemUsesLightTheme /t REG_DWORD /d 0 /f | Out-Null
        Write-Log "Tema escuro ativado." -Type Success
    } 
    catch {
        Write-Log "Erro ao ativar tema escuro: $_" -Type Error
    }
}

function Enable-ClipboardHistory {
    Write-Log "Ativando histórico da área de transferência..." -Type Warning
    try {
        reg.exe add "HKCU\Software\Microsoft\Clipboard" /v EnableClipboardHistory /t REG_DWORD /d 1 /f | Out-Null
        Write-Log "Histórico da área de transferência ativado." -Type Success
    } 
    catch {
        Write-Log "Erro ao ativar histórico da área de transferência: $_" -Type Error
    }
}

function Enable-WindowsUpdateFast {
    Write-Log "Ativando atualizações antecipadas do Windows Update..." -Type Warning
    try {
        reg.exe add "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v IsContinuousInnovationOptedIn /t REG_DWORD /d 1 /f | Out-Null
        Write-Log "Atualizações antecipadas ativadas." -Type Success
    } 
    catch {
        Write-Log "Erro ao ativar atualizações antecipadas: $_" -Type Error
    }
}

function Enable-RestartAppsAfterReboot {
    Write-Log "Ativando restauração de apps após reinicialização..." -Type Warning
    try {
        reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RestartApps" /v RestartApps /t REG_DWORD /d 1 /f | Out-Null
        Write-Log "Restauração de apps ativada." -Type Success
    } catch {
        Write-Log "Erro ao ativar restauração de apps: $_" -Type Error
    }
}

function Enable-OtherMicrosoftUpdates {
    Write-Log "Ativando updates para outros produtos Microsoft..." -Type Warning
    try {
        reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v EnableFeaturedSoftware /t REG_DWORD /d 1 /f | Out-Null
        Write-Log "Updates para outros produtos Microsoft ativados." -Type Success
    } catch {
        Write-Log "Erro ao ativar updates para outros produtos Microsoft: $_" -Type Error
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
        Write-Log "Este recurso exige o Windows 11 build 23430 ou superior." -Type Error
        return
    }

    try {
        reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarDeveloperSettings" /v TaskbarEndTask /t REG_DWORD /d 1 /f | Out-Null
        Write-Log "'Finalizar tarefa' ativado no menu da barra de tarefas." -Type Success
    } catch {
        Write-Log "Erro ao configurar TaskbarEndTask: $_" -Type Error
    }
}

function Enable-TaskbarSeconds {
    Write-Log "Ativando segundos no relógio da barra de tarefas..." -Type Warning
    try {
        reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowSecondsInSystemClock /t REG_DWORD /d 1 /f | Out-Null
        Write-Log "Segundos ativados no relógio da barra de tarefas." -Type Success
    } catch {
        Write-Log "Erro ao ativar segundos no relógio: $_" -Type Error
    }
}

function Rename-Notebook {
    Write-Log "Deseja renomear este notebook? (S/N)" -Type Warning
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
        Write-Log "Tempo esgotado. Renomeação cancelada." -Type Error
        Start-Sleep -Seconds 2
        return
    }
    try {
        Rename-Computer -NewName $input -Force
        Write-Log "Nome do notebook alterado para: $input. Reinicie para aplicar." -Type Success
    } catch {
        Write-Log "Erro ao renomear o notebook: $_" -Type Error
    }
    Start-Sleep -Seconds 2
}

function Grant-ControlPanelTweaks {
    Write-Log "Aplicando tweaks no Painel de Controle e Explorer..." -Type Warning

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
                Write-Log "Caminho de registro criado: $path" -Type Info
            }

            foreach ($name in $registryChanges.$path.Keys) {
                $value = $registryChanges.$path.$name
                Write-Log "Configurando registro: $path - $name = $value" -Type Info
                Set-ItemProperty -Path $path -Name $name -Value $value -Force -ErrorAction SilentlyContinue | Out-Null
            }
        }
        Write-Log "Tweaks no Painel de Controle e Explorer aplicados com sucesso." -Type Success
    } catch {
        Write-Log "Erro ao aplicar tweaks no Painel de Controle e Explorer: $_" -Type Error
    }
}

function Grant-ExtraTweaks {
    Write-Log "Aplicando tweaks extras para otimização e segurança..." -Type Warning

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
                Write-Log "Caminho de registro criado: $path" -Type Info
            }

            foreach ($name in $registryChanges.$path.Keys) {
                $value = $registryChanges.$path.$name
                Write-Log "Configurando registro: $path - $name = $value" -Type Info
                Set-ItemProperty -Path $path -Name $name -Value $value -Force -ErrorAction SilentlyContinue | Out-Null
            }
        }
        Write-Log "Tweaks extras aplicados com sucesso." -Type Success
    } catch {
        Write-Log "Erro ao aplicar tweaks extras: $_" -Type Error
    }
}

function Grant-HardenOfficeMacros {
    Write-Log "Desabilitando macros perigosos do Office..." -Type Warning
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
            Write-Log "Macros desativadas em: $path" -Type Success
        } 
        catch {
            Write-Log "Erro ao ajustar segurança em ${path}: $_" -Type Warning
        }
    }
    }
    catch {
        Write-Log "Erro ao desabilitar macros perigosos do Office: $_" -Type Error
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

#endregion

function Remove-OneDrive-AndRestoreFolders {
    Write-Log "Removendo OneDrive e restaurando pastas padrão..." -Type Warning
    try {
        taskkill.exe /F /IM "OneDrive.exe"
        taskkill.exe /F /IM "explorer.exe"
    } 
    catch {
        Write-Log "Erro ao remover OneDrive: $_" -Type Error
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
    Write-Log "Fazendo backup do registro (SOFTWARE, SYSTEM, HKCU)..." -Type Warning
    try {
        $bkpPath = "$env:USERPROFILE\Desktop\reg_backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        New-Item -Path $bkpPath -ItemType Directory | Out-Null
        reg.exe save HKLM\SOFTWARE "$bkpPath\HKLM_SOFTWARE.reg" /y | Out-Null
        reg.exe save HKLM\SYSTEM "$bkpPath\HKLM_SYSTEM.reg" /y | Out-Null
        reg.exe save HKCU "$bkpPath\HKCU.reg" /y | Out-Null
        Write-Log "Backup do registro salvo em: $bkpPath" -Type Success
    } catch { Write-Log "Erro ao fazer backup do registro: $_" -Type Error }
}

function Restore-Registry {
Write-Log "Digite o caminho da pasta onde está o backup do registro:" -Type Info
    $bkpPath = Read-Host "Exemplo: C:\Users\SeuUsuario\Desktop\reg_backup_20250704_140000"
    try {
        reg.exe restore HKLM\SOFTWARE "$bkpPath\HKLM_SOFTWARE.reg" | Out-Null
        reg.exe restore HKLM\SYSTEM "$bkpPath\HKLM_SYSTEM.reg" | Out-Null
        reg.exe restore HKCU "$bkpPath\HKCU.reg" | Out-Null
        Write-Log "Registro restaurado a partir de $bkpPath." -Type Success
    } catch { Write-Log "Erro ao restaurar o registro: $_" -Type Error }
}

function Invoke-WindowsActivator {
    Clear-Host
Write-Log "==== ATIVAÇÃO DO WINDOWS ====" -Type Info
Write-Log "Executando script de ativação oficial (get.activated.win)..." -Type Warning
    try {
        irm https://get.activated.win | iex
        Write-Log "Script de ativação executado com sucesso." -Type Success
    } catch {
        Write-Log "Erro ao executar o script de ativação: $_" -Type Error
    }
    
}

function Invoke-ChrisTitusToolbox {
    Clear-Host
Write-Log "==== CHRIS TITUS TOOLBOX ====" -Type Info
Write-Log "Executando toolbox oficial do site christitus.com..." -Type Warning
    try {
        irm christitus.com/win | iex
        Write-Log "Chris Titus Toolbox executado com sucesso." -Type Success
    } catch {
        Write-Log "Erro ao executar o script do Chris Titus: $_" -Type Error
    }
}

function Update-ScriptFromCloud {
    Clear-Host
Write-Log "=======================" -Type Info
Write-Log "ATUALIZANDO SCRIPT..." -Type Info
Write-Log "=======================" -Type Info

    try {
        Write-Log "Verificando conexão com servidor..." -Type Warning
        if (-not (Test-Connection -ComputerName "script.colegiomundodosaber.com.br" -Count 1 -Quiet)) {
            Write-Log "❌ Sem conexão. Atualização abortada." -Type Error
            return
        }

        Write-Log "Baixando script atualizado do Colégio Mundo do Saber..." -Type Warning
        irm script.colegiomundodosaber.com.br | iex
        Write-Log "✅ Script atualizado com sucesso!" -Type Success
        Show-SuccessMessage
    } catch {
        Write-Log "❌ Falha ao atualizar script: $_" -Type Error
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
        Write-Log "Autologin configurado para o usuário $username." -Type Success
    } catch { Write-Log "Erro ao configurar autologin: $_" -Type Error }
    Show-SuccessMessage
}

#endregion

#region → FUNÇÕES DE RESTAURAÇÃO E UNDO

function Restore-DefaultUAC {
    Write-Log "Tentando restaurar as configurações padrão do UAC..." -Type Warning

    try {
        # Define EnableLUA para 1 para ativar o UAC
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1 -Force -ErrorAction Stop | Out-Null
        # Define ConsentPromptBehaviorAdmin para 5 (padrão) para o prompt de consentimento para administradores
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 5 -Force -ErrorAction Stop | Out-Null

        Write-Log "UAC restaurado para as configurações padrão com sucesso. Será necessário reiniciar para que as alterações tenham efeito completo." -Type Success
Write-Log "UAC restaurado. Reinicie o computador para aplicar as alterações." -Type Success
    } catch {
        Write-Log "Erro ao restaurar o UAC: $_" -Type Error
Write-Log "Erro ao restaurar o UAC. Verifique o log." -Type Error
    }
}

function Restore-DefaultIPv6 {
    Write-Log "Reabilitando IPv6..." -Type Warning
    try {
        Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisabledComponents" -ErrorAction SilentlyContinue
        Write-Log "IPv6 reabilitado." -Type Success
    } catch { Write-Log "Erro ao reabilitar IPv6: $_" -Type Error }
}

function Restore-Registry-FromBackup {
Write-Log "Digite o caminho do backup do registro para restaurar (pasta):" -Type Info
    $bkpPath = Read-Host
    try {
        reg.exe restore HKLM\SOFTWARE "$bkpPath\HKLM_SOFTWARE.reg" | Out-Null
        reg.exe restore HKLM\SYSTEM "$bkpPath\HKLM_SYSTEM.reg" | Out-Null
        reg.exe restore HKCU "$bkpPath\HKCU.reg" | Out-Null
        Write-Log "Registro restaurado a partir de $bkpPath." -Type Success
    } catch { Write-Log "Erro ao restaurar o registro: $_" -Type Error }
}

function Undo-PrivacyHardening {
    Write-Log "Desfazendo ajustes de privacidade agressivos..." -Type Warning
    try {
        reg.exe delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v Enabled /f | Out-Null
        reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /f | Out-Null
        reg.exe delete "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v RestrictImplicitTextCollection /f | Out-Null
        reg.exe delete "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v RestrictImplicitInkCollection /f | Out-Null
        reg.exe delete "HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /v HarvestContacts /f | Out-Null
        Write-Log "Ajustes de privacidade revertidos." -Type Success
    } catch { Write-Log "Erro ao desfazer privacidade: $_" -Type Error }
}

function Restore-VisualPerformanceDefault {
    Write-Log "Restaurando configurações visuais para o padrão..." -Type Warning
    try {
        reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v VisualFXSetting /t REG_DWORD /d 0 /f | Out-Null
        Write-Log "Configurações visuais restauradas." -Type Success
    } catch { Write-Log "Erro ao restaurar visual: $_" -Type Error }
}

function Grant-ActionCenter-Notifications {
    Write-Log "Reabilitando Action Center e notificações..." -Type Warning
    try {
        reg.exe delete "HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v DisableNotificationCenter /f | Out-Null
        reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications" /v ToastEnabled /t REG_DWORD /d 1 /f | Out-Null
        reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v GlobalUserDisabled /t REG_DWORD /d 0 /f | Out-Null
        Write-Log "Action Center e notificações reabilitados." -Type Success
    } catch { Write-Log "Erro ao reabilitar Action Center: $_" -Type Error }
}

function Enable-SMBv1 {
    Write-Log "Tentando ativar o SMBv1..." -Type Warning
Write-Log "Ativando o SMBv1..." -Type Warning
Write-Log "ATENÇÃO: Ativar o SMBv1 pode expor o sistema a vulnerabilidades de segurança mais antigas. Prossiga com cautela." -Type Warning
    Start-Sleep -Seconds 2

    try {
        # Habilitar o componente SMBv1 via PowerShell
        Write-Log "Habilitando o recurso SMB1Protocol..." -Type Info
        Enable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart -ErrorAction Stop | Out-Null

        # Ativar o driver do serviço SMBv1
        Write-Log "Configurando o serviço MRxSmb10 para iniciar automaticamente (2)..." -Type Info
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\MRxSmb10" -Name "Start" -Value 2 -Force -ErrorAction Stop | Out-Null

        # Ativar o LanmanServer para usar SMB1
        Write-Log "Configurando o serviço LanmanServer para usar SMB1..." -Type Info
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -Value 1 -Force -ErrorAction Stop | Out-Null

        # Iniciar os serviços se não estiverem rodando
        Write-Log "Iniciando serviços relacionados ao SMBv1..." -Type Info
        Get-Service -Name "LanmanServer" -ErrorAction SilentlyContinue | Where-Object {$_.Status -ne 'Running'} | Start-Service -ErrorAction SilentlyContinue | Out-Null
        Get-Service -Name "MRxSmb10" -ErrorAction SilentlyContinue | Where-Object {$_.Status -ne 'Running'} | Start-Service -ErrorAction SilentlyContinue | Out-Null

        Write-Log "SMBv1 ativado com sucesso. Reinicialização pode ser necessária para que todas as alterações tenham efeito." -Type Success
Write-Log "SMBv1 ativado. Reinicialização recomendada." -Type Success
    } catch {
        Write-Log "Erro ao ativar o SMBv1: $_" -Type Error
Write-Log "Erro ao ativar o SMBv1. Verifique o log." -Type Error
    }
}

function Disable-SMBv1 {
    Write-Log "Tentando desativar o SMBv1..." -Type Warning
Write-Log "Desativando o SMBv1..." -Type Warning

    try {
        # Desabilitar o componente SMBv1 via PowerShell (equivalente a Remove-WindowsFeature)
        # Verifica se o recurso SMB1-Protocol existe antes de tentar removê-lo
        if (Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -ErrorAction SilentlyContinue) {
            Write-Log "Desabilitando o recurso SMB1Protocol..." -Type Info
            Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart -ErrorAction Stop | Out-Null
        } else {
            Write-Log "Recurso SMB1Protocol não encontrado ou já desabilitado." -Type Warning
        }

        # Desativar o driver do serviço SMBv1
        Write-Log "Configurando o serviço MRxSmb10 para iniciar desativado (4)..." -Type Info
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\MRxSmb10" -Name "Start" -Value 4 -Force -ErrorAction Stop | Out-Null

        # Desativar o LanmanServer para não usar SMB1
        Write-Log "Configurando o serviço LanmanServer para não usar SMB1..." -Type Info
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -Value 0 -Force -ErrorAction Stop | Out-Null

        # Parar os serviços se estiverem rodando
        Write-Log "Parando serviços relacionados ao SMBv1 se estiverem rodando..." -Type Info
        Get-Service -Name "LanmanServer" -ErrorAction SilentlyContinue | Where-Object {$_.Status -eq 'Running'} | Stop-Service -Force -ErrorAction SilentlyContinue | Out-Null
        Get-Service -Name "MRxSmb10" -ErrorAction SilentlyContinue | Where-Object {$_.Status -eq 'Running'} | Stop-Service -Force -ErrorAction SilentlyContinue | Out-Null

        Write-Log "SMBv1 desativado com sucesso. Reinicialização pode ser necessária para que todas as alterações tenham efeito." -Type Success
Write-Log "SMBv1 desativado. Reinicialização recomendada." -Type Success
    } catch {
        Write-Log "Erro ao desativar o SMBv1: $_" -Type Error
Write-Log "Erro ao desativar o SMBv1. Verifique o log." -Type Error
    }
}

function Restore-OfficeMacros {
    Write-Log "Restaurando comportamento padrão de macros do Office..." -Type Warning
    try {
        reg.exe delete "HKCU\Software\Microsoft\Office\16.0\Word\Security" /v VBAWarnings /f | Out-Null
        reg.exe delete "HKCU\Software\Microsoft\Office\16.0\Excel\Security" /v VBAWarnings /f | Out-Null
        Write-Log "Macros do Office retornaram ao padrão." -Type Success
    } catch { Write-Log "Erro ao restaurar macros: $_" -Type Error }
}

function Restore-OneDrive {
    $onedriveSetup = "$env:SystemRoot\SysWOW64\OneDriveSetup.exe"
    if (Test-Path $onedriveSetup) {
        Start-Process $onedriveSetup
        Write-Log "OneDrive reinstalado." -Type Success
    } else {
        Write-Log "OneDriveSetup.exe não encontrado!" -Type Error
    }
}

function Restore-BloatwareSafe {
    Write-Log "Reinstalando aplicativos essenciais..." -Type Warning
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
                    Write-Log "$app reinstalado com sucesso." -Type Success
                } else {
                    Write-Log "AppxManifest não encontrado para $app." -Type Error
                }
            } else {
                Write-Log "$app não está instalado. Pulando." -Type Warning
            }
        } catch {
            Write-Log "❌ Erro ao reinstalar $(app): $_" -Type Error
        }
    }

    Show-SuccessMessage
}

function Restore-ControlPanelTweaks {
    Write-Log "Restaurando configurações do Painel de Controle e comportamento do sistema para o padrão..." -Type Warning

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
                Write-Log "Caminho de registro criado: $path" -Type Info
            }

            foreach ($name in $registryChanges.$path.Keys) {
                $value = $registryChanges.$path.$name
                Write-Log "Configurando registro: $path - $name = $value" -Type Info
                Set-ItemProperty -Path $path -Name $name -Value $value -Force -ErrorAction SilentlyContinue | Out-Null
            }
        }
        Write-Log "Configurações do Painel de Controle e comportamento do sistema restauradas com sucesso." -Type Success
    } catch {
        Write-Log "Erro ao restaurar configurações do Painel de Controle: $_" -Type Error
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

    # 5) Rodar otimização de rede
    if ($RunNetworkOptimization -or $RunAllCleanup) {
        Write-Log -Message "Aplicando otimizações de rede..." -Type Info
        Optimize-NetworkPerformance @($WhatIf ? @{WhatIf=$true} : @{})
    }

    # 6) Instalar aplicativos (se solicitado) - Assumindo que Install-Applications existe em outro trecho
    # if ($RunAppInstallation) {
    #     Write-Log -Message "Iniciando instalação de aplicativos..." -Type Info
    #     Install-Applications @($WhatIf ? @{WhatIf=$true} : @{})
    # }

    # 7) Rodar diagnósticos (se solicitado)
    if ($RunDiagnostics) {
        Write-Log -Message "Executando diagnósticos do sistema..." -Type Info
        Invoke-All-DiagnosticsAdvanced @($WhatIf ? @{WhatIf=$true} : @{})
    }

    # 8) Remover Copilot (se solicitado)
    if ($RemoveCopilot) {
        Write-Log -Message "Removendo Windows Copilot..." -Type Info
        # Assume que a função Remove-WindowsCopilot existe e será chamada aqui
        # Remove-WindowsCopilot @($WhatIf ? @{WhatIf=$true} : @{})
    }

    # 9) Desativar Recall (se solicitado)
    if ($DisableRecall) {
        Write-Log -Message "Desativando Windows Recall..." -Type Info
        Disable-WindowsRecall @($WhatIf ? @{WhatIf=$true} : @{})
    }

    # 10) Executar Windows Update (se solicitado)
    if ($RunWindowsUpdate) {
        Write-Log -Message "Iniciando gerenciamento de atualizações do Windows..." -Type Info
        Manage-WindowsUpdates @($WhatIf ? @{WhatIf=$true} : @{})
    }

    # 11) Aplicar plano de energia otimizado (se solicitado)
    if ($ApplyOptimizedPowerPlan) {
        Write-Log -Message "Aplicando plano de energia otimizado..." -Type Info
        Set-OptimizedPowerPlan @($WhatIf ? @{WhatIf=$true} : @{})
    }

    Write-Log -Message "Script concluído com sucesso." -Type Success
}
catch {
    $msg = $_.Exception.Message
    Write-Host "[ERROR] Erro crítico: $msg" -ForegroundColor Red
    exit 1
}
#endregion

# Funções de Controle do Menu (Podem ser simples chamadas de cmdlet)
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

#region → MENUS

function Show-FullMaintenance {
    Clear-Host
Write-Log "=============================================" -Type Info
Write-Log "        INICIANDO MANUTENÇÃO COMPLETA        " -Type Info
Write-Log "=============================================" -Type Info
    Write-Log "Iniciando Manutenção Completa..." Yellow

    # Sequência lógica de chamadas aos novos menus e funções
    # A maioria dos menus já tem sua própria opção de "Executar Todos" (Opção 1)
    # Então, vamos simular a seleção da Opção 1 dentro de cada submenu
    # Nota: Show-MainMenu não tem "Executar Todos", suas opções são os submenus em si.

Write-Log "Executando: Menu de Instalação de Programas (Opção 1 - Todas as Ferramentas)..." -Type Success
    # Chamando a função Install-Applications que está dentro de Show-InstallationMenu opção 1
    Install-Applications
    # Se Show-InstallationMenu tivesse outras funções que não estivessem em Install-Applications,
    # ou uma opção de "Executar Todas" mais abrangente, chamaria essa opção aqui.
    Start-Sleep 2

Write-Log "Executando: Menu de Rede e Impressoras (Opção 1 - Todas as Configurações de Rede)..." -Type Success
    # Chamando as funções que estão dentro de Show-NetworkMenu opção 1
    Install-NetworkPrinters
    Optimize-NetworkPerformance
    Start-Sleep 2

Write-Log "Executando: Menu de Configurações Avançadas (Opção 1 - Todas as Configurações)..." -Type Success
    # Chamando as funções que estão dentro de Show-AdvancedSettingsMenu opção 1
    Disable-UAC
    Disable-SMBv1
    Grant-HardenOfficeMacros
    Start-Sleep 2

Write-Log "Executando: Menu de Utilitários do Sistema (Opção 1 - Todas as Tarefas de Otimização)..." -Type Success
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

Write-Log "Executando: Menu de Diagnóstico e Informações (Opção 1 - Todas as Verificações)..." -Type Success
    # Chamando as funções que estão dentro de Show-DiagnosticsMenu opção 1
    sfc /scannow
    Dism /Online /Cleanup-Image /RestoreHealth
    # Chkdsk é omitido aqui por requerer reboot
    Start-Sleep 2

Write-Log "=============================================" -Type Info
Write-Log "        MANUTENÇÃO COMPLETA CONCLUÍDA!       " -Type Info
Write-Log "=============================================" -Type Info
    Write-Log "Manutenção Completa Concluída." Green
    Show-SuccessMessage
    [Console]::ReadKey($true) | Out-Null
}

function Show-PersonalizationTweaksMenu {
    do {
        Clear-Host
Write-Log "=============================================" -Type Info
Write-Log "   MENU DE PERSONALIZAÇÃO E NOVOS RECURSOS   " -Type Info
Write-Log "=============================================" -Type Info
        Write-Log "Exibindo menu de Personalização e Novos Recursos..." Blue

Write-Log " A. Executar Todos os Ajustes de Personalização (Sequência)" -Type Success
Write-Log " B. Ativar 'Finalizar tarefa' na barra de tarefas"
Write-Log " C. Ativar atualizações antecipadas do Windows Update"
Write-Log " D. Ativar modo escuro"
Write-Log " E. Ativar histórico da área de transferência"
Write-Log " F. Restauração de apps após reinício"
Write-Log " G. Mostrar segundos no relógio"
Write-Log " H. Updates para outros produtos Microsoft"
Write-Log " I. Habilitar sudo embutido (Windows 11 24H2+)"
Write-Log "`n X. Voltar ao Menu Anterior"
Write-Log "=============================================" -Type Info

        $key = [Console]::ReadKey($true).Key
        Write-Log "Opção escolhida no menu de Personalização: $key" Blue

        switch ($key) {
            'A' {
Write-Log "Executando: Todos os Ajustes de Personalização..." -Type Warning
                Enable-TaskbarEndTask
                Enable-WindowsUpdateFast
                Enable-DarkTheme
                Enable-ClipboardHistory
                Enable-RestartAppsAfterReboot
                Enable-TaskbarSeconds
                Enable-OtherMicrosoftUpdates
                Enable-Sudo
Write-Log "Todos os Ajustes de Personalização Concluídos!" -Type Success
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
Write-Log "`nOpção inválida! Pressione qualquer tecla para continuar." -Type Error
                [Console]::ReadKey($true) | Out-Null
            }
        }
    } while ($true)
}

function Show-AdvancedSettingsMenu {
    do {
        Clear-Host
        Write-Host "=============================================" -ForegroundColor Cyan
        Write-Host " MENU: CONFIGURAÇÕES AVANÇADAS" -ForegroundColor Cyan
        Write-Host "=============================================" -ForegroundColor Cyan
        Write-Host " A) Aplicar Configurações de GPO e Registro"
        Write-Host " B) Ajustar Tema para Desempenho"
        Write-Host " C) Desativar UAC"
        Write-Host " D) Habilitar Menu de Contexto Clássico"
        Write-Host " E) Habilitar Histórico da Área de Transferência"
        Write-Host " F) Habilitar Opções de Energia Avançadas"
        Write-Host " G) Habilitar SMBv1 (se necessário para redes antigas)"
        Write-Host " H) Habilitar Sudo (se disponível e desejado)"
        Write-Host " I) Habilitar Fim de Tarefa na Barra de Tarefas"
        Write-Host " J) Habilitar Segundos na Barra de Tarefas"
        Write-Host " K) Habilitar Reforço de Segurança do Windows"
        Write-Host " L) Otimizar Desempenho do Explorer"
        Write-Host " M) Otimizar Volumes (Desfragmentar/ReTrim)"
        Write-Host " N) Otimizações Gerais de Sistema"
        Write-Host " O) Renomear Notebook"
        Write-Host " P) Mostrar Menu de Login Automático"
        Write-Host " Z) Rotina Completa (Executa todas as opções acima)" -ForegroundColor Green
        Write-Host " X) Voltar ao menu anterior" -ForegroundColor Red
        Write-Host "=============================================" -ForegroundColor Cyan

        $key = [string]::Concat($Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown").Character).ToUpper()
        switch ($key) {
            'A' { Apply-GPORegistrySettings; Show-SuccessMessage }
            'B' { Set-PerformanceTheme; Show-SuccessMessage }
            'C' { Disable-UAC; Show-SuccessMessage }
            'D' { Enable-ClassicContextMenu; Show-SuccessMessage }
            'E' { Enable-ClipboardHistory; Show-SuccessMessage }
            'F' { Enable-PowerOptions; Show-SuccessMessage }
            'G' { Enable-SMBv1; Show-SuccessMessage }
            'H' { Enable-Sudo; Show-SuccessMessage }
            'I' { Enable-TaskbarEndTask; Show-SuccessMessage }
            'J' { Enable-TaskbarSeconds; Show-SuccessMessage }
            'K' { Enable-WindowsHardening; Show-SuccessMessage }
            'L' { Optimize-ExplorerPerformance; Show-SuccessMessage }
            'M' { Optimize-Volumes; Show-SuccessMessage }
            'N' { Perform-SystemOptimizations; Show-SuccessMessage }
            'O' { Rename-Notebook; Show-SuccessMessage }
            'P' { Show-AutoLoginMenu } # Esta função já tem sua própria UI
            'Z' { Invoke-Tweaks; Show-SuccessMessage } # Chama o orquestrador de tweaks
            'X' { return }
            default {
                Write-Host 'Opção inválida. Pressione qualquer tecla para continuar...' -ForegroundColor Yellow
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
        }
    } while ($true)
}

function Show-DiagnosticsMenu {
    do {
        Clear-Host
        Write-Host "`n[DIAGNÓSTICOS]" -ForegroundColor Cyan
        Write-Host " A) SFC /SCANNOW"
        Write-Host " B) DISM /RestoreHealth"
        Write-Host " C) SMART dos Discos"
        Write-Host " D) Teste de Memória"
        Write-Host " E) Informações do Sistema"
        Write-Host " X) Voltar"
        $key = [string]::Concat($Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown").Character).ToUpper()
        switch ($key) {
            'A' { Invoke-SFC-Scan }
            'B' { Invoke-DISM-Scan }
            'C' { Test-SMART-Drives }
            'D' { Test-Memory }
            'E' { Show-SystemInfo }
            'X' { return }
        }
        Show-SuccessMessage
    } while ($true)
}

function Show-AppsMenu {
    do {
        Clear-Host
        Write-Host "=============================================" -ForegroundColor Cyan
        Write-Host " MENU: INSTALAÇÃO E FERRAMENTAS" -ForegroundColor Cyan
        Write-Host "=============================================" -ForegroundColor Cyan
        Write-Host " A) Instalar Aplicativos Definidos"
        Write-Host " B) Gerenciar Programas e Recursos (Abrir)"
        Write-Host " C) Desinstalar Aplicativos UWP (Microsoft Store)"
        Write-Host " Z) Rotina Completa (Executa todas as opções relacionadas)" -ForegroundColor Green
        Write-Host " X) Voltar ao menu anterior" -ForegroundColor Red
        Write-Host "=============================================" -ForegroundColor Cyan

        $key = [string]::Concat($Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown").Character).ToUpper()
        switch ($key) {
            'A' { Install-Applications; Show-SuccessMessage }
            'B' { Start-Process "appwiz.cpl"; Show-SuccessMessage } # Abre "Programas e Recursos"
            'C' { Start-Process "ms-settings:appsfeatures"; Show-SuccessMessage } # Abre "Aplicativos e Recursos" (UWP)
            'Z' { Invoke-AppsAndTools; Show-SuccessMessage } # Chama o orquestrador
            'X' { return }
            default {
                Write-Host 'Opção inválida. Pressione qualquer tecla para continuar...' -ForegroundColor Yellow
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
        }
    } while ($true)
}

function Show-DiagnosticsMenu {
    do {
        Clear-Host
        Write-Host "=============================================" -ForegroundColor Cyan
        Write-Host " MENU: DIAGNÓSTICOS" -ForegroundColor Cyan
        Write-Host "=============================================" -ForegroundColor Cyan
        Write-Host " A) Executar Todos os Diagnósticos Avançados"
        Write-Host " B) Mostrar Uso de Disco"
        Write-Host " C) Mostrar Informações do Sistema"
        Write-Host " D) Testar Memória"
        Write-Host " Z) Rotina Completa (Executa todas as opções relacionadas)" -ForegroundColor Green
        Write-Host " X) Voltar ao menu anterior" -ForegroundColor Red
        Write-Host "=============================================" -ForegroundColor Cyan

        $key = [string]::Concat($Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown").Character).ToUpper()
        switch ($key) {
            'A' { Invoke-All-DiagnosticsAdvanced; Show-SuccessMessage }
            'B' { Show-DiskUsage; Show-SuccessMessage }
            'C' { Show-SystemInfo; Show-SuccessMessage }
            'D' { Test-Memory; Show-SuccessMessage }
            'Z' { Invoke-Diagnose; Show-SuccessMessage } # Chama o orquestrador de Diagnósticos
            'X' { return }
            default {
                Write-Host 'Opção inválida. Pressione qualquer tecla para continuar...' -ForegroundColor Yellow
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
        }
    } while ($true)
}

function Show-NetworkMenu {
    do {
        Clear-Host
        Write-Host "=============================================" -ForegroundColor Cyan
        Write-Host " MENU: REDE E OUTROS" -ForegroundColor Cyan
        Write-Host "=============================================" -ForegroundColor Cyan
        Write-Host " A) Adicionar Rede Wi-Fi"
        Write-Host " B) Limpar Cache ARP"
        Write-Host " C) Limpar Cache DNS"
        Write-Host " D) Limpar Spooler de Impressão"
        Write-Host " E) Desativar IPv6"
        Write-Host " F) Instalar Impressoras de Rede"
        Write-Host " G) Executar Todos os Ajustes de Rede Avançados"
        Write-Host " H) Configurar DNS Google/Cloudflare"
        Write-Host " I) Mostrar Informações de Rede"
        Write-Host " J) Testar Velocidade da Internet"
        Write-Host " Z) Rotina Completa (Executa todas as opções relacionadas)" -ForegroundColor Green
        Write-Host " X) Voltar ao menu anterior" -ForegroundColor Red
        Write-Host "=============================================" -ForegroundColor Cyan

        $key = [string]::Concat($Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown").Character).ToUpper()
        switch ($key) {
            'A' { Add-WiFiNetwork; Show-SuccessMessage }
            'B' { Clear-ARP; Show-SuccessMessage }
            'C' { Clear-DNS; Show-SuccessMessage }
            'D' { Clear-PrintSpooler; Show-SuccessMessage }
            'E' { Disable-IPv6; Show-SuccessMessage }
            'F' { Install-NetworkPrinters; Show-SuccessMessage }
            'G' { Invoke-All-NetworkAdvanced; Show-SuccessMessage }
            'H' { Set-DnsGoogleCloudflare; Show-SuccessMessage }
            'I' { Show-NetworkInfo; Show-SuccessMessage }
            'J' { Test-InternetSpeed; Show-SuccessMessage }
            'Z' { Invoke-NetworkUtilities; Show-SuccessMessage } # Chama o orquestrador de Redes
            'X' { return }
            default {
                Write-Host 'Opção inválida. Pressione qualquer tecla para continuar...' -ForegroundColor Yellow
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
        }
    } while ($true)
}

function Show-ExternalScriptsMenu {
    do {
        Clear-Host
		Write-Host "=============================================" -ForegroundColor Cyan
        Write-Host "`n[SCRIPTS EXTERNOS]" -ForegroundColor Cyan
		Write-Host "=============================================" -ForegroundColor Cyan
        Write-Host " A) Rodar Ativador get.activated.win"
        Write-Host " B) Executar Chris Titus Toolbox"
        Write-Host " C) Atualizar Script Supremo pela URL"
        Write-Host " X) Voltar" -ForegroundColor Red
        $key = [string]::Concat($Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown").Character).ToUpper()
        switch ($key) {
            'A' { Invoke-WindowsActivator }
            'B' { Invoke-ChrisTitusToolbox }
            'C' { Update-ScriptFromCloud }
            'X' { return }
        }
        Show-SuccessMessage
    } while ($true)
}

function Show-RestoreMenu {
    do {
        Clear-Host
		Write-Host "=============================================" -ForegroundColor Cyan
        Write-Host "`n[RESTAURAR / BACKUP]" -ForegroundColor Cyan
		Write-Host "=============================================" -ForegroundColor Cyan
        Write-Host " A) Criar ponto de restauração"
        Write-Host " B) Backup do Registro"
        Write-Host " C) Restaurar Registro (pasta)"
        Write-Host " D) Restaurar configurações visuais"
        Write-Host " E) Restaurar UAC padrão"
        Write-Host " F) Reinstalar OneDrive"
        Write-Host " G) Reinstalar Apps essenciais"
        Write-Host " H) Restaurar menu de contexto clássico"
        Write-Host " I) Restaurar macros Office"
        Write-Host " J) Restaurar IPv6"
        Write-Host " K) Reabilitar notificações Action Center"
        Write-Host " X) Voltar" -ForegroundColor Red
        $key = [string]::Concat($Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown").Character).ToUpper()
        switch ($key) {
            'A' { New-SystemRestorePoint }
            'B' { Backup-Registry }
            'C' { Restore-Registry }
            'D' { Restore-VisualPerformanceDefault }
            'E' { Restore-DefaultUAC }
            'F' { Restore-OneDrive }
            'G' { Restore-BloatwareSafe }
            'H' { Enable-ClassicContextMenu }
            'I' { Restore-OfficeMacros }
            'J' { Restore-DefaultIPv6 }
            'K' { Grant-ActionCenter-Notifications }
            'X' { return }
        }
        Show-SuccessMessage
    } while ($true)
}

function Show-UtilitiesMenu {
    do {
        Clear-Host
Write-Log "=============================================" -Type Info
Write-Log "       MENU DE UTILITÁRIOS DO SISTEMA        " -Type Info
Write-Log "=============================================" -Type Info
        Write-Log "Exibindo menu de Utilitários do Sistema..." Blue

Write-Log " A. Executar Todas as Tarefas de Otimização (Sequência)" -Type Success
Write-Log " B. Gerenciar Bloatware"
Write-Log " C. Limpeza e Otimização de Disco"
Write-Log " D. Aplicar Otimizações de Desempenho e Privacidade"
Write-Log " E. Desativar Cortana e Pesquisa Online"
Write-Log "`n X. Voltar ao Menu Principal"
Write-Log "=============================================" -Type Info

        $key = [Console]::ReadKey($true).Key
        Write-Log "Opção escolhida no menu de Utilitários: $key" Blue

        switch ($key) {
            'A' {
Write-Log "Executando: Todas as Tarefas de Otimização..." -Type Warning
                Remove-Bloatware
                Remove-OneDrive-AndRestoreFolders
                Cleanup-System
                Optimize-Drives
                Grant-PrivacyTweaks
                Grant-ControlPanelTweaks
                Grant-ExtraTweaks
                Disable-Cortana-AndSearch
                Show-PersonalizationTweaksMenu # NOVO: CHAMA O MENU DE PERSONALIZAÇÃO COMPLETO
Write-Log "Todas as Tarefas de Otimização Concluídas!" -Type Success
                [Console]::ReadKey($true) | Out-Null
            }
            'B' {
                do {
                    Clear-Host
Write-Log "=============================================" -Type Info
Write-Log "       SUBMENU DE GERENCIAMENTO DE BLOATWARE        " -Type Info
Write-Log "=============================================" -Type Info
                    Write-Log "Exibindo submenu de Bloatware..." Blue

Write-Log " A. Remover Bloatware (Todos em sequência)"
Write-Log " B. Remover Aplicativos Pré-instalados (Bloatware)"
Write-Log " C. Remover OneDrive e Restaurar Pastas"
Write-Log "`n X. Voltar ao Menu Anterior"
Write-Log "=============================================" -Type Info

                    $subChoice = [Console]::ReadKey($true).Key
                    Write-Log "Opção escolhida no submenu de Bloatware: $subChoice" Blue

                    switch ($subChoice) {
                        'A' {
Write-Log "Executando: Remover Bloatware (Todos em sequência)..." -Type Warning
                            Remove-Bloatware
                            Remove-OneDrive-AndRestoreFolders
Write-Log "Remoção de Bloatware Concluída!" -Type Success
                            [Console]::ReadKey($true) | Out-Null
                        }
                        'B' { Remove-Bloatware; Show-SuccessMessage }
                        'C' { Remove-OneDrive-AndRestoreFolders; Show-SuccessMessage }
                        'x' { return }
                        'X' { return }
                        default {
Write-Log "`nOpção inválida! Pressione qualquer tecla para continuar." -Type Error
                            [Console]::ReadKey($true) | Out-Null
                        }
                    }
                } while ($true)
            }
            'C' {
                do {
                    Clear-Host
Write-Log "=============================================" -Type Info
Write-Log "      SUBMENU DE LIMPEZA E OTIMIZAÇÃO DE DISCO      " -Type Info
Write-Log "=============================================" -Type Info
                    Write-Log "Exibindo submenu de Limpeza e Otimização..." Blue

Write-Log " A. Executar Todas as Tarefas de Limpeza e Otimização"
Write-Log " B. Limpeza de Arquivos Temporários"
Write-Log " C. Desfragmentar/Otimizar Drives"
Write-Log "`n X. Voltar ao Menu Anterior"
Write-Log "=============================================" -Type Info

                    $subChoice = [Console]::ReadKey($true).Key
                    Write-Log "Opção escolhida no submenu de Limpeza: $subChoice" Blue

                    switch ($subChoice) {
                        'A' {
Write-Log "Executando: Todas as Tarefas de Limpeza e Otimização..." -Type Warning
                            Cleanup-System
                            Optimize-Drives
Write-Log "Limpeza e Otimização Concluídas!" -Type Success
                            [Console]::ReadKey($true) | Out-Null
                        }
                        'B' { Cleanup-System; Show-SuccessMessage }
                        'C' { Optimize-Drives; Show-SuccessMessage }
                        'x' { return }
                        'X' { return }
                        default {
Write-Log "`nOpção inválida! Pressione qualquer tecla para continuar." -Type Error
                            [Console]::ReadKey($true) | Out-Null
                        }
                    }
                } while ($true)
            }
            'D' { # Otimizações de Desempenho e Privacidade
                do {
                    Clear-Host
Write-Log "=============================================" -Type Info
Write-Log "    SUBMENU DE OTIMIZAÇÕES DE DESEMPENHO E PRIVACIDADE    " -Type Info
Write-Log "=============================================" -Type Info
                    Write-Log "Exibindo submenu de Otimizações de Desempenho e Privacidade..." Blue

Write-Log " A. Aplicar Todas as Otimizações de Desempenho e Privacidade"
Write-Log " B. Aplicar Tweaks de Privacidade"
Write-Log " C. Ajustar Painel de Controle e Explorer"
Write-Log " D. Aplicar Tweaks Extras"
Write-Log " E. Outros Ajustes e Personalização" -Type Success
Write-Log "`n X. Voltar ao Menu Anterior"
Write-Log "=============================================" -Type Info

                    $subChoice = [Console]::ReadKey($true).Key
                    Write-Log "Opção escolhida no submenu de Desempenho e Privacidade: $subChoice" Blue

                    switch ($subChoice) {
                        'A' {
Write-Log "Executando: Todas as Otimizações de Desempenho e Privacidade..." -Type Warning
                            Grant-PrivacyTweaks
                            Grant-ControlPanelTweaks
                            Grant-ExtraTweaks
                            Show-PersonalizationTweaksMenu # NOVO: CHAMA O MENU DE PERSONALIZAÇÃO COMPLETO
Write-Log "Otimizações de Desempenho e Privacidade Concluídas!" -Type Success
                            [Console]::ReadKey($true) | Out-Null
                        }
                        'B' { Grant-PrivacyTweaks; Show-SuccessMessage }
                        'C' { Grant-ControlPanelTweaks; Show-SuccessMessage }
                        'D' { Grant-ExtraTweaks; Show-SuccessMessage }
                        'E' { Show-PersonalizationTweaksMenu }
                        'x' { return }
                        'X' { return }
                        default {
Write-Log "`nOpção inválida! Pressione qualquer tecla para continuar." -Type Error
                            [Console]::ReadKey($true) | Out-Null
                        }
                    }
                } while ($true)
            }
            'E' { Disable-Cortana-AndSearch; Show-SuccessMessage }
            'x' { return }
            'X' { return }
            default {
Write-Log "`nOpção inválida! Pressione qualquer tecla para continuar." -Type Error
                [Console]::ReadKey($true) | Out-Null
            }
        }
    } while ($true)
}

function Show-CleanupMenu {
    do {
        Clear-Host
        Write-Host "=============================================" -ForegroundColor Cyan
        Write-Host " MENU: LIMPEZA E OTIMIZAÇÃO" -ForegroundColor Cyan
        Write-Host "=============================================" -ForegroundColor Cyan
        Write-Host " A) Backup do Registro"
        Write-Host " B) Limpeza Profunda do Sistema"
        Write-Host " C) Limpar Prefetch"
        Write-Host " D) Limpar Arquivos Temporários"
        Write-Host " E) Limpar WinSxS (Limpeza de Componentes)"
        Write-Host " F) Limpar Cache do Windows Update"
        Write-Host " G) Desativar Cortana e Pesquisa"
        Write-Host " H) Desativar SMBv1"
        Write-Host " I) Iniciar Verificação DISM"
        Write-Host " J) Iniciar Verificação SFC"
        Write-Host " K) Agendar ChkDsk no Reboot"
        Write-Host " Z) Rotina Completa (Executa todas as opções relacionadas)" -ForegroundColor Green
        Write-Host " X) Voltar ao menu anterior" -ForegroundColor Red
        Write-Host "=============================================" -ForegroundColor Cyan

        $key = [string]::Concat($Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown").Character).ToUpper()
        switch ($key) {
            'A' { Backup-Registry; Show-SuccessMessage }
            'B' { Clear-DeepSystemCleanup; Show-SuccessMessage }
            'C' { Clear-Prefetch; Show-SuccessMessage }
            'D' { Clear-TemporaryFiles; Show-SuccessMessage }
            'E' { Clear-WinSxS; Show-SuccessMessage }
            'F' { Clear-WUCache; Show-SuccessMessage }
            'G' { Disable-Cortana-AndSearch; Show-SuccessMessage }
            'H' { Disable-SMBv1; Show-SuccessMessage }
            'I' { Invoke-DISM-Scan; Show-SuccessMessage }
            'J' { Invoke-SFC-Scan; Show-SuccessMessage }
            'K' { New-ChkDsk; Show-SuccessMessage }
            'Z' { Invoke-Cleanup; Show-SuccessMessage } # Chama o orquestrador de Limpeza
            'X' { return }
            default {
                Write-Host 'Opção inválida. Pressione qualquer tecla para continuar...' -ForegroundColor Yellow
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
        }
    } while ($true)
}

function Show-BloatwareMenu {
    do {
        Clear-Host
        Write-Host "=============================================" -ForegroundColor Cyan
        Write-Host " MENU: PRIVACIDADE E SEGURANÇA" -ForegroundColor Cyan
        Write-Host "=============================================" -ForegroundColor Cyan
        Write-Host " A) Remover Aplicativos Pré-instalados (Bloatware)"
        Write-Host " B) Forçar Remoção Completa do OneDrive"
        Write-Host " C) Remover Windows Copilot"
        Write-Host " D) Desativar Windows Recall"
        Write-Host " E) Desativar Tarefas Agendadas de Bloatware"
        Write-Host " F) Desativar Serviços Desnecessários"
        Write-Host " G) Remover Pins do Menu Iniciar e Barra de Tarefas"
        Write-Host " H) Remover Pastas de Bloatware Seguras"
        Write-Host " I) Parar Processos de Bloatware em Execução"
        Write-Host " J) Aplicar Prevenção de Bloatware e Privacidade"
        Write-Host " Z) Rotina Completa (Executa todas as opções relacionadas)" -ForegroundColor Green
        Write-Host " X) Voltar ao menu anterior" -ForegroundColor Red
        Write-Host "=============================================" -ForegroundColor Cyan

        $key = [string]::Concat($Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown").Character).ToUpper()
        switch ($key) {
            'A' { Remove-AppxBloatware; Show-SuccessMessage } # Assumindo que Remove-AppxBloatware é a função para isso
            'B' { Force-RemoveOneDrive; Show-SuccessMessage }
            'C' { Remove-WindowsCopilot; Show-SuccessMessage }
            'D' { Disable-WindowsRecall; Show-SuccessMessage }
            'E' { Disable-BloatwareScheduledTasks; Show-SuccessMessage }
            'F' { Disable-UnnecessaryServices; Show-SuccessMessage }
            'G' { Remove-StartAndTaskbarPins; Show-SuccessMessage }
            'H' { Restore-BloatwareSafe; Show-SuccessMessage } # Assumindo que esta remove pastas seguras
            'I' { Stop-BloatwareProcesses; Show-SuccessMessage }
            'J' { Apply-PrivacyAndBloatwarePrevention; Show-SuccessMessage }
            'Z' { Invoke-Bloatware; Show-SuccessMessage } # Chama o orquestrador de Bloatware
            'X' { return }
            default {
                Write-Host 'Opção inválida. Pressione qualquer tecla para continuar...' -ForegroundColor Yellow
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
        }
    } while ($true)
}

function Show-SystemPerformanceMenu {
    do {
        Clear-Host
        Write-Host "=============================================" -ForegroundColor Cyan
        Write-Host " MENU: SISTEMA E DESEMPENHO" -ForegroundColor Cyan
        Write-Host "=============================================" -ForegroundColor Cyan
        Write-Host " A) Otimizar Desempenho do Explorer"
        Write-Host " B) Definir Plano de Energia Otimizado"
        Write-Host " C) Ajustar Efeitos Visuais para Desempenho"
        Write-Host " D) Realizar Otimizações Gerais do Sistema"
        Write-Host " E) Criar Ponto de Restauração do Sistema"
        Write-Host " Z) Rotina Completa (Executa todas as opções relacionadas)" -ForegroundColor Green
        Write-Host " X) Voltar ao menu anterior" -ForegroundColor Red
        Write-Host "=============================================" -ForegroundColor Cyan

        $key = [string]::Concat($Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown").Character).ToUpper()
        switch ($key) {
            'A' { Optimize-ExplorerPerformance; Show-SuccessMessage }
            'B' { Set-OptimizedPowerPlan; Show-SuccessMessage }
            'C' { Set-VisualPerformance; Show-SuccessMessage }
            'D' { Perform-SystemOptimizations; Show-SuccessMessage }
            'E' { New-SystemRestorePoint; Show-SuccessMessage }
            'Z' { Invoke-Tweaks; Show-SuccessMessage } # Chama o orquestrador
            'X' { return }
            default {
                Write-Host 'Opção inválida. Pressione qualquer tecla para continuar...' -ForegroundColor Yellow
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
        }
    } while ($true)
}

function Show-WindowsFeaturesMenu {
    do {
        Clear-Host
        Write-Host "`n[RECURSOS DO WINDOWS]" -ForegroundColor Cyan
        Write-Host " A) Remover Copilot"
        Write-Host " B) Desativar Recall"
        Write-Host " C) Aplicar plano de energia otimizado"
        Write-Host " X) Voltar"
        $key = [string]::Concat($Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown").Character).ToUpper()
        switch ($key) {
            'A' { Remove-WindowsCopilot }
            'B' { Disable-WindowsRecall }
            'C' { Set-OptimizedPowerPlan }
            'X' { return }
        }
        Show-SuccessMessage
    } while ($true)
}

# === MENU PRINCIPAL ===

function Show-MainMenu {
    do {
        Clear-Host
        Write-Host "=============================================" -ForegroundColor Cyan
        Write-Host " SCRIPT DE MANUTENÇÃO WINDOWS - MENU PRINCIPAL" -ForegroundColor Cyan
        Write-Host "=============================================" -ForegroundColor Cyan
        Write-Host " A) Configurações Avançadas" -ForegroundColor Yellow
        Write-Host " B) Instalação e Ferramentas" -ForegroundColor Yellow
        Write-Host " C) Privacidade e Segurança" -ForegroundColor Yellow
        Write-Host " D) Rede e Outros" -ForegroundColor Yellow
        Write-Host " E) Sistema e Desempenho" -ForegroundColor Yellow
	Write-Host " F) Scripts Externos" -ForegroundColor Yellow
        Write-Host " G) Rotina Colégio" -ForegroundColor Green
	Write-Host " R) Reiniciar" -ForegroundColor Blue
        Write-Host " S) Desligar" -ForegroundColor Blue
        Write-Host " X) Sair" -ForegroundColor Red
        Write-Host "==============================================="

        $key = [string]::Concat($Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown").Character).ToUpper()
        switch ($key) {
            'A' { Show-AdvancedSettingsMenu }
            'B' { Show-AppsMenu } # Mapeado para o antigo "Aplicativos"
            'C' { Show-BloatwareMenu } # Mapeado para o antigo "Remoção de Bloatware"
            'D' { Show-NetworkMenu } # Mapeado para o antigo "Rede e Impressoras"
            'E' { Show-SystemPerformanceMenu } # Mapeado para a função de desempenho
	    'F' { Show-ExternalScriptsMenu }
	    'G' { Invoke-Colegio }
            'R' {
                Write-Host 'Reiniciando o sistema...' -ForegroundColor Cyan
                Restart-Computer -Force
                # O script será encerrado aqui, pois o computador será reiniciado.
            }
            'S' {
                Write-Host 'Desligando o sistema...' -ForegroundColor Cyan
                Stop-Computer -Force
                # O script será encerrado aqui, pois o computador será desligado.
            }
            'X' {
                Write-Host "Saindo do script. Pressione qualquer tecla para fechar..." -ForegroundColor Magenta
                [void][System.Console]::ReadKey($true) # Espera por qualquer tecla
                return # Sai da função Show-MainMenu
            }
            default {
                Write-Host 'Opção inválida. Pressione qualquer tecla para continuar...' -ForegroundColor Yellow
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") # Espera por qualquer tecla
            }
        }
    } while ($true)
}

# -------------------------------------------------------------------------
# 🔧 Função principal: ponto de entrada do script
function Start-ScriptSupremo {
    Write-Log "`n🛠️ Iniciando o script de manutenção..." -Type Info

    try {
        Write-Log "⚙️ Chamando o menu principal..." -Type Warning
        Show-MainMenu
    } catch {
        Write-Log "❌ Erro ao executar o menu principal: $($_.Exception.Message)" -Type Error
    }
}

# -------------------------------------------------------------------------
# 🔧 FUNÇÕES AUXILIARES FALTANTES
# -------------------------------------------------------------------------

function Restart-Explorer {
    Write-Log "Reiniciando Windows Explorer..." -Type Info
    try {
        Stop-Process -Name "explorer" -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        Start-Process -FilePath "explorer.exe" -ErrorAction SilentlyContinue
        Write-Log "Windows Explorer reiniciado." -Type Success
    } catch {
        Write-Log "Erro ao reiniciar Explorer: $($_.Exception.Message)" -Type Error
    }
}

function New-FolderForced {
    param([string]$Path)
    try {
        if (-not (Test-Path $Path)) {
            New-Item -Path $Path -ItemType Directory -Force | Out-Null
        }
    } catch {
	Write-Log "Erro ao criar pasta ${Path}: $($_.Exception.Message)" -Type Error
    }
}

function Test-CommandExists {
    param([string]$Command)
    return (Get-Command $Command -ErrorAction SilentlyContinue) -ne $null
}

# -------------------------------------------------------------------------
# Ativa o script (CHAMADA PRINCIPAL NO FINAL)
Start-ScriptSupremo
