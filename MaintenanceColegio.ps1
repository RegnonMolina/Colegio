#region → PARÂMETROS DE EXECUÇÃO (Manter para compatibilidade se o script for chamado com parâmetros)
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

# Cores padrão para cada tipo de log (Definição essencial)
$global:defaultColors = @{ # Usado $global: para garantir acessibilidade em todo o script
    'Info'    = 'Cyan'
    'Success' = 'Green'
    'Warning' = 'Yellow'
    'Error'   = 'Red'
    'Debug'   = 'DarkGray'
    'Verbose' = 'Gray'
}

# Variável de configuração (simulada, assumindo que existiria no ambiente real)
# Se você tiver um arquivo de configuração ou um objeto $script:ScriptConfig real, use-o.
# Caso contrário, esta linha é um placeholder para evitar erros.
if (-not (Get-Variable -Name ScriptConfig -Scope Script -ErrorAction SilentlyContinue)) {
    $script:ScriptConfig = [PSCustomObject]@{
        LogFilePath = Join-Path $env:TEMP 'ScriptSupremo.log'
    }
}

# -------------------------------------------------------------------------
# Funções Auxiliares
# -------------------------------------------------------------------------

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
    
    # Valida e usa a cor da hash table global
    if ($global:defaultColors.ContainsKey($Type)) {
        $color = $global:defaultColors[$Type]
    } else {
        $color = 'White' # Cor padrão se o tipo não for encontrado, para evitar erro
        Write-Host "ATENÇÃO: Tipo de log '$Type' não encontrado em \$defaultColors. Usando branco." -ForegroundColor Yellow
    }

    Write-Host $entry -ForegroundColor $color

    $logPath = $script:ScriptConfig.LogFilePath
    if (-not $logPath) { $logPath = Join-Path $env:TEMP 'ScriptSupremo.log' }

    try {
        $entry | Out-File -FilePath $logPath -Append -Encoding UTF8
    } catch {
        Write-Host "ERRO ao gravar log: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Show-SuccessMessage {
    Write-Log "`n✅ Tarefa concluída com sucesso!" -Type Success
}

function Suspend-Script {
    Write-Log "`nPressione ENTER para continuar..." -Type Info
    do {
        $key = [System.Console]::ReadKey($true)
    } until ($key.Key -eq 'Enter')
}

# -------------------------------------------------------------------------
# Funções de Ação (Exemplos corrigidos - Lembre-se de corrigir todas as suas funções de ação!)
# -------------------------------------------------------------------------

function Install-Applications {
    Write-Log "Iniciando instalação de aplicativos..." -Type Info
    try {
        # Exemplo de lógica para instalar apps
        # Ex: winget install -e --id Microsoft.VisualStudioCode
        Write-Log "Aplicativo de exemplo instalado com sucesso." -Type Success
    }
    catch {
        Write-Log "Erro ao instalar aplicativos: $($_.Exception.Message)" -Type Error
    }
}

function Apply-PrivacyAndBloatwarePrevention {
    Write-Log "Aplicando prevenções de privacidade e bloatware..." -Type Info
    try {
        # Exemplo de lógica
        Write-Log "Prevenções aplicadas." -Type Success
    }
    catch {
        Write-Log "Erro ao aplicar prevenções: $($_.Exception.Message)" -Type Error
    }
}

function Disable-BloatwareScheduledTasks {
    Write-Log "Desabilitando tarefas agendadas de bloatware..." -Type Info
    try {
        # Exemplo de lógica
        Write-Log "Tarefas desabilitadas." -Type Success
    }
    catch {
        Write-Log "Erro ao desabilitar tarefas: $($_.Exception.Message)" -Type Error
    }
}

function Disable-UnnecessaryServices {
    Write-Log "Desabilitando serviços desnecessários..." -Type Info
    try {
        # Exemplo de lógica
        Write-Log "Serviços desabilitados." -Type Success
    }
    catch {
        Write-Log "Erro ao desabilitar serviços: $($_.Exception.Message)" -Type Error
    }
}

function Disable-WindowsRecall {
    Write-Log "Desabilitando Windows Recall..." -Type Info
    try {
        # Exemplo de lógica
        Write-Log "Windows Recall desabilitado." -Type Success
    }
    catch {
        Write-Log "Erro ao desabilitar Windows Recall: $($_.Exception.Message)" -Type Error
    }
}

function Force-RemoveOneDrive {
    Write-Log "Forçando remoção completa do OneDrive..." -Type Info
    try {
        # Exemplo de lógica
        Write-Log "OneDrive removido." -Type Success
    }
    catch {
        Write-Log "Erro ao remover OneDrive: $($_.Exception.Message)" -Type Error
    }
}

function Invoke-ExternalDebloaters {
    Write-Log "Invocando ferramentas externas de debloating..." -Type Info
    try {
        # Exemplo de lógica
        Write-Log "Ferramentas invocadas." -Type Success
    }
    catch {
        Write-Log "Erro ao invocar ferramentas: $($_.Exception.Message)" -Type Error
    }
}

function Remove-Bloatware {
    Write-Log "Removendo bloatware e aplicativos pré-instalados..." -Type Info
    try {
        # Exemplo de lógica
        Write-Log "Bloatware removido." -Type Success
    }
    catch {
        Write-Log "Erro ao remover bloatware: $($_.Exception.Message)" -Type Error
    }
}

function Remove-Copilot {
    Write-Log "Removendo Copilot..." -Type Info
    try {
        # Exemplo de lógica
        Write-Log "Copilot removido." -Type Success
    }
    catch {
        Write-Log "Erro ao remover Copilot: $($_.Exception.Message)" -Type Error
    }
}

function Remove-StartAndTaskbarPins {
    Write-Log "Removendo pins do Menu Iniciar e Barra de Tarefas..." -Type Info
    try {
        # Exemplo de lógica
        Write-Log "Pins removidos." -Type Success
    }
    catch {
        Write-Log "Erro ao remover pins: $($_.Exception.Message)" -Type Error
    }
}

function Remove-ScheduledTasksAggressive {
    Write-Log "Removendo tarefas agendadas agressivamente..." -Type Info
    try {
        # Exemplo de lógica
        Write-Log "Tarefas removidas." -Type Success
    }
    catch {
        Write-Log "Erro ao remover tarefas agendadas: $($_.Exception.Message)" -Type Error
    }
}

function Remove-WindowsOld {
    Write-Log "Removendo Windows.old..." -Type Info
    try {
        # Exemplo de lógica
        Write-Log "Windows.old removido." -Type Success
    }
    catch {
        Write-Log "Erro ao remover Windows.old: $($_.Exception.Message)" -Type Error
    }
}

function Stop-BloatwareProcesses {
    Write-Log "Parando processos de bloatware..." -Type Info
    try {
        # Exemplo de lógica
        Write-Log "Processos parados." -Type Success
    }
    catch {
        Write-Log "Erro ao parar processos: $($_.Exception.Message)" -Type Error
    }
}

function Invoke-All-DiagnosticsAdvanced {
    Write-Log "Executando todos os diagnósticos avançados..." -Type Info
    try {
        # Exemplo de lógica
        Write-Log "Diagnósticos concluídos." -Type Success
    }
    catch {
        Write-Log "Erro ao executar diagnósticos: $($_.Exception.Message)" -Type Error
    }
}

function Show-DiskUsage {
    Write-Log "Exibindo uso do disco..." -Type Info
    try {
        # Exemplo de lógica
        Write-Log "Uso do disco exibido." -Type Success
    }
    catch {
        Write-Log "Erro ao exibir uso do disco: $($_.Exception.Message)" -Type Error
    }
}

function Show-SystemInfo {
    Write-Log "Exibindo informações do sistema..." -Type Info
    try {
        # Exemplo de lógica
        Write-Log "Informações do sistema exibidas." -Type Success
    }
    catch {
        Write-Log "Erro ao exibir informações do sistema: $($_.Exception.Message)" -Type Error
    }
}

function Test-Memory {
    Write-Log "Agendando teste de memória..." -Type Info
    try {
        # Exemplo de lógica
        Write-Log "Teste de memória agendado." -Type Success
    }
    catch {
        Write-Log "Erro ao agendar teste de memória: $($_.Exception.Message)" -Type Error
    }
}

function Test-SMART-Drives {
    Write-Log "Testando integridade de drives SMART..." -Type Info
    try {
        # Exemplo de lógica
        Write-Log "Testes SMART concluídos." -Type Success
    }
    catch {
        Write-Log "Erro ao testar drives SMART: $($_.Exception.Message)" -Type Error
    }
}

function Clear-DeepSystemCleanup {
    Write-Log "Iniciando limpeza profunda do sistema..." -Type Info
    try {
        # Exemplo de lógica
        Write-Log "Limpeza profunda concluída." -Type Success
    }
    catch {
        Write-Log "Erro na limpeza profunda: $($_.Exception.Message)" -Type Error
    }
}

function Clear-Prefetch {
    Write-Log "Limpando prefetch..." -Type Info
    try {
        # Exemplo de lógica
        Write-Log "Prefetch limpo." -Type Success
    }
    catch {
        Write-Log "Erro ao limpar prefetch: $($_.Exception.Message)" -Type Error
    }
}

function Clear-PrintSpooler {
    Write-Log "Limpando spooler de impressão..." -Type Info
    try {
        # Exemplo de lógica
        Write-Log "Spooler limpo." -Type Success
    }
    catch {
        Write-Log "Erro ao limpar spooler: $($_.Exception.Message)" -Type Error
    }
}

function Clear-TemporaryFiles {
    Write-Log "Limpando arquivos temporários..." -Type Info
    try {
        # Exemplo de lógica
        Write-Log "Arquivos temporários limpos." -Type Success
    }
    catch {
        Write-Log "Erro ao limpar arquivos temporários: $($_.Exception.Message)" -Type Error
    }
}

function Clear-WinSxS {
    Write-Log "Limpando WinSxS (Component Store)..." -Type Info
    try {
        # Exemplo de lógica
        Write-Log "WinSxS limpo." -Type Success
    }
    catch {
        Write-Log "Erro ao limpar WinSxS: $($_.Exception.Message)" -Type Error
    }
}

function Clear-WUCache {
    Write-Log "Limpando cache do Windows Update..." -Type Info
    try {
        # Exemplo de lógica
        Write-Log "Cache do Windows Update limpo." -Type Success
    }
    catch {
        Write-Log "Erro ao limpar cache do WU: $($_.Exception.Message)" -Type Error
    }
}

function Invoke-DISM-Scan {
    Write-Log "Iniciando verificação DISM..." -Type Info
    try {
        # Exemplo de lógica
        Write-Log "Verificação DISM concluída." -Type Success
    }
    catch {
        Write-Log "Erro na verificação DISM: $($_.Exception.Message)" -Type Error
    }
}

function Invoke-SFC-Scan {
    Write-Log "Iniciando verificação SFC..." -Type Info
    try {
        # Exemplo de lógica
        Write-Log "Verificação SFC concluída." -Type Success
    }
    catch {
        Write-Log "Erro na verificação SFC: $($_.Exception.Message)" -Type Error
    }
}

function New-ChkDsk {
    Write-Log "Agendando verificação de disco (ChkDsk)..." -Type Info
    try {
        # Exemplo de lógica
        Write-Log "ChkDsk agendado." -Type Success
    }
    catch {
        Write-Log "Erro ao agendar ChkDsk: $($_.Exception.Message)" -Type Error
    }
}

function Perform-Cleanup {
    Write-Log "Executando limpeza geral..." -Type Info
    try {
        # Exemplo de lógica
        Write-Log "Limpeza geral concluída." -Type Success
    }
    catch {
        Write-Log "Erro na limpeza geral: $($_.Exception.Message)" -Type Error
    }
}

function Add-WiFiNetwork {
    Write-Log "Adicionando rede Wi-Fi..." -Type Info
    try {
        # Exemplo de lógica
        Write-Log "Rede Wi-Fi adicionada." -Type Success
    }
    catch {
        Write-Log "Erro ao adicionar rede Wi-Fi: $($_.Exception.Message)" -Type Error
    }
}

function Clear-DNS {
    Write-Log "Limpando cache DNS..." -Type Info
    try {
        ipconfig /flushdns | Out-Null
        Write-Log "Cache DNS limpo." -Type Success
    }
    catch { Write-Log "Erro ao limpar cache DNS: $($_.Exception.Message)" -Type Error }
}

function Disable-IPv6 {
    Write-Log "Desabilitando IPv6..." -Type Info
    try {
        # Exemplo de lógica
        Write-Log "IPv6 desabilitado." -Type Success
    }
    catch {
        Write-Log "Erro ao desabilitar IPv6: $($_.Exception.Message)" -Type Error
    }
}

function Disable-SMBv1 {
    Write-Log "Desabilitando SMBv1..." -Type Info
    try {
        # Exemplo de lógica
        Write-Log "SMBv1 desabilitado." -Type Success
    }
    catch {
        Write-Log "Erro ao desabilitar SMBv1: $($_.Exception.Message)" -Type Error
    }
}

function Install-NetworkPrinters {
    Write-Log "Instalando impressoras de rede..." -Type Info
    try {
        # Exemplo de lógica
        Write-Log "Impressoras de rede instaladas." -Type Success
    }
    catch {
        Write-Log "Erro ao instalar impressoras de rede: $($_.Exception.Message)" -Type Error
    }
}

function Invoke-All-NetworkAdvanced {
    Write-Log "Executando todas as otimizações de rede avançadas..." -Type Info
    try {
        # Exemplo de lógica
        Write-Log "Otimizações de rede concluídas." -Type Success
    }
    catch {
        Write-Log "Erro nas otimizações de rede: $($_.Exception.Message)" -Type Error
    }
}

function Optimize-NetworkPerformance {
    Write-Log "Otimizando desempenho de rede..." -Type Info
    try {
        # Exemplo de lógica
        Write-Log "Desempenho de rede otimizado." -Type Success
    }
    catch {
        Write-Log "Erro ao otimizar rede: $($_.Exception.Message)" -Type Error
    }
}

function Set-DnsGoogleCloudflare {
    Write-Log "Configurando DNS Google/Cloudflare..." -Type Info
    try {
        # Exemplo de lógica
        Write-Log "DNS configurado." -Type Success
    }
    catch {
        Write-Log "Erro ao configurar DNS: $($_.Exception.Message)" -Type Error
    }
}

function Show-NetworkInfo {
    Write-Log "Exibindo informações de rede..." -Type Info
    try {
        # Exemplo de lógica
        Write-Log "Informações de rede exibidas." -Type Success
    }
    catch {
        Write-Log "Erro ao exibir informações de rede: $($_.Exception.Message)" -Type Error
    }
}

function Test-InternetSpeed {
    Write-Log "Testando velocidade da internet..." -Type Info
    try {
        # Exemplo de lógica
        Write-Log "Teste de velocidade concluído." -Type Success
    }
    catch {
        Write-Log "Erro ao testar velocidade da internet: $($_.Exception.Message)" -Type Error
    }
}

function Invoke-ChrisTitusToolbox {
    Write-Log "Invocando Chris Titus Toolbox..." -Type Info
    try {
        # Exemplo de lógica
        Write-Log "Chris Titus Toolbox invocada." -Type Success
    }
    catch {
        Write-Log "Erro ao invocar Chris Titus Toolbox: $($_.Exception.Message)" -Type Error
    }
}

function Invoke-Colégio {
    Write-Log "Invocando Script Colégio..." -Type Info
    try {
        # Exemplo de lógica
        Write-Log "Script Colégio invocado." -Type Success
    }
    catch {
        Write-Log "Erro ao invocar Script Colégio: $($_.Exception.Message)" -Type Error
    }
}

function Invoke-WindowsActivator {
    Write-Log "Invocando Ativador do Windows..." -Type Info
    try {
        # Exemplo de lógica
        Write-Log "Ativador do Windows invocado." -Type Success
    }
    catch {
        Write-Log "Erro ao invocar Ativador do Windows: $($_.Exception.Message)" -Type Error
    }
}

# Funções de Tweaks de UI
function Apply-UITweaks {
    Write-Log "Aplicando Tweaks de Interface..." -Type Info
    try {
        # Lógica para aplicar tweaks de UI
        Write-Log "Tweaks de UI aplicados." -Type Success
    } catch {
        Write-Log "Erro ao aplicar tweaks de UI: $($_.Exception.Message)" -Type Error
    }
}
function Enable-ClassicContextMenu {
    Write-Log "Habilitando Menu de Contexto Clássico (Win11)..." -Type Info
    try {
        # Lógica para habilitar menu clássico
        Write-Log "Menu de Contexto Clássico habilitado." -Type Success
    } catch {
        Write-Log "Erro ao habilitar menu clássico: $($_.Exception.Message)" -Type Error
    }
}
function Enable-ClipboardHistory {
    Write-Log "Habilitando Histórico da Área de Transferência..." -Type Info
    try {
        # Lógica para habilitar histórico
        Write-Log "Histórico da Área de Transferência habilitado." -Type Success
    } catch {
        Write-Log "Erro ao habilitar histórico: $($_.Exception.Message)" -Type Error
    }
}
function Enable-DarkTheme {
    Write-Log "Habilitando Tema Escuro..." -Type Info
    try {
        # Lógica para habilitar tema escuro
        Write-Log "Tema Escuro habilitado." -Type Success
    } catch {
        Write-Log "Erro ao habilitar tema escuro: $($_.Exception.Message)" -Type Error
    }
}
function Enable-TaskbarEndTask {
    Write-Log "Habilitando Finalizar Tarefa na Barra de Tarefas..." -Type Info
    try {
        # Lógica para habilitar
        Write-Log "Finalizar Tarefa na Barra de Tarefas habilitado." -Type Success
    } catch {
        Write-Log "Erro ao habilitar Finalizar Tarefa: $($_.Exception.Message)" -Type Error
    }
}
function Enable-TaskbarSeconds {
    Write-Log "Habilitando Segundos na Barra de Tarefas..." -Type Info
    try {
        # Lógica para habilitar
        Write-Log "Segundos na Barra de Tarefas habilitados." -Type Success
    } catch {
        Write-Log "Erro ao habilitar segundos: $($_.Exception.Message)" -Type Error
    }
}
function Grant-ControlPanelTweaks {
    Write-Log "Aplicando Tweaks do Painel de Controle..." -Type Info
    try {
        # Lógica para tweaks painel controle
        Write-Log "Tweaks do Painel de Controle aplicados." -Type Success
    } catch {
        Write-Log "Erro ao aplicar tweaks do Painel de Controle: $($_.Exception.Message)" -Type Error
    }
}
function Optimize-ExplorerPerformance {
    Write-Log "Otimizando Desempenho do Explorer..." -Type Info
    try {
        # Lógica para otimizar explorer
        Write-Log "Desempenho do Explorer otimizado." -Type Success
    } catch {
        Write-Log "Erro ao otimizar Explorer: $($_.Exception.Message)" -Type Error
    }
}
function Set-PerformanceTheme {
    Write-Log "Definindo Tema de Desempenho..." -Type Info
    try {
        # Lógica para definir tema
        Write-Log "Tema de Desempenho definido." -Type Success
    } catch {
        Write-Log "Erro ao definir tema de desempenho: $($_.Exception.Message)" -Type Error
    }
}
function Set-VisualPerformance {
    Write-Log "Definindo Performance Visual..." -Type Info
    try {
        # Lógica para definir performance visual
        Write-Log "Performance Visual definida." -Type Success
    } catch {
        Write-Log "Erro ao definir performance visual: $($_.Exception.Message)" -Type Error
    }
}

# Funções de Tweaks de Privacidade
function Disable-ActionCenter-Notifications {
    Write-Log "Desabilitando Action Center e Notificações..." -Type Info
    try {
        # Lógica para desabilitar
        Write-Log "Action Center e Notificações desabilitados." -Type Success
    } catch {
        Write-Log "Erro ao desabilitar Action Center: $($_.Exception.Message)" -Type Error
    }
}
function Disable-Cortana-AndSearch {
    Write-Log "Desabilitando Cortana e Pesquisa na Nuvem..." -Type Info
    try {
        # Lógica para desabilitar
        Write-Log "Cortana e Pesquisa na Nuvem desabilitados." -Type Success
    } catch {
        Write-Log "Erro ao desabilitar Cortana: $($_.Exception.Message)" -Type Error
    }
}
function Enable-PrivacyHardening {
    Write-Log "Habilitando Reforço de Privacidade..." -Type Info
    try {
        # Lógica para reforço
        Write-Log "Reforço de Privacidade habilitado." -Type Success
    } catch {
        Write-Log "Erro ao habilitar reforço de privacidade: $($_.Exception.Message)" -Type Error
    }
}
function Grant-PrivacyTweaks {
    Write-Log "Aplicando Tweaks de Privacidade..." -Type Info
    try {
        # Lógica para tweaks
        Write-Log "Tweaks de Privacidade aplicados." -Type Success
    } catch {
        Write-Log "Erro ao aplicar tweaks de privacidade: $($_.Exception.Message)" -Type Error
    }
}
function Show-AutoLoginMenu {
    Write-Log "Exibindo Menu de AutoLogin..." -Type Info
    try {
        # Lógica para exibir menu
        Write-Log "Menu de AutoLogin exibido." -Type Success
    } catch {
        Write-Log "Erro ao exibir menu de AutoLogin: $($_.Exception.Message)" -Type Error
    }
}

# Funções de Tweaks de Sistema
function Apply-GPORegistrySettings {
    Write-Log "Aplicando Configurações GPO/Registro..." -Type Info
    try {
        # Lógica para GPO/Registro
        Write-Log "Configurações GPO/Registro aplicadas." -Type Success
    } catch {
        Write-Log "Erro ao aplicar GPO/Registro: $($_.Exception.Message)" -Type Error
    }
}
function Disable-UAC {
    Write-Log "Desabilitando UAC..." -Type Info
    try {
        # Lógica para desabilitar UAC
        Write-Log "UAC desabilitado." -Type Success
    } catch {
        Write-Log "Erro ao desabilitar UAC: $($_.Exception.Message)" -Type Error
    }
}
function Enable-OtherMicrosoftUpdates {
    Write-Log "Habilitando Outras Atualizações Microsoft..." -Type Info
    try {
        # Lógica para habilitar
        Write-Log "Outras Atualizações Microsoft habilitadas." -Type Success
    } catch {
        Write-Log "Erro ao habilitar Outras Atualizações: $($_.Exception.Message)" -Type Error
    }
}
function Enable-PowerOptions {
    Write-Log "Habilitando Opções de Energia Avançadas..." -Type Info
    try {
        # Lógica para habilitar
        Write-Log "Opções de Energia Avançadas habilitadas." -Type Success
    } catch {
        Write-Log "Erro ao habilitar Opções de Energia: $($_.Exception.Message)" -Type Error
    }
}
function Enable-RestartAppsAfterReboot {
    Write-Log "Habilitando Reinício de Apps Após Reboot..." -Type Info
    try {
        # Lógica para habilitar
        Write-Log "Reinício de Apps Após Reboot habilitado." -Type Success
    } catch {
        Write-Log "Erro ao habilitar Reinício de Apps: $($_.Exception.Message)" -Type Error
    }
}
function Enable-Sudo {
    Write-Log "Habilitando Sudo..." -Type Info
    try {
        # Lógica para habilitar Sudo
        Write-Log "Sudo habilitado." -Type Success
    } catch {
        Write-Log "Erro ao habilitar Sudo: $($_.Exception.Message)" -Type Error
    }
}
function Enable-WindowsHardening {
    Write-Log "Habilitando Reforço do Windows..." -Type Info
    try {
        # Lógica para reforço
        Write-Log "Reforço do Windows habilitado." -Type Success
    } catch {
        Write-Log "Erro ao habilitar Reforço do Windows: $($_.Exception.Message)" -Type Error
    }
}
function Enable-WindowsUpdateFast {
    Write-Log "Habilitando Windows Update Rápido..." -Type Info
    try {
        # Lógica para habilitar
        Write-Log "Windows Update Rápido habilitado." -Type Success
    } catch {
        Write-Log "Erro ao habilitar WU Rápido: $($_.Exception.Message)" -Type Error
    }
}
function Grant-ExtraTweaks {
    Write-Log "Aplicando Tweaks Extras..." -Type Info
    try {
        # Lógica para aplicar
        Write-Log "Tweaks Extras aplicados." -Type Success
    } catch {
        Write-Log "Erro ao aplicar Tweaks Extras: $($_.Exception.Message)" -Type Error
    }
}
function Grant-HardenOfficeMacros {
    Write-Log "Reforçando Macros do Office..." -Type Info
    try {
        # Lógica para reforçar
        Write-Log "Macros do Office reforçadas." -Type Success
    } catch {
        Write-Log "Erro ao reforçar Macros do Office: $($_.Exception.Message)" -Type Error
    }
}
function New-FolderForced {
    Write-Log "Criando Pasta Forçada..." -Type Info
    try {
        # Lógica para criar
        Write-Log "Pasta Forçada criada." -Type Success
    } catch {
        Write-Log "Erro ao criar Pasta Forçada: $($_.Exception.Message)" -Type Error
    }
}
function New-SystemRestorePoint {
    Write-Log "Criando Ponto de Restauração do Sistema..." -Type Info
    try {
        Checkpoint-Computer -Description "Ponto de Restauração do Script Supremo" | Out-Null
        Write-Log "Ponto de Restauração criado." -Type Success
    } catch {
        Write-Log "Erro ao criar Ponto de Restauração: $($_.Exception.Message)" -Type Error
    }
}
function Optimize-Volumes {
    Write-Log "Otimizando Volumes (Desfragmentação/Trim)..." -Type Info
    try {
        # Lógica para otimizar
        Write-Log "Volumes otimizados." -Type Success
    } catch {
        Write-Log "Erro ao otimizar Volumes: $($_.Exception.Message)" -Type Error
    }
}
function Perform-SystemOptimizations {
    Write-Log "Realizando Otimizações do Sistema..." -Type Info
    try {
        # Lógica para otimizações
        Write-Log "Otimizações do Sistema realizadas." -Type Success
    } catch {
        Write-Log "Erro ao realizar Otimizações do Sistema: $($_.Exception.Message)" -Type Error
    }
}
function Rename-Notebook {
    Write-Log "Renomeando Notebook..." -Type Info
    try {
        # Lógica para renomear
        Write-Log "Notebook renomeado." -Type Success
    } catch {
        Write-Log "Erro ao renomear Notebook: $($_.Exception.Message)" -Type Error
    }
}
function Set-OptimizedPowerPlan {
    Write-Log "Definindo Plano de Energia Otimizado..." -Type Info
    try {
        # Lógica para definir
        Write-Log "Plano de Energia Otimizado definido." -Type Success
    } catch {
        Write-Log "Erro ao definir Plano de Energia Otimizado: $($_.Exception.Message)" -Type Error
    }
}

# Funções de Undo
function Backup-Registry {
    Write-Log "Fazendo Backup do Registro..." -Type Info
    try {
        # Exemplo de lógica para backup do registro
        Write-Log "Backup do Registro concluído." -Type Success
    } catch {
        Write-Log "Erro ao fazer Backup do Registro: $($_.Exception.Message)" -Type Error
    }
}

# Assumindo Grant-ActionCenter-Notifications agora como uma função de "restaurar" neste contexto
function Grant-ActionCenter-Notifications {
    Write-Log "Restaurando Action Center e Notificações..." -Type Info
    try {
        # Lógica para restaurar Action Center e Notificações
        Write-Log "Action Center e Notificações restaurados." -Type Success
    } catch {
        Write-Log "Erro ao restaurar Action Center e Notificações: $($_.Exception.Message)" -Type Error
    }
}

function Restore-ControlPanelTweaks {
    Write-Log "Restaurando Tweaks do Painel de Controle..." -Type Info
    try {
        # Lógica para restaurar tweaks do painel de controle
        Write-Log "Tweaks do Painel de Controle restaurados." -Type Success
    } catch {
        Write-Log "Erro ao restaurar Tweaks do Painel de Controle: $($_.Exception.Message)" -Type Error
    }
}

function Restore-DefaultIPv6 {
    Write-Log "Restaurando IPv6 Padrão..." -Type Info
    try {
        # Lógica para restaurar IPv6
        Write-Log "IPv6 Padrão restaurado." -Type Success
    } catch {
        Write-Log "Erro ao restaurar IPv6 Padrão: $($_.Exception.Message)" -Type Error
    }
}

function Restore-DefaultUAC {
    Write-Log "Restaurando UAC Padrão..." -Type Info
    try {
        # Lógica para restaurar UAC
        Write-Log "UAC Padrão restaurado." -Type Success
    } catch {
        Write-Log "Erro ao restaurar UAC Padrão: $($_.Exception.Message)" -Type Error
    }
}

function Restore-OfficeMacros {
    Write-Log "Restaurando Macros do Office..." -Type Info
    try {
        # Lógica para restaurar macros
        Write-Log "Macros do Office restauradas." -Type Success
    } catch {
        Write-Log "Erro ao restaurar Macros do Office: $($_.Exception.Message)" -Type Error
    }
}

function Restore-OneDrive {
    Write-Log "Restaurando OneDrive..." -Type Info
    try {
        # Lógica para restaurar OneDrive
        Write-Log "OneDrive restaurado." -Type Success
    } catch {
        Write-Log "Erro ao restaurar OneDrive: $($_.Exception.Message)" -Type Error
    }
}

function Restore-Registry {
    Write-Log "Restaurando Registro..." -Type Info
    try {
        # Lógica para restaurar registro
        Write-Log "Registro restaurado." -Type Success
    } catch {
        Write-Log "Erro ao restaurar Registro: $($_.Exception.Message)" -Type Error
    }
}

function Restore-VisualPerformanceDefault {
    Write-Log "Restaurando Performance Visual Padrão..." -Type Info
    try {
        # Lógica para restaurar performance visual
        Write-Log "Performance Visual Padrão restaurada." -Type Success
    } catch {
        Write-Log "Erro ao restaurar Performance Visual Padrão: $($_.Exception.Message)" -Type Error
    }
}

function Undo-PrivacyHardening {
    Write-Log "Desfazendo Reforço de Privacidade..." -Type Info
    try {
        # Lógica para desfazer reforço
        Write-Log "Reforço de Privacidade desfeito." -Type Success
    } catch {
        Write-Log "Erro ao desfazer Reforço de Privacidade: $($_.Exception.Message)" -Type Error
    }
}

# Funções de Windows Update
function Manage-WindowsUpdates {
    Write-Log "Gerenciando Atualizações do Windows..." -Type Info
    try {
        # Exemplo de lógica
        Write-Log "Atualizações gerenciadas." -Type Success
    }
    catch {
        Write-Log "Erro ao gerenciar atualizações: $($_.Exception.Message)" -Type Error
    }
}

function Update-PowerShell {
    Write-Log "Atualizando PowerShell..." -Type Info
    try {
        # Exemplo de lógica
        Write-Log "PowerShell atualizado." -Type Success
    }
    catch {
        Write-Log "Erro ao atualizar PowerShell: $($_.Exception.Message)" -Type Error
    }
}

function Update-ScriptFromCloud {
    Write-Log "Atualizando Script da Nuvem..." -Type Info
    try {
        # Exemplo de lógica
        Write-Log "Script atualizado da nuvem." -Type Success
    }
    catch {
        Write-Log "Erro ao atualizar script da nuvem: $($_.Exception.Message)" -Type Error
    }
}

function Update-WindowsAndDrivers {
    Write-Log "Atualizando Windows e Drivers..." -Type Info
    try {
        # Exemplo de lógica
        Write-Log "Windows e Drivers atualizados." -Type Success
    }
    catch {
        Write-Log "Erro ao atualizar Windows e Drivers: $($_.Exception.Message)" -Type Error
    }
}


# -------------------------------------------------------------------------
# Funções de Exibição de Menus (As mesmas que já havíamos definido, com pequenas adaptações)
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
                Perform-Cleanup; Show-SuccessMessage
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

# --- Novos Sub-submenus para Tweaks ---

function Show-TweaksMenu {
    do {
        clear-host
        Write-Host "==================================================="
        Write-Host "             Menu: Tweaks e Otimizações"
        Write-Host "==================================================="
        Write-Host "Selecione uma categoria de Tweaks:"
        Write-Host ""
        Write-Host " B) Tweaks de UI (Interface do Usuário)"
        Write-Host " C) Tweaks de Privacidade"
        Write-Host " D) Tweaks de Sistema (Geral/Performance)"
        Write-Host ""
        Write-Host " A) Executar Todas as Tarefas de TODOS os Tweaks em Sequência"
        Write-Host " Y) Voltar ao Menu Anterior"
        Write-Host " Z) Voltar ao Menu Principal"
        Write-Host "==================================================="

        $key = [string]::Concat($Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown").Character).ToUpper()
        switch ($key) {
            'B' { Show-UITweaksMenu }
            'C' { Show-PrivacyTweaksMenu }
            'D' { Show-SystemTweaksMenu }
            'A' {
                Write-Log "Executando todas as tarefas de TODOS os Tweaks em sequência..." -Type Info
                # Chamando os blocos "A" de cada sub-submenu
                Show-UITweaksMenu 'RunAll'
                Show-PrivacyTweaksMenu 'RunAll'
                Show-SystemTweaksMenu 'RunAll'
                Suspend-Script
            }
            'Y' { break }
            'Z' { Show-MainMenu; return }
            default { Write-Log "Opção inválida. Tente novamente." -Type Warning; Suspend-Script }
        }
    } while ($true)
}

function Show-UITweaksMenu {
    param([string]$Action = "ShowMenu")
    if ($Action -eq "RunAll") {
        Write-Log "Executando todas as tarefas de Tweaks de UI em sequência..." -Type Info
        Apply-UITweaks; Show-SuccessMessage
        Enable-ClassicContextMenu; Show-SuccessMessage
        Enable-ClipboardHistory; Show-SuccessMessage
        Enable-DarkTheme; Show-SuccessMessage
        Enable-TaskbarEndTask; Show-SuccessMessage
        Enable-TaskbarSeconds; Show-SuccessMessage
        Grant-ControlPanelTweaks; Show-SuccessMessage
        Optimize-ExplorerPerformance; Show-SuccessMessage
        Set-PerformanceTheme; Show-SuccessMessage
        Set-VisualPerformance; Show-SuccessMessage
        return
    }

    do {
        clear-host
        Write-Host "==================================================="
        Write-Host "             Menu: Tweaks de UI"
        Write-Host "==================================================="
        Write-Host "Selecione uma opção:"
        Write-Host ""
        Write-Host " B) Aplicar Tweaks de Interface (Apply-UITweaks)"
        Write-Host " C) Habilitar Menu de Contexto Clássico (Win11) (Enable-ClassicContextMenu)"
        Write-Host " D) Habilitar Histórico da Área de Transferência (Enable-ClipboardHistory)"
        Write-Host " E) Habilitar Tema Escuro (Enable-DarkTheme)"
        Write-Host " F) Habilitar Finalizar Tarefa na Barra de Tarefas (Enable-TaskbarEndTask)"
        Write-Host " G) Habilitar Segundos na Barra de Tarefas (Enable-TaskbarSeconds)"
        Write-Host " H) Aplicar Tweaks do Painel de Controle (Grant-ControlPanelTweaks)"
        Write-Host " I) Otimizar Desempenho do Explorer (Optimize-ExplorerPerformance)"
        Write-Host " J) Definir Tema de Desempenho (Set-PerformanceTheme)"
        Write-Host " K) Definir Performance Visual (Set-VisualPerformance)"
        Write-Host ""
        Write-Host " A) Executar Todas as Tarefas em Sequência"
        Write-Host " Y) Voltar ao Menu Anterior"
        Write-Host " Z) Voltar ao Menu Principal"
        Write-Host "==================================================="

        $key = [string]::Concat($Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown").Character).ToUpper()
        switch ($key) {
            'B' { Apply-UITweaks; Show-SuccessMessage; Suspend-Script }
            'C' { Enable-ClassicContextMenu; Show-SuccessMessage; Suspend-Script }
            'D' { Enable-ClipboardHistory; Show-SuccessMessage; Suspend-Script }
            'E' { Enable-DarkTheme; Show-SuccessMessage; Suspend-Script }
            'F' { Enable-TaskbarEndTask; Show-SuccessMessage; Suspend-Script }
            'G' { Enable-TaskbarSeconds; Show-SuccessMessage; Suspend-Script }
            'H' { Grant-ControlPanelTweaks; Show-SuccessMessage; Suspend-Script }
            'I' { Optimize-ExplorerPerformance; Show-SuccessMessage; Suspend-Script }
            'J' { Set-PerformanceTheme; Show-SuccessMessage; Suspend-Script }
            'K' { Set-VisualPerformance; Show-SuccessMessage; Suspend-Script }
            'A' {
                Show-UITweaksMenu 'RunAll'
                Suspend-Script
            }
            'Y' { break }
            'Z' { Show-MainMenu; return }
            default { Write-Log "Opção inválida. Tente novamente." -Type Warning; Suspend-Script }
        }
    } while ($true)
}

function Show-PrivacyTweaksMenu {
    param([string]$Action = "ShowMenu")
    if ($Action -eq "RunAll") {
        Write-Log "Executando todas as tarefas de Tweaks de Privacidade em sequência..." -Type Info
        Disable-ActionCenter-Notifications; Show-SuccessMessage
        Disable-Cortana-AndSearch; Show-SuccessMessage
        Enable-PrivacyHardening; Show-SuccessMessage
        Grant-PrivacyTweaks; Show-SuccessMessage
        Show-AutoLoginMenu; Show-SuccessMessage
        return
    }

    do {
        clear-host
        Write-Host "==================================================="
        Write-Host "             Menu: Tweaks de Privacidade"
        Write-Host "==================================================="
        Write-Host "Selecione uma opção:"
        Write-Host ""
        Write-Host " B) Desabilitar Action Center e Notificações (Disable-ActionCenter-Notifications)"
        Write-Host " C) Desabilitar Cortana e Pesquisa na Nuvem (Disable-Cortana-AndSearch)"
        Write-Host " D) Habilitar Reforço de Privacidade (Enable-PrivacyHardening)"
        Write-Host " E) Aplicar Tweaks de Privacidade (Grant-PrivacyTweaks)"
        Write-Host " F) Exibir Menu de AutoLogin (Show-AutoLoginMenu)"
        Write-Host ""
        Write-Host " A) Executar Todas as Tarefas em Sequência"
        Write-Host " Y) Voltar ao Menu Anterior"
        Write-Host " Z) Voltar ao Menu Principal"
        Write-Host "==================================================="

        $key = [string]::Concat($Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown").Character).ToUpper()
        switch ($key) {
            'B' { Disable-ActionCenter-Notifications; Show-SuccessMessage; Suspend-Script }
            'C' { Disable-Cortana-AndSearch; Show-SuccessMessage; Suspend-Script }
            'D' { Enable-PrivacyHardening; Show-SuccessMessage; Suspend-Script }
            'E' { Grant-PrivacyTweaks; Show-SuccessMessage; Suspend-Script }
            'F' { Show-AutoLoginMenu; Show-SuccessMessage; Suspend-Script }
            'A' {
                Show-PrivacyTweaksMenu 'RunAll'
                Suspend-Script
            }
            'Y' { break }
            'Z' { Show-MainMenu; return }
            default { Write-Log "Opção inválida. Tente novamente." -Type Warning; Suspend-Script }
        }
    } while ($true)
}

function Show-SystemTweaksMenu {
    param([string]$Action = "ShowMenu")
    if ($Action -eq "RunAll") {
        Write-Log "Executando todas as tarefas de Tweaks de Sistema em sequência..." -Type Info
        Apply-GPORegistrySettings; Show-SuccessMessage
        Disable-UAC; Show-SuccessMessage
        Enable-OtherMicrosoftUpdates; Show-SuccessMessage
        Enable-PowerOptions; Show-SuccessMessage
        Enable-RestartAppsAfterReboot; Show-SuccessMessage
        Enable-Sudo; Show-SuccessMessage
        Enable-WindowsHardening; Show-SuccessMessage
        Enable-WindowsUpdateFast; Show-SuccessMessage
        Grant-ExtraTweaks; Show-SuccessMessage
        Grant-HardenOfficeMacros; Show-SuccessMessage
        New-FolderForced; Show-SuccessMessage
        New-SystemRestorePoint; Show-SuccessMessage
        Optimize-Volumes; Show-SuccessMessage
        Perform-SystemOptimizations; Show-SuccessMessage
        Rename-Notebook; Show-SuccessMessage
        Set-OptimizedPowerPlan; Show-SuccessMessage
        return
    }

    do {
        clear-host
        Write-Host "==================================================="
        Write-Host "             Menu: Tweaks de Sistema"
        Write-Host "==================================================="
        Write-Host "Selecione uma opção:"
        Write-Host ""
        Write-Host " B) Aplicar Configurações GPO/Registro (Apply-GPORegistrySettings)"
        Write-Host " C) Desabilitar UAC (Disable-UAC)"
        Write-Host " D) Habilitar Outras Atualizações Microsoft (Enable-OtherMicrosoftUpdates)"
        Write-Host " E) Habilitar Opções de Energia Avançadas (Enable-PowerOptions)"
        Write-Host " F) Habilitar Reinício de Apps Após Reboot (Enable-RestartAppsAfterReboot)"
        Write-Host " G) Habilitar Sudo (Enable-Sudo)"
        Write-Host " H) Habilitar Reforço do Windows (Enable-WindowsHardening)"
        Write-Host " I) Habilitar Windows Update Rápido (Enable-WindowsUpdateFast)"
        Write-Host " J) Aplicar Tweaks Extras (Grant-ExtraTweaks)"
        Write-Host " K) Reforçar Macros do Office (Grant-HardenOfficeMacros)"
        Write-Host " L) Criar Pasta Forçada (New-FolderForced)"
        Write-Host " M) Criar Ponto de Restauração do Sistema (New-SystemRestorePoint)"
        Write-Host " N) Otimizar Volumes (Desfragmentação/Trim) (Optimize-Volumes)"
        Write-Host " O) Realizar Otimizações do Sistema (Perform-SystemOptimizations)"
        Write-Host " P) Renomear Notebook (Rename-Notebook)"
        Write-Host " Q) Definir Plano de Energia Otimizado (Set-OptimizedPowerPlan)"
        Write-Host ""
        Write-Host " A) Executar Todas as Tarefas em Sequência"
        Write-Host " Y) Voltar ao Menu Anterior"
        Write-Host " Z) Voltar ao Menu Principal"
        Write-Host "==================================================="

        $key = [string]::Concat($Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown").Character).ToUpper()
        switch ($key) {
            'B' { Apply-GPORegistrySettings; Show-SuccessMessage; Suspend-Script }
            'C' { Disable-UAC; Show-SuccessMessage; Suspend-Script }
            'D' { Enable-OtherMicrosoftUpdates; Show-SuccessMessage; Suspend-Script }
            'E' { Enable-PowerOptions; Show-SuccessMessage; Suspend-Script }
            'F' { Enable-RestartAppsAfterReboot; Show-SuccessMessage; Suspend-Script }
            'G' { Enable-Sudo; Show-SuccessMessage; Suspend-Script }
            'H' { Enable-WindowsHardening; Show-SuccessMessage; Suspend-Script }
            'I' { Enable-WindowsUpdateFast; Show-SuccessMessage; Suspend-Script }
            'J' { Grant-ExtraTweaks; Show-SuccessMessage; Suspend-Script }
            'K' { Grant-HardenOfficeMacros; Show-SuccessMessage; Suspend-Script }
            'L' { New-FolderForced; Show-SuccessMessage; Suspend-Script }
            'M' { New-SystemRestorePoint; Show-SuccessMessage; Suspend-Script }
            'N' { Optimize-Volumes; Show-SuccessMessage; Suspend-Script }
            'O' { Perform-SystemOptimizations; Show-SuccessMessage; Suspend-Script }
            'P' { Rename-Notebook; Show-SuccessMessage; Suspend-Script }
            'Q' { Set-OptimizedPowerPlan; Show-SuccessMessage; Suspend-Script }
            'A' {
                Show-SystemTweaksMenu 'RunAll'
                Suspend-Script
            }
            'Y' { break }
            'Z' { Show-MainMenu; return }
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
            'C' { Grant-ActionCenter-Notifications; Show-SuccessMessage; Suspend-Script }
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
                Grant-ActionCenter-Notifications; Show-SuccessMessage
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

# -------------------------------------------------------------------------
# 🔧 Função principal: ponto de entrada do script
function Start-ScriptSupremo {
    Write-Log "`n🛠️ Iniciando o script de manutenção..." -Type Info

    try {
        Write-Log "⚙️ Chamando o menu principal..." -Type Info # Alterado de Warning para Info
        Show-MainMenu
    } catch {
        Write-Log "❌ Erro ao executar o menu principal: $($_.Exception.Message)" -Type Error
    }
}

# -------------------------------------------------------------------------
# Ativa o script quando o arquivo é executado diretamente
Start-ScriptSupremo
