# ============================================================================
# Gui.ps1: interface gráfica (WPF) do Script Supremo de Manutenção
# ============================================================================
# Orientada a dados: Get-GuiActionCatalog é a fonte única das ações (Categoria,
# Título, Função, Descrição, Destrutivo, Parâmetros). A janela renderiza o catálogo
# em ordem alfabética.
#
# Dot-sourced pelo MaintenanceColegio.ps1 via Show-Gui. As funções reais já estão
# no escopo quando este arquivo roda. Requer WPF (Windows + .NET).
#
# Recursos desta versão:
#  - Painel de status com um cartão por rotina (Apps, Bloatware, Completa, Contas, Impressoras,
#    Limpeza, Portáteis, Rede): última execução e resultado (sucesso, aviso, erro),
#    guardados em %APPDATA%\ScriptSupremo\gui-status.json. Clicar no cartão abre a ação.
#  - Janela de checkbox única (Show-GuiCheckboxPicker) para bloatware, apps portáteis,
#    apps e impressoras, com "Marcar todos" e "Desmarcar todos". No runspace de fundo
#    ela substitui Show-CheckboxPicker, então as funções do MaintenanceColegio a usam
#    sem alteração.
#  - Nenhum Read-Host dentro do GUI: no runspace de fundo, Read-Host é substituído por
#    Read-GuiHost (janela de texto; senha em janela mascarada, nunca gravada; perguntas
#    (s/n) viram Sim/Não).
#  - Simular (WhatIf) sempre visível e marcado por padrão em ações destrutivas. Antes de
#    executar uma ação destrutiva, resumo do que vai acontecer e pedido de confirmação.
#  - Log ao vivo com filtro por nível (aviso, erro, info, sucesso, todos) e exportação
#    em .txt. Cópia do log para a área de transferência.
#  - Atalhos: Ctrl+F foca a busca; Enter executa a ação selecionada (fora de campos de
#    texto); Ctrl+Enter executa de qualquer lugar; Esc fecha.
#  - Temas: Automático (segue o Windows), Claro, Escuro e Alto contraste. Cores em um
#    único lugar ($global:GuiTemas). Cor principal verde-petróleo #0f5c56.
#  - Todo manipulador de evento (Click, SelectionChanged, TextChanged, etc.) tem
#    try/catch com Show-GuiHandlerError.
#  - Parâmetros por ação com campos dinâmicos (pastas, arquivos, senha mascarada),
#    argumentos extras, presets por ação (sem senha), comando equivalente e janela que
#    lembra tamanho, posição e última ação.
# ============================================================================

Add-Type -AssemblyName PresentationFramework -ErrorAction SilentlyContinue
Add-Type -AssemblyName PresentationCore      -ErrorAction SilentlyContinue
Add-Type -AssemblyName WindowsBase           -ErrorAction SilentlyContinue
Add-Type -AssemblyName System.Windows.Forms  -ErrorAction SilentlyContinue  # FolderBrowserDialog para os campos de pasta
Add-Type -AssemblyName System.Drawing        -ErrorAction SilentlyContinue  # gera o ícone da janela sem depender de arquivo externo

# ----------------------------------------------------------------------------
# Tokens de cor: ÚNICO lugar onde as cores são definidas. A janela e os diálogos
# leem estes valores via DynamicResource, então trocar o tema não exige mexer em XAML.
# Globais (e não $script:) para o runspace de fundo enxergar os mesmos valores.
# ----------------------------------------------------------------------------
$global:GuiTemas = @{
    Escuro        = @{ Bg='#0f1419'; Panel='#161b22'; PanelDark='#0d1117'; Ink='#e6edf3'; Muted='#9aa4ad'; Border='#30363d'; Accent='#0f5c56'; AccentInk='#ffffff'; Selecao='#173f3b'; Danger='#f85149'; Sucesso='#3fb950'; Aviso='#d29922'; Func='#58a6ff' }
    Claro         = @{ Bg='#f3f6f5'; Panel='#ffffff'; PanelDark='#e9f0ee'; Ink='#1b2b29'; Muted='#5a6b68'; Border='#d3dfdc'; Accent='#0f5c56'; AccentInk='#ffffff'; Selecao='#d6ebe8'; Danger='#c62828'; Sucesso='#1a7f37'; Aviso='#9a6700'; Func='#146c94' }
    # Alto contraste: leitura em qualquer luz (acessibilidade). Destaque em amarelo para ficar visível.
    AltoContraste = @{ Bg='#000000'; Panel='#000000'; PanelDark='#000000'; Ink='#ffffff'; Muted='#e0e0e0'; Border='#ffffff'; Accent='#ffcc00'; AccentInk='#000000'; Selecao='#333300'; Danger='#ff5c5c'; Sucesso='#5cff8a'; Aviso='#ffd866'; Func='#7fd4ff' }
}

# Ordem das rotinas nos cartões de status (alfabética). Chave = rótulo do cartão; valor = Função do catálogo.
$global:GuiRotinas = [ordered]@{
    'Apps'        = 'Install-Applications'
    'Bloatware'   = 'Invoke-BloatwareReview'
    'Completa'    = 'Invoke-Colegio'
    'Contas'      = 'Invoke-ContasEscola'
    'Impressoras' = 'Install-NetworkPrinters'
    'Limpeza'     = 'Invoke-Cleanup'
    'Portáteis'   = 'Install-PortableApps'
    'Rede'        = 'Invoke-NetworkUtilities'
}

# ----------------------------------------------------------------------------
# Pasta de dados e preferências (JSON em %APPDATA%\ScriptSupremo)
# ----------------------------------------------------------------------------
function Get-GuiPastaDados {
    $dir = Join-Path $env:APPDATA 'ScriptSupremo'
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    return $dir
}

function Get-GuiPrefsPath {
    return (Join-Path (Get-GuiPastaDados) 'gui-prefs.json')
}

function Get-GuiPrefs {
    $padrao = [pscustomobject]@{
        Tema='Automatico'           # Automatico | Claro | Escuro | AltoContraste
        Fonte=13
        ConfirmarDestrutivas=$true
        AutoScrollLog=$true
        OcultarDestrutivas=$false
        CategoriasOcultas=@()       # nomes de categorias ocultas da lista de ações
        Presets=@()                 # { Func; Nome; Splat (sem senhas); Extra; Simular }
        JanelaLargura=$null
        JanelaAltura=$null
        JanelaX=$null
        JanelaY=$null
        JanelaMaximizada=$false
        UltimaCategoria=$null
        UltimaAcao=$null
    }
    try {
        $p = Get-GuiPrefsPath
        if (Test-Path -LiteralPath $p) {
            $j = Get-Content -LiteralPath $p -Raw -Encoding UTF8 | ConvertFrom-Json
            foreach ($k in 'Tema','Fonte','ConfirmarDestrutivas','AutoScrollLog','OcultarDestrutivas',
                           'CategoriasOcultas','Presets','JanelaLargura','JanelaAltura','JanelaX','JanelaY',
                           'JanelaMaximizada','UltimaCategoria','UltimaAcao') {
                if ($null -ne $j.$k) { $padrao.$k = $j.$k }
            }
        }
    } catch { }
    # Migração: o tema "Petróleo" foi unificado no tema Claro (mesma cor principal).
    if ($padrao.Tema -eq 'Petroleo' -or $padrao.Tema -eq 'Petróleo (CMS)') { $padrao.Tema = 'Claro' }
    # ConvertFrom-Json devolve o item sozinho quando o array tinha 1 elemento: normaliza.
    $padrao.CategoriasOcultas = if ($null -eq $padrao.CategoriasOcultas) { @() } else { @($padrao.CategoriasOcultas) }
    $padrao.Presets           = if ($null -eq $padrao.Presets)           { @() } else { @($padrao.Presets) }
    return $padrao
}

function Save-GuiPrefs {
    param($Prefs)
    # -Depth maior: Presets tem Splat aninhado; o padrão (2) truncaria esses níveis.
    try { $Prefs | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Get-GuiPrefsPath) -Encoding UTF8 } catch { }
}

# ----------------------------------------------------------------------------
# Status das rotinas (cartões) e resultado das execuções
# ----------------------------------------------------------------------------
function Get-GuiStatusPath {
    return (Join-Path (Get-GuiPastaDados) 'gui-status.json')
}

function Get-GuiStatus {
    $mapa = @{}
    try {
        $p = Get-GuiStatusPath
        if (Test-Path -LiteralPath $p) {
            $j = Get-Content -LiteralPath $p -Raw -Encoding UTF8 | ConvertFrom-Json
            foreach ($prop in $j.PSObject.Properties) { $mapa[$prop.Name] = $prop.Value }
        }
    } catch { }
    return $mapa
}

function Set-GuiRotinaStatus {
    param([string]$Rotina, [string]$Resultado, [string]$Acao)
    try {
        $mapa = Get-GuiStatus
        $mapa[$Rotina] = [pscustomobject]@{ Quando = (Get-Date).ToString('yyyy-MM-dd HH:mm'); Resultado = $Resultado; Acao = $Acao }
        $saida = [ordered]@{}
        foreach ($k in ($mapa.Keys | Sort-Object)) { $saida[$k] = $mapa[$k] }
        [pscustomobject]$saida | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Get-GuiStatusPath) -Encoding UTF8
    } catch { }
}

function Get-GuiRotinaPorFunc {
    param([string]$Func)
    foreach ($k in $global:GuiRotinas.Keys) {
        if ($global:GuiRotinas[$k] -eq $Func) { return $k }
    }
    return $null
}

# Níveis: 'erro', 'aviso', 'sucesso' ou 'info'. Lê a tag [Type] que o Write-Log grava.
function ConvertTo-GuiNivelLog {
    param([string]$Linha)
    if ($Linha -match '\[(Critical|Error)\]') { return 'erro' }
    if ($Linha -match '\[Warning\]')          { return 'aviso' }
    if ($Linha -match '\[Success\]')          { return 'sucesso' }
    return 'info'
}

# Resultado de uma execução a partir dos níveis do log gerado durante ela.
function Get-GuiResultadoExec {
    param([object[]]$Niveis, [bool]$FalhaTecnica, [int]$CodigoSaida = 0)
    # Código de saída diferente de 0 (3010 = sucesso com reinício pendente) também conta como falha.
    if ($CodigoSaida -ne 0 -and $CodigoSaida -ne 3010) { return 'erro' }
    if ($FalhaTecnica -or ($Niveis -contains 'erro')) { return 'erro' }
    if ($Niveis -contains 'aviso') { return 'aviso' }
    return 'sucesso'
}

# ----------------------------------------------------------------------------
# Ícone da janela (gerado uma vez e cacheado em %APPDATA%\ScriptSupremo)
# ----------------------------------------------------------------------------
function Get-GuiAppIconPath {
    param($AccentHex = '#0f5c56')
    try {
        $caminho = Join-Path (Get-GuiPastaDados) 'app-icon.png'
        if (Test-Path -LiteralPath $caminho) { return $caminho }

        $tam = 256
        $bmp = New-Object System.Drawing.Bitmap($tam, $tam)
        $g = [System.Drawing.Graphics]::FromImage($bmp)
        try {
            $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
            $g.Clear([System.Drawing.Color]::Transparent)
            $cor = [System.Drawing.ColorTranslator]::FromHtml($AccentHex)
            $brush = New-Object System.Drawing.SolidBrush($cor)
            $raio = 48
            $path = New-Object System.Drawing.Drawing2D.GraphicsPath
            $d = $raio * 2
            $path.AddArc(0, 0, $d, $d, 180, 90)
            $path.AddArc($tam - $d, 0, $d, $d, 270, 90)
            $path.AddArc($tam - $d, $tam - $d, $d, $d, 0, 90)
            $path.AddArc(0, $tam - $d, $d, $d, 90, 90)
            $path.CloseFigure()
            $g.FillPath($brush, $path)

            $fonte = New-Object System.Drawing.Font('Segoe UI', 92, [System.Drawing.FontStyle]::Bold)
            $fmt = New-Object System.Drawing.StringFormat
            $fmt.Alignment = [System.Drawing.StringAlignment]::Center
            $fmt.LineAlignment = [System.Drawing.StringAlignment]::Center
            $rect = New-Object System.Drawing.RectangleF(0, 0, $tam, $tam)
            $g.DrawString('SS', $fonte, [System.Drawing.Brushes]::White, $rect, $fmt)
        } finally { $g.Dispose() }

        $bmp.Save($caminho, [System.Drawing.Imaging.ImageFormat]::Png)
        $bmp.Dispose()
        return $caminho
    } catch { return $null }
}

# ----------------------------------------------------------------------------
# Catálogo de ações (fonte de verdade). Todas as Funcoes existem no MaintenanceColegio.ps1.
# Destr = $true marca ações destrutivas. Params (opcional) = parâmetros da ação.
#   Param: @{ Nome; Rotulo; Tipo='text'|'paths'|'files'|'switch'|'choice'|'password'; Default; Opcoes; Exemplo; Pasta=$true; Arquivo=$true }
# ----------------------------------------------------------------------------
function Get-GuiActionCatalog {
    # Um checkbox por app para "Instalar aplicativos" (mesma fonte de Install-Applications:
    # Get-ScriptSupremoAppsList). Os marcados viram um único -Apps na montagem do splat.
    $paramsInstalarApps = @()
    try {
        foreach ($appDisp in (Get-ScriptSupremoAppsList)) {
            # Checkbox começa vazio: só instala o que o usuário marcar (Install-Applications sem -Apps instalaria TUDO).
            $paramsInstalarApps += @{ Nome = "App_$($appDisp.Id)"; Rotulo = "$($appDisp.Name)  ($($appDisp.Id))"; Tipo = 'switch'; Default = $false; AppObj = $appDisp }
        }
    } catch { $paramsInstalarApps = @() }

    @(
        # --- Limpeza ---
        [pscustomobject]@{ Cat='Limpeza'; Titulo='Agendar CHKDSK no reinício';          Func='New-ChkDsk';                  Desc='Executa "chkdsk C: /f /r /x". Como o disco do sistema está em uso, o Windows agenda a verificação para a próxima reinicialização e repara erros e setores defeituosos.'; Destr=$false }
        [pscustomobject]@{ Cat='Limpeza'; Titulo='Varredura de limpeza (escolher o que remover)'; Func='Invoke-CleanupReview'; Desc='Lista as pastas de cache e temporários (TEMP do usuário, Windows\Temp, Prefetch, cache do Windows Update e relatórios de erro) com o tamanho de cada uma. Marque o que deseja limpar e confirme: só as pastas marcadas são esvaziadas. Nada é removido antes da confirmação.'; Destr=$true }
        [pscustomobject]@{ Cat='Limpeza'; Titulo='Limpar arquivos e pastas vazias';     Func='Clear-EmptyFilesAndFolders';  Desc='Remove arquivos de 0 byte e pastas vazias (protege .gitkeep e desktop.ini). Suporta simulação.'; Destr=$true; Params=@(
                                            @{ Nome='Path';             Rotulo='Pastas-raiz (vazio = %TEMP% padrão)'; Tipo='paths';  Default=''; Exemplo='Ex.: D:\Outra Pasta;E:\Downloads (separe várias pastas por ;)'; Pasta=$true }
                                            @{ Nome='IncludeEmptyFiles'; Rotulo='Também remover arquivos de 0 byte';    Tipo='switch'; Default=$true }
                                          ) }
        [pscustomobject]@{ Cat='Limpeza'; Titulo='Limpar arquivos temporários';         Func='Clear-TemporaryFiles';        Desc='Apaga tudo dentro de %TEMP% (pasta temporária do usuário) e C:\Windows\Temp.'; Destr=$true }
        [pscustomobject]@{ Cat='Limpeza'; Titulo='Limpar cache do Windows Update';      Func='Clear-WUCache';               Desc='Para o serviço Windows Update (wuauserv), apaga os arquivos baixados em C:\Windows\SoftwareDistribution\Download e reinicia o serviço. Resolve atualizações travadas ou corrompidas.'; Destr=$true }
        [pscustomobject]@{ Cat='Limpeza'; Titulo='Limpar Prefetch';                     Func='Clear-Prefetch';              Desc='Apaga os arquivos em C:\Windows\Prefetch (cache de programas usados com frequência; o Windows recria aos poucos).'; Destr=$true }
        [pscustomobject]@{ Cat='Limpeza'; Titulo='Limpar WinSxS (componentes)';         Func='Clear-WinSxS';                Desc='Executa "DISM /Online /Cleanup-Image /StartComponentCleanup /ResetBase". Reduz a pasta WinSxS de forma permanente. Atenção: com /ResetBase, as atualizações já instaladas deixam de poder ser desinstaladas.'; Destr=$true }
        [pscustomobject]@{ Cat='Limpeza'; Titulo='Limpeza profunda do sistema';         Func='Clear-DeepSystemCleanup';     Desc='Remove logs antigos do CBS e do DISM e os arquivos de despejo de memória (minidumps e Memory.dmp) em C:\Windows.'; Destr=$true }
        [pscustomobject]@{ Cat='Limpeza'; Titulo='Otimizar volumes (desfrag/ReTrim)';   Func='Optimize-Volumes';            Desc='Em cada volume fixo: se for NTFS, roda desfragmentação; se não for NTFS/FAT32/exFAT (normalmente SSD), roda ReTrim. FAT32 e exFAT são pulados. A escolha é pelo sistema de arquivos, não detecta HDD ou SSD de fato.'; Destr=$false }
        [pscustomobject]@{ Cat='Limpeza'; Titulo='Remover arquivos duplicados';         Func='Remove-DuplicateFiles';       Desc='Procura duplicatas com conteúdo idêntico (hash SHA256) em Downloads, Documentos, Área de Trabalho, Imagens, Vídeos e Música (com subpastas). Mantém 1 cópia por grupo. Por padrão MOVE as demais para revisão em C:\ScriptsLogs\Duplicatas_<data>, com backup automático. Marque "Deletar" para apagar de verdade.'; Destr=$true; Params=@(
                                            @{ Nome='Path';    Rotulo='Pastas-raiz (vazio = Downloads, Documentos, Área de Trabalho, Imagens, Vídeos e Música)'; Tipo='paths'; Default=''; Exemplo='Ex.: D:\Fotos;E:\Backup (separe várias pastas por ;)'; Pasta=$true }
                                            @{ Nome='Manter';  Rotulo='Qual cópia manter em cada grupo'; Tipo='choice'; Default='MaisAntigo'; Opcoes=@('Maior','MaisAntigo','MaisNovo') }
                                            @{ Nome='TiposArquivo'; Rotulo='Filtrar por extensão (vazio = todos)'; Tipo='paths'; Default=''; Exemplo='Ex.: *.jpg;*.pdf (separe por ;)' }
                                            @{ Nome='IncluirComuns'; Rotulo='Filtrar só tipos comuns (fotos, vídeos, documentos e zip)'; Tipo='switch'; Default=$false }
                                            @{ Nome='TamanhoMinimoKB'; Rotulo='Ignorar arquivos menores que (KB)'; Tipo='text'; Default='1' }
                                            @{ Nome='Deletar'; Rotulo='Deletar de verdade (em vez de só mover para revisão)'; Tipo='switch'; Default=$false }
                                            @{ Nome='SemBackup'; Rotulo='Desativar o backup automático antes de mover ou deletar'; Tipo='switch'; Default=$false }
                                          ) }
        [pscustomobject]@{ Cat='Limpeza'; Titulo='Remover pasta Windows.old';          Func='Remove-WindowsOld';           Desc='Se existir C:\Windows.old (backup da instalação anterior, criado em atualizações de versão), apaga a pasta inteira. Libera vários GB.'; Destr=$true }
        [pscustomobject]@{ Cat='Limpeza'; Titulo='Rotina completa de limpeza';         Func='Invoke-Cleanup';              Desc='Roda em sequência: limpeza profunda, Prefetch, spooler de impressão, temporários, arquivos e pastas vazias, cache do Windows Update, WinSxS, limpeza de rede (ARP, DNS, temp, spooler, WU, WinSxS, limpeza profunda, Windows.old, CHKDSK, otimização de volumes), remove Windows.old, faz backup do registro, desativa SMBv1 e roda DISM e SFC.'; Destr=$true }
        [pscustomobject]@{ Cat='Limpeza'; Titulo='Verificação DISM';                    Func='Invoke-DISM-Scan';            Desc='DISM /RestoreHealth: repara a imagem de componentes do Windows.'; Destr=$false }
        [pscustomobject]@{ Cat='Limpeza'; Titulo='Verificação SFC';                    Func='Invoke-SFC-Scan';             Desc='sfc /scannow: verifica e repara arquivos de sistema.'; Destr=$false }

        # --- Privacidade ---
        [pscustomobject]@{ Cat='Privacidade'; Titulo='Desativar Cortana e pesquisa online'; Func='Disable-Cortana-AndSearch'; Desc='Pelo registro: desativa a Cortana (AllowCortana=0) e a busca na nuvem e no Bing (AllowCloudSearch=0), além de ajustes de telemetria e relatório de erros.'; Destr=$false }
        [pscustomobject]@{ Cat='Privacidade'; Titulo='Desativar serviços desnecessários'; Func='Disable-UnnecessaryServices'; Desc='Desativa DiagTrack e dmwappushservice (telemetria), WMPNetworkSvc, serviços do Xbox, MapsBroker, Fax, RemoteRegistry, RetailDemo e WerSvc (relatório de erros), entre outros de baixo uso. Não mexe em biometria (WbioSrvc), compartilhamento de internet (SharedAccess), localização (lfsvc), TrkWks nem PrintNotify.'; Destr=$true }
        [pscustomobject]@{ Cat='Privacidade'; Titulo='Desativar Windows Recall';        Func='Disable-WindowsRecall';       Desc='Ajustes de registro que desativam o Windows Recall (gravação de tela do Windows 11 24H2 ou superior), se o recurso estiver presente.'; Destr=$false }
        [pscustomobject]@{ Cat='Privacidade'; Titulo='Endurecimento de privacidade';    Func='Enable-PrivacyHardening';     Desc='Equivale a Privacidade consolidada (Set-PrivacyBaseline): telemetria, ID de publicidade e coleta de entrada, junto com os demais ajustes. Mantida por compatibilidade.'; Destr=$false }
        [pscustomobject]@{ Cat='Privacidade'; Titulo='Forçar remoção do OneDrive';      Func='Remove-OneDrive-AndRestoreFolders'; Desc='Desinstala o OneDrive e restaura Documentos, Imagens, Área de Trabalho e outras pastas para as pastas locais, fora da sincronização.'; Destr=$true }
        [pscustomobject]@{ Cat='Privacidade'; Titulo='Prevenção de bloatware e privacidade'; Func='Grant-PrivacyAndBloatwarePrevention'; Desc='Equivale a Privacidade consolidada (Set-PrivacyBaseline); os itens opcionais continuam seguindo $ScriptConfig.PrivacyTweaks (ex.: Wi-Fi Sense). Mantida por compatibilidade.'; Destr=$false }
        [pscustomobject]@{ Cat='Privacidade'; Titulo='Privacidade consolidada';       Func='Set-PrivacyBaseline';         Desc='Linha de base única de privacidade (une as três funções antigas): telemetria, diagnóstico e feedback, publicidade e sugestões, localização, Cortana e Bing, apps em segundo plano, câmera e microfone, Wi-Fi Sense, SMBv1, prevenção de bloatware, OneDrive e Game Bar. Mantém UAC, SmartScreen, Defender e Windows Update. Chaves do usuário valem só para a conta atual.'; Destr=$false }
        [pscustomobject]@{ Cat='Privacidade'; Titulo='Reforço de segurança (Defender)';  Func='Enable-WindowsHardening';     Desc='Aplica configurações de segurança do Microsoft Defender (ASR, bloqueio na nuvem, PUA e outras).'; Destr=$false }
        [pscustomobject]@{ Cat='Bloatware'; Titulo='Varredura de bloatware (escolher o que remover)'; Func='Invoke-BloatwareReview';     Desc='Lista os apps Appx e os programas instalados (sem componentes do Windows) numa janela com checkbox. Os que costumam ser bloatware de fábrica já vêm marcados. Remove só o que você marcar e salva o relatório em C:\ScriptsLogs.'; Destr=$true }
        [pscustomobject]@{ Cat='Bloatware'; Titulo='Remover bloatware (padrão)';     Func='Remove-SystemBloatware';      Desc='Remove apps pré-instalados que não são do colégio (Bing, News, Weather, Xbox, Solitaire etc.), respeitando a lista de exceções: winget, Terminal, Store, Calculadora, Fotos, Defender e codecs ficam. O Edge não é removido. Pastas do OneDrive só com -ConfirmarOneDrive.'; Destr=$true }
        [pscustomobject]@{ Cat='Bloatware'; Titulo='Rotina completa de bloatware';    Func='Invoke-Bloatware';            Desc='Roda em sequência: prevenção de bloatware e privacidade, remover bloatware (padrão, sem remover o Edge), desativar serviços desnecessários, desativar Recall, forçar remoção do OneDrive e remover pasta Windows.old.'; Destr=$true }
        [pscustomobject]@{ Cat='Desinstalações'; Titulo='Varredura de desinstalações (escolher o que remover)'; Func='Invoke-UninstallReview'; Desc='Lê tudo o que há na máquina: apps da Store, programas que vêm com o notebook (Lenovo, McAfee, Dropbox etc.), programas instalados e programas do usuário atual. Mostra tudo com os checkboxes vazios. Marque o que deseja e confirme: a remoção é silenciosa e só atinge os itens marcados. Componentes do Windows, runtimes, drivers e atualizações não aparecem. O relatório fica em C:\ScriptsLogs.'; Destr=$true }
        [pscustomobject]@{ Cat='Scripts externos'; Titulo='Atualizar o Script Supremo pela URL'; Func='Update-ScriptFromCloud'; Desc='Baixa a versão mais recente do Script Supremo do GitHub (https) e executa em seguida.'; Destr=$true }
        [pscustomobject]@{ Cat='Scripts externos'; Titulo='Chris Titus Toolbox'; Func='Invoke-ChrisTitusToolbox'; Desc='Baixa e executa o toolbox de terceiros christitus.com/win como administrador. Roda código remoto: use com cuidado.'; Destr=$true }
        [pscustomobject]@{ Cat='Scripts externos'; Titulo='Ativador get.activated.win'; Func='Invoke-WindowsActivator'; Desc='Baixa e executa o script de terceiros get.activated.win como administrador. Roda código remoto: use com cuidado.'; Destr=$true }
        [pscustomobject]@{ Cat='Privacidade'; Titulo='Segurança de macros do Office';   Func='Grant-HardenOfficeMacros';     Desc='Desabilita macros perigosos do Office (Word, Excel e PowerPoint).'; Destr=$false }

        # --- Rede ---
        [pscustomobject]@{ Cat='Rede'; Titulo='Adicionar rede Wi-Fi';                  Func='Add-WiFiNetwork';             Desc='Adiciona o perfil de rede Wi-Fi "VemProMundo - Adm". A senha vem de CMS_WIFI_KEY ou de WiFi.local.json. Use o campo abaixo só para informar outra senha. O campo é mascarado e a senha não é gravada.'; Destr=$false; Params=@(
                                            @{ Nome='WifiKey'; Rotulo='Senha do Wi-Fi (opcional: deixe em branco para usar a configurada)'; Tipo='password'; Default=''; Exemplo='Só preencha para substituir a senha já configurada.' }
                                          ) }
        [pscustomobject]@{ Cat='Rede'; Titulo='Configurar DNS Google e Cloudflare';    Func='Set-DnsGoogleCloudflare';     Desc='Define DNS Google e Cloudflare só no adaptador ativo, com gateway, físico e fora de domínio. Guarda o DNS anterior em C:\ScriptsLogs\dns_backup.json. Não altera adaptadores virtuais (Hyper-V, VPN, Bluetooth).'; Destr=$false }
        [pscustomobject]@{ Cat='Rede'; Titulo='Desativar IPv6';                        Func='Disable-IPv6';                Desc='Desativa o IPv6 pelo registro (DisabledComponents = 0xFF em Tcpip6\Parameters) em todos os adaptadores. Precisa reiniciar o computador para valer.'; Destr=$false }
        [pscustomobject]@{ Cat='Rede'; Titulo='Instalar impressoras de rede';          Func='Install-NetworkPrinters';     Desc='Instala os drivers (Epson WF-C5810, Epson L3250 e Samsung M337x/387x/407x) da pasta de drivers compartilhada e cadastra as impressoras da unidade 2 por IP, porta 9100.'; Destr=$false }
        [pscustomobject]@{ Cat='Rede'; Titulo='Limpar cache ARP';                      Func='Clear-ARP';                   Desc='Executa "netsh interface ip delete arpcache". Limpa a tabela ARP (mapeamento IP e MAC) da rede local.'; Destr=$false }
        [pscustomobject]@{ Cat='Rede'; Titulo='Limpar cache DNS';                      Func='Clear-DNS';                   Desc='Executa "ipconfig /flushdns". Limpa o cache local de resolução de nomes.'; Destr=$false }
        [pscustomobject]@{ Cat='Rede'; Titulo='Limpar spooler de impressão';           Func='Clear-PrintSpooler';          Desc='Para o serviço Spooler, apaga os arquivos presos em C:\Windows\System32\spool\PRINTERS e reinicia o serviço. Resolve impressões presas na fila.'; Destr=$false }
        [pscustomobject]@{ Cat='Rede'; Titulo='Mostrar informações de rede';           Func='Show-NetworkInfo';            Desc='Mostra "ipconfig /all" e um resumo de cada adaptador (interface, IPv4, gateway e servidor DNS) via Get-NetIPConfiguration.'; Destr=$false }
        [pscustomobject]@{ Cat='Rede'; Titulo='Otimizar desempenho de rede';          Func='Optimize-NetworkPerformance'; Desc='Ajustes seguros por registro e netsh: RSS (multi-core), descoberta de MTU, TTL e sem limitação de banda. Não desativa mais o auto-ajuste nem o provedor de congestionamento.'; Destr=$false }
        [pscustomobject]@{ Cat='Rede'; Titulo='Resetar Google Drive Desktop';          Func='Reset-GoogleDriveDesktop';    Desc='Encerra o Google Drive para computador, apaga cache, configurações e contas conectadas localmente (AppData e a chave HKCU\Software\Google\DriveFS) e reabre o app para novo login. NÃO apaga nada da nuvem, mas alterações locais ainda não sincronizadas podem ser perdidas.'; Destr=$true }
        [pscustomobject]@{ Cat='Rede'; Titulo='Rotina completa de rede';               Func='Invoke-NetworkUtilities';     Desc='Roda em sequência: adiciona o Wi-Fi "VemProMundo - Adm", limpa ARP e DNS, limpa o spooler, desativa IPv6, instala as impressoras de rede, aplica as otimizações de rede, configura DNS Google e Cloudflare, mostra as informações de rede e testa a velocidade da internet.'; Destr=$false }
        [pscustomobject]@{ Cat='Rede'; Titulo='Testar velocidade da internet';         Func='Test-InternetSpeed';          Desc='Instala o Speedtest CLI da Ookla (Ookla.Speedtest.CLI) pelo winget, se ainda não estiver instalado, e roda o teste de download, upload e ping, com tempo limite de 3 minutos e log.'; Destr=$false }

        # --- Sistema ---
        [pscustomobject]@{ Cat='Sistema'; Titulo='Criar contas Suporte e Colégio';    Func='Invoke-ContasEscola';         Desc='Cria a conta Suporte (administradora, para manutenção) e a conta Colégio (padrão, para uso diário), se ainda não existirem. As senhas são digitadas em janelas mascaradas e nunca são gravadas. A conta Colégio só sai dos administradores com a sessão Suporte ativa.'; Destr=$true; Params=@(
                                            @{ Nome='SenhaSuporte'; Rotulo='Senha da conta Suporte (campo mascarado, nunca gravada)'; Tipo='password'; Default=''; Exemplo='Em branco: a conta Suporte não é criada.' }
                                            @{ Nome='SenhaColegio'; Rotulo='Senha da conta Colégio (campo mascarado, nunca gravada)'; Tipo='password'; Default=''; Exemplo='Em branco: a conta Colégio não é criada.' }
                                          ) }
        [pscustomobject]@{ Cat='Sistema'; Titulo='Criar ponto de restauração';        Func='New-SystemRestorePoint';      Desc='Habilita a Proteção do Sistema e cria um ponto de restauração.'; Destr=$false }
        [pscustomobject]@{ Cat='Sistema'; Titulo='Efeitos visuais para desempenho';   Func='Set-VisualPerformance';       Desc='Pelo registro: VisualFXSetting=2 ("Ajustar para obter um melhor desempenho") e ajusta o UserPreferencesMask. Desliga animações, sombras e transparências. Pode ser preciso reiniciar o Explorer.'; Destr=$false }
        [pscustomobject]@{ Cat='Sistema'; Titulo='Otimizações gerais do sistema';     Func='Grant-SystemOptimizations';   Desc='Ativa a otimização de inicialização (BootOptimizeFunction) e outros ajustes gerais de registro.'; Destr=$false }
        [pscustomobject]@{ Cat='Sistema'; Titulo='Otimizar desempenho do Explorer';   Func='Optimize-ExplorerPerformance'; Desc='Pelo registro: desativa animações de seleção e sombra dos ícones e da barra de tarefas, e desliga os painéis de detalhes e visualização do Explorer.'; Destr=$false }
        [pscustomobject]@{ Cat='Sistema'; Titulo='Plano de energia otimizado';        Func='Set-OptimizedPowerPlan';      Desc='Ativa o plano de energia "Alto desempenho" (powercfg). Se o plano estiver oculto no sistema, cria uma cópia a partir do GUID embutido (powercfg /duplicatescheme) e ativa. Mantém a inicialização rápida LIGADA. Não altera tempos de tela.'; Destr=$false }
        [pscustomobject]@{ Cat='Sistema'; Titulo='Renomear notebook';                 Func='Rename-Notebook';             Desc='Renomeia o computador. Requer reinício para aplicar.'; Destr=$false; Params=@(
                                            @{ Nome='NovoNome'; Rotulo='Novo nome do notebook'; Tipo='text'; Default=''; Exemplo='Ex.: CMS-NOTE-14 (sem espaços nem acentos, máximo de ~15 caracteres)' }
                                          ) }

        # --- Personalização ---
        [pscustomobject]@{ Cat='Personalização'; Titulo='Ajustes de UI (widgets e barra)'; Func='Grant-UITweaks';          Desc='Aplica os ajustes de UI configurados em $ScriptConfig.UITweaks (ex.: ocultar o botão de Widgets no Windows 11). Só faz algo para as opções ativadas na configuração do script.'; Destr=$false }
        [pscustomobject]@{ Cat='Personalização'; Titulo='Ativar tema escuro';          Func='Enable-DarkTheme';            Desc='Registro: AppsUseLightTheme=0 e SystemUsesLightTheme=0 (HKCU\...\Themes\Personalize). Ativa o modo escuro nos apps e no shell do Windows.'; Destr=$false }
        [pscustomobject]@{ Cat='Personalização'; Titulo='Finalizar tarefa na barra';   Func='Enable-TaskbarEndTask';       Desc='Registro: TaskbarEndTask=1. Adiciona "Finalizar tarefa" no menu do botão direito da barra de tarefas. Só funciona no Windows 11 build 23430 ou superior (a função verifica e avisa).'; Destr=$false }
        [pscustomobject]@{ Cat='Personalização'; Titulo='Habilitar sudo';              Func='Enable-Sudo';                 Desc='Registro: EnableSudo=1. Ativa o "sudo" nativo do Windows 11 24H2 ou superior. Precisa fechar e abrir o terminal para valer.'; Destr=$false }
        [pscustomobject]@{ Cat='Personalização'; Titulo='Histórico da área de transferência'; Func='Enable-ClipboardHistory'; Desc='Registro: EnableClipboardHistory=1. Ativa o histórico da área de transferência (Win+V).'; Destr=$false }
        [pscustomobject]@{ Cat='Personalização'; Titulo='Menu de contexto clássico';   Func='Enable-ClassicContextMenu';   Desc='Restaura o menu de contexto clássico, com todas as opções de uma vez, no lugar do menu reduzido do Windows 11.'; Destr=$false }
        [pscustomobject]@{ Cat='Personalização'; Titulo='Restaurar apps após reinício'; Func='Enable-RestartAppsAfterReboot'; Desc='Registro: RestartApps=1 (HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon). Reabre os programas que estavam abertos antes do reinício.'; Destr=$false }
        [pscustomobject]@{ Cat='Personalização'; Titulo='Segundos no relógio';         Func='Enable-TaskbarSeconds';       Desc='Registro: ShowSecondsInSystemClock=1. Mostra os segundos no relógio da barra de tarefas.'; Destr=$false }
        [pscustomobject]@{ Cat='Personalização'; Titulo='Atualizações de outros produtos Microsoft'; Func='Enable-OtherMicrosoftUpdates'; Desc='Registro: EnableFeaturedSoftware=1. Faz o Windows Update atualizar também outros produtos Microsoft instalados.'; Destr=$false }
        [pscustomobject]@{ Cat='Personalização'; Titulo='Windows Update antecipado';   Func='Enable-WindowsUpdateFast';    Desc='Registro: IsContinuousInnovationOptedIn=1. Recebe atualizações assim que disponíveis, antes do lançamento padrão.'; Destr=$false }

        # --- Diagnósticos ---
        [pscustomobject]@{ Cat='Diagnósticos'; Titulo='Diagnósticos avançados';        Func='Invoke-All-DiagnosticsAdvanced'; Desc='Roda em sequência: informações do sistema, uso de disco, informações de rede, SFC, DISM, saúde dos discos (SMART) e agenda o teste de memória do Windows.'; Destr=$false }
        [pscustomobject]@{ Cat='Diagnósticos'; Titulo='Informações do sistema';        Func='Show-SystemInfo';             Desc='Executa "systeminfo" e mostra no log: versão do Windows, memória, hotfixes e outros dados.'; Destr=$false }
        [pscustomobject]@{ Cat='Diagnósticos'; Titulo='Testar memória';                Func='Test-Memory';                 Desc='Abre a Ferramenta de Diagnóstico de Memória do Windows (mdsched.exe). É preciso escolher reiniciar o computador para o teste rodar.'; Destr=$false }
        [pscustomobject]@{ Cat='Diagnósticos'; Titulo='Uso de disco';                  Func='Show-DiskUsage';              Desc='Mostra uma tabela com letra, rótulo, tamanho total e espaço livre (em GB) de cada volume.'; Destr=$false }

        # --- Restauração ---
        [pscustomobject]@{ Cat='Restauração'; Titulo='Backup do registro';             Func='Backup-Registry';             Desc='Exporta HKLM\SOFTWARE, HKLM\SYSTEM e HKCU para 3 arquivos .reg em uma pasta nova em Documentos (reg_backup_<data_hora>).'; Destr=$false }
        [pscustomobject]@{ Cat='Restauração'; Titulo='Desfazer reforço de privacidade'; Func='Undo-PrivacyHardening';     Desc='Desfaz os ajustes aplicados por "Endurecimento de privacidade" (Enable-PrivacyHardening).'; Destr=$false }
        [pscustomobject]@{ Cat='Restauração'; Titulo='Desfazer tudo (rotina)';         Func='Invoke-Undo';                 Desc='Roda em sequência: reativa as notificações da Central de Ações, restaura os tweaks do Painel de Controle, restaura IPv6 e UAC padrão, restaura macros do Office, reinstala o OneDrive, restaura o registro (backup mais recente) e restaura os efeitos visuais padrão.'; Destr=$true }
        [pscustomobject]@{ Cat='Restauração'; Titulo='Reinstalar OneDrive';            Func='Restore-OneDrive';            Desc='Executa C:\Windows\SysWOW64\OneDriveSetup.exe (instalador do próprio Windows). Se o arquivo não existir, avisa o erro e não faz nada.'; Destr=$false }
        [pscustomobject]@{ Cat='Restauração'; Titulo='Restaurar registro';             Func='Restore-Registry';            Desc='Restaura o registro (HKLM\SOFTWARE, HKLM\SYSTEM e HKCU) a partir de uma pasta de backup gerada por "Backup do registro".'; Destr=$true; Params=@(
                                            @{ Nome='BkpPath'; Rotulo='Pasta do backup do registro'; Tipo='text'; Default=''; Exemplo='Ex.: C:\Users\SeuUsuario\Documents\reg_backup_20260814_140000'; Pasta=$true }
                                          ) }
        [pscustomobject]@{ Cat='Restauração'; Titulo='Restaurar todos os padrões';     Func='Restore-SystemDefaults';      Desc='Grava de volta os valores padrão de fábrica do Windows no registro (Explorer, efeitos visuais, privacidade e outros). Desfaz de uma vez os tweaks de Painel de Controle, Privacidade, Extras e o endurecimento de privacidade.'; Destr=$true }

        # --- Instalação ---
        [pscustomobject]@{ Cat='Instalação'; Titulo='Atualizar PowerShell';           Func='Update-PowerShell';           Desc='Instala ou atualiza o PowerShell (aka.ms/install-powershell).'; Destr=$false }
        [pscustomobject]@{ Cat='Instalação'; Titulo='Atualizações do Windows (escolher o modo)'; Func='Grant-WindowsUpdates'; Desc='Usa o módulo PSWindowsUpdate. Listar só mostra o que está pendente. Críticas instala só as de segurança e as críticas. Todas instala tudo. O computador só reinicia sozinho se a opção de reinício automático for marcada.'; Destr=$true; Params=@(
                                            @{ Nome='Modo'; Rotulo='Modo de atualização'; Tipo='choice'; Default='Listar'; Opcoes=@('Criticas','Listar','Todas') }
                                            @{ Nome='AutoReboot'; Rotulo='Reiniciar automaticamente se for preciso'; Tipo='switch'; Default=$false }
                                          ) }
        [pscustomobject]@{ Cat='Instalação'; Titulo='Atualizar Windows e drivers';     Func='Update-WindowsAndDrivers';    Desc='Instala o módulo PSWindowsUpdate (se faltar) e roda Get-WindowsUpdate com instalação automática, sem reiniciar sozinho. Depois roda "winget upgrade --all", que atualiza TODOS os programas instalados pelo winget, não só drivers.'; Destr=$false }
        [pscustomobject]@{ Cat='Instalação'; Titulo='Instalar aplicativos';           Func='Install-Applications';        Desc='Escolha os aplicativos abaixo (winget; usa Apps.json se existir) e clique em Executar. Janela de checkbox com "Marcar todos" e "Desmarcar todos".'; Destr=$false; Params=$paramsInstalarApps }
        [pscustomobject]@{ Cat='Instalação'; Titulo='Instalar apps portáteis';        Func='Install-PortableApps';        Desc='Copia para C:\Portateis os apps portáteis da pasta compartilhada da Tecnologia (cada pasta com um .exe) que você marcar na janela de checkbox, e cria atalho no menu Iniciar.'; Destr=$false }
        [pscustomobject]@{ Cat='Instalação'; Titulo='Instalar Lightshot';             Func='Install-Lightshot';           Desc='Instala (ou atualiza para) a versão mais recente do Lightshot pelo winget (Skillbrains.Lightshot).'; Destr=$false }
        [pscustomobject]@{ Cat='Instalação'; Titulo='Instalar perfil PowerShell (produtividade)'; Func='Install-PowerShellProfile'; Desc='Instala uma cópia "limpa" do perfil pessoal neste notebook: funções de log, limpeza e rede, aliases, e PSReadLine, oh-my-posh, Terminal-Icons, zoxide e PSFzf (cada um só ativa se já estiver instalado). Faz backup do perfil existente antes de sobrescrever. Precisa abrir um terminal novo depois.'; Destr=$true; Params=@(
                                            @{ Nome='Modo'; Rotulo='Modo do perfil'; Tipo='choice'; Default='Basico'; Opcoes=@('Aprimorado','Basico'); Exemplo='Básico: funções e aliases. Aprimorado: acrescenta PSReadLine, oh-my-posh, Terminal-Icons, zoxide e PSFzf.' }
                                            @{ Nome='SemBackup'; Rotulo='Desativar o backup automático do perfil existente antes de sobrescrever'; Tipo='switch'; Default=$false }
                                          ) }
        [pscustomobject]@{ Cat='Instalação'; Titulo='Reparar Ferramenta de Captura e instalar Lightshot'; Func='Invoke-ScreenshotToolFix'; Desc='Corrige a Ferramenta de Captura nativa (reativa o Print Screen, reregistra o pacote Microsoft.ScreenSketch e confirma a instalação pelo winget ou pela Microsoft Store) e em seguida instala a versão mais recente do Lightshot. Uso típico: o print nativo parou de funcionar.'; Destr=$false }

        # --- Avançado ---
        [pscustomobject]@{ Cat='Avançado'; Titulo='Configurações de GPO e registro';   Func='Grant-GPORegistrySettings';   Desc='Aplica configurações de GPO pelo registro (Edge, Chrome, busca de drivers e outras).'; Destr=$false }
        [pscustomobject]@{ Cat='Avançado'; Titulo='Desativar UAC';                    Func='Disable-UAC';                 Desc='Desativa o Controle de Conta de Usuário (UAC).'; Destr=$false }
        [pscustomobject]@{ Cat='Avançado'; Titulo='Tweaks de Painel de Controle';     Func='Grant-ControlPanelTweaks';    Desc='Registro: mostra extensões de arquivo e arquivos ocultos do sistema, desativa "sacudir para minimizar", itens recentes e frequentes e a animação de minimizar. Garante o acesso ao Painel de Controle, ao menu de contexto, à Área de Trabalho e ao Localizar.'; Destr=$false }
        [pscustomobject]@{ Cat='Avançado'; Titulo='Tweaks de privacidade';            Func='Grant-PrivacyTweaks';         Desc='Equivale a Privacidade consolidada (Set-PrivacyBaseline): dezenas de chaves de registro de privacidade. Mantém o UAC ativado. Mantida por compatibilidade.'; Destr=$false }
        [pscustomobject]@{ Cat='Avançado'; Titulo='Tweaks extras';                    Func='Grant-ExtraTweaks';           Desc='Registro: desativa telemetria do Edge e do Office, SysMain, SmartScreen, Game DVR, hibernação rápida, reinício automático após tela azul, serviços de Fax, RAS e discagem, indexação (WSearch) e Relatório de Erros. ATENÇÃO: também APAGA a chave StartupApproved\Run (reseta os itens de inicialização gerenciados).'; Destr=$false }

        # --- Rotinas ---
        [pscustomobject]@{ Cat='Rotinas'; Titulo='Manutenção completa';               Func='Show-FullMaintenance';        Desc='Roda em sequência: aplicativos padrão, impressoras de rede e otimização de rede, desativa SMBv1 e reforça macros do Office, remove bloatware, OneDrive, rotina completa de limpeza, tweaks de privacidade, painel de controle e extras, desativa Cortana e termina com SFC e DISM. Não agenda CHKDSK (exige reinício).'; Destr=$true }
        [pscustomobject]@{ Cat='Rotinas'; Titulo='Rotina Colégio (completa)';         Func='Invoke-Colegio';              Desc='Pré-checagem (administrador, espaço, bateria, internet, reinício pendente) e depois as etapas, nesta ordem: ponto de restauração e backup do registro, atualizações críticas, remoções (OneDrive, bloatware, Recall), privacidade e segurança, ajustes de desempenho e, por último, a limpeza. Desatendida por padrão; Wi-Fi, apps e personalização são opcionais. Termina com a tabela de resultado por etapa e o caminho do log. Nunca reinicia sozinha. Fora da rotina: DNS Google/Cloudflare, tweaks extras e macros do Office.'; Destr=$true; Params=@(
                                            @{ Nome='Wifi'; Rotulo='Cadastrar o Wi-Fi VemProMundo - Adm (abre janela de senha)'; Tipo='switch'; Default=$false }
                                            @{ Nome='Apps'; Rotulo='Instalar aplicativos no fim (abre o seletor de apps)'; Tipo='switch'; Default=$false }
                                            @{ Nome='Personalizacao'; Rotulo='Incluir personalização (menu clássico, tema escuro, sudo, relógio com segundos)'; Tipo='switch'; Default=$false }
                                            @{ Nome='IgnorarPreChecagem'; Rotulo='Ignorar a pré-checagem (não recomendado)'; Tipo='switch'; Default=$false }
                                          ) }
        [pscustomobject]@{ Cat='Rotinas'; Titulo='Rotina Colégio: ver as etapas';     Func='Show-ColegioEtapas';          Desc='Mostra, sem executar nada, as etapas que a Rotina Colégio rodaria, na ordem. É a mesma lista que a rotina usa.'; Destr=$false; Params=@(
                                            @{ Nome='Wifi'; Rotulo='Incluir o Wi-Fi'; Tipo='switch'; Default=$false }
                                            @{ Nome='Apps'; Rotulo='Incluir a instalação de aplicativos'; Tipo='switch'; Default=$false }
                                            @{ Nome='Personalizacao'; Rotulo='Incluir personalização'; Tipo='switch'; Default=$false }
                                          ) }

        # --- Ferramentas ---
        [pscustomobject]@{ Cat='Ferramentas'; Titulo='Converter vídeos iVMS-4200 (HEVC para MP4)'; Func='Convert-IvmsCctvVideos'; Desc='Converte vídeos exportados do iVMS-4200 (H.265, com proporção errada) para MP4 compatível, via ffmpeg: remuxa o vídeo sem recodificar, corrige a proporção, recodifica o áudio para AAC e ativa o faststart. Salva com o mesmo nome do arquivo de origem e não sobrescreve por padrão. Requer ffmpeg no PATH.'; Destr=$false; Params=@(
                                            @{ Nome='SourceFiles'; Rotulo='Vídeo(s) de origem (.mp4 do iVMS-4200)'; Tipo='files'; Default=''; Exemplo='Clique no botão para escolher um ou mais arquivos (pode clicar de novo para somar).'; Arquivo=$true }
                                            @{ Nome='DestFolder'; Rotulo='Pasta de destino'; Tipo='text'; Default=''; Exemplo='Ex.: C:\Videos\Convertidos'; Pasta=$true }
                                            @{ Nome='SobrescreverExistente'; Rotulo='Sobrescrever se já existir arquivo com o mesmo nome no destino'; Tipo='switch'; Default=$false }
                                          ) }
        [pscustomobject]@{ Cat='Ferramentas'; Titulo='Comprimir vídeos (WhatsApp e e-mail)'; Func='Compress-Videos'; Desc='Reduz o tamanho de vídeos (MP4, MKV, AVI, MOV...) via ffmpeg, salvando como "nome_comprimido.mp4"; o ORIGINAL nunca é alterado nem apagado. Perfil Leve (qualidade alta, até 1080p), Médio (equilíbrio, até 720p) ou Forte (bem menor, até 480p). Se preencher "Tamanho máximo (MB)", o script calcula o bitrate pela duração para ficar nesse tamanho e o perfil é ignorado. Se o resultado não ficar menor que o original, é descartado. Requer ffmpeg no PATH (winget install Gyan.FFmpeg).'; Destr=$false; Params=@(
                                            @{ Nome='SourceFiles'; Rotulo='Vídeo(s) de origem'; Tipo='files'; Default=''; Exemplo='Clique no botão para escolher um ou mais arquivos (pode clicar de novo para somar).'; Arquivo=$true }
                                            @{ Nome='DestFolder'; Rotulo='Pasta de destino (vazio = mesma pasta do vídeo)'; Tipo='text'; Default=''; Exemplo='Ex.: C:\Videos\Menores'; Pasta=$true }
                                            @{ Nome='Perfil'; Rotulo='Perfil de compressão'; Tipo='choice'; Default='Medio'; Opcoes=@('Leve','Medio','Forte') }
                                            @{ Nome='TamanhoAlvoMB'; Rotulo='Tamanho máximo por vídeo, em MB (opcional; vazio = usa o perfil)'; Tipo='text'; Default=''; Exemplo='Ex.: 15 (o script calcula pela duração; fica próximo, com margem de 8%)' }
                                            @{ Nome='SobrescreverExistente'; Rotulo='Sobrescrever se já existir o arquivo "_comprimido" no destino'; Tipo='switch'; Default=$false }
                                          ) }
        [pscustomobject]@{ Cat='Ferramentas'; Titulo='Organizar fotos e vídeos (CamFix)'; Func='Invoke-CamFix'; Desc='Porta do script pessoal CamFix. rename: renomeia fotos e vídeos pela data EXIF (requer exiftool no PATH). clean: remove espaços duplicados no nome. emptyfolders: remove pastas vazias (sempre recursivo). dedupe-suffix: MOVE (não apaga) arquivos "nome 2.ext" que já têm um "nome.ext" para a subpasta _DUPLICADOS_PADRAO, para revisão.'; Destr=$true; Params=@(
                                            @{ Nome='Command'; Rotulo='O que fazer'; Tipo='choice'; Default='rename'; Opcoes=@('clean','dedupe-suffix','emptyfolders','rename') }
                                            @{ Nome='Path'; Rotulo='Pasta-raiz'; Tipo='text'; Default=''; Exemplo='Ex.: D:\Fotos\Viagem'; Pasta=$true }
                                            @{ Nome='Recurse'; Rotulo='Incluir subpastas (emptyfolders já é sempre recursivo)'; Tipo='switch'; Default=$false }
                                            @{ Nome='IncludeVideos'; Rotulo='(só rename) Também renomear vídeos pela data EXIF'; Tipo='switch'; Default=$false }
                                            @{ Nome='AllFiles'; Rotulo='(só rename) Renomear qualquer arquivo, não só fotos e vídeos conhecidos'; Tipo='switch'; Default=$false }
                                          ) }
    )
}

# ----------------------------------------------------------------------------
# Estilos compartilhados (ResourceDictionary). Usa só DynamicResource: assim o XAML
# faz parse sozinho em qualquer janela, sem depender dos recursos do dono.
# ----------------------------------------------------------------------------
$global:GuiEstilosXaml = @'
<ResourceDictionary xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
                    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml">
  <Style TargetType="TextBlock">
    <Setter Property="Foreground" Value="{DynamicResource Ink}"/>
    <Setter Property="FontSize" Value="{DynamicResource FSBody}"/>
  </Style>
  <Style x:Key="RotuloCaps" TargetType="TextBlock">
    <Setter Property="Foreground" Value="{DynamicResource Muted}"/>
    <Setter Property="FontSize" Value="{DynamicResource FSCaps}"/>
    <Setter Property="FontWeight" Value="SemiBold"/>
    <Setter Property="Margin" Value="0,10,0,4"/>
  </Style>
  <Style TargetType="CheckBox">
    <Setter Property="Foreground" Value="{DynamicResource Ink}"/>
    <Setter Property="FontSize" Value="{DynamicResource FSBody}"/>
    <Setter Property="Margin" Value="0,3"/>
  </Style>
  <Style TargetType="TextBox">
    <Setter Property="Background" Value="{DynamicResource PanelDark}"/>
    <Setter Property="Foreground" Value="{DynamicResource Ink}"/>
    <Setter Property="CaretBrush" Value="{DynamicResource Ink}"/>
    <Setter Property="BorderBrush" Value="{DynamicResource Border}"/>
    <Setter Property="FontSize" Value="{DynamicResource FSBody}"/>
    <Setter Property="Padding" Value="8,5"/>
    <Setter Property="VerticalContentAlignment" Value="Center"/>
  </Style>
  <Style TargetType="PasswordBox">
    <Setter Property="Background" Value="{DynamicResource PanelDark}"/>
    <Setter Property="Foreground" Value="{DynamicResource Ink}"/>
    <Setter Property="CaretBrush" Value="{DynamicResource Ink}"/>
    <Setter Property="BorderBrush" Value="{DynamicResource Border}"/>
    <Setter Property="FontSize" Value="{DynamicResource FSBody}"/>
    <Setter Property="Padding" Value="8,5"/>
  </Style>
  <Style TargetType="ComboBox">
    <Setter Property="Background" Value="{DynamicResource PanelDark}"/>
    <Setter Property="Foreground" Value="{DynamicResource Ink}"/>
    <Setter Property="BorderBrush" Value="{DynamicResource Border}"/>
    <Setter Property="FontSize" Value="{DynamicResource FSBody}"/>
  </Style>
  <Style TargetType="ComboBoxItem">
    <Setter Property="Background" Value="{DynamicResource Panel}"/>
    <Setter Property="Foreground" Value="{DynamicResource Ink}"/>
    <Setter Property="Padding" Value="8,4"/>
  </Style>
  <Style TargetType="ListBox">
    <Setter Property="Background" Value="{DynamicResource Panel}"/>
    <Setter Property="Foreground" Value="{DynamicResource Ink}"/>
    <Setter Property="BorderBrush" Value="{DynamicResource Border}"/>
    <Setter Property="FontSize" Value="{DynamicResource FSBody}"/>
  </Style>
  <Style TargetType="ListBoxItem">
    <Setter Property="Foreground" Value="{DynamicResource Ink}"/>
    <Setter Property="Padding" Value="8,5"/>
    <Style.Triggers>
      <Trigger Property="IsSelected" Value="True">
        <Setter Property="Background" Value="{DynamicResource Selecao}"/>
      </Trigger>
    </Style.Triggers>
  </Style>
  <Style x:Key="BotaoPrimario" TargetType="Button">
    <Setter Property="Background" Value="{DynamicResource Accent}"/>
    <Setter Property="Foreground" Value="{DynamicResource AccentInk}"/>
    <Setter Property="BorderThickness" Value="0"/>
    <Setter Property="Padding" Value="16,8"/>
    <Setter Property="FontWeight" Value="SemiBold"/>
    <Setter Property="FontSize" Value="{DynamicResource FSBody}"/>
    <Setter Property="Cursor" Value="Hand"/>
    <Style.Triggers>
      <Trigger Property="IsEnabled" Value="False"><Setter Property="Opacity" Value="0.45"/></Trigger>
    </Style.Triggers>
  </Style>
  <Style x:Key="BotaoSecundario" TargetType="Button">
    <Setter Property="Background" Value="{DynamicResource Panel}"/>
    <Setter Property="Foreground" Value="{DynamicResource Ink}"/>
    <Setter Property="BorderBrush" Value="{DynamicResource Border}"/>
    <Setter Property="BorderThickness" Value="1"/>
    <Setter Property="Padding" Value="12,6"/>
    <Setter Property="FontSize" Value="{DynamicResource FSBody}"/>
    <Setter Property="Cursor" Value="Hand"/>
    <Style.Triggers>
      <Trigger Property="IsEnabled" Value="False"><Setter Property="Opacity" Value="0.45"/></Trigger>
    </Style.Triggers>
  </Style>
  <Style x:Key="Cartao" TargetType="Border">
    <Setter Property="Background" Value="{DynamicResource Panel}"/>
    <Setter Property="BorderBrush" Value="{DynamicResource Border}"/>
    <Setter Property="BorderThickness" Value="1"/>
    <Setter Property="CornerRadius" Value="10"/>
    <Setter Property="Padding" Value="12"/>
    <Setter Property="Effect">
      <Setter.Value>
        <DropShadowEffect BlurRadius="14" ShadowDepth="2" Opacity="0.22" Color="#000000"/>
      </Setter.Value>
    </Setter>
  </Style>
  <Style x:Key="Divisor" TargetType="GridSplitter">
    <Setter Property="Background" Value="{DynamicResource Border}"/>
    <Style.Triggers>
      <Trigger Property="IsMouseOver" Value="True"><Setter Property="Background" Value="{DynamicResource Accent}"/></Trigger>
    </Style.Triggers>
  </Style>
</ResourceDictionary>
'@

# ----------------------------------------------------------------------------
# XAML da janela principal (cores e fontes via DynamicResource: tema e fonte ao vivo)
# ----------------------------------------------------------------------------
$script:GuiXaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Script Supremo de Manutenção" Height="800" Width="1140" MinWidth="860" MinHeight="600"
        WindowStartupLocation="CenterScreen" Background="{DynamicResource Bg}" FontFamily="Segoe UI">
  <Grid Margin="16">
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="*" MinHeight="170"/>
      <RowDefinition Height="8"/>
      <RowDefinition Height="200" MinHeight="110"/>
    </Grid.RowDefinitions>

    <!-- 0: cabeçalho -->
    <Grid Grid.Row="0" Margin="0,0,0,12">
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="*"/>
        <ColumnDefinition Width="Auto"/>
      </Grid.ColumnDefinitions>
      <StackPanel>
        <TextBlock Text="COLÉGIO MUNDO DO SABER" Style="{DynamicResource RotuloCaps}" Margin="0"/>
        <TextBlock Text="Script Supremo de Manutenção" FontSize="24" FontWeight="SemiBold" Margin="0,2,0,0"/>
      </StackPanel>
      <Button x:Name="BtnPersonalizar" Grid.Column="1" Content="&#9881; Personalizar" Style="{DynamicResource BotaoSecundario}" VerticalAlignment="Center"/>
    </Grid>

    <!-- 1: status das rotinas (cartões preenchidos em código) -->
    <StackPanel Grid.Row="1" Margin="0,0,0,4">
      <TextBlock Text="STATUS DAS ROTINAS" Style="{DynamicResource RotuloCaps}" Margin="0,0,0,6"/>
      <WrapPanel x:Name="PnlCards"/>
    </StackPanel>

    <!-- 2: busca + simular -->
    <Grid Grid.Row="2" Margin="0,6,0,12">
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="*"/>
        <ColumnDefinition Width="Auto"/>
        <ColumnDefinition Width="Auto"/>
      </Grid.ColumnDefinitions>
      <TextBox x:Name="TxtBusca" Height="36" ToolTip="Buscar ação (Ctrl+F)"/>
      <CheckBox x:Name="ChkWhatIf" Grid.Column="1" Content="Simular (WhatIf)" Margin="16,0,0,0" VerticalAlignment="Center" FontWeight="SemiBold"
                ToolTip="Mostra o que seria feito, sem alterar o computador. Marcado por padrão em ações destrutivas."/>
      <TextBlock x:Name="TxtAtalhos" Grid.Column="2" Margin="16,0,0,0" VerticalAlignment="Center" Foreground="{DynamicResource Muted}"
                 Text="Ctrl+F buscar  |  Enter executar  |  Esc fechar"/>
    </Grid>

    <!-- 3: categorias | ações | detalhe -->
    <Grid Grid.Row="3">
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="190" MinWidth="120"/>
        <ColumnDefinition Width="6"/>
        <ColumnDefinition Width="*" MinWidth="240"/>
        <ColumnDefinition Width="6"/>
        <ColumnDefinition Width="360" MinWidth="260"/>
      </Grid.ColumnDefinitions>

      <ListBox x:Name="LstCategorias" Grid.Column="0"/>

      <GridSplitter Grid.Column="1" Width="6" HorizontalAlignment="Stretch" VerticalAlignment="Stretch"
                    Cursor="SizeWE" Style="{DynamicResource Divisor}"/>

      <Grid Grid.Column="2">
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="*" MinHeight="80"/>
          <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>
        <!-- Barra da lista: marcar/desmarcar todas as ações visíveis e contador das marcadas -->
        <Grid Grid.Row="0" Margin="0,0,0,6">
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="Auto"/>
            <ColumnDefinition Width="Auto"/>
            <ColumnDefinition Width="*"/>
          </Grid.ColumnDefinitions>
          <Button x:Name="BtnMarcarTodas" Grid.Column="0" Content="Marcar todas" Style="{DynamicResource BotaoSecundario}" Padding="10,4"/>
          <Button x:Name="BtnDesmarcarTodas" Grid.Column="1" Content="Desmarcar todas" Style="{DynamicResource BotaoSecundario}" Padding="10,4" Margin="6,0,0,0"/>
          <TextBlock x:Name="TxtMarcadas" Grid.Column="2" VerticalAlignment="Center" HorizontalAlignment="Right" Foreground="{DynamicResource Muted}"/>
        </Grid>
        <ListBox x:Name="LstAcoes" Grid.Row="1">
          <ListBox.ItemTemplate>
            <DataTemplate>
              <StackPanel Orientation="Horizontal" Margin="2">
                <CheckBox IsChecked="{Binding Marcado, Mode=TwoWay}" VerticalAlignment="Center" Margin="0,0,8,0" ToolTip="Marcar para executar em sequência"/>
                <TextBlock Text="{Binding Marca}" Width="18" Foreground="{Binding Cor}" FontWeight="Bold"/>
                <TextBlock Text="{Binding Titulo}" Foreground="{Binding Cor}"/>
                <TextBlock Text="{Binding ResultadoTexto}" Foreground="{Binding ResultadoCor}" FontWeight="Bold" Margin="8,0,0,0"/>
              </StackPanel>
            </DataTemplate>
          </ListBox.ItemTemplate>
        </ListBox>
        <Border Grid.Row="2" Background="{DynamicResource PanelDark}" BorderBrush="{DynamicResource Border}"
                BorderThickness="1" CornerRadius="6" Margin="0,6,0,0" Padding="10,8">
          <ScrollViewer VerticalScrollBarVisibility="Auto" MaxHeight="110">
            <TextBlock x:Name="TxtAcaoResumo" TextWrapping="Wrap" Foreground="{DynamicResource Muted}"
                       Text="Selecione uma ação à esquerda para ver o que ela faz."/>
          </ScrollViewer>
        </Border>
      </Grid>

      <GridSplitter Grid.Column="3" Width="6" HorizontalAlignment="Stretch" VerticalAlignment="Stretch"
                    Cursor="SizeWE" Style="{DynamicResource Divisor}"/>

      <Border Grid.Column="4" Style="{DynamicResource Cartao}" Padding="0">
        <ScrollViewer VerticalScrollBarVisibility="Auto">
          <StackPanel Margin="14">
            <TextBlock x:Name="TxtDetTitulo" FontSize="17" FontWeight="SemiBold" TextWrapping="Wrap"/>
            <TextBlock x:Name="TxtDetCat" Foreground="{DynamicResource Muted}" Margin="0,4,0,0"/>
            <TextBlock x:Name="TxtDetFunc" Foreground="{DynamicResource Func}" FontFamily="Consolas" Margin="0,2,0,10"/>

            <TextBlock Text="DESCRIÇÃO" Style="{DynamicResource RotuloCaps}"/>
            <TextBlock x:Name="TxtDetDesc" TextWrapping="Wrap" Margin="0,0,0,8"/>
            <TextBlock x:Name="TxtDetAviso" Foreground="{DynamicResource Danger}" TextWrapping="Wrap" FontWeight="SemiBold" Margin="0,0,0,8"/>

            <TextBlock x:Name="TxtParamsTitulo" Text="PARÂMETROS" Style="{DynamicResource RotuloCaps}" Visibility="Collapsed"/>
            <StackPanel x:Name="PnlParams"/>

            <TextBlock Text="PRESETS SALVOS DESTA AÇÃO" Style="{DynamicResource RotuloCaps}"/>
            <Grid>
              <Grid.ColumnDefinitions>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="Auto"/>
              </Grid.ColumnDefinitions>
              <ComboBox x:Name="CboPresets" Grid.Column="0"/>
              <Button x:Name="BtnCarregarPreset" Grid.Column="1" Content="Carregar" Style="{DynamicResource BotaoSecundario}" Margin="6,0,0,0"/>
            </Grid>
            <StackPanel Orientation="Horizontal" Margin="0,6,0,0">
              <Button x:Name="BtnSalvarPreset" Content="Salvar preset" Style="{DynamicResource BotaoSecundario}"/>
              <Button x:Name="BtnExcluirPreset" Content="Excluir preset" Style="{DynamicResource BotaoSecundario}" Margin="6,0,0,0"/>
            </StackPanel>

            <TextBlock Text="ARGUMENTOS EXTRAS (AVANÇADO)" Style="{DynamicResource RotuloCaps}"/>
            <TextBox x:Name="TxtExtra" Height="30"/>
            <TextBlock x:Name="TxtArgDica" Foreground="{DynamicResource Muted}" FontSize="11" FontStyle="Italic" TextWrapping="Wrap" Margin="0,3,0,0"/>

            <Button x:Name="BtnExecutar" Content="Executar" Style="{DynamicResource BotaoPrimario}" Height="42" IsEnabled="False" Margin="0,14,0,0"/>
            <Button x:Name="BtnVerComando" Content="Ver comando equivalente" Style="{DynamicResource BotaoSecundario}" Margin="0,6,0,0" HorizontalAlignment="Stretch"/>
            <ProgressBar x:Name="PrgExec" Height="10" Margin="0,10,0,0" Visibility="Collapsed" IsIndeterminate="False"
                         Foreground="{DynamicResource Accent}" Background="{DynamicResource PanelDark}" BorderThickness="0"/>
            <TextBlock x:Name="TxtStatus" Margin="0,8,0,0" Foreground="{DynamicResource Muted}" TextWrapping="Wrap"/>
          </StackPanel>
        </ScrollViewer>
      </Border>
    </Grid>

    <GridSplitter Grid.Row="4" Height="8" HorizontalAlignment="Stretch" VerticalAlignment="Stretch"
                  Cursor="SizeNS" Style="{DynamicResource Divisor}"/>

    <!-- 5: log ao vivo -->
    <Border Grid.Row="5" Style="{DynamicResource Cartao}" Padding="10">
      <Grid>
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="*"/>
        </Grid.RowDefinitions>
        <Grid Grid.Row="0" Margin="0,0,0,6">
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="Auto"/>
            <ColumnDefinition Width="*"/>
            <ColumnDefinition Width="Auto"/>
          </Grid.ColumnDefinitions>
          <TextBlock Text="LOG AO VIVO" Style="{DynamicResource RotuloCaps}" Margin="0" VerticalAlignment="Center"/>
          <StackPanel Grid.Column="2" Orientation="Horizontal">
            <TextBlock Text="Mostrar:" Foreground="{DynamicResource Muted}" VerticalAlignment="Center" Margin="0,0,6,0"/>
            <ComboBox x:Name="CboNivel" Width="130" DisplayMemberPath="Rotulo"/>
            <Button x:Name="BtnCopiarLog" Content="Copiar" Style="{DynamicResource BotaoSecundario}" Margin="10,0,0,0" Padding="10,4"/>
            <Button x:Name="BtnExportarLog" Content="Exportar .txt" Style="{DynamicResource BotaoSecundario}" Margin="6,0,0,0" Padding="10,4"/>
          </StackPanel>
        </Grid>
        <TextBox x:Name="TxtLog" Grid.Row="1" IsReadOnly="True" TextWrapping="NoWrap" VerticalContentAlignment="Top"
                 VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto"
                 FontFamily="Consolas" FontSize="{DynamicResource FSLog}" BorderThickness="0"/>
      </Grid>
    </Border>
  </Grid>
</Window>
'@

# ----------------------------------------------------------------------------
# Tema e fonte: tokens e tamanhos aplicados em recursos (janela ou diálogo)
# ----------------------------------------------------------------------------
function Resolve-GuiTemaNome {
    param([string]$Nome)
    if ($Nome -eq 'Automatico') {
        # Segue o Windows: AppsUseLightTheme=1 é modo claro.
        try {
            $v = Get-ItemPropertyValue -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize' -Name AppsUseLightTheme -ErrorAction Stop
            if ([int]$v -eq 1) { return 'Claro' } else { return 'Escuro' }
        } catch { return 'Escuro' }
    }
    if ($global:GuiTemas.ContainsKey($Nome)) { return $Nome }
    return 'Escuro'
}

function Get-GuiTemaPorNome {
    param([string]$Nome)
    $resolvido = Resolve-GuiTemaNome -Nome $Nome
    $t = @{}
    foreach ($k in $global:GuiTemas[$resolvido].Keys) { $t[$k] = $global:GuiTemas[$resolvido][$k] }
    $t['Nome'] = $resolvido
    return $t
}

function Get-GuiTemaDefault {
    if ($global:GuiTemaAtivo) { return $global:GuiTemaAtivo }
    return (Get-GuiTemaPorNome -Nome 'Escuro')
}

function Set-GuiTokens {
    param($Recursos, $Tema)
    $conv = New-Object System.Windows.Media.BrushConverter
    foreach ($k in $Tema.Keys) {
        if ($k -eq 'Nome') { continue }
        try { $Recursos[$k] = $conv.ConvertFromString([string]$Tema[$k]) } catch { }
    }
}

function Set-GuiTamanhoFonte {
    param($Recursos, [double]$Tamanho)
    if ($Tamanho -lt 10) { $Tamanho = 13 }
    $Recursos['FSBody']  = $Tamanho
    $Recursos['FSLog']   = [double]([math]::Max(10, $Tamanho - 1))
    $Recursos['FSCaps']  = [double]([math]::Max(10, $Tamanho - 2))
}

# Aplica tema e fonte na janela principal. Devolve o tema efetivo (hashtable com Nome).
function Set-GuiAppearance {
    param($Window, $Prefs)
    $tema = Get-GuiTemaPorNome -Nome $Prefs.Tema
    Set-GuiTokens -Recursos $Window.Resources -Tema $tema
    Set-GuiTamanhoFonte -Recursos $Window.Resources -Tamanho ([double]$Prefs.Fonte)
    return $tema
}

# ----------------------------------------------------------------------------
# Janelas de diálogo (código, sem XAML fixo): mesmo tema e estilos da janela principal
# ----------------------------------------------------------------------------
function New-GuiBotao {
    param($Janela, [string]$Texto, [switch]$Primario)
    $b = New-Object System.Windows.Controls.Button
    $b.Content = $Texto
    $b.MinWidth = 96
    $b.Margin = '8,0,0,0'
    $b.Style = $Janela.FindResource($(if ($Primario) { 'BotaoPrimario' } else { 'BotaoSecundario' }))
    return $b
}

function New-GuiJanela {
    param([string]$Titulo, [int]$Largura = 520, [int]$Altura = 400, $Tema, $Dono = $null)
    if (-not $Tema) { $Tema = Get-GuiTemaDefault }
    $win = New-Object System.Windows.Window
    $win.Title = $Titulo
    $win.Width = $Largura
    $win.Height = $Altura
    $win.MinWidth = 360
    $win.MinHeight = 220
    $win.ResizeMode = 'CanResizeWithGrip'
    $win.FontFamily = New-Object System.Windows.Media.FontFamily('Segoe UI')
    if ($Dono) {
        $win.Owner = $Dono
        $win.WindowStartupLocation = 'CenterOwner'
    } else {
        $win.WindowStartupLocation = 'CenterScreen'
    }
    [void]$win.Resources.MergedDictionaries.Add([System.Windows.Markup.XamlReader]::Parse($global:GuiEstilosXaml))
    Set-GuiTokens -Recursos $win.Resources -Tema $Tema
    if ($Dono -and $Dono.Resources.Contains('FSBody')) {
        foreach ($k in 'FSBody','FSLog','FSCaps') { $win.Resources[$k] = $Dono.Resources[$k] }
    } else {
        Set-GuiTamanhoFonte -Recursos $win.Resources -Tamanho 13
    }
    $win.SetResourceReference([System.Windows.Window]::BackgroundProperty, 'Bg')
    return $win
}

# Janela de checkbox ÚNICA do GUI: bloatware, apps, portáteis e impressoras.
# Componente único de checkbox do GUI: usado nas janelas de seleção, nos parâmetros "sim/não"
# e (via GuiAcaoItem, no DataTemplate da lista de ações) em todas as listas.
function New-GuiCheckBox {
    param([string]$Texto = '', [bool]$Marcado = $false)
    $cb = New-Object System.Windows.Controls.CheckBox
    $cb.Content = $Texto
    $cb.IsChecked = $Marcado
    $cb.Margin = '0,4'
    $cb.TextWrapping = 'Wrap'
    return $cb
}

# Item da lista de ações (classe .NET para o binding TwoWay do CheckBox e a atualização da marca ✓/✗).
# Add-Type só roda uma vez por sessão.
if (-not ('GuiAcaoItem' -as [type])) {
    Add-Type -TypeDefinition @'
using System.ComponentModel;
public class GuiAcaoItem : INotifyPropertyChanged {
    private bool _marcado;
    private string _marca = "", _titulo = "", _cor = "", _resultado = "", _resultadoCor = "";
    public object Acao { get; set; }
    public event PropertyChangedEventHandler PropertyChanged;
    private void Avisar(string nome) {
        var h = PropertyChanged;
        if (h != null) h(this, new PropertyChangedEventArgs(nome));
    }
    public bool Marcado { get { return _marcado; } set { if (_marcado != value) { _marcado = value; Avisar("Marcado"); } } }
    public string Marca { get { return _marca; } set { _marca = value; Avisar("Marca"); } }
    public string Titulo { get { return _titulo; } set { _titulo = value; Avisar("Titulo"); } }
    public string Cor { get { return _cor; } set { _cor = value; Avisar("Cor"); } }
    // Resultado: "" (ainda não executada), "exec" (em execução), "ok" (✓) ou "erro" (✗).
    public string ResultadoTexto {
        get {
            if (_resultado == "ok") return "✓";
            if (_resultado == "erro") return "✗";
            if (_resultado == "exec") return "…";
            return "";
        }
    }
    public string ResultadoCor { get { return _resultadoCor; } }
    public string Estado { get { return _resultado; } }
    public void Definir(string resultado, string cor) {
        _resultado = resultado ?? "";
        _resultadoCor = cor ?? "";
        Avisar("ResultadoTexto");
        Avisar("ResultadoCor");
    }
}
'@
}

# Substitui Show-CheckboxPicker no runspace de fundo (ver New-GuiWorkerRunspace).
# Itens: @{ Texto; Valor; Marcado }. Devolve os itens marcados ou $null se cancelar.
function Show-GuiCheckboxPicker {
    [CmdletBinding()]
    param([string]$Titulo = 'Escolha os itens', [object[]]$Itens)
    $tema = Get-GuiTemaDefault
    $win = New-GuiJanela -Titulo $Titulo -Largura 660 -Altura 620 -Tema $tema

    $raiz = New-Object System.Windows.Controls.Grid
    $raiz.Margin = '16'
    foreach ($h in 'Auto','*','Auto') {
        $rd = New-Object System.Windows.Controls.RowDefinition
        $rd.Height = if ($h -eq '*') { New-Object System.Windows.GridLength(1, [System.Windows.GridUnitType]::Star) } else { 'Auto' }
        [void]$raiz.RowDefinitions.Add($rd)
    }

    $cabecalho = New-Object System.Windows.Controls.StackPanel
    $lblTitulo = New-Object System.Windows.Controls.TextBlock
    $lblTitulo.Text = $Titulo
    $lblTitulo.FontSize = 16
    $lblTitulo.FontWeight = 'SemiBold'
    $lblTitulo.TextWrapping = 'Wrap'
    $lblContador = New-Object System.Windows.Controls.TextBlock
    $lblContador.Foreground = $win.FindResource('Muted')
    $lblContador.Margin = '0,4,0,8'
    [void]$cabecalho.Children.Add($lblTitulo)
    [void]$cabecalho.Children.Add($lblContador)
    [System.Windows.Controls.Grid]::SetRow($cabecalho, 0)
    [void]$raiz.Children.Add($cabecalho)

    $scroll = New-Object System.Windows.Controls.ScrollViewer
    $scroll.VerticalScrollBarVisibility = 'Auto'
    $painel = New-Object System.Windows.Controls.StackPanel
    $scroll.Content = $painel
    [System.Windows.Controls.Grid]::SetRow($scroll, 1)
    [void]$raiz.Children.Add($scroll)

    # Todas as opções começam DESMARCADAS. Itens que o sistema sugere ganham a marca "(sugerido)" no texto.
    $checks = New-Object System.Collections.Generic.List[object]
    foreach ($item in $Itens) {
        $texto = [string]$item.Texto
        if ($item.Marcado) { $texto = "$texto  (sugerido)" }
        $cb = New-GuiCheckBox -Texto $texto
        [void]$painel.Children.Add($cb)
        $checks.Add([pscustomobject]@{ Caixa = $cb; Item = $item })
    }

    $atualizarContador = {
        try {
            $n = @($checks | Where-Object { $_.Caixa.IsChecked -eq $true }).Count
            $lblContador.Text = "$n de $($checks.Count) marcado(s)"
        } catch { Show-GuiHandlerError -Contexto 'Contador da seleção' -ErroObj $_ }
    }.GetNewClosure()
    foreach ($c in $checks) {
        $c.Caixa.Add_Click({ param($s, $e) try { & $atualizarContador } catch { Show-GuiHandlerError -Contexto 'Marcar item' -ErroObj $_ } }.GetNewClosure())
    }
    & $atualizarContador

    $rodape = New-Object System.Windows.Controls.StackPanel
    $rodape.Orientation = 'Horizontal'
    $rodape.HorizontalAlignment = 'Right'
    $rodape.Margin = '0,12,0,0'
    $bMarcar    = New-GuiBotao -Janela $win -Texto 'Marcar todos'
    $bDesmarcar = New-GuiBotao -Janela $win -Texto 'Desmarcar todos'
    $bCancelar  = New-GuiBotao -Janela $win -Texto 'Cancelar'
    $bOk        = New-GuiBotao -Janela $win -Texto 'Aplicar aos marcados' -Primario
    foreach ($b in $bMarcar, $bDesmarcar, $bCancelar, $bOk) { [void]$rodape.Children.Add($b) }
    [System.Windows.Controls.Grid]::SetRow($rodape, 2)
    [void]$raiz.Children.Add($rodape)

    $resultado = @{ Ok = $false; Itens = @() }
    $bMarcar.Add_Click({ param($s, $e)
        try { foreach ($c in $checks) { $c.Caixa.IsChecked = $true }; & $atualizarContador }
        catch { Show-GuiHandlerError -Contexto 'Marcar todos' -ErroObj $_ }
    }.GetNewClosure())
    $bDesmarcar.Add_Click({ param($s, $e)
        try { foreach ($c in $checks) { $c.Caixa.IsChecked = $false }; & $atualizarContador }
        catch { Show-GuiHandlerError -Contexto 'Desmarcar todos' -ErroObj $_ }
    }.GetNewClosure())
    $bOk.Add_Click({ param($s, $e)
        try {
            $resultado.Itens = @($checks | Where-Object { $_.Caixa.IsChecked -eq $true } | ForEach-Object { $_.Item })
            $resultado.Ok = $true
            $win.Close()
        } catch { Show-GuiHandlerError -Contexto 'Aplicar seleção' -ErroObj $_ }
    }.GetNewClosure())
    $bCancelar.Add_Click({ param($s, $e)
        try { $win.Close() } catch { Show-GuiHandlerError -Contexto 'Cancelar seleção' -ErroObj $_ }
    }.GetNewClosure())

    $win.Content = $raiz
    [void]$win.ShowDialog()
    if (-not $resultado.Ok) { return $null }
    return @($resultado.Itens)
}

# Janela de confirmação com resumo. Devolve $true se o usuário confirmar.
function Show-GuiConfirmacao {
    param([string]$Titulo, [string]$Texto, [string]$TextoBotao = 'Executar', [bool]$Perigosa = $false, $Tema, $Dono = $null)
    if (-not $Tema) { $Tema = Get-GuiTemaDefault }
    $win = New-GuiJanela -Titulo $Titulo -Largura 560 -Altura 480 -Tema $Tema -Dono $Dono

    $raiz = New-Object System.Windows.Controls.Grid
    $raiz.Margin = '18'
    foreach ($h in '*','Auto') {
        $rd = New-Object System.Windows.Controls.RowDefinition
        $rd.Height = if ($h -eq '*') { New-Object System.Windows.GridLength(1, [System.Windows.GridUnitType]::Star) } else { 'Auto' }
        [void]$raiz.RowDefinitions.Add($rd)
    }
    $scroll = New-Object System.Windows.Controls.ScrollViewer
    $scroll.VerticalScrollBarVisibility = 'Auto'
    $lbl = New-Object System.Windows.Controls.TextBlock
    $lbl.Text = $Texto
    $lbl.TextWrapping = 'Wrap'
    $scroll.Content = $lbl
    [void]$raiz.Children.Add($scroll)

    $rodape = New-Object System.Windows.Controls.StackPanel
    $rodape.Orientation = 'Horizontal'
    $rodape.HorizontalAlignment = 'Right'
    $rodape.Margin = '0,14,0,0'
    $bCancelar = New-GuiBotao -Janela $win -Texto 'Cancelar'
    $bCancelar.IsCancel = $true
    $bOk = New-GuiBotao -Janela $win -Texto $TextoBotao -Primario
    $bOk.IsDefault = $true
    if ($Perigosa) { $bOk.SetResourceReference([System.Windows.Controls.Button]::BackgroundProperty, 'Danger') }
    [void]$rodape.Children.Add($bCancelar)
    [void]$rodape.Children.Add($bOk)
    [System.Windows.Controls.Grid]::SetRow($rodape, 1)
    [void]$raiz.Children.Add($rodape)

    $resultado = @{ Ok = $false }
    $bOk.Add_Click({ param($s, $e)
        try { $resultado.Ok = $true; $win.Close() } catch { Show-GuiHandlerError -Contexto 'Confirmar' -ErroObj $_ }
    }.GetNewClosure())
    $bCancelar.Add_Click({ param($s, $e)
        try { $win.Close() } catch { Show-GuiHandlerError -Contexto 'Cancelar' -ErroObj $_ }
    }.GetNewClosure())

    $win.Content = $raiz
    [void]$win.ShowDialog()
    return [bool]$resultado.Ok
}

# Entrada de um valor: texto normal ou senha mascarada. Cancelar devolve vazio.
# Senha: devolve SecureString, nunca gravada em arquivo nem em log.
function Read-GuiEntrada {
    param([string]$Prompt = '', [switch]$Secreta, [string]$Titulo = 'Informe o valor', $Dono = $null)
    $win = New-GuiJanela -Titulo $Titulo -Largura 480 -Altura 230 -Tema (Get-GuiTemaDefault) -Dono $Dono

    $raiz = New-Object System.Windows.Controls.Grid
    $raiz.Margin = '18'
    foreach ($h in 'Auto','*','Auto') {
        $rd = New-Object System.Windows.Controls.RowDefinition
        $rd.Height = if ($h -eq '*') { New-Object System.Windows.GridLength(1, [System.Windows.GridUnitType]::Star) } else { 'Auto' }
        [void]$raiz.RowDefinitions.Add($rd)
    }
    $lbl = New-Object System.Windows.Controls.TextBlock
    $lbl.Text = if ($Prompt) { $Prompt } else { 'Digite o valor:' }
    $lbl.TextWrapping = 'Wrap'
    $lbl.Margin = '0,0,0,10'
    [System.Windows.Controls.Grid]::SetRow($lbl, 0)
    [void]$raiz.Children.Add($lbl)

    if ($Secreta) {
        $campo = New-Object System.Windows.Controls.PasswordBox
    } else {
        $campo = New-Object System.Windows.Controls.TextBox
    }
    $campo.VerticalAlignment = 'Top'
    [System.Windows.Controls.Grid]::SetRow($campo, 1)
    [void]$raiz.Children.Add($campo)

    $rodape = New-Object System.Windows.Controls.StackPanel
    $rodape.Orientation = 'Horizontal'
    $rodape.HorizontalAlignment = 'Right'
    $rodape.Margin = '0,12,0,0'
    $bCancelar = New-GuiBotao -Janela $win -Texto 'Cancelar'
    $bCancelar.IsCancel = $true
    $bOk = New-GuiBotao -Janela $win -Texto 'OK' -Primario
    $bOk.IsDefault = $true
    [void]$rodape.Children.Add($bCancelar)
    [void]$rodape.Children.Add($bOk)
    [System.Windows.Controls.Grid]::SetRow($rodape, 2)
    [void]$raiz.Children.Add($rodape)

    $resultado = @{ Ok = $false }
    $bOk.Add_Click({ param($s, $e)
        try { $resultado.Ok = $true; $win.Close() } catch { Show-GuiHandlerError -Contexto 'Confirmar entrada' -ErroObj $_ }
    }.GetNewClosure())
    $bCancelar.Add_Click({ param($s, $e)
        try { $win.Close() } catch { Show-GuiHandlerError -Contexto 'Cancelar entrada' -ErroObj $_ }
    }.GetNewClosure())
    $win.Add_Loaded({ param($s, $e) try { [void]$campo.Focus() } catch { } }.GetNewClosure())

    $win.Content = $raiz
    [void]$win.ShowDialog()
    if ($Secreta) {
        if (-not $resultado.Ok) { return (New-Object System.Security.SecureString) }
        return $campo.SecurePassword
    }
    if (-not $resultado.Ok) { return '' }
    return [string]$campo.Text
}

# Substitui Read-Host no runspace de fundo (que não tem console). Perguntas "(s/n)"
# viram Sim/Não; pedidos de senha viram janela mascarada; o resto vira janela de texto.
function Read-GuiHost {
    param([Parameter(Position = 0)][string]$Prompt, [switch]$AsSecureString)
    if ($Prompt -match '\(s/n\)\s*$') {
        $pergunta = $Prompt -replace '\s*\(s/n\)\s*$', ''
        $r = [System.Windows.MessageBox]::Show($pergunta, 'Confirmação', 'YesNo', 'Question')
        if ($r -eq 'Yes') { return 's' } else { return 'n' }
    }
    if ($AsSecureString) { return (Read-GuiEntrada -Prompt $Prompt -Secreta -Titulo 'Senha') }
    return (Read-GuiEntrada -Prompt $Prompt -Titulo 'Informe o valor')
}

# ----------------------------------------------------------------------------
# Tratamento de erro dos manipuladores: log + aviso visível, sem derrubar o Dispatcher
# ----------------------------------------------------------------------------
function Show-GuiHandlerError {
    param($Contexto, $ErroObj)
    try { Write-Log "ERRO na GUI ($Contexto): $($ErroObj.Exception.Message)" -Type Error } catch { }
    try { [System.Windows.MessageBox]::Show("Ocorreu um erro em '$Contexto':`n`n$($ErroObj.Exception.Message)", 'Erro', 'OK', 'Error') | Out-Null } catch { }
}

# Prévia em texto do comando equivalente. Parâmetros de senha aparecem como <oculta>.
function ConvertTo-GuiCommandPreview {
    param([string]$FuncName, [hashtable]$Splat, [string[]]$Extra, [bool]$Simular, [string[]]$Senhas = @())
    $escapar = { param($s) "'" + ([string]$s -replace "'", "''") + "'" }
    $partes = New-Object System.Collections.Generic.List[string]
    $partes.Add($FuncName)
    foreach ($k in $Splat.Keys) {
        $v = $Splat[$k]
        if ($Senhas -contains $k) { $partes.Add("-$k '<oculta>'"); continue }
        if ($v -is [bool]) {
            if ($v) { $partes.Add("-$k") }
        } elseif ($v -is [array]) {
            $itens = @($v | ForEach-Object { & $escapar $_ }) -join ', '
            $partes.Add("-$k @($itens)")
        } else {
            $partes.Add("-$k " + (& $escapar $v))
        }
    }
    if ($Extra -and $Extra.Count) { $partes.AddRange([string[]]$Extra) }
    if ($Simular) { $partes.Add('-WhatIf') }
    return ($partes -join ' ')
}

# Resumo legível do que a ação destrutiva vai fazer (mostrado antes da confirmação).
function ConvertTo-GuiResumoExec {
    param($Acao, [hashtable]$Splat, [string[]]$Extra, [string[]]$Senhas = @(), [bool]$Simular)
    $l = New-Object System.Collections.Generic.List[string]
    $l.Add("Ação: $($Acao.Titulo)")
    $l.Add("Função: $($Acao.Func)")
    $l.Add('')
    $l.Add('O que vai acontecer:')
    $l.Add($(if ($Acao.Desc) { [string]$Acao.Desc } else { 'Sem descrição disponível.' }))
    $l.Add('')
    if ($Splat.Count -gt 0) {
        $l.Add('Parâmetros:')
        foreach ($k in $Splat.Keys) {
            $v = $Splat[$k]
            if ($Senhas -contains $k) { $txt = '(senha informada, oculta)' }
            elseif ($v -is [bool]) { $txt = $(if ($v) { 'sim' } else { 'não' }) }
            elseif ($v -is [array]) { $txt = (@($v | ForEach-Object { if ($_.Nome) { $_.Nome } else { [string]$_ } })) -join ', ' }
            else { $txt = [string]$v }
            $l.Add("  - ${k}: $txt")
        }
        $l.Add('')
    }
    if ($Extra -and $Extra.Count) { $l.Add("Argumentos extras: $($Extra -join ' ')"); $l.Add('') }
    if ($Simular) {
        $l.Add('MODO SIMULAÇÃO: nada será alterado. O log mostra o que seria feito.')
    } else {
        $l.Add('ATENÇÃO: execução REAL. Esta ação altera o computador e pode não ser reversível.')
    }
    return ($l -join "`r`n")
}

# Nível de log para o filtro: 'erro', 'aviso', 'info' ou 'sucesso' (já vem de ConvertTo-GuiNivelLog).

# ----------------------------------------------------------------------------
# Janela de preferências (modal). Devolve $true se salvou.
# ----------------------------------------------------------------------------
function Show-GuiPreferences {
    param($Owner, $Prefs, $Catalogo)
    $tema = Get-GuiTemaPorNome -Nome $Prefs.Tema
    $win = New-GuiJanela -Titulo 'Personalizar' -Largura 420 -Altura 560 -Tema $tema -Dono $Owner

    $scroll = New-Object System.Windows.Controls.ScrollViewer
    $scroll.VerticalScrollBarVisibility = 'Auto'
    $painel = New-Object System.Windows.Controls.StackPanel
    $painel.Margin = '18'
    $scroll.Content = $painel

    $rotulo = {
        param([string]$t)
        $x = New-Object System.Windows.Controls.TextBlock
        $x.Text = $t; $x.FontWeight = 'SemiBold'; $x.Margin = '0,10,0,4'
        [void]$painel.Children.Add($x)
    }
    # Itens na ordem alfabética dos rótulos; o valor interno fica na mesma posição.
    $temaRotulos = @('Alto contraste','Automático (segue o Windows)','Claro','Escuro')
    $temaValores = @('AltoContraste','Automatico','Claro','Escuro')
    & $rotulo 'Tema'
    $cboTema = New-Object System.Windows.Controls.ComboBox
    foreach ($r in $temaRotulos) { [void]$cboTema.Items.Add($r) }
    [void]$painel.Children.Add($cboTema)

    & $rotulo 'Tamanho da fonte'
    $cboFonte = New-Object System.Windows.Controls.ComboBox
    foreach ($r in 'Pequeno','Médio','Grande') { [void]$cboFonte.Items.Add($r) }
    [void]$painel.Children.Add($cboFonte)

    $chkConfirmar = New-Object System.Windows.Controls.CheckBox
    $chkConfirmar.Content = 'Confirmar antes de ações destrutivas'
    $chkAutoScroll = New-Object System.Windows.Controls.CheckBox
    $chkAutoScroll.Content = 'Rolar o log automaticamente'
    $chkOcultarDestr = New-Object System.Windows.Controls.CheckBox
    $chkOcultarDestr.Content = 'Ocultar ações destrutivas da lista'
    $chkConfirmar.Margin = '0,10,0,2'
    [void]$painel.Children.Add($chkConfirmar)
    [void]$painel.Children.Add($chkAutoScroll)
    [void]$painel.Children.Add($chkOcultarDestr)

    & $rotulo 'Ocultar categorias inteiras'
    $chksCategorias = @{}
    $categoriasOcultasAtuais = @($Prefs.CategoriasOcultas)
    if ($Catalogo) {
        foreach ($cat in ($Catalogo | Select-Object -ExpandProperty Cat -Unique | Sort-Object)) {
            $chk = New-Object System.Windows.Controls.CheckBox
            $chk.Content = $cat
            $chk.IsChecked = ($categoriasOcultasAtuais -contains $cat)
            [void]$painel.Children.Add($chk)
            $chksCategorias[$cat] = $chk
        }
    }

    $idxTema = [array]::IndexOf($temaValores, [string]$Prefs.Tema)
    if ($idxTema -lt 0) { $idxTema = [array]::IndexOf($temaValores, 'Automatico') }
    $cboTema.SelectedIndex  = $idxTema
    $cboFonte.SelectedIndex = switch ([int]$Prefs.Fonte) { 12 {0} 16 {2} default {1} }
    $chkConfirmar.IsChecked    = [bool]$Prefs.ConfirmarDestrutivas
    $chkAutoScroll.IsChecked   = [bool]$Prefs.AutoScrollLog
    $chkOcultarDestr.IsChecked = [bool]$Prefs.OcultarDestrutivas

    $rodape = New-Object System.Windows.Controls.StackPanel
    $rodape.Orientation = 'Horizontal'
    $rodape.HorizontalAlignment = 'Right'
    $rodape.Margin = '0,18,0,0'
    $btnCancelar = New-GuiBotao -Janela $win -Texto 'Cancelar'
    $btnOk = New-GuiBotao -Janela $win -Texto 'Salvar' -Primario
    [void]$rodape.Children.Add($btnCancelar)
    [void]$rodape.Children.Add($btnOk)
    [void]$painel.Children.Add($rodape)

    $result = @{ Salvou = $false }
    $btnOk.Add_Click({ param($s, $e)
        try {
            $Prefs.Tema = $temaValores[$cboTema.SelectedIndex]
            $Prefs.Fonte = switch ($cboFonte.SelectedIndex) { 0 {12} 2 {16} default {14} }
            $Prefs.ConfirmarDestrutivas = [bool]$chkConfirmar.IsChecked
            $Prefs.AutoScrollLog        = [bool]$chkAutoScroll.IsChecked
            $Prefs.OcultarDestrutivas   = [bool]$chkOcultarDestr.IsChecked
            $Prefs.CategoriasOcultas    = @($chksCategorias.Keys | Where-Object { [bool]$chksCategorias[$_].IsChecked })
            $result.Salvou = $true
            $win.Close()
        } catch { Show-GuiHandlerError -Contexto 'Salvar preferências' -ErroObj $_ }
    }.GetNewClosure())
    $btnCancelar.Add_Click({ param($s, $e)
        try { $win.Close() } catch { Show-GuiHandlerError -Contexto 'Cancelar preferências' -ErroObj $_ }
    }.GetNewClosure())

    $win.Content = $scroll
    [void]$win.ShowDialog()
    return $result.Salvou
}

# ----------------------------------------------------------------------------
# Runspace de fundo com as funções do script + globais essenciais.
# Substituições (só neste runspace; o script principal não muda):
#   Read-Host              -> Read-GuiHost (sem console, usa janelas)
#   Show-CheckboxPicker    -> Show-GuiCheckboxPicker (janela de checkbox única, com tema)
# Read-SenhaConfirmada (MaintenanceColegio) usa Read-Host -AsSecureString, então já é coberta.
# ----------------------------------------------------------------------------
function New-GuiWorkerRunspace {
    $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault2()
    $substituidas = @('Read-Host','Show-CheckboxPicker')
    Get-ChildItem Function:\ | Where-Object { $_.Name -match '-' -and $_.Name -notin $substituidas } | ForEach-Object {
        try { $iss.Commands.Add((New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry($_.Name, $_.Definition))) } catch { }
    }
    $iss.Commands.Add((New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry('Read-Host', (Get-Item Function:\Read-GuiHost).Definition)))
    $iss.Commands.Add((New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry('Show-CheckboxPicker', (Get-Item Function:\Show-GuiCheckboxPicker).Definition)))
    foreach ($vn in 'ScriptConfig','IsWindows11','defaultColors','GuiTemas','GuiEstilosXaml') {
        $v = Get-Variable -Name $vn -Scope Global -ErrorAction SilentlyContinue
        if ($v) { $iss.Variables.Add((New-Object System.Management.Automation.Runspaces.SessionStateVariableEntry($vn, $v.Value, ''))) }
    }
    $rs = [runspacefactory]::CreateRunspace($iss)
    $rs.ApartmentState = 'STA'
    $rs.ThreadOptions  = 'ReuseThread'
    $rs.Open()
    return $rs
}

# Script executado no runspace de fundo. Define o tema para os diálogos e sempre
# ajusta WhatIf nas duas direções (o runspace é reaproveitado entre execuções).
$global:GuiWorkerScript = {
    param($FuncName, $Simular, $Splat, $Extra, $Tema)
    $global:WhatIf = [bool]$Simular
    $WhatIfPreference = [bool]$Simular
    $global:GuiTemaAtivo = $Tema
    # Resultado real da execução, lido pela janela: exceção e código de saída do último comando nativo.
    $global:LASTEXITCODE = 0
    $global:GuiUltimoResultado = [pscustomobject]@{ Excecao = $null; CodigoSaida = 0 }
    try { & $FuncName @Splat @Extra }
    catch {
        $global:GuiUltimoResultado.Excecao = $_.Exception.Message
        Write-Log "ERRO na GUI ao executar $FuncName : $($_.Exception.Message)" -Type Error
    }
    if ($LASTEXITCODE -is [int]) { $global:GuiUltimoResultado.CodigoSaida = $LASTEXITCODE }
}

# ----------------------------------------------------------------------------
# Cartões de status (uma rotina por cartão)
# ----------------------------------------------------------------------------
function New-GuiCard {
    param([string]$Rotina, [string]$Func, $Registro, $Tema, $Janela, $SelecionarAcao)
    $conv = New-Object System.Windows.Media.BrushConverter
    $card = New-Object System.Windows.Controls.Border
    $card.Style = $Janela.FindResource('Cartao')
    $card.Width = 176
    $card.Margin = '0,0,12,12'
    $card.Cursor = [System.Windows.Input.Cursors]::Hand
    $card.Tag = $Func
    $card.ToolTip = "Abrir a ação: $Func"

    $sp = New-Object System.Windows.Controls.StackPanel
    $t1 = New-Object System.Windows.Controls.TextBlock
    $t1.Text = $Rotina
    $t1.FontSize = 15
    $t1.FontWeight = 'SemiBold'
    [void]$sp.Children.Add($t1)

    $t2 = New-Object System.Windows.Controls.TextBlock
    $t2.Foreground = $Janela.FindResource('Muted')
    $t2.Margin = '0,4,0,0'
    $t2.Text = if ($Registro) { "Última: $($Registro.Quando)" } else { 'Nunca executada' }
    [void]$sp.Children.Add($t2)

    $badge = New-Object System.Windows.Controls.Border
    $badge.CornerRadius = '8'
    $badge.Padding = '8,2'
    $badge.Margin = '0,8,0,0'
    $badge.HorizontalAlignment = 'Left'
    $badge.Background = $Janela.FindResource('PanelDark')
    $t3 = New-Object System.Windows.Controls.TextBlock
    $t3.FontSize = 12
    $t3.FontWeight = 'SemiBold'
    switch ([string]$(if ($Registro) { $Registro.Resultado } else { '' })) {
        'sucesso' { $t3.Text = 'Sucesso'; $t3.Foreground = $conv.ConvertFromString([string]$Tema.Sucesso) }
        'aviso'   { $t3.Text = 'Aviso';   $t3.Foreground = $conv.ConvertFromString([string]$Tema.Aviso) }
        'erro'    { $t3.Text = 'Erro';    $t3.Foreground = $conv.ConvertFromString([string]$Tema.Danger) }
        default   { $t3.Text = 'Sem registro'; $t3.Foreground = $Janela.FindResource('Muted') }
    }
    $badge.Child = $t3
    [void]$sp.Children.Add($badge)
    $card.Child = $sp

    $card.Add_MouseLeftButtonUp({ param($s, $e)
        try { & $SelecionarAcao ([string]$s.Tag) }
        catch { Show-GuiHandlerError -Contexto 'Abrir ação pelo cartão' -ErroObj $_ }
    }.GetNewClosure())
    return $card
}

# ----------------------------------------------------------------------------
# Monta e exibe a janela principal (deve rodar em thread STA).
# ----------------------------------------------------------------------------
function Invoke-MaintenanceGuiWindow {
    $catalogo = Get-GuiActionCatalog | Sort-Object Cat, Titulo
    $prefs = Get-GuiPrefs

    $window = [Windows.Markup.XamlReader]::Parse($script:GuiXaml)
    [void]$window.Resources.MergedDictionaries.Add([System.Windows.Markup.XamlReader]::Parse($global:GuiEstilosXaml))
    $F = { param($n) $window.FindName($n) }
    $pnlCards   = & $F 'PnlCards'
    $txtBusca   = & $F 'TxtBusca'
    $chkWhatIf  = & $F 'ChkWhatIf'
    $btnPers    = & $F 'BtnPersonalizar'
    $lstCat     = & $F 'LstCategorias'
    $lstAcoes   = & $F 'LstAcoes'
    $txtAcaoResumo = & $F 'TxtAcaoResumo'
    $detTitulo  = & $F 'TxtDetTitulo'
    $detCat     = & $F 'TxtDetCat'
    $detFunc    = & $F 'TxtDetFunc'
    $detDesc    = & $F 'TxtDetDesc'
    $detAviso   = & $F 'TxtDetAviso'
    $paramsTit  = & $F 'TxtParamsTitulo'
    $pnlParams  = & $F 'PnlParams'
    $cboPresets        = & $F 'CboPresets'
    $btnCarregarPreset = & $F 'BtnCarregarPreset'
    $btnSalvarPreset   = & $F 'BtnSalvarPreset'
    $btnExcluirPreset  = & $F 'BtnExcluirPreset'
    $txtExtra   = & $F 'TxtExtra'
    $txtArgDica = & $F 'TxtArgDica'
    $btnExec    = & $F 'BtnExecutar'
    $btnVerComando = & $F 'BtnVerComando'
    $prgExec    = & $F 'PrgExec'
    $txtStatus  = & $F 'TxtStatus'
    $cboNivel   = & $F 'CboNivel'
    $txtLog     = & $F 'TxtLog'
    $btnCopiarLog   = & $F 'BtnCopiarLog'
    $btnExportarLog = & $F 'BtnExportarLog'
    $btnMarcarTodas   = & $F 'BtnMarcarTodas'
    $btnDesmarcarTodas = & $F 'BtnDesmarcarTodas'
    $txtMarcadas      = & $F 'TxtMarcadas'

    $tema = Set-GuiAppearance -Window $window -Prefs $prefs

    $versaoTxt = if ($global:ScriptConfig -and $global:ScriptConfig.Versao) { " v$($global:ScriptConfig.Versao)" }
                 elseif ($global:ScriptConfig -and $global:ScriptConfig.Version) { " v$($global:ScriptConfig.Version)" }
                 else { '' }
    $window.Title = "Script Supremo de Manutenção$versaoTxt | Colégio Mundo do Saber"
    try {
        $iconPath = Get-GuiAppIconPath -AccentHex $tema.Accent
        if ($iconPath -and (Test-Path -LiteralPath $iconPath)) {
            $bmpIcone = New-Object System.Windows.Media.Imaging.BitmapImage
            $bmpIcone.BeginInit()
            $bmpIcone.CacheOption = 'OnLoad'
            $bmpIcone.UriSource = New-Object System.Uri($iconPath, [System.UriKind]::Absolute)
            $bmpIcone.EndInit()
            $bmpIcone.Freeze()
            $window.Icon = $bmpIcone
        }
    } catch { }

    # Restaura tamanho e posição salvos, com limites mínimos e sem sair da tela.
    if ($prefs.JanelaLargura -and $prefs.JanelaAltura) {
        try {
            $areaUtil = [System.Windows.SystemParameters]::WorkArea
            $window.Width  = [Math]::Max(860, [Math]::Min([double]$prefs.JanelaLargura, $areaUtil.Width))
            $window.Height = [Math]::Max(600, [Math]::Min([double]$prefs.JanelaAltura, $areaUtil.Height))
            if ($null -ne $prefs.JanelaX -and $null -ne $prefs.JanelaY) {
                $x = [double]$prefs.JanelaX
                $y = [double]$prefs.JanelaY
                if ($x -ge $areaUtil.Left -and $x -le ($areaUtil.Right - 100) -and $y -ge $areaUtil.Top -and $y -le ($areaUtil.Bottom - 100)) {
                    $window.WindowStartupLocation = 'Manual'
                    $window.Left = $x
                    $window.Top = $y
                }
            }
            if ([bool]$prefs.JanelaMaximizada) { $window.WindowState = 'Maximized' }
        } catch { }
    }

    $st = @{
        Worker=$null; PS=$null; Handle=$null; Cronometro=$null; StatusBase=''
        LogPath=(Join-Path 'C:\ScriptsLogs' "$env:COMPUTERNAME-ScriptLog.log"); LogPos=0; Pendente=''
        Linhas=(New-Object System.Collections.Generic.List[object]); RunInicio=0; FiltroNivel='todos'
        Selecao=$null; Acao=$null; Simular=$false; ParamControls=@{}; TemaAtual=$tema; Prefs=$prefs
        # Fila de execução (ações marcadas, em sequência) e contadores do resultado geral
        Fila=(New-Object System.Collections.Generic.List[object]); FilaIdx=0; FilaSimular=$false
        FilaTotal=0; FilaOk=0; FilaErros=0; FilaAvisos=0; CronometroFila=$null
    }
    if ($global:ScriptConfig -and $global:ScriptConfig.LogFilePath) { $st.LogPath = $global:ScriptConfig.LogFilePath }

    # Filtro do log: 'todos' ou um nível
    $filtrosLog = @(
        [pscustomobject]@{ Rotulo='Todos';   Nivel='todos' }
        [pscustomobject]@{ Rotulo='Aviso';   Nivel='aviso' }
        [pscustomobject]@{ Rotulo='Erro';    Nivel='erro' }
        [pscustomobject]@{ Rotulo='Info';    Nivel='info' }
        [pscustomobject]@{ Rotulo='Sucesso'; Nivel='sucesso' }
    )
    foreach ($f in $filtrosLog) { [void]$cboNivel.Items.Add($f) }
    $cboNivel.SelectedIndex = 0

    # Adiciona linhas ao log: guarda tudo (para exportar) e mostra as que passam no filtro.
    $anexarLog = {
        param([string]$Texto, [string]$Nivel = '')
        foreach ($linha in ($Texto -split "`r?`n")) {
            if ([string]::IsNullOrWhiteSpace($linha)) { continue }
            $nv = if ($Nivel) { $Nivel } else { ConvertTo-GuiNivelLog -Linha $linha }
            $st.Linhas.Add([pscustomobject]@{ Nivel = $nv; Texto = $linha })
            if ($st.FiltroNivel -eq 'todos' -or $st.FiltroNivel -eq $nv) { $txtLog.AppendText($linha + "`r`n") }
        }
        if ($st.Prefs.AutoScrollLog) { $txtLog.ScrollToEnd() }
    }

    # Redesenha o log inteiro (troca de filtro)
    $renderLog = {
        $sb = New-Object System.Text.StringBuilder
        foreach ($e in $st.Linhas) {
            if ($st.FiltroNivel -eq 'todos' -or $e.Nivel -eq $st.FiltroNivel) { [void]$sb.AppendLine($e.Texto) }
        }
        $txtLog.Text = $sb.ToString()
        $txtLog.ScrollToEnd()
    }

    # Categorias (Todas + distintas, em ordem alfabética, exceto ocultas)
    $preencherCategorias = {
        $sel = '' + $lstCat.SelectedItem
        $lstCat.Items.Clear()
        [void]$lstCat.Items.Add('Todas')
        $ocultas = @($st.Prefs.CategoriasOcultas)
        foreach ($c in ($catalogo | Select-Object -ExpandProperty Cat -Unique | Sort-Object)) {
            if ($ocultas -contains $c) { continue }
            [void]$lstCat.Items.Add($c)
        }
        $lstCat.SelectedItem = if ($sel -and $lstCat.Items.Contains($sel)) {
            $sel
        } elseif (-not $sel -and $st.Prefs.UltimaCategoria -and $lstCat.Items.Contains($st.Prefs.UltimaCategoria)) {
            $st.Prefs.UltimaCategoria
        } else {
            'Todas'
        }
        if (-not $lstCat.SelectedItem) { $lstCat.SelectedIndex = 0 }
    }
    & $preencherCategorias

    # Filtro da lista de ações (busca + categoria + ocultas)
    # Estado de cada ação (marcada e resultado ✓/✗) guardado por Função, para sobreviver ao filtro.
    $st.Marcados = @{}
    $st.Resultados = @{}
    $atualizarMarcadas = {
        try {
            $n = @($lstAcoes.Items | Where-Object { $_.Marcado }).Count
            $txtMarcadas.Text = if ($n) { "$n marcada(s)" } else { '' }
            if (-not $st.Handle) {
                $btnExec.Content = if ($n) { "Executar ($n marcada$(if ($n -gt 1) { 's' }))" } else { 'Executar' }
                $btnExec.IsEnabled = ($n -gt 0) -or ($null -ne $lstAcoes.SelectedItem)
            }
        } catch { Show-GuiHandlerError -Contexto 'Contador de marcadas' -ErroObj $_ }
    }
    $Refiltrar = {
        try {
            # Guarda o estado atual antes de redesenhar a lista
            foreach ($it in $lstAcoes.Items) {
                $st.Marcados[$it.Acao.Func] = [bool]$it.Marcado
                if ($it.Estado -and $it.Estado -ne 'exec') { $st.Resultados[$it.Acao.Func] = @{ Estado = $it.Estado; Cor = $it.ResultadoCor } }
            }
            $termo = ('' + $txtBusca.Text).Trim().ToLower()
            $cat = '' + $lstCat.SelectedItem
            $lstAcoes.Items.Clear()
            foreach ($a in $catalogo) {
                if ($cat -ne 'Todas' -and $a.Cat -ne $cat) { continue }
                if (@($st.Prefs.CategoriasOcultas) -contains $a.Cat) { continue }
                if ($st.Prefs.OcultarDestrutivas -and $a.Destr) { continue }
                if ($termo -and -not (
                        ($a.Titulo.ToLower().Contains($termo)) -or
                        ($a.Desc.ToLower().Contains($termo)) -or
                        ($a.Func.ToLower().Contains($termo)) -or
                        ($a.Cat.ToLower().Contains($termo)))) { continue }
                $cor = if ($a.Destr) { [string]$st.TemaAtual.Danger } else { [string]$st.TemaAtual.Ink }
                $marca = if ($a.Destr) { [string][char]0x26A0 } else { [string][char]0x2022 }
                $item = New-Object GuiAcaoItem
                $item.Titulo = $a.Titulo
                $item.Marca = $marca
                $item.Cor = $cor
                $item.Acao = $a
                $item.Marcado = [bool]$st.Marcados[$a.Func]
                if ($st.Resultados.ContainsKey($a.Func)) {
                    $res = $st.Resultados[$a.Func]
                    $item.Definir([string]$res.Estado, [string]$res.Cor)
                }
                [void]$lstAcoes.Items.Add($item)
            }
            $txtStatus.Text = "$($lstAcoes.Items.Count) ação(ões) listada(s)."
            & $atualizarMarcadas
        } catch { Show-GuiHandlerError -Contexto 'Filtrar ações' -ErroObj $_ }
    }

    # Cartões de status
    $renderCards = {
        $pnlCards.Children.Clear()
        $statusAtual = Get-GuiStatus
        foreach ($rot in $global:GuiRotinas.Keys) {
            $reg = $statusAtual[$rot]
            [void]$pnlCards.Children.Add((New-GuiCard -Rotina $rot -Func $global:GuiRotinas[$rot] -Registro $reg -Tema $st.TemaAtual -Janela $window -SelecionarAcao $selecionarAcao))
        }
    }

    # Seleciona uma ação pela Função (usado pelos cartões)
    $selecionarAcao = {
        param([string]$Func)
        $txtBusca.Text = ''
        $lstCat.SelectedItem = 'Todas'
        & $Refiltrar
        foreach ($item in $lstAcoes.Items) {
            if ($item.Acao.Func -eq $Func) { $lstAcoes.SelectedItem = $item; $lstAcoes.ScrollIntoView($item); break }
        }
    }

    $txtBusca.Add_TextChanged({ param($s, $e) try { & $Refiltrar } catch { Show-GuiHandlerError -Contexto 'Busca' -ErroObj $_ } })
    $lstCat.Add_SelectionChanged({ param($s, $e) try { & $Refiltrar } catch { Show-GuiHandlerError -Contexto 'Trocar categoria' -ErroObj $_ } })

    # Marcar / desmarcar todas as ações visíveis (lista filtrada). Qualquer CheckBox da lista dispara o contador.
    $btnMarcarTodas.Add_Click({ param($s, $e)
        try { foreach ($it in $lstAcoes.Items) { $it.Marcado = $true }; & $atualizarMarcadas }
        catch { Show-GuiHandlerError -Contexto 'Marcar todas' -ErroObj $_ }
    })
    $btnDesmarcarTodas.Add_Click({ param($s, $e)
        try { foreach ($it in $lstAcoes.Items) { $it.Marcado = $false }; & $atualizarMarcadas }
        catch { Show-GuiHandlerError -Contexto 'Desmarcar todas' -ErroObj $_ }
    })
    $manipuladorMarca = [System.Windows.RoutedEventHandler]{ param($s, $e)
        try { & $atualizarMarcadas } catch { Show-GuiHandlerError -Contexto 'Marcar ação' -ErroObj $_ }
    }
    $lstAcoes.AddHandler([System.Windows.Controls.Primitives.ToggleButton]::CheckedEvent, $manipuladorMarca)
    $lstAcoes.AddHandler([System.Windows.Controls.Primitives.ToggleButton]::UncheckedEvent, $manipuladorMarca)

    & $Refiltrar
    & $renderCards

    # Log: nível inicial e troca de filtro
    $cboNivel.Add_SelectionChanged({ param($s, $e)
        try { $st.FiltroNivel = [string]$cboNivel.SelectedItem.Nivel; & $renderLog }
        catch { Show-GuiHandlerError -Contexto 'Filtrar log' -ErroObj $_ }
    })

    # Monta os controles dinâmicos de parâmetros da ação selecionada
    $renderParams = {
        param($a)
        $pnlParams.Children.Clear()
        $st.ParamControls = @{}
        $temParams = ($a.PSObject.Properties.Name -contains 'Params') -and $a.Params
        $paramsTit.Visibility = if ($temParams) { 'Visible' } else { 'Collapsed' }
        if (-not $temParams) { return }
        foreach ($p in $a.Params) {
            $c = $null
            if ($p.Tipo -eq 'switch') {
                $c = New-Object System.Windows.Controls.CheckBox
                $c.Content = $p.Rotulo
                $c.IsChecked = [bool]$p.Default
                $c.Margin = '0,4,0,0'
                [void]$pnlParams.Children.Add($c)
            } else {
                $lbl = New-Object System.Windows.Controls.TextBlock
                $lbl.Text = $p.Rotulo
                $lbl.Margin = '0,8,0,3'
                $lbl.TextWrapping = 'Wrap'
                $lbl.Foreground = $window.FindResource('Muted')
                [void]$pnlParams.Children.Add($lbl)
                switch ($p.Tipo) {
                    'choice' {
                        $c = New-Object System.Windows.Controls.ComboBox
                        foreach ($o in $p.Opcoes) { [void]$c.Items.Add($o) }
                        if ($p.Default) { $c.SelectedItem = $p.Default } elseif ($c.Items.Count) { $c.SelectedIndex = 0 }
                    }
                    'password' {
                        $c = New-Object System.Windows.Controls.PasswordBox
                    }
                    default {
                        $c = New-Object System.Windows.Controls.TextBox
                        $c.Text = [string]$p.Default
                    }
                }
                $c.Margin = '0,0,0,0'

                # Botão "Procurar pasta..." ou "Procurar arquivo(s)..." ao lado de campos com Pasta/Arquivo.
                # NOTA: $p é Hashtable; acesso direto ($p.Pasta) retorna $null se a chave não existir.
                $temBotaoPasta = [bool]$p.Pasta -and ($c -is [System.Windows.Controls.TextBox])
                $temBotaoArquivo = [bool]$p.Arquivo -and ($c -is [System.Windows.Controls.TextBox])
                if ($temBotaoPasta -or $temBotaoArquivo) {
                    $gridPasta = New-Object System.Windows.Controls.Grid
                    $colTxt = New-Object System.Windows.Controls.ColumnDefinition
                    $colTxt.Width = New-Object System.Windows.GridLength(1, [System.Windows.GridUnitType]::Star)
                    $colBtn = New-Object System.Windows.Controls.ColumnDefinition
                    $colBtn.Width = 'Auto'
                    [void]$gridPasta.ColumnDefinitions.Add($colTxt)
                    [void]$gridPasta.ColumnDefinitions.Add($colBtn)
                    [System.Windows.Controls.Grid]::SetColumn($c, 0)
                    [void]$gridPasta.Children.Add($c)

                    $btnPasta = New-Object System.Windows.Controls.Button
                    $btnPasta.Content = if ($temBotaoArquivo) { 'Arquivo' } else { 'Pasta' }
                    $btnPasta.Padding = '8,4'
                    $btnPasta.Margin = '6,0,0,0'
                    $btnPasta.ToolTip = if ($temBotaoArquivo) { 'Procurar arquivo(s)...' } else { 'Procurar pasta...' }
                    $btnPasta.Style = $window.FindResource('BotaoSecundario')
                    [System.Windows.Controls.Grid]::SetColumn($btnPasta, 1)

                    $txtRef = $c
                    $ehListaDePastas = ($p.Tipo -eq 'paths')
                    $ehListaDeArquivos = ($p.Tipo -eq 'files')
                    $ehArquivo = $temBotaoArquivo
                    $btnPasta.Add_Click({ param($s, $e)
                        try {
                            if ($ehArquivo) {
                                $dlg = New-Object System.Windows.Forms.OpenFileDialog
                                $dlg.Title = 'Selecione o(s) arquivo(s)'
                                $dlg.Multiselect = $true
                                $dlg.Filter = 'Vídeos (*.mp4;*.mkv;*.avi;*.mov)|*.mp4;*.mkv;*.avi;*.mov|Todos os arquivos (*.*)|*.*'
                                if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
                                    $selecionados = $dlg.FileNames -join ';'
                                    if ($ehListaDeArquivos -and $txtRef.Text.Trim()) {
                                        $txtRef.Text = $txtRef.Text.TrimEnd(';') + ';' + $selecionados
                                    } else {
                                        $txtRef.Text = $selecionados
                                    }
                                }
                            } else {
                                $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
                                $dlg.Description = 'Selecione a pasta'
                                $dlg.ShowNewFolderButton = $true
                                if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
                                    if ($ehListaDePastas -and $txtRef.Text.Trim()) {
                                        $txtRef.Text = $txtRef.Text.TrimEnd(';') + ';' + $dlg.SelectedPath
                                    } else {
                                        $txtRef.Text = $dlg.SelectedPath
                                    }
                                }
                            }
                        } catch { Show-GuiHandlerError -Contexto 'Procurar pasta ou arquivo' -ErroObj $_ }
                    }.GetNewClosure())

                    [void]$gridPasta.Children.Add($btnPasta)
                    [void]$pnlParams.Children.Add($gridPasta)
                } else {
                    [void]$pnlParams.Children.Add($c)
                }
            }
            # AppObj (só nos checkboxes de "Instalar aplicativos") junta todos os marcados em um único -Apps.
            $st.ParamControls[$p.Nome] = @{ Ctrl=$c; Tipo=$p.Tipo; AppObj=$p.AppObj }

            if ($p.Exemplo) {
                $hint = New-Object System.Windows.Controls.TextBlock
                $hint.Text = $p.Exemplo
                $hint.FontSize = 11
                $hint.FontStyle = 'Italic'
                $hint.TextWrapping = 'Wrap'
                $hint.Margin = '0,2,0,4'
                $hint.Foreground = $window.FindResource('Muted')
                [void]$pnlParams.Children.Add($hint)
            }
        }
    }

    # Presets salvos da ação selecionada
    $AtualizarPresetsCombo = {
        param($a)
        $cboPresets.Items.Clear()
        if (-not $a) { return }
        $presetsDaAcao = @($st.Prefs.Presets | Where-Object { $_.Func -eq $a.Func })
        foreach ($ps in ($presetsDaAcao | Sort-Object Nome)) { [void]$cboPresets.Items.Add($ps.Nome) }
        if ($cboPresets.Items.Count) { $cboPresets.SelectedIndex = 0 }
    }

    # Monta { Splat; Extra; Senhas } a partir dos controles. Senhas ficam só em memória.
    $MontarSplatExtra = {
        $splat = @{}
        $appsMarcados = @()
        $senhas = @()
        foreach ($nome in $st.ParamControls.Keys) {
            $pc = $st.ParamControls[$nome]
            if ($pc.AppObj) {
                if ([bool]$pc.Ctrl.IsChecked) { $appsMarcados += $pc.AppObj }
                continue
            }
            switch ($pc.Tipo) {
                'switch'   { $splat[$nome] = [bool]$pc.Ctrl.IsChecked }
                'choice'   { $v = '' + $pc.Ctrl.SelectedItem; if ($v) { $splat[$nome] = $v } }
                'paths'    { $v = ('' + $pc.Ctrl.Text).Trim(); if ($v) { $splat[$nome] = @($v -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) } }
                'files'    { $v = ('' + $pc.Ctrl.Text).Trim(); if ($v) { $splat[$nome] = @($v -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) } }
                'password' {
                    # Senhas das contas vão como SecureString direto do PasswordBox (sem passar por texto em claro)
                    if ($nome -like 'Senha*') {
                        $sp = $pc.Ctrl.SecurePassword
                        if ($sp -and $sp.Length -gt 0) { $splat[$nome] = $sp; $senhas += $nome }
                    }
                    else { $v = $pc.Ctrl.Password; if ($v) { $splat[$nome] = $v; $senhas += $nome } }
                }
                default    { $v = ('' + $pc.Ctrl.Text).Trim(); if ($v) { $splat[$nome] = $v } }
            }
        }
        if ($appsMarcados.Count) { $splat['Apps'] = $appsMarcados }
        $extra = @()
        $rawExtra = ('' + $txtExtra.Text).Trim()
        if ($rawExtra) { $extra = @($rawExtra -split '\s+') }
        return @{ Splat = $splat; Extra = $extra; Senhas = $senhas }
    }

    $lstAcoes.Add_SelectionChanged({ param($s, $e)
      try {
        $sel = $lstAcoes.SelectedItem
        if (-not $sel) {
            $btnExec.IsEnabled = $false
            $txtAcaoResumo.Text = 'Selecione uma ação à esquerda para ver o que ela faz.'
            return
        }
        $a = $sel.Acao
        $st.Selecao = $a
        $detTitulo.Text = $a.Titulo
        $detCat.Text = "Categoria: $($a.Cat)"
        $detFunc.Text = $a.Func + '()'
        $detDesc.Text = if ($a.Desc) { $a.Desc } else { 'Sem descrição disponível.' }
        $txtAcaoResumo.Text = if ($a.Desc) { "$($a.Titulo): $($a.Desc)" } else { "$($a.Titulo): sem descrição disponível." }
        $detAviso.Text = if ($a.Destr) { 'Ação destrutiva. Confira o resumo antes de executar.' } else { '' }
        # Simular marcado por padrão em ações destrutivas (continua editável)
        if ($a.Destr) { $chkWhatIf.IsChecked = $true }
        $txtExtra.Text = ''
        & $renderParams $a
        & $AtualizarPresetsCombo $a
        $temParams = ($a.PSObject.Properties.Name -contains 'Params') -and $a.Params
        $txtArgDica.Text = if ($temParams) {
            'Use os campos acima (mais simples) ou digite parâmetros extras, se souber a sintaxe.'
        } else {
            'Deixe em branco, a menos que saiba os parâmetros aceitos por esta função.'
        }
        $txtStatus.Text = ''
        $btnExec.IsEnabled = $true
      } catch { Show-GuiHandlerError -Contexto 'Selecionar ação' -ErroObj $_ }
    })

    # Duplo clique numa ação SEM parâmetros executa direto (ações com parâmetros pedem o botão).
    $lstAcoes.Add_MouseLeftButtonDown({ param($s, $e)
        try {
            if ($e.ClickCount -ne 2) { return }
            $origem = $e.OriginalSource
            while ($origem -and -not ($origem -is [System.Windows.Controls.ListBoxItem])) {
                $origem = [System.Windows.Media.VisualTreeHelper]::GetParent($origem)
            }
            if (-not $origem) { return }
            $sel = $lstAcoes.SelectedItem
            if (-not $sel) { return }
            $temParams = ($sel.Acao.PSObject.Properties.Name -contains 'Params') -and $sel.Acao.Params
            if (-not $temParams -and $btnExec.IsEnabled) {
                $btnExec.RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Button]::ClickEvent)))
            }
        } catch { Show-GuiHandlerError -Contexto 'Duplo clique na ação' -ErroObj $_ }
    })

    # Executar: confirmação com resumo para ações destrutivas, depois runspace de fundo.
    # Parâmetros padrão de uma ação (checkboxes vazios por padrão, então só entram os valores default).
    $ParamsPadrao = {
        param($a)
        $splat = @{}
        $temParams = ($a.PSObject.Properties.Name -contains 'Params') -and $a.Params
        $apps = @()
        if ($temParams) {
            foreach ($p in $a.Params) {
                if ($p.AppObj) { if ([bool]$p.Default) { $apps += $p.AppObj }; continue }
                switch ($p.Tipo) {
                    'switch'   { $splat[$p.Nome] = [bool]$p.Default }
                    'password' { }
                    'paths'    { if ($p.Default) { $splat[$p.Nome] = @(('' + $p.Default) -split ';' | Where-Object { $_ }) } }
                    'files'    { if ($p.Default) { $splat[$p.Nome] = @(('' + $p.Default) -split ';' | Where-Object { $_ }) } }
                    default    { if ($p.Default) { $splat[$p.Nome] = $p.Default } }
                }
            }
        }
        if ($apps.Count) { $splat['Apps'] = $apps }
        return @{ Splat = $splat; Extra = @(); Senhas = @() }
    }

    # Monta a fila: as ações marcadas (na ordem da lista) ou, se nenhuma estiver marcada, a ação selecionada.
    # A ação selecionada usa os parâmetros da tela; as outras usam os padrões da ação.
    $montarFila = {
        $fila = New-Object System.Collections.Generic.List[object]
        $marcadas = @($lstAcoes.Items | Where-Object { $_.Marcado } | ForEach-Object { $_.Acao })
        if ($marcadas.Count -eq 0 -and $st.Selecao) { $marcadas = @($st.Selecao) }
        foreach ($a in $marcadas) {
            $ehSelecionada = ($st.Selecao -and $a.Func -eq $st.Selecao.Func)
            $m = if ($ehSelecionada) { & $MontarSplatExtra } else { & $ParamsPadrao $a }
            # Install-Applications sem -Apps instalaria TUDO: sem app marcado, a ação é pulada.
            if ($a.Func -eq 'Install-Applications' -and -not $m.Splat.ContainsKey('Apps')) {
                & $anexarLog "[Warning] $($a.Titulo): nenhum aplicativo marcado. Ação pulada." 'aviso'
                continue
            }
            $fila.Add([pscustomobject]@{ Acao = $a; Splat = $m.Splat; Extra = $m.Extra; Senhas = $m.Senhas })
        }
        return ,$fila
    }

    # Acha o item da lista (ação) pela Função e troca a marca ✓/✗ ou "em execução".
    $marcarItem = {
        param([string]$Func, [string]$Estado, [string]$Cor)
        $st.Resultados[$Func] = @{ Estado = $Estado; Cor = $Cor }
        foreach ($it in $lstAcoes.Items) {
            if ($it.Acao.Func -eq $Func) { $it.Definir($Estado, $Cor) }
        }
    }

    # Encerra a fila: restaura botões e mostra o resultado geral.
    $finalizarFila = {
        $prgExec.IsIndeterminate = $false
        $prgExec.Visibility = 'Collapsed'
        $tempoTxt = if ($st.CronometroFila) { ' (' + $st.CronometroFila.Elapsed.ToString('mm\:ss') + ')' } else { '' }
        $st.Fila = New-Object System.Collections.Generic.List[object]
        $st.FilaIdx = 0
        $st.Acao = $null
        & $atualizarMarcadas
        $geral = if ($st.FilaErros -gt 0) { 'erro' } elseif ($st.FilaAvisos -gt 0) { 'aviso' } else { 'sucesso' }
        $resumoFila = "$($st.FilaTotal) ação(ões): $($st.FilaOk) ✓, $($st.FilaErros) ✗."
        switch ($geral) {
            'erro'  { $txtStatus.Text = "Concluído com falhas. $resumoFila$tempoTxt Veja o log."; $txtStatus.Foreground = $window.FindResource('Danger') }
            'aviso' { $txtStatus.Text = "Concluído com avisos. $resumoFila$tempoTxt Veja o log."; $txtStatus.Foreground = $window.FindResource('Aviso') }
            default { $txtStatus.Text = "Concluído. $resumoFila$tempoTxt"; $txtStatus.Foreground = $window.FindResource('Ink') }
        }
        & $anexarLog ">>> Fim da fila: $resumoFila$tempoTxt" 'info'
    }

    # Inicia a próxima ação da fila no runspace de fundo (ou encerra a fila).
    $iniciarProximo = {
        if ($st.FilaIdx -ge $st.Fila.Count) { & $finalizarFila; return }
        $item = $st.Fila[$st.FilaIdx]
        $a = $item.Acao
        $st.Acao = $a
        $n = $st.FilaIdx + 1
        $modo = if ($st.FilaSimular) { ' (SIMULAÇÃO)' } else { '' }
        $st.StatusBase = "Executando $n de $($st.Fila.Count): $($a.Titulo)$modo..."
        $txtStatus.Text = $st.StatusBase
        $txtStatus.Foreground = $window.FindResource('Muted')
        & $marcarItem $a.Func 'exec' ([string]$st.TemaAtual.Func)
        & $anexarLog ">>> $($a.Titulo) -> $($a.Func)$modo" 'info'
        try {
            if (-not $st.Worker) { $st.Worker = New-GuiWorkerRunspace }
            $st.RunInicio = $st.Linhas.Count
            $st.PS = [powershell]::Create()
            $st.PS.Runspace = $st.Worker
            [void]$st.PS.AddScript($global:GuiWorkerScript).AddArgument($a.Func).AddArgument($st.FilaSimular).AddArgument($item.Splat).AddArgument($item.Extra).AddArgument($st.TemaAtual)
            $st.Handle = $st.PS.BeginInvoke()
            $st.Cronometro = [System.Diagnostics.Stopwatch]::StartNew()
        } catch {
            # Falha ao iniciar: conta como ✗ e segue para a próxima
            $st.Handle = $null
            & $anexarLog ("[Error] Falha ao iniciar $($a.Titulo): " + $_.Exception.Message) 'erro'
            & $marcarItem $a.Func 'erro' ([string]$st.TemaAtual.Danger)
            $st.FilaErros = [int]$st.FilaErros + 1
            $st.FilaIdx = [int]$st.FilaIdx + 1
            & $iniciarProximo
            return
        }
        $prgExec.Visibility = 'Visible'
        $prgExec.IsIndeterminate = $true
        $btnExec.IsEnabled = $false
        $btnExec.Content = 'Executando...'
    }

    # Executar: confirmação única com o resumo da fila (se houver destrutivas), depois a fila no runspace de fundo.
    $executar = {
        if ($st.Handle -or $st.Fila.Count -gt 0) { return }
        $fila = & $montarFila
        if ($fila.Count -eq 0) { $txtStatus.Text = 'Nada para executar. Marque ações na lista ou selecione uma.'; return }
        $simular = [bool]$chkWhatIf.IsChecked
        $temDestrutiva = @($fila | Where-Object { $_.Acao.Destr }).Count -gt 0
        if ($temDestrutiva -and $st.Prefs.ConfirmarDestrutivas) {
            $linhas = @($fila | ForEach-Object { "- $($_.Acao.Titulo)  [$($_.Acao.Func)]" })
            $modoTxt = if ($simular) { 'Modo: SIMULAÇÃO (nada será alterado).' } else { 'Modo: EXECUÇÃO REAL. As alterações serão feitas no computador.' }
            $resumo = "Ações a executar em sequência ($($fila.Count)):`n" + ($linhas -join "`n") + "`n`n" + $modoTxt
            $textoBtn = if ($simular) { 'Simular' } else { 'Executar' }
            $ok = Show-GuiConfirmacao -Titulo 'Confirmar ações' -Texto $resumo -TextoBotao $textoBtn -Perigosa (-not $simular) -Tema $st.TemaAtual -Dono $window
            if (-not $ok) { $txtStatus.Text = 'Execução cancelada.'; return }
        }
        $st.Fila = $fila
        $st.FilaIdx = 0
        $st.FilaSimular = $simular
        $st.Simular = $simular
        $st.FilaTotal = $fila.Count
        $st.FilaOk = 0; $st.FilaErros = 0; $st.FilaAvisos = 0
        $st.CronometroFila = [System.Diagnostics.Stopwatch]::StartNew()
        & $iniciarProximo
    }

    $btnExec.Add_Click({ param($s, $e)
        try { & $executar } catch { Show-GuiHandlerError -Contexto 'Executar ação' -ErroObj $_ }
    })

    # Personalizar
    $btnPers.Add_Click({ param($s, $e)
        try {
            if (Show-GuiPreferences -Owner $window -Prefs $st.Prefs -Catalogo $catalogo) {
                Save-GuiPrefs -Prefs $st.Prefs
                $st.TemaAtual = Set-GuiAppearance -Window $window -Prefs $st.Prefs
                & $preencherCategorias
                & $Refiltrar
                & $renderCards
                $txtStatus.Text = 'Preferências aplicadas.'
            }
        } catch { Show-GuiHandlerError -Contexto 'Abrir Personalizar' -ErroObj $_ }
    })

    # Presets (sem senha: senhas nunca são gravadas em arquivo)
    $btnCarregarPreset.Add_Click({ param($s, $e)
        try {
            $a = $st.Selecao
            if (-not $a) { return }
            $nomePreset = '' + $cboPresets.SelectedItem
            if (-not $nomePreset) { return }
            $preset = $st.Prefs.Presets | Where-Object { $_.Func -eq $a.Func -and $_.Nome -eq $nomePreset } | Select-Object -First 1
            if (-not $preset) { return }
            foreach ($nomeParam in $st.ParamControls.Keys) {
                $pc = $st.ParamControls[$nomeParam]
                if ($pc.AppObj) {
                    $appsSalvos = @($preset.Splat.Apps)
                    $pc.Ctrl.IsChecked = [bool]($appsSalvos | Where-Object { $_.Id -eq $pc.AppObj.Id })
                    continue
                }
                $valor = $preset.Splat.$nomeParam
                switch ($pc.Tipo) {
                    'switch'   { $pc.Ctrl.IsChecked = [bool]$valor }
                    'choice'   { if ($valor) { $pc.Ctrl.SelectedItem = [string]$valor } }
                    'paths'    { $pc.Ctrl.Text = if ($valor) { (@($valor) -join ';') } else { '' } }
                    'files'    { $pc.Ctrl.Text = if ($valor) { (@($valor) -join ';') } else { '' } }
                    'password' { }
                    default    { $pc.Ctrl.Text = [string]$valor }
                }
            }
            $txtExtra.Text = [string]$preset.Extra
            $chkWhatIf.IsChecked = [bool]$preset.Simular
            $txtStatus.Text = "Preset '$nomePreset' carregado."
        } catch { Show-GuiHandlerError -Contexto 'Carregar preset' -ErroObj $_ }
    })

    $btnSalvarPreset.Add_Click({ param($s, $e)
        try {
            $a = $st.Selecao
            if (-not $a) { return }
            $nome = Read-GuiEntrada -Prompt 'Nome do preset (ex.: "Fotos, só JPG"):' -Titulo 'Salvar preset' -Dono $window
            $nome = ('' + $nome).Trim()
            if (-not $nome) { return }
            $montado = & $MontarSplatExtra
            # Senhas não entram no preset (ficariam gravadas no gui-prefs.json)
            $splatSemSenha = @{}
            foreach ($k in $montado.Splat.Keys) { if ($montado.Senhas -notcontains $k) { $splatSemSenha[$k] = $montado.Splat[$k] } }
            $jaExiste = $st.Prefs.Presets | Where-Object { $_.Func -eq $a.Func -and $_.Nome -eq $nome }
            if ($jaExiste) {
                $r = [System.Windows.MessageBox]::Show("Já existe um preset '$nome' para esta ação. Substituir?", 'Preset existente', 'YesNo', 'Question')
                if ($r -ne 'Yes') { return }
                $st.Prefs.Presets = @($st.Prefs.Presets | Where-Object { -not ($_.Func -eq $a.Func -and $_.Nome -eq $nome) })
            }
            $novoPreset = [pscustomobject]@{ Func=$a.Func; Nome=$nome; Splat=$splatSemSenha; Extra=($montado.Extra -join ' '); Simular=[bool]$chkWhatIf.IsChecked }
            $st.Prefs.Presets = @($st.Prefs.Presets) + $novoPreset
            Save-GuiPrefs -Prefs $st.Prefs
            & $AtualizarPresetsCombo $a
            $cboPresets.SelectedItem = $nome
            $txtStatus.Text = "Preset '$nome' salvo."
        } catch { Show-GuiHandlerError -Contexto 'Salvar preset' -ErroObj $_ }
    })

    $btnExcluirPreset.Add_Click({ param($s, $e)
        try {
            $a = $st.Selecao
            if (-not $a) { return }
            $nomePreset = '' + $cboPresets.SelectedItem
            if (-not $nomePreset) { return }
            $r = [System.Windows.MessageBox]::Show("Excluir o preset '$nomePreset'?", 'Confirmar exclusão', 'YesNo', 'Warning')
            if ($r -ne 'Yes') { return }
            $st.Prefs.Presets = @($st.Prefs.Presets | Where-Object { -not ($_.Func -eq $a.Func -and $_.Nome -eq $nomePreset) })
            Save-GuiPrefs -Prefs $st.Prefs
            & $AtualizarPresetsCombo $a
            $txtStatus.Text = "Preset '$nomePreset' excluído."
        } catch { Show-GuiHandlerError -Contexto 'Excluir preset' -ErroObj $_ }
    })

    # Mostra o comando equivalente (senhas ocultas) sem executar nada
    $btnVerComando.Add_Click({ param($s, $e)
        try {
            $a = $st.Selecao
            if (-not $a) { return }
            $montado = & $MontarSplatExtra
            $cmd = ConvertTo-GuiCommandPreview -FuncName $a.Func -Splat $montado.Splat -Extra $montado.Extra -Simular ([bool]$chkWhatIf.IsChecked) -Senhas $montado.Senhas
            [System.Windows.MessageBox]::Show($cmd, 'Comando equivalente', 'OK', 'Information') | Out-Null
        } catch { Show-GuiHandlerError -Contexto 'Ver comando equivalente' -ErroObj $_ }
    })

    # Copiar log (texto visível no filtro atual)
    $btnCopiarLog.Add_Click({ param($s, $e)
        try {
            if ($txtLog.Text) {
                [System.Windows.Clipboard]::SetText($txtLog.Text)
                $txtStatus.Text = 'Log copiado para a área de transferência.'
            }
        } catch { Show-GuiHandlerError -Contexto 'Copiar log' -ErroObj $_ }
    })

    # Exportar log completo (todas as linhas, independente do filtro)
    $btnExportarLog.Add_Click({ param($s, $e)
        try {
            $dlg = New-Object Microsoft.Win32.SaveFileDialog
            $dlg.Filter = 'Texto (*.txt)|*.txt'
            $dlg.FileName = "log-script-supremo-$(Get-Date -Format 'yyyyMMdd-HHmm').txt"
            if ($dlg.ShowDialog($window) -eq $true) {
                $linhas = @($st.Linhas | ForEach-Object { $_.Texto })
                Set-Content -LiteralPath $dlg.FileName -Value $linhas -Encoding UTF8
                $txtStatus.Text = "Log exportado: $($dlg.FileName)"
            }
        } catch { Show-GuiHandlerError -Contexto 'Exportar log' -ErroObj $_ }
    })

    # Atalhos: Ctrl+F busca; Enter executa (fora de campos de texto); Ctrl+Enter executa de qualquer lugar; Esc fecha.
    $window.Add_KeyDown({ param($s, $e)
        try {
            $ctrl = (([int][System.Windows.Input.Keyboard]::Modifiers) -band ([int][System.Windows.Input.ModifierKeys]::Control)) -ne 0
            $origem = $e.OriginalSource
            if ($ctrl -and $e.Key -eq 'F') {
                [void]$txtBusca.Focus()
                $txtBusca.SelectAll()
                $e.Handled = $true
            } elseif ($ctrl -and $e.Key -eq 'Return') {
                if ($btnExec.IsEnabled) { $btnExec.RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Button]::ClickEvent))) }
                $e.Handled = $true
            } elseif ($e.Key -eq 'Return' -and -not $ctrl) {
                $executavel = ($origem -eq $txtBusca) -or ($origem -is [System.Windows.Controls.ListBox]) -or ($origem -is [System.Windows.Controls.ListBoxItem]) -or ($origem -is [System.Windows.Window])
                if ($executavel -and $btnExec.IsEnabled) {
                    $btnExec.RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Button]::ClickEvent)))
                    $e.Handled = $true
                }
            } elseif ($e.Key -eq 'Escape') {
                $window.Close()
                $e.Handled = $true
            }
        } catch { Show-GuiHandlerError -Contexto 'Atalho de teclado' -ErroObj $_ }
    })

    # Runspace de fundo: lê o log ao vivo e detecta o fim da execução
    $timer = New-Object System.Windows.Threading.DispatcherTimer
    $timer.Interval = [TimeSpan]::FromMilliseconds(700)
    $timer.Add_Tick({ param($s, $e)
        try {
            if (Test-Path -LiteralPath $st.LogPath) {
                $fs = [System.IO.File]::Open($st.LogPath, 'Open', 'Read', 'ReadWrite')
                try {
                    if ($fs.Length -lt $st.LogPos) { $st.LogPos = 0; $st.Pendente = '' }
                    if ($fs.Length -gt $st.LogPos) {
                        $fs.Seek($st.LogPos, 'Begin') | Out-Null
                        $sr = New-Object System.IO.StreamReader($fs)
                        $novo = $sr.ReadToEnd()
                        $st.LogPos = $fs.Length
                        $texto = $st.Pendente + $novo
                        $ultimoFim = $texto.LastIndexOf("`n")
                        if ($ultimoFim -ge 0) {
                            $st.Pendente = $texto.Substring($ultimoFim + 1)
                            & $anexarLog $texto.Substring(0, $ultimoFim)
                        } else {
                            $st.Pendente = $texto
                        }
                    }
                } finally { $fs.Close() }
            }
        } catch { }

        # Tudo abaixo roda dentro do Tick do WPF: exceção sem tratamento derrubaria o ShowDialog.
        try {
        if ($st.Handle -and -not $st.Handle.IsCompleted -and $st.Cronometro) {
            $txtStatus.Text = $st.StatusBase + ' (' + $st.Cronometro.Elapsed.ToString('mm\:ss') + ')'
            # Barra de progresso real: se a função emitiu Write-Progress (Grant-WriteProgress), usa o último
            # percentual; sem progresso, a barra segue indeterminada (animada).
            try {
                $regs = $st.PS.Streams.Progress
                if ($regs -and $regs.Count -gt 0) {
                    $ult = $regs[$regs.Count - 1]
                    $regs.Clear()
                    $pctGui = [int]$ult.PercentComplete
                    if ($pctGui -ge 0 -and $pctGui -le 100) {
                        $prgExec.IsIndeterminate = $false
                        $prgExec.Minimum = 0; $prgExec.Maximum = 100
                        $prgExec.Value = $pctGui
                        if ($ult.StatusDescription) { $txtStatus.Text = $st.StatusBase + ' - ' + $ult.StatusDescription + ' (' + $st.Cronometro.Elapsed.ToString('mm\:ss') + ')' }
                    }
                }
            } catch { }
        }

        if ($st.Handle -and $st.Handle.IsCompleted) {
            $falha = $false
            try { [void]$st.PS.EndInvoke($st.Handle) }
            catch { $falha = $true; & $anexarLog ("[Error] Falha na execução: " + $_.Exception.Message) 'erro' }
            if ($st.PS.HadErrors) { $falha = $true }
            # Exceção e código de saída gravados pelo script de fundo (resultado real, não presumido)
            $codigoSaida = 0
            try {
                $ur = $st.Worker.SessionStateProxy.GetVariable('GuiUltimoResultado')
                if ($ur) {
                    if ($ur.Excecao) { $falha = $true }
                    $codigoSaida = [int]$ur.CodigoSaida
                    if ($codigoSaida -ne 0 -and $codigoSaida -ne 3010) { & $anexarLog ("[Error] Código de saída $codigoSaida.") 'erro' }
                }
            } catch { }
            try { $st.PS.Dispose() } catch { }
            $st.PS = $null; $st.Handle = $null
            if ($st.Cronometro) { $st.Cronometro.Stop() }
            $prgExec.IsIndeterminate = $false
            $prgExec.Visibility = 'Collapsed'
            $tempoTxt = if ($st.Cronometro) { ' (' + $st.Cronometro.Elapsed.ToString('mm\:ss') + ')' } else { '' }

            # Resultado real: exceção, erro do PowerShell ou linha [Error]/[Critical] no log desta ação.
            # Aviso ([Warning]) não conta como falha.
            $seg = $st.Linhas.GetRange($st.RunInicio, $st.Linhas.Count - $st.RunInicio)
            $niveis = @($seg | ForEach-Object { $_.Nivel })
            $resultado = Get-GuiResultadoExec -Niveis $niveis -FalhaTecnica $falha -CodigoSaida $codigoSaida
            $rotina = Get-GuiRotinaPorFunc -Func $st.Acao.Func
            if (-not $st.Simular -and $rotina) {
                Set-GuiRotinaStatus -Rotina $rotina -Resultado $resultado -Acao $st.Acao.Titulo
                & $renderCards
            }
            if ($resultado -eq 'erro') {
                $st.FilaErros = [int]$st.FilaErros + 1
                & $marcarItem $st.Acao.Func 'erro' ([string]$st.TemaAtual.Danger)
            } else {
                $st.FilaOk = [int]$st.FilaOk + 1
                if ($resultado -eq 'aviso') { $st.FilaAvisos = [int]$st.FilaAvisos + 1 }
                & $marcarItem $st.Acao.Func 'ok' ([string]$st.TemaAtual.Sucesso)
            }
            & $anexarLog ("<<< $($st.Acao.Titulo): " + $(if ($resultado -eq 'erro') { 'falhou' } elseif ($resultado -eq 'aviso') { 'concluído com avisos' } else { 'concluído' }) + $tempoTxt) 'info'

            # Próxima ação da fila (ou encerra)
            $st.PS = $null; $st.Handle = $null
            $st.FilaIdx = [int]$st.FilaIdx + 1
            & $iniciarProximo
        }
        } catch {
            try { Write-Log ("Erro no acompanhamento da execução: " + $_.Exception.Message) -Type Error } catch { }
            Show-GuiHandlerError -Contexto 'Acompanhar execução' -ErroObj $_
        }
    })
    $timer.Start()

    $window.Add_Closed({ param($s, $e)
        try { $timer.Stop() } catch { }
        try { if ($st.PS) { $st.PS.Dispose() } } catch { }
        try { if ($st.Worker) { $st.Worker.Close(); $st.Worker.Dispose() } } catch { }
        try {
            $maximizada = ($window.WindowState -eq 'Maximized')
            if ($maximizada) {
                $st.Prefs.JanelaLargura = $window.RestoreBounds.Width
                $st.Prefs.JanelaAltura  = $window.RestoreBounds.Height
                $st.Prefs.JanelaX = $window.RestoreBounds.Left
                $st.Prefs.JanelaY = $window.RestoreBounds.Top
            } else {
                $st.Prefs.JanelaLargura = $window.Width
                $st.Prefs.JanelaAltura  = $window.Height
                $st.Prefs.JanelaX = $window.Left
                $st.Prefs.JanelaY = $window.Top
            }
            $st.Prefs.JanelaMaximizada = $maximizada
            $st.Prefs.UltimaCategoria = '' + $lstCat.SelectedItem
            $st.Prefs.UltimaAcao = if ($st.Selecao) { $st.Selecao.Func } else { $null }
            Save-GuiPrefs -Prefs $st.Prefs
        } catch { }
    })

    # Reabre na última ação usada, se ainda existir e não estiver oculta
    if ($prefs.UltimaAcao) {
        foreach ($item in $lstAcoes.Items) {
            if ($item.Acao.Func -eq $prefs.UltimaAcao) { $lstAcoes.SelectedItem = $item; break }
        }
    }

    & $anexarLog 'Interface gráfica iniciada. Selecione uma ação à esquerda ou um cartão de status.' 'info'
    [void]$window.ShowDialog()
}

# ----------------------------------------------------------------------------
# Ponto de entrada: garante thread STA (WPF exige) e exibe a janela.
# ----------------------------------------------------------------------------
function Show-MaintenanceGui {
    param([string]$GuiPath)
    $staAtual = [System.Threading.Thread]::CurrentThread.GetApartmentState()
    if ($staAtual -eq [System.Threading.ApartmentState]::STA) {
        Invoke-MaintenanceGuiWindow
        return
    }

    Write-Log "Abrindo a interface gráfica em thread STA..." -Type Info
    if (-not $GuiPath -or -not (Test-Path -LiteralPath $GuiPath)) {
        Write-Log "Caminho do Gui.ps1 não encontrado para o modo STA. Abortando GUI." -Type Error
        return
    }
    $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault2()
    Get-ChildItem Function:\ | Where-Object { $_.Name -match '-' } | ForEach-Object {
        try { $iss.Commands.Add((New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry($_.Name, $_.Definition))) } catch { }
    }
    foreach ($vn in 'ScriptConfig','IsWindows11','defaultColors') {
        $v = Get-Variable -Name $vn -Scope Global -ErrorAction SilentlyContinue
        if ($v) { $iss.Variables.Add((New-Object System.Management.Automation.Runspaces.SessionStateVariableEntry($vn, $v.Value, ''))) }
    }
    $rs = [runspacefactory]::CreateRunspace($iss)
    $rs.ApartmentState = 'STA'
    $rs.ThreadOptions  = 'ReuseThread'
    $rs.Open()
    $ps = [powershell]::Create()
    $ps.Runspace = $rs
    [void]$ps.AddScript('param($p) . $p; Invoke-MaintenanceGuiWindow').AddArgument($GuiPath)
    $ps.Invoke()
    $ps.Dispose(); $rs.Close(); $rs.Dispose()
}
