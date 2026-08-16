# ============================================================================
# Gui.ps1 — Interface grafica (WPF) do Script Supremo de Manutencao
# ============================================================================
# Orientada a dados: Get-GuiActionCatalog e a fonte unica de verdade das acoes
# (Categoria/Titulo/Funcao/Descricao/Destrutivo/Parametros). A janela renderiza
# o catalogo em ordem alfabetica (categorias e acoes).
#
# Dot-sourced pelo MaintenanceColegio.ps1 via Show-Gui. As funcoes reais ja
# estao no escopo quando este arquivo roda. Requer WPF (Windows + .NET).
#
# Recursos: busca em tempo real, filtro por categoria, painel de descricao,
# PARAMETROS por acao (campos dinamicos, com botao "Procurar pasta..." nos
# campos de pasta) + "argumentos extras", checkbox "Simular (WhatIf)",
# confirmacao/destaque p/ acoes destrutivas, execucao em runspace de fundo
# (nao trava a janela), log ao vivo (tail do log, com botao "Copiar log") e
# botao "Personalizar" (tema, fonte, confirmacoes, categorias ocultas) com
# preferencias salvas em JSON. Tambem: icone/identidade da janela, indicador
# de progresso + status com tempo decorrido, atalhos de teclado (Ctrl+F busca,
# Ctrl+Enter executa, Esc fecha), botao "Ver comando equivalente", 4 temas
# (Escuro/Claro/Alto Contraste/Petroleo), presets salvos de parametros por
# acao e janela que lembra tamanho/posicao/ultima acao entre sessoes.
# ============================================================================

Add-Type -AssemblyName PresentationFramework -ErrorAction SilentlyContinue
Add-Type -AssemblyName PresentationCore      -ErrorAction SilentlyContinue
Add-Type -AssemblyName WindowsBase           -ErrorAction SilentlyContinue
Add-Type -AssemblyName System.Windows.Forms  -ErrorAction SilentlyContinue  # NOVO: FolderBrowserDialog para os campos de pasta
Add-Type -AssemblyName System.Drawing        -ErrorAction SilentlyContinue  # NOVO: gera o icone da janela em tempo real (sem depender de arquivo externo)
Add-Type -AssemblyName Microsoft.VisualBasic -ErrorAction SilentlyContinue  # NOVO: InputBox nativo p/ nomear presets salvos

# ----------------------------------------------------------------------------
# Paletas de tema
# ----------------------------------------------------------------------------
$script:GuiTemas = @{
    Escuro        = @{ Bg='#0f1419'; Panel='#161b22'; PanelDark='#0d1117'; Ink='#e6edf3'; Muted='#8b949e'; Border='#30363d'; Accent='#0f5c56'; Danger='#f85149'; Func='#58a6ff' }
    Claro         = @{ Bg='#f6f8fa'; Panel='#ffffff'; PanelDark='#f0f2f5'; Ink='#1f2328'; Muted='#57606a'; Border='#d0d7de'; Accent='#0f5c56'; Danger='#cf222e'; Func='#0969da' }
    # NOVO: alto contraste para leitura em qualquer condicao de luz / acessibilidade.
    AltoContraste = @{ Bg='#000000'; Panel='#000000'; PanelDark='#000000'; Ink='#ffffff'; Muted='#d0d0d0'; Border='#ffffff'; Accent='#ffcc00'; Danger='#ff5c5c'; Func='#7fd4ff' }
    # NOVO: variante clara com identidade mais forte na cor institucional do CMS (mesmo
    # verde-petroleo #0f5c56 usado nos web apps do ecossistema).
    Petroleo      = @{ Bg='#eef5f4'; Panel='#ffffff'; PanelDark='#e0edeb'; Ink='#0b2b28'; Muted='#4f6b68'; Border='#c7ded9'; Accent='#0f5c56'; Danger='#c0392b'; Func='#146c94' }
}

# ----------------------------------------------------------------------------
# Preferencias (persistidas em JSON no APPDATA)
# ----------------------------------------------------------------------------
function Get-GuiPrefsPath {
    $dir = Join-Path $env:APPDATA 'ScriptSupremo'
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    Join-Path $dir 'gui-prefs.json'
}

function Get-GuiPrefs {
    $padrao = [pscustomobject]@{
        Tema='Escuro'
        Fonte=13
        ConfirmarDestrutivas=$true
        AutoScrollLog=$true
        OcultarDestrutivas=$false
        # NOVO: categorias inteiras ocultas da lista de acoes (nomes de Cat do catalogo)
        CategoriasOcultas=@()
        # NOVO: perfis/presets salvos por acao -- cada item: { Func; Nome; Splat; Extra; Simular }
        Presets=@()
        # NOVO: estado da janela lembrado entre sessoes (posicao/tamanho + ultima selecao)
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
        if (Test-Path $p) {
            $j = Get-Content $p -Raw -Encoding UTF8 | ConvertFrom-Json
            foreach ($k in 'Tema','Fonte','ConfirmarDestrutivas','AutoScrollLog','OcultarDestrutivas',
                           'CategoriasOcultas','Presets','JanelaLargura','JanelaAltura','JanelaX','JanelaY',
                           'JanelaMaximizada','UltimaCategoria','UltimaAcao') {
                if ($null -ne $j.$k) { $padrao.$k = $j.$k }
            }
        }
    } catch { }
    # Normaliza arrays: ConvertFrom-Json devolve o item sozinho (fora de array) quando o
    # JSON original tinha exatamente 1 elemento -- @() sozinho nao resolve pq @($null) vira
    # um array de 1 elemento nulo, nao um array vazio.
    $padrao.CategoriasOcultas = if ($null -eq $padrao.CategoriasOcultas) { @() } else { @($padrao.CategoriasOcultas) }
    $padrao.Presets           = if ($null -eq $padrao.Presets)           { @() } else { @($padrao.Presets) }
    return $padrao
}

function Save-GuiPrefs {
    param($Prefs)
    # -Depth maior: Prefs agora tem Presets (array de objetos com Splat aninhado) -- o
    # padrao (2) truncaria esses niveis extras em texto tipo "System.Collections.Hashtable".
    try { $Prefs | ConvertTo-Json -Depth 6 | Set-Content -Path (Get-GuiPrefsPath) -Encoding UTF8 } catch { }
}

# ----------------------------------------------------------------------------
# NOVO: gera (uma vez, cacheado em disco) um icone simples para a janela/barra
# de tarefas -- nao depende de nenhum arquivo externo nem de internet: desenha
# um quadrado arredondado na cor de destaque com as iniciais "SS" (Script
# Supremo) por cima.
# ----------------------------------------------------------------------------
function Get-GuiAppIconPath {
    param($AccentHex = '#0f5c56')
    try {
        $dir = Join-Path $env:APPDATA 'ScriptSupremo'
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        $caminho = Join-Path $dir 'app-icon.png'
        if (Test-Path $caminho) { return $caminho }

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
# Catalogo de acoes (fonte de verdade). Todas as Funcoes existem no script.
# Destr = $true marca acoes destrutivas. Params (opcional) = parametros da acao.
#   Param: @{ Nome; Rotulo; Tipo='text'|'paths'|'files'|'switch'|'choice'|'password'; Default; Opcoes; Pasta=$true; Arquivo=$true }
# ----------------------------------------------------------------------------
function Get-GuiActionCatalog {
    # NOVO: gera um checkbox por app pra "Instalar Aplicativos" (mesma fonte que
    # Install-Applications/Show-AppInstallPicker usam: Get-ScriptSupremoAppsList ->
    # Apps.json ao lado do script, ou a lista embutida). Cada Param carrega o app
    # inteiro em AppObj; MontarSplatExtra junta os marcados num unico -Apps em vez
    # de mandar cada checkbox como parametro proprio pra Install-Applications.
    $paramsInstalarApps = @()
    try {
        foreach ($appDisp in (Get-ScriptSupremoAppsList)) {
            $paramsInstalarApps += @{ Nome = "App_$($appDisp.Id)"; Rotulo = "$($appDisp.Name)  ($($appDisp.Id))"; Tipo = 'switch'; Default = $true; AppObj = $appDisp }
        }
    } catch { $paramsInstalarApps = @() }

    @(
        # --- Limpeza e Otimizacao ---
        [pscustomobject]@{ Cat='Limpeza'; Titulo='Agendar ChkDsk no Reboot';           Func='New-ChkDsk';                  Desc='Executa "chkdsk C: /f /r /x" -- como o disco do sistema esta em uso, o Windows agenda pra rodar na proxima reinicializacao e repara erros/setores defeituosos.'; Destr=$false }
        [pscustomobject]@{ Cat='Limpeza'; Titulo='Limpar Arquivos e Pastas Vazias';    Func='Clear-EmptyFilesAndFolders';  Desc='Remove arquivos de 0 byte e pastas vazias (protege .gitkeep/desktop.ini). Suporta -WhatIf.'; Destr=$true; Params=@(
                                            @{ Nome='Path';             Rotulo='Pastas-raiz (vazio = %TEMP% padrao)'; Tipo='paths';  Default=''; Exemplo='Ex.: D:\Outra Pasta;E:\Downloads (separe varias pastas por ;)'; Pasta=$true }
                                            @{ Nome='IncludeEmptyFiles'; Rotulo='Tambem remover arquivos de 0 byte';    Tipo='switch'; Default=$true }
                                          ) }
        [pscustomobject]@{ Cat='Limpeza'; Titulo='Limpar Arquivos Temporarios';        Func='Clear-TemporaryFiles';        Desc='Apaga tudo dentro de %TEMP% (pasta temp do usuario) e C:\Windows\Temp.'; Destr=$true }
        [pscustomobject]@{ Cat='Limpeza'; Titulo='Limpar Cache do Windows Update';     Func='Clear-WUCache';               Desc='Para o servico "Windows Update" (wuauserv), apaga os arquivos baixados em C:\Windows\SoftwareDistribution\Download e reinicia o servico -- resolve updates travados/corrompidos.'; Destr=$true }
        [pscustomobject]@{ Cat='Limpeza'; Titulo='Limpar Prefetch';                    Func='Clear-Prefetch';              Desc='Apaga os arquivos em C:\Windows\Prefetch (cache de pre-carregamento de programas usados com frequencia -- o Windows recria sozinho aos poucos).'; Destr=$true }
        [pscustomobject]@{ Cat='Limpeza'; Titulo='Limpar WinSxS (Componentes)';        Func='Clear-WinSxS';                Desc='Executa "DISM /Online /Cleanup-Image /StartComponentCleanup /ResetBase" -- reduz o tamanho da pasta WinSxS de forma permanente. Atencao: com /ResetBase, updates do Windows ja instalados deixam de poder ser desinstalados.'; Destr=$true }
        [pscustomobject]@{ Cat='Limpeza'; Titulo='Limpeza Profunda do Sistema';        Func='Clear-DeepSystemCleanup';     Desc='Remove logs antigos do CBS/DISM e os arquivos de despejo de memoria (minidumps e Memory.dmp) em C:\Windows.'; Destr=$true }
        [pscustomobject]@{ Cat='Limpeza'; Titulo='Otimizar Volumes (Desfrag/ReTrim)';  Func='Optimize-Volumes';            Desc='Em cada volume fixo: se for NTFS, roda Optimize-Volume -Defrag; se nao for NTFS/FAT32/exFAT (normalmente SSD), roda -ReTrim. FAT32/exFAT sao pulados. A escolha e por sistema de arquivos, nao detecta HDD/SSD de verdade.'; Destr=$false }
        [pscustomobject]@{ Cat='Limpeza'; Titulo='Remover Arquivos Duplicados';        Func='Remove-DuplicateFiles';       Desc='Procura duplicatas por conteúdo idêntico (hash SHA256) em Downloads/Documentos/Área de Trabalho/Imagens/Vídeos/Música (com subpastas). Mantém 1 cópia por grupo. Por padrão MOVE as demais para revisão em C:\ScriptsLogs\Duplicatas_<data> (com backup automático) — marque "Deletar" pra apagar de verdade.'; Destr=$true; Params=@(
                                            @{ Nome='Path';    Rotulo='Pastas-raiz (vazio = Downloads/Documentos/Área de Trabalho/Imagens/Vídeos/Música)'; Tipo='paths'; Default=''; Exemplo='Ex.: D:\Fotos;E:\Backup (separe varias pastas por ;)'; Pasta=$true }
                                            @{ Nome='Manter';  Rotulo='Qual cópia manter em cada grupo'; Tipo='choice'; Default='MaisAntigo'; Opcoes=@('MaisAntigo','MaisNovo','Maior') }
                                            @{ Nome='TiposArquivo'; Rotulo='Filtrar por extensão (vazio = todos)'; Tipo='paths'; Default=''; Exemplo='Ex.: *.jpg;*.pdf (separe por ;)' }
                                            @{ Nome='IncluirComuns'; Rotulo='Filtrar só tipos comuns (fotos/vídeos/documentos/zip)'; Tipo='switch'; Default=$false }
                                            @{ Nome='TamanhoMinimoKB'; Rotulo='Ignorar arquivos menores que (KB)'; Tipo='text'; Default='1' }
                                            @{ Nome='Deletar'; Rotulo='Deletar de verdade (em vez de só mover para revisão)'; Tipo='switch'; Default=$false }
                                            @{ Nome='SemBackup'; Rotulo='Desativar o backup automático antes de mover/deletar'; Tipo='switch'; Default=$false }
                                          ) }
        [pscustomobject]@{ Cat='Limpeza'; Titulo='Remover Pasta Windows.old';          Func='Remove-WindowsOld';           Desc='Se existir C:\Windows.old (backup da instalacao anterior do Windows, criado em upgrades), apaga a pasta inteira. Libera vários GB.'; Destr=$true }
        [pscustomobject]@{ Cat='Limpeza'; Titulo='Rotina Completa de Limpeza';         Func='Invoke-Cleanup';              Desc='Roda em sequencia: limpeza profunda, prefetch, spooler de impressao, arquivos temporarios, arquivos/pastas vazias, cache do Windows Update, WinSxS, a rotina de limpeza de rede (Grant-Cleanup: ARP/DNS/temp/spooler/WU/WinSxS/limpeza profunda/Windows.old/chkdsk/otimizar volumes), remove Windows.old, faz backup do registro, desativa SMBv1 e roda verificacao DISM + SFC.'; Destr=$true }
        [pscustomobject]@{ Cat='Limpeza'; Titulo='Verificacao DISM';                   Func='Invoke-DISM-Scan';            Desc='DISM /RestoreHealth — repara a imagem de componentes do Windows.'; Destr=$false }
        [pscustomobject]@{ Cat='Limpeza'; Titulo='Verificacao SFC';                    Func='Invoke-SFC-Scan';             Desc='sfc /scannow — verifica e repara arquivos de sistema.'; Destr=$false }

        # --- Privacidade e Seguranca ---
        [pscustomobject]@{ Cat='Privacidade'; Titulo='Desativar Cortana e Pesquisa Online'; Func='Disable-Cortana-AndSearch'; Desc='Via registro: desativa a Cortana (AllowCortana=0) e a busca na nuvem/Bing na pesquisa do Windows (AllowCloudSearch=0), alem de outros ajustes de telemetria/relatorio de erros.'; Destr=$false }
        [pscustomobject]@{ Cat='Privacidade'; Titulo='Desativar Servicos Desnecessarios';   Func='Disable-UnnecessaryServices'; Desc='Desativa os servicos: DiagTrack e dmwappushservice (telemetria), WMPNetworkSvc (compartilhamento do Windows Media Player), XblAuthManager/XblGameSave/XboxNetApiSvc (Xbox Live), MapsBroker (Mapas), Fax, PrintNotify, RemoteRegistry, RetailDemo (modo vitrine), SharedAccess (compartilhar internet) e WerSvc (relatorio de erros).'; Destr=$true }
        [pscustomobject]@{ Cat='Privacidade'; Titulo='Desativar Windows Recall';            Func='Disable-WindowsRecall';     Desc='Ajustes de registro que desativam o Windows Recall (gravacao continua de tela/atividades do Windows 11 24H2+), se o recurso estiver presente.'; Destr=$false }
        [pscustomobject]@{ Cat='Privacidade'; Titulo='Endurecimento de Privacidade';        Func='Enable-PrivacyHardening';   Desc='Aplica ajustes agressivos de privacidade (telemetria, ID de publicidade, coleta de entrada).'; Destr=$false }
        [pscustomobject]@{ Cat='Privacidade'; Titulo='Forcar Remocao do OneDrive';          Func='Remove-OneDrive-AndRestoreFolders'; Desc='Desinstala o OneDrive e restaura Documentos/Imagens/Desktop/etc. pra apontar de volta pras pastas locais (fora da sincronizacao).'; Destr=$true }
        [pscustomobject]@{ Cat='Privacidade'; Titulo='Prevencao de Bloatware e Privacidade';Func='Grant-PrivacyAndBloatwarePrevention'; Desc='Aplica os ajustes ligados em $ScriptConfig.PrivacyTweaks (ex.: desativar Wi-Fi Sense) -- assim como os "Ajustes de UI", so faz algo pras opcoes que estiverem ativadas na configuracao do script.'; Destr=$false }
        [pscustomobject]@{ Cat='Privacidade'; Titulo='Reforco de Seguranca (Defender)';     Func='Enable-WindowsHardening';   Desc='Aplica configuracoes de seguranca do Windows Defender (ASR, cloud block, PUA...).'; Destr=$false }
        [pscustomobject]@{ Cat='Privacidade'; Titulo='Remover Bloatware';                   Func='Remove-SystemBloatware';    Desc='Remove por padrao dezenas de apps pre-instalados (Bing, News, Weather, Xbox, Skype, Solitaire, Netflix, Spotify, TikTok, Instagram, Facebook, LinkedIn, Maps, OneNote, Paint3D, People, Dolby, extensoes de video, etc.) e apps especificos por nome (Copilot, Microsoft Teams, Clipchamp, Microsoft To Do, Notas Autoadesivas, novo Outlook, Xbox, Solitaire Collection). ATENCAO: um dos padroes e "*Edge*", entao o Microsoft Edge tambem e desinstalado. Nao mexe em OneDrive/Recall/tarefas agendadas por padrao (sao opcoes separadas, off aqui).'; Destr=$true }
        [pscustomobject]@{ Cat='Privacidade'; Titulo='Rotina Completa de Bloatware';        Func='Invoke-Bloatware';          Desc='Roda em sequencia: Prevencao de Bloatware e Privacidade, Remover Bloatware (com os padroes/apps padrao, incluindo o Edge), Desativar Servicos Desnecessarios, Desativar Windows Recall, Forcar Remocao do OneDrive e Remover Pasta Windows.old.'; Destr=$true }
        [pscustomobject]@{ Cat='Privacidade'; Titulo='Seguranca de Macros do Office';       Func='Grant-HardenOfficeMacros';  Desc='Desabilita macros perigosos do Office (Word/Excel/PowerPoint).'; Destr=$false }

        # --- Rede ---
        [pscustomobject]@{ Cat='Rede'; Titulo='Adicionar Rede Wi-Fi';          Func='Add-WiFiNetwork';             Desc='Adiciona o perfil de rede Wi-Fi "VemProMundo - Adm". A senha vem de CMS_WIFI_KEY / WiFi.local.json; use o campo abaixo so se quiser informar outra.'; Destr=$false; Params=@(
                                            @{ Nome='WifiKey'; Rotulo='Senha do Wi-Fi (opcional — deixe em branco p/ usar a configurada)'; Tipo='password'; Default=''; Exemplo='So preencha se quiser sobrescrever a senha ja configurada.' }
                                          ) }
        [pscustomobject]@{ Cat='Rede'; Titulo='Configurar DNS Google/Cloudflare'; Func='Set-DnsGoogleCloudflare';  Desc='Define DNS 8.8.8.8/8.8.4.4 (Google) na interface "Ethernet" e 1.1.1.1/1.0.0.1 (Cloudflare) na interface "Wi-Fi" -- nao os dois em cada uma. So funciona se as interfaces tiverem exatamente esses nomes.'; Destr=$false }
        [pscustomobject]@{ Cat='Rede'; Titulo='Desativar IPv6';               Func='Disable-IPv6';                Desc='Desativa o IPv6 via registro (DisabledComponents = 0xFF em Tcpip6\Parameters) em todos os adaptadores. Precisa reiniciar o computador pra valer.'; Destr=$false }
        [pscustomobject]@{ Cat='Rede'; Titulo='Instalar Impressoras de Rede';  Func='Install-NetworkPrinters';     Desc='Instala os drivers Samsung Universal Print e Epson L3250 (do drive compartilhado MundoCOC\Tecnologia\Gerais\Drivers) e cadastra as 4 impressoras por IP dos 2 colegios: Samsung Mundo1 (172.16.40.40), Samsung Mundo2 (172.17.40.25), EpsonMundo1 (172.16.40.37) e EpsonMundo2 (172.17.40.72).'; Destr=$false }
        [pscustomobject]@{ Cat='Rede'; Titulo='Limpar Cache ARP';             Func='Clear-ARP';                   Desc='Executa "netsh interface ip delete arpcache" -- limpa a tabela ARP (mapeamento IP-MAC) da rede local.'; Destr=$false }
        [pscustomobject]@{ Cat='Rede'; Titulo='Limpar Cache DNS';             Func='Clear-DNS';                   Desc='Executa "ipconfig /flushdns" -- limpa o cache local de resolucao de nomes DNS.'; Destr=$false }
        [pscustomobject]@{ Cat='Rede'; Titulo='Limpar Spooler de Impressao';  Func='Clear-PrintSpooler';          Desc='Para o servico Spooler, apaga os arquivos travados em C:\Windows\System32\spool\PRINTERS e reinicia o servico -- resolve impressoes presas na fila.'; Destr=$false }
        [pscustomobject]@{ Cat='Rede'; Titulo='Mostrar Informacoes de Rede';  Func='Show-NetworkInfo';            Desc='Mostra "ipconfig /all" e um resumo (interface, IPv4, gateway, servidor DNS) de cada adaptador via Get-NetIPConfiguration.'; Destr=$false }
        [pscustomobject]@{ Cat='Rede'; Titulo='Otimizar Desempenho de Rede';  Func='Optimize-NetworkPerformance'; Desc='Ajustes via netsh/registro: desativa auto-tuning de recebimento TCP, ativa RSS (multi-core), desativa o provedor de congestionamento (CUBIC) e aumenta a janela TCP/desativa limitacao de banda do SMB no registro.'; Destr=$false }
        [pscustomobject]@{ Cat='Rede'; Titulo='Rotina Completa de Rede';      Func='Invoke-NetworkUtilities';     Desc='Roda em sequencia: adiciona o Wi-Fi "VemProMundo - Adm", limpa cache ARP e DNS, limpa o spooler de impressao, desativa IPv6, instala as impressoras de rede, aplica as otimizacoes de rede avancadas, configura DNS Google/Cloudflare, mostra informacoes de rede e testa a velocidade da internet.'; Destr=$false }
        [pscustomobject]@{ Cat='Rede'; Titulo='Testar Velocidade da Internet';Func='Test-InternetSpeed';          Desc='Instala o Speedtest CLI da Ookla via winget (se ainda nao tiver) e roda o teste de velocidade (download/upload/ping) no terminal.'; Destr=$false }

        # --- Sistema e Desempenho ---
        [pscustomobject]@{ Cat='Sistema'; Titulo='Criar Ponto de Restauracao';      Func='New-SystemRestorePoint';      Desc='Habilita a Protecao do Sistema e cria um ponto de restauracao.'; Destr=$false }
        [pscustomobject]@{ Cat='Sistema'; Titulo='Efeitos Visuais para Desempenho'; Func='Set-VisualPerformance';       Desc='Via registro: define VisualFXSetting=2 ("Ajustar para obter um melhor desempenho") e ajusta o UserPreferencesMask -- desliga animacoes/sombras/transparencias. Pode precisar reiniciar o Explorer/sistema pra ver tudo.'; Destr=$false }
        [pscustomobject]@{ Cat='Sistema'; Titulo='Otimizacoes Gerais do Sistema';   Func='Grant-SystemOptimizations';   Desc='Ativa a otimizacao de inicializacao (BootOptimizeFunction) e outros ajustes gerais de registro/sistema.'; Destr=$false }
        [pscustomobject]@{ Cat='Sistema'; Titulo='Otimizar Desempenho do Explorer'; Func='Optimize-ExplorerPerformance';Desc='Via registro: desativa animacoes de selecao/sombra de icones e da barra de tarefas, e desliga os paineis de detalhes/visualizacao do Explorer.'; Destr=$false }
        [pscustomobject]@{ Cat='Sistema'; Titulo='Plano de Energia Otimizado';      Func='Set-OptimizedPowerPlan';      Desc='Ativa o plano de energia "Alto Desempenho" (powercfg); se nao existir no sistema, cai pro plano "Equilibrado".'; Destr=$false }
        [pscustomobject]@{ Cat='Sistema'; Titulo='Renomear Notebook';               Func='Rename-Notebook';             Desc='Renomeia o computador. Requer reinicio para aplicar.'; Destr=$false; Params=@(
                                            @{ Nome='NovoNome'; Rotulo='Novo nome do notebook'; Tipo='text'; Default=''; Exemplo='Ex.: CMS-NOTE-14 (sem espacos/acentos, max ~15 caracteres)' }
                                          ) }

        # --- Personalizacao ---
        [pscustomobject]@{ Cat='Personalização'; Titulo='Ajustes de UI (Widgets/Barra)';   Func='Grant-UITweaks';              Desc='Aplica os ajustes de UI configurados em $ScriptConfig.UITweaks (ex.: ocultar o botao de Widgets no Windows 11) -- so faz algo se a opcao correspondente estiver ativada na configuracao do script.'; Destr=$false }
        [pscustomobject]@{ Cat='Personalização'; Titulo='Ativar Tema Escuro';              Func='Enable-DarkTheme';            Desc='Registro: AppsUseLightTheme=0 e SystemUsesLightTheme=0 (HKCU\...\Themes\Personalize) -- ativa o modo escuro nos apps e no shell do Windows.'; Destr=$false }
        [pscustomobject]@{ Cat='Personalização'; Titulo='Finalizar Tarefa na Barra';       Func='Enable-TaskbarEndTask';       Desc='Registro: TaskbarEndTask=1 (TaskbarDeveloperSettings) -- adiciona "Finalizar tarefa" no menu do botao direito da barra de tarefas. So funciona no Windows 11 build 23430 ou superior (a funcao checa e avisa se nao for compativel).'; Destr=$false }
        [pscustomobject]@{ Cat='Personalização'; Titulo='Habilitar Sudo';                  Func='Enable-Sudo';                 Desc='Registro: EnableSudo=1 (HKLM\...\Windows\CurrentVersion\Sudo) -- ativa o "sudo" nativo do Windows 11 24H2+. Precisa fechar e abrir o terminal de novo pra valer.'; Destr=$false }
        [pscustomobject]@{ Cat='Personalização'; Titulo='Historico da Area de Transferencia'; Func='Enable-ClipboardHistory';  Desc='Registro: EnableClipboardHistory=1 (HKCU\Software\Microsoft\Clipboard) -- ativa o historico da area de transferencia (Win+V).'; Destr=$false }
        [pscustomobject]@{ Cat='Personalização'; Titulo='Menu de Contexto Classico';       Func='Enable-ClassicContextMenu';   Desc='Restaura o menu de contexto classico (com todas as opcoes de uma vez) no lugar do menu reduzido do Windows 11, via ajuste de registro.'; Destr=$false }
        [pscustomobject]@{ Cat='Personalização'; Titulo='Restaurar Apps apos Reinicio';    Func='Enable-RestartAppsAfterReboot';Desc='Registro: RestartApps=1 (HKCU\...\Explorer\RestartApps) -- reabre automaticamente os programas que estavam abertos antes de reiniciar/desligar.'; Destr=$false }
        [pscustomobject]@{ Cat='Personalização'; Titulo='Segundos no Relogio';             Func='Enable-TaskbarSeconds';       Desc='Registro: ShowSecondsInSystemClock=1 (HKCU\...\Explorer\Advanced) -- mostra os segundos no relogio da barra de tarefas.'; Destr=$false }
        [pscustomobject]@{ Cat='Personalização'; Titulo='Updates de Outros Produtos MS';   Func='Enable-OtherMicrosoftUpdates';Desc='Registro: EnableFeaturedSoftware=1 (WindowsUpdate\Auto Update) -- faz o Windows Update tambem atualizar outros produtos Microsoft instalados (nao so o Windows).'; Destr=$false }
        [pscustomobject]@{ Cat='Personalização'; Titulo='Windows Update Antecipado';       Func='Enable-WindowsUpdateFast';    Desc='Registro: IsContinuousInnovationOptedIn=1 (WindowsUpdate\UX\Settings) -- opta por receber atualizacoes do Windows Update assim que disponiveis, antes do rollout padrao.'; Destr=$false }

        # --- Diagnosticos ---
        [pscustomobject]@{ Cat='Diagnósticos'; Titulo='Diagnosticos Avancados';   Func='Invoke-All-DiagnosticsAdvanced'; Desc='Roda em sequencia: Informacoes do Sistema, Uso de Disco, Informacoes de Rede, verificacao SFC, verificacao DISM, saude dos discos (SMART) e agenda o Teste de Memoria do Windows.'; Destr=$false }
        [pscustomobject]@{ Cat='Diagnósticos'; Titulo='Informacoes do Sistema';   Func='Show-SystemInfo';             Desc='Executa "systeminfo" e mostra no log (versao do Windows, memoria, hotfixes, etc.).'; Destr=$false }
        [pscustomobject]@{ Cat='Diagnósticos'; Titulo='Testar Memoria';           Func='Test-Memory';                 Desc='Abre a Ferramenta de Diagnostico de Memoria do Windows (mdsched.exe) -- e preciso escolher reiniciar o computador pra ela rodar o teste de verdade.'; Destr=$false }
        [pscustomobject]@{ Cat='Diagnósticos'; Titulo='Uso de Disco';             Func='Show-DiskUsage';              Desc='Mostra uma tabela com letra, rotulo, tamanho total e espaco livre (em GB) de cada volume.'; Destr=$false }

        # --- Restauracao ---
        [pscustomobject]@{ Cat='Restauração'; Titulo='Backup do Registro';              Func='Backup-Registry';        Desc='Exporta HKLM\SOFTWARE, HKLM\SYSTEM e HKCU pra 3 arquivos .reg numa pasta nova em Documentos (reg_backup_<data_hora>).'; Destr=$false }
        [pscustomobject]@{ Cat='Restauração'; Titulo='Desfazer Reforco de Privacidade'; Func='Undo-PrivacyHardening';  Desc='Desfaz os ajustes aplicados por "Endurecimento de Privacidade" (Enable-PrivacyHardening).'; Destr=$false }
        [pscustomobject]@{ Cat='Restauração'; Titulo='Desfazer Tudo (Rotina)';          Func='Invoke-Undo';            Desc='Roda em sequencia: reabilita notificacoes do Action Center, restaura tweaks do Painel de Controle, restaura IPv6/UAC padrao, restaura macros do Office, reinstala o OneDrive, restaura o registro (backup mais recente) e restaura efeitos visuais padrao.'; Destr=$true }
        [pscustomobject]@{ Cat='Restauração'; Titulo='Reinstalar OneDrive';             Func='Restore-OneDrive';       Desc='Executa C:\Windows\SysWOW64\OneDriveSetup.exe (instalador embutido do Windows) pra reinstalar o OneDrive. Se esse arquivo nao existir na maquina, avisa erro e nao faz nada.'; Destr=$false }
        [pscustomobject]@{ Cat='Restauração'; Titulo='Restaurar Registro';              Func='Restore-Registry';       Desc='Restaura o registro (HKLM\SOFTWARE, HKLM\SYSTEM, HKCU) a partir de uma pasta de backup gerada por "Backup do Registro".'; Destr=$true; Params=@(
                                            @{ Nome='BkpPath'; Rotulo='Pasta do backup do registro'; Tipo='text'; Default=''; Exemplo='Ex.: C:\Users\SeuUsuario\Documents\reg_backup_20260814_140000'; Pasta=$true }
                                          ) }
        [pscustomobject]@{ Cat='Restauração'; Titulo='Restaurar TODOS os Padroes';      Func='Restore-SystemDefaults'; Desc='Grava de volta os valores PADRAO de fabrica do Windows no registro (Explorer, efeitos visuais, privacidade, etc.) -- desfaz de uma vez os tweaks de "Tweaks de Painel de Controle/Privacidade/Extras" e "Endurecimento de Privacidade".'; Destr=$true }

        # --- Instalacao e Ferramentas ---
        [pscustomobject]@{ Cat='Instalação'; Titulo='Atualizar PowerShell';        Func='Update-PowerShell';        Desc='Instala/atualiza o PowerShell (aka.ms/install-powershell).'; Destr=$false }
        [pscustomobject]@{ Cat='Instalação'; Titulo='Atualizar Windows e Drivers';  Func='Update-WindowsAndDrivers'; Desc='Instala o modulo PSWindowsUpdate (se faltar) e roda "Get-WindowsUpdate -AcceptAll -Install -AutoReboot" -- ATENCAO: pode reiniciar o computador sozinho se algum update pedir reinicio. Depois roda "winget upgrade --all", que atualiza TODOS os programas instalados via winget (nao so drivers, apesar do titulo).'; Destr=$false }
        [pscustomobject]@{ Cat='Instalação'; Titulo='Instalar Aplicativos';         Func='Install-Applications';     Desc='Escolha os aplicativos abaixo (winget; usa Apps.json se existir) e clique em Executar.'; Destr=$false; Params=$paramsInstalarApps }
        [pscustomobject]@{ Cat='Instalação'; Titulo='Instalar Perfil PowerShell (produtividade)'; Func='Install-PowerShellProfile'; Desc='Instala uma copia "limpa" do perfil pessoal do Regnon neste notebook: funcoes de log/limpeza/rede, aliases, e PSReadLine/oh-my-posh/Terminal-Icons/zoxide/PSFzf (cada um so ativa se ja estiver instalado). Faz backup automatico do perfil existente antes de sobrescrever. Precisa abrir um terminal novo depois pra carregar.'; Destr=$true; Params=@(
                                            @{ Nome='SemBackup'; Rotulo='Desativar o backup automatico do perfil existente antes de sobrescrever'; Tipo='switch'; Default=$false }
                                          ) }

        # --- Avancado ---
        [pscustomobject]@{ Cat='Avançado'; Titulo='Configuracoes de GPO e Registro'; Func='Grant-GPORegistrySettings'; Desc='Aplica configuracoes de GPO via registro (Edge/Chrome/driver search...).'; Destr=$false }
        [pscustomobject]@{ Cat='Avançado'; Titulo='Desativar UAC';                   Func='Disable-UAC';               Desc='Desativa o Controle de Conta de Usuario (UAC).'; Destr=$false }
        [pscustomobject]@{ Cat='Avançado'; Titulo='Tweaks de Painel de Controle';    Func='Grant-ControlPanelTweaks';  Desc='Registro: mostra extensoes de arquivo, mostra arquivos ocultos do sistema, desativa "sacudir pra minimizar", desativa itens recentes/frequentes e animacao de minimizar janela, e garante acesso liberado ao Painel de Controle/menu de contexto/Desktop/Localizar.'; Destr=$false }
        [pscustomobject]@{ Cat='Avançado'; Titulo='Tweaks de Privacidade';           Func='Grant-PrivacyTweaks';       Desc='Dezenas de chaves de registro de privacidade: desativa telemetria, sugestoes/apps patrocinados da Start, Cortana/Bing na pesquisa, localizacao, nega acesso a camera/microfone, desativa SMBv1, compartilhamento entre dispositivos e Game Bar, restringe sincronizacao pessoal do OneDrive -- e mantem o UAC ativado.'; Destr=$false }
        [pscustomobject]@{ Cat='Avançado'; Titulo='Tweaks Extras';                   Func='Grant-ExtraTweaks';         Desc='Registro: desativa telemetria do Edge/Office, Superfetch/SysMain, SmartScreen, Game DVR, hibernacao rapida, reinicio automatico apos tela azul, os servicos Fax/RAS/discagem automatica, indexacao de pesquisa (WSearch) e Relatorio de Erros do Windows. ATENCAO: tambem APAGA TUDO da chave StartupApproved\Run (reseta os itens gerenciados de inicializacao).'; Destr=$false }

        # --- Rotinas ---
        [pscustomobject]@{ Cat='Rotinas'; Titulo='Manutencao Completa';       Func='Show-FullMaintenance'; Desc='Roda em sequencia: instala aplicativos padrao, instala impressoras de rede + otimiza rede, desativa SMBv1 e reforca macros do Office, remove bloatware + remove OneDrive + Rotina Completa de Limpeza + tweaks de Privacidade/Painel de Controle/Extras + desativa Cortana, e finaliza com sfc /scannow + DISM /RestoreHealth. Nao agenda chkdsk (exige reboot, foi deixado de fora de proposito).'; Destr=$true }
        [pscustomobject]@{ Cat='Rotinas'; Titulo='Rotina Colegio (completa)'; Func='Invoke-Colegio';       Desc='A rotina mais completa do script: primeiro cria ponto de restauracao + backup do registro (checkpoint de seguranca), depois roda quase toda funcao do sistema em ordem alfabetica -- limpeza (temp/prefetch/WinSxS/cache WU/Windows.old/otimizar volumes), rede (Wi-Fi/DNS Google-Cloudflare/ARP/IPv6 off), bloatware/privacidade (remove bloatware/OneDrive, servicos desnecessarios, Recall off, tweaks de privacidade/GPO/macros Office), personalizacao (tema escuro/sudo/clipboard/segundos no relogio/apps apos reboot/updates antecipados), desempenho (visual/energia/Explorer) e reforco do Defender -- termina instalando os aplicativos padrao. ATENCAO: no meio da sequencia tambem roda Enable-SMBv1 (reativa o protocolo SMBv1, legado e inseguro) -- parece inconsistente com o resto da rotina, que reforca seguranca em quase tudo mais.'; Destr=$true }

        # --- Ferramentas ---
        [pscustomobject]@{ Cat='Ferramentas'; Titulo='Converter Videos iVMS-4200 (HEVC -> MP4)'; Func='Convert-IvmsCctvVideos'; Desc='Converte videos exportados do iVMS-4200 (H.265 com aspect ratio errado) para MP4 compativel via ffmpeg: remuxa o video (sem recodificar), corrige o SAR, marca hvc1, recodifica o audio pra AAC 64kbps/16kHz e ativa faststart. Salva no destino com o mesmo nome do arquivo de origem (nao sobrescreve por padrao). Requer ffmpeg no PATH.'; Destr=$false; Params=@(
                                            @{ Nome='SourceFiles'; Rotulo='Video(s) de origem (.mp4 do iVMS-4200)'; Tipo='files'; Default=''; Exemplo='Clique no botao para escolher 1+ arquivos (pode clicar de novo pra somar mais).'; Arquivo=$true }
                                            @{ Nome='DestFolder'; Rotulo='Pasta de destino'; Tipo='text'; Default=''; Exemplo='Ex.: C:\Videos\Convertidos'; Pasta=$true }
                                            @{ Nome='SobrescreverExistente'; Rotulo='Sobrescrever se ja existir arquivo com o mesmo nome no destino'; Tipo='switch'; Default=$false }
                                          ) }
        [pscustomobject]@{ Cat='Ferramentas'; Titulo='Organizar Fotos/Videos (CamFix)'; Func='Invoke-CamFix'; Desc='Porta do script pessoal Camfix do Regnon. rename: renomeia fotos/videos pela data EXIF (requer exiftool no PATH). clean: remove espacos duplicados no nome dos arquivos. emptyfolders: remove pastas vazias (sempre recursivo). dedupe-suffix: move (nao apaga) arquivos "nome 2.ext" que ja tem um "nome.ext" original pra uma subpasta _DUPLICADOS_PADRAO, pra revisao.'; Destr=$true; Params=@(
                                            @{ Nome='Command'; Rotulo='O que fazer'; Tipo='choice'; Default='rename'; Opcoes=@('rename','clean','emptyfolders','dedupe-suffix') }
                                            @{ Nome='Path'; Rotulo='Pasta-raiz'; Tipo='text'; Default=''; Exemplo='Ex.: D:\Fotos\Viagem'; Pasta=$true }
                                            @{ Nome='Recurse'; Rotulo='Incluir subpastas (emptyfolders ja e sempre recursivo)'; Tipo='switch'; Default=$false }
                                            @{ Nome='IncludeVideos'; Rotulo='(so rename) Tambem renomear videos pela data EXIF'; Tipo='switch'; Default=$false }
                                            @{ Nome='AllFiles'; Rotulo='(so rename) Renomear qualquer arquivo, nao so fotos/videos conhecidos'; Tipo='switch'; Default=$false }
                                          ) }
    )
}

# ----------------------------------------------------------------------------
# XAML da janela principal (cores e fontes via DynamicResource, p/ tema/fonte)
# ----------------------------------------------------------------------------
$script:GuiXaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        xmlns:sys="clr-namespace:System;assembly=mscorlib"
        Title="Script Supremo de Manutencao" Height="720" Width="1080"
        WindowStartupLocation="CenterScreen" Background="{DynamicResource Bg}">
  <Window.Resources>
    <SolidColorBrush x:Key="Bg"        Color="#0f1419"/>
    <SolidColorBrush x:Key="Panel"     Color="#161b22"/>
    <SolidColorBrush x:Key="PanelDark" Color="#0d1117"/>
    <SolidColorBrush x:Key="Ink"       Color="#e6edf3"/>
    <SolidColorBrush x:Key="Muted"     Color="#8b949e"/>
    <SolidColorBrush x:Key="Border"    Color="#30363d"/>
    <SolidColorBrush x:Key="Accent"    Color="#0f5c56"/>
    <SolidColorBrush x:Key="Danger"    Color="#f85149"/>
    <SolidColorBrush x:Key="Func"      Color="#58a6ff"/>
    <sys:Double x:Key="FSBody">13</sys:Double>
    <sys:Double x:Key="FSLog">12</sys:Double>
    <Style TargetType="TextBlock"><Setter Property="Foreground" Value="{DynamicResource Ink}"/></Style>
    <Style x:Key="AccentButton" TargetType="Button">
      <Setter Property="Background" Value="{DynamicResource Accent}"/>
      <Setter Property="Foreground" Value="White"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="BorderThickness" Value="0"/>
      <Setter Property="Padding" Value="14,8"/>
      <Setter Property="Cursor" Value="Hand"/>
    </Style>
    <Style x:Key="GhostButton" TargetType="Button">
      <Setter Property="Background" Value="{DynamicResource Panel}"/>
      <Setter Property="Foreground" Value="{DynamicResource Ink}"/>
      <Setter Property="BorderBrush" Value="{DynamicResource Border}"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="Padding" Value="12,6"/>
      <Setter Property="Cursor" Value="Hand"/>
    </Style>
    <!-- Splitter: barra arrastável pra redimensionar os painéis (igual o Explorer do Windows). -->
    <Style x:Key="Splitter" TargetType="GridSplitter">
      <Setter Property="Background" Value="{DynamicResource Border}"/>
      <Style.Triggers>
        <Trigger Property="IsMouseOver" Value="True">
          <Setter Property="Background" Value="{DynamicResource Accent}"/>
        </Trigger>
      </Style.Triggers>
    </Style>
  </Window.Resources>

  <Grid Margin="12">
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="*" MinHeight="160"/>
      <RowDefinition Height="6"/>
      <RowDefinition Height="170" MinHeight="70"/>
    </Grid.RowDefinitions>

    <!-- Topo: busca + WhatIf + Personalizar -->
    <Grid Grid.Row="0" Margin="0,0,0,10">
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="*"/>
        <ColumnDefinition Width="Auto"/>
        <ColumnDefinition Width="Auto"/>
      </Grid.ColumnDefinitions>
      <TextBox x:Name="TxtBusca" Grid.Column="0" Height="34" FontSize="{DynamicResource FSBody}"
               Background="{DynamicResource Panel}" Foreground="{DynamicResource Ink}"
               BorderBrush="{DynamicResource Border}" Padding="8,6" VerticalContentAlignment="Center"/>
      <CheckBox x:Name="ChkWhatIf" Grid.Column="1" Content="Simular (WhatIf)" Margin="12,0,0,0"
                VerticalAlignment="Center" Foreground="{DynamicResource Ink}"/>
      <Button x:Name="BtnPersonalizar" Grid.Column="2" Content="&#9881; Personalizar" Margin="12,0,0,0"
              Style="{StaticResource GhostButton}"/>
    </Grid>

    <!-- Meio: categorias | splitter | acoes | splitter | detalhe -->
    <Grid Grid.Row="1">
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="200" MinWidth="120"/>
        <ColumnDefinition Width="6"/>
        <ColumnDefinition Width="*" MinWidth="220"/>
        <ColumnDefinition Width="6"/>
        <ColumnDefinition Width="340" MinWidth="240"/>
      </Grid.ColumnDefinitions>

      <ListBox x:Name="LstCategorias" Grid.Column="0" Background="{DynamicResource Panel}"
               Foreground="{DynamicResource Ink}" BorderBrush="{DynamicResource Border}" FontSize="{DynamicResource FSBody}"/>

      <GridSplitter Grid.Column="1" Width="6" HorizontalAlignment="Stretch" VerticalAlignment="Stretch"
                    Cursor="SizeWE" Style="{StaticResource Splitter}"/>

      <!-- NOVO: coluna do meio virou um grid de 2 linhas: a lista de acoes em cima e,
           fixo embaixo dela, um resumo do que a acao selecionada faz (o usuario pediu pra
           ver "quais tarefas ela executa" sem precisar olhar o painel de Detalhe a direita). -->
      <Grid Grid.Column="2">
        <Grid.RowDefinitions>
          <RowDefinition Height="*" MinHeight="80"/>
          <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <ListBox x:Name="LstAcoes" Grid.Row="0" Background="{DynamicResource Panel}"
                 Foreground="{DynamicResource Ink}" BorderBrush="{DynamicResource Border}" FontSize="{DynamicResource FSBody}">
          <ListBox.ItemTemplate>
            <DataTemplate>
              <StackPanel Orientation="Horizontal" Margin="2">
                <TextBlock Text="{Binding Marca}" Width="18" Foreground="{Binding Cor}" FontWeight="Bold"/>
                <TextBlock Text="{Binding Titulo}" Foreground="{Binding Cor}"/>
              </StackPanel>
            </DataTemplate>
          </ListBox.ItemTemplate>
        </ListBox>

        <Border Grid.Row="1" Background="{DynamicResource PanelDark}" BorderBrush="{DynamicResource Border}"
                BorderThickness="1" CornerRadius="4" Margin="0,6,0,0" Padding="10,8">
          <ScrollViewer VerticalScrollBarVisibility="Auto" MaxHeight="110">
            <TextBlock x:Name="TxtAcaoResumo" TextWrapping="Wrap" FontSize="{DynamicResource FSBody}"
                       Foreground="{DynamicResource Muted}" Text="Selecione uma acao a esquerda pra ver o que ela faz."/>
          </ScrollViewer>
        </Border>
      </Grid>

      <GridSplitter Grid.Column="3" Width="6" HorizontalAlignment="Stretch" VerticalAlignment="Stretch"
                    Cursor="SizeWE" Style="{StaticResource Splitter}"/>

      <Border Grid.Column="4" Background="{DynamicResource Panel}" BorderBrush="{DynamicResource Border}" BorderThickness="1" CornerRadius="6">
        <ScrollViewer VerticalScrollBarVisibility="Auto">
          <StackPanel Margin="14">
            <TextBlock x:Name="TxtDetTitulo" FontSize="16" FontWeight="Bold" TextWrapping="Wrap"/>
            <TextBlock x:Name="TxtDetCat" Foreground="{DynamicResource Muted}" Margin="0,4,0,0"/>
            <TextBlock x:Name="TxtDetFunc" Foreground="{DynamicResource Func}" FontFamily="Consolas" Margin="0,2,0,10"/>

            <Border BorderThickness="0,1,0,0" BorderBrush="{DynamicResource Border}" Margin="0,0,0,8"/>
            <TextBlock Text="DESCRIÇÃO" Foreground="{DynamicResource Muted}" FontWeight="SemiBold" FontSize="11" Margin="0,0,0,4"/>
            <TextBlock x:Name="TxtDetDesc" TextWrapping="Wrap" Margin="0,0,0,10"/>

            <TextBlock x:Name="TxtDetAviso" Foreground="{DynamicResource Danger}" TextWrapping="Wrap" FontWeight="SemiBold" Margin="0,0,0,10"/>

            <TextBlock x:Name="TxtParamsTitulo" Text="PARÂMETROS" Foreground="{DynamicResource Muted}" FontWeight="SemiBold" FontSize="11" Margin="0,4,0,4" Visibility="Collapsed"/>
            <StackPanel x:Name="PnlParams"/>

            <TextBlock Text="PRESETS SALVOS DESTA AÇÃO" Foreground="{DynamicResource Muted}" FontSize="11" FontWeight="SemiBold" Margin="0,10,0,4"/>
            <Grid>
              <Grid.ColumnDefinitions>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="Auto"/>
              </Grid.ColumnDefinitions>
              <ComboBox x:Name="CboPresets" Grid.Column="0"/>
              <Button x:Name="BtnCarregarPreset" Grid.Column="1" Content="Carregar" Style="{StaticResource GhostButton}" Margin="4,0,0,0"/>
            </Grid>
            <StackPanel Orientation="Horizontal" Margin="0,4,0,0">
              <Button x:Name="BtnSalvarPreset" Content="Salvar preset..." Style="{StaticResource GhostButton}"/>
              <Button x:Name="BtnExcluirPreset" Content="Excluir preset" Style="{StaticResource GhostButton}" Margin="6,0,0,0"/>
            </StackPanel>

            <TextBlock Text="ARGUMENTOS EXTRAS (AVANÇADO)" Foreground="{DynamicResource Muted}" FontSize="11" FontWeight="SemiBold" Margin="0,10,0,2"/>
            <TextBox x:Name="TxtExtra" Height="28" Background="{DynamicResource PanelDark}" Foreground="{DynamicResource Ink}"
                     BorderBrush="{DynamicResource Border}" Padding="6,3" VerticalContentAlignment="Center"/>
            <TextBlock x:Name="TxtArgDica" Foreground="{DynamicResource Muted}" FontSize="11" FontStyle="Italic" TextWrapping="Wrap" Margin="0,3,0,0"/>

            <Button x:Name="BtnExecutar" Content="Executar" Style="{StaticResource AccentButton}" Height="40" IsEnabled="False" Margin="0,14,0,0"/>
            <Button x:Name="BtnVerComando" Content="Ver comando equivalente" Style="{StaticResource GhostButton}" Margin="0,6,0,0" HorizontalAlignment="Stretch"/>
            <ProgressBar x:Name="PrgExec" Height="6" Margin="0,10,0,0" Visibility="Collapsed" IsIndeterminate="False"
                         Foreground="{DynamicResource Accent}" Background="{DynamicResource PanelDark}" BorderThickness="0"/>
            <TextBlock x:Name="TxtStatus" Margin="0,8,0,0" Foreground="{DynamicResource Muted}" TextWrapping="Wrap"/>
          </StackPanel>
        </ScrollViewer>
      </Border>
    </Grid>

    <GridSplitter Grid.Row="2" Height="6" HorizontalAlignment="Stretch" VerticalAlignment="Stretch"
                  Cursor="SizeNS" Style="{StaticResource Splitter}"/>

    <!-- Rodape: log ao vivo -->
    <Border Grid.Row="3" Margin="0,4,0,0" Background="{DynamicResource PanelDark}" BorderBrush="{DynamicResource Border}" BorderThickness="1" CornerRadius="6">
      <Grid Margin="8">
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="*"/>
        </Grid.RowDefinitions>
        <Grid Grid.Row="0" Margin="0,0,0,4">
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="*"/>
            <ColumnDefinition Width="Auto"/>
          </Grid.ColumnDefinitions>
          <TextBlock Grid.Column="0" Text="Log ao vivo" Foreground="{DynamicResource Muted}" Margin="2,0,0,0" VerticalAlignment="Center"/>
          <Button x:Name="BtnCopiarLog" Grid.Column="1" Content="Copiar log" Style="{StaticResource GhostButton}" Padding="10,3"/>
        </Grid>
        <TextBox x:Name="TxtLog" Grid.Row="1" IsReadOnly="True" TextWrapping="NoWrap"
                 VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto"
                 Background="{DynamicResource PanelDark}" Foreground="{DynamicResource Muted}"
                 FontFamily="Consolas" FontSize="{DynamicResource FSLog}" BorderThickness="0"/>
      </Grid>
    </Border>
  </Grid>
</Window>
'@

# ----------------------------------------------------------------------------
# XAML da janela de preferencias
# ----------------------------------------------------------------------------
$script:PrefsXaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        xmlns:sys="clr-namespace:System;assembly=mscorlib"
        Title="Personalizar" Height="520" Width="400" WindowStartupLocation="CenterOwner"
        ResizeMode="NoResize" Background="{DynamicResource Bg}">
  <Window.Resources>
    <!-- Autocontido: valores-padrao proprios (sobrescritos pelo tema do Owner logo apos o
         parse). Necessario porque StaticResource (usado nos Styles abaixo) e resolvido NA
         HORA DO PARSE, dentro do PROPRIO documento XAML: ele nao enxerga os recursos da
         janela principal. Sem isso, XamlReader.Parse lancava excecao ao achar os Styles dos
         botoes, e uma excecao nao tratada dentro de um Add_Click do WPF trava o Dispatcher
         (era a causa do "travou o app" ao clicar em Personalizar). -->
    <SolidColorBrush x:Key="Bg"        Color="#0f1419"/>
    <SolidColorBrush x:Key="Panel"     Color="#161b22"/>
    <SolidColorBrush x:Key="PanelDark" Color="#0d1117"/>
    <SolidColorBrush x:Key="Ink"       Color="#e6edf3"/>
    <SolidColorBrush x:Key="Muted"     Color="#8b949e"/>
    <SolidColorBrush x:Key="Border"    Color="#30363d"/>
    <SolidColorBrush x:Key="Accent"    Color="#0f5c56"/>
    <SolidColorBrush x:Key="Danger"    Color="#f85149"/>
    <SolidColorBrush x:Key="Func"      Color="#58a6ff"/>
    <sys:Double x:Key="FSBody">13</sys:Double>
    <sys:Double x:Key="FSLog">12</sys:Double>
    <Style x:Key="AccentButton" TargetType="Button">
      <Setter Property="Background" Value="{DynamicResource Accent}"/>
      <Setter Property="Foreground" Value="White"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="BorderThickness" Value="0"/>
      <Setter Property="Padding" Value="14,8"/>
      <Setter Property="Cursor" Value="Hand"/>
    </Style>
    <Style x:Key="GhostButton" TargetType="Button">
      <Setter Property="Background" Value="{DynamicResource Panel}"/>
      <Setter Property="Foreground" Value="{DynamicResource Ink}"/>
      <Setter Property="BorderBrush" Value="{DynamicResource Border}"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="Padding" Value="12,6"/>
      <Setter Property="Cursor" Value="Hand"/>
    </Style>
  </Window.Resources>
  <ScrollViewer VerticalScrollBarVisibility="Auto">
  <StackPanel Margin="18">
    <TextBlock Text="Tema" Foreground="{DynamicResource Ink}" FontWeight="SemiBold"/>
    <ComboBox x:Name="CboTema" Margin="0,4,0,12">
      <ComboBoxItem Content="Escuro"/>
      <ComboBoxItem Content="Claro"/>
      <ComboBoxItem Content="Alto Contraste"/>
      <ComboBoxItem Content="Petróleo (CMS)"/>
    </ComboBox>

    <TextBlock Text="Tamanho da fonte" Foreground="{DynamicResource Ink}" FontWeight="SemiBold"/>
    <ComboBox x:Name="CboFonte" Margin="0,4,0,12">
      <ComboBoxItem Content="Pequeno"/>
      <ComboBoxItem Content="Médio"/>
      <ComboBoxItem Content="Grande"/>
    </ComboBox>

    <CheckBox x:Name="ChkConfirmar" Content="Confirmar antes de ações destrutivas" Foreground="{DynamicResource Ink}" Margin="0,4"/>
    <CheckBox x:Name="ChkAutoScroll" Content="Rolar o log automaticamente" Foreground="{DynamicResource Ink}" Margin="0,4"/>
    <CheckBox x:Name="ChkOcultarDestr" Content="Ocultar ações destrutivas da lista" Foreground="{DynamicResource Ink}" Margin="0,4"/>

    <TextBlock Text="Ocultar categorias inteiras" Foreground="{DynamicResource Ink}" FontWeight="SemiBold" Margin="0,14,0,4"/>
    <StackPanel x:Name="PnlCategoriasOcultas"/>

    <StackPanel Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,18,0,0">
      <Button x:Name="BtnCancelar" Content="Cancelar" Style="{StaticResource GhostButton}" Margin="0,0,8,0"/>
      <Button x:Name="BtnOk" Content="Salvar" Style="{StaticResource AccentButton}"/>
    </StackPanel>
  </StackPanel>
  </ScrollViewer>
</Window>
'@

# ----------------------------------------------------------------------------
# Aplica tema + tamanho de fonte na janela (via DynamicResource)
# ----------------------------------------------------------------------------
function Set-GuiAppearance {
    param($Window, $Prefs)
    $temaNome = if ($script:GuiTemas.ContainsKey($Prefs.Tema)) { $Prefs.Tema } else { 'Escuro' }
    $tema = $script:GuiTemas[$temaNome]
    $conv = New-Object System.Windows.Media.BrushConverter
    foreach ($k in $tema.Keys) {
        try { $Window.Resources[$k] = $conv.ConvertFromString($tema[$k]) } catch { }
    }
    $fs = [double]$Prefs.Fonte
    if ($fs -lt 10) { $fs = 13 }
    $Window.Resources['FSBody'] = $fs
    $Window.Resources['FSLog']  = [double]([math]::Max(10, $fs - 1))
    return $tema
}

# ----------------------------------------------------------------------------
# Runspace de fundo com as funcoes do script + globais essenciais.
# ----------------------------------------------------------------------------
function New-GuiWorkerRunspace {
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
    return $rs
}

# ----------------------------------------------------------------------------
# Mostra um erro de forma segura (log + MessageBox) em vez de deixar uma excecao
# nao tratada escapar de dentro de um evento WPF (Add_Click/Add_Tick), o que trava
# o Dispatcher da UI em vez de so falhar visivelmente.
# ----------------------------------------------------------------------------
function Show-GuiHandlerError {
    param($Contexto, $ErroObj)
    try { Write-Log "ERRO na GUI ($Contexto): $($ErroObj.Exception.Message)" -Type Error } catch { }
    try { [System.Windows.MessageBox]::Show("Ocorreu um erro em '$Contexto':`n`n$($ErroObj.Exception.Message)", 'Erro', 'OK', 'Error') | Out-Null } catch { }
}

# ----------------------------------------------------------------------------
# NOVO: monta uma previa em texto do comando PowerShell equivalente ao que o
# botao "Executar" vai rodar de fato (mesma logica de montagem de Splat/Extra
# usada em Invoke-MaintenanceGuiWindow) -- so para o usuario conferir/copiar,
# nao executa nada.
# ----------------------------------------------------------------------------
function ConvertTo-GuiCommandPreview {
    param([string]$FuncName, [hashtable]$Splat, [string[]]$Extra, [bool]$Simular)
    $escapar = { param($s) "'" + ([string]$s -replace "'", "''") + "'" }
    $partes = New-Object System.Collections.Generic.List[string]
    $partes.Add($FuncName)
    foreach ($k in $Splat.Keys) {
        $v = $Splat[$k]
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

# ----------------------------------------------------------------------------
# Janela de preferencias (modal). Retorna $true se salvou.
# ----------------------------------------------------------------------------
function Show-GuiPreferences {
    param($Owner, $Prefs, $Catalogo)
    $win = [Windows.Markup.XamlReader]::Parse($script:PrefsXaml)
    $win.Owner = $Owner
    # herda os recursos de tema do owner p/ o modal ficar no mesmo estilo
    foreach ($k in 'Bg','Panel','PanelDark','Ink','Muted','Border','Accent','Danger','Func','FSBody','FSLog') {
        if ($Owner.Resources.Contains($k)) { $win.Resources[$k] = $Owner.Resources[$k] }
    }
    $cboTema        = $win.FindName('CboTema')
    $cboFonte       = $win.FindName('CboFonte')
    $chkConfirmar   = $win.FindName('ChkConfirmar')
    $chkAutoScroll  = $win.FindName('ChkAutoScroll')
    $chkOcultarDestr= $win.FindName('ChkOcultarDestr')
    $pnlCatOcultas  = $win.FindName('PnlCategoriasOcultas')
    $btnOk          = $win.FindName('BtnOk')
    $btnCancelar    = $win.FindName('BtnCancelar')

    # NOVO: 4 temas -- indice do combo mapeado pelo nome interno (mesma ordem dos itens no XAML).
    $temaNomes = @('Escuro','Claro','AltoContraste','Petroleo')
    $idxTema = [array]::IndexOf($temaNomes, $Prefs.Tema)
    $cboTema.SelectedIndex  = if ($idxTema -ge 0) { $idxTema } else { 0 }
    $cboFonte.SelectedIndex = switch ([int]$Prefs.Fonte) { 12 {0} 16 {2} default {1} }
    $chkConfirmar.IsChecked    = [bool]$Prefs.ConfirmarDestrutivas
    $chkAutoScroll.IsChecked   = [bool]$Prefs.AutoScrollLog
    $chkOcultarDestr.IsChecked = [bool]$Prefs.OcultarDestrutivas

    # NOVO: 1 checkbox por categoria do catalogo, marcado se ja estiver oculta.
    $categoriasOcultasAtuais = @($Prefs.CategoriasOcultas)
    $chksCategorias = @{}
    if ($Catalogo) {
        foreach ($cat in ($Catalogo | Select-Object -ExpandProperty Cat -Unique | Sort-Object)) {
            $chk = New-Object System.Windows.Controls.CheckBox
            $chk.Content = $cat
            $chk.Margin = '0,2'
            $chk.IsChecked = ($categoriasOcultasAtuais -contains $cat)
            $chk.SetResourceReference([System.Windows.Controls.CheckBox]::ForegroundProperty, 'Ink')
            [void]$pnlCatOcultas.Children.Add($chk)
            $chksCategorias[$cat] = $chk
        }
    }

    $result = @{ Salvou = $false }
    $btnOk.Add_Click({
        try {
            $Prefs.Tema = $temaNomes[$cboTema.SelectedIndex]
            $Prefs.Fonte = switch ($cboFonte.SelectedIndex) { 0 {12} 2 {16} default {14} }
            $Prefs.ConfirmarDestrutivas = [bool]$chkConfirmar.IsChecked
            $Prefs.AutoScrollLog        = [bool]$chkAutoScroll.IsChecked
            $Prefs.OcultarDestrutivas   = [bool]$chkOcultarDestr.IsChecked
            $Prefs.CategoriasOcultas    = @($chksCategorias.Keys | Where-Object { [bool]$chksCategorias[$_].IsChecked })
            $result.Salvou = $true
            $win.Close()
        } catch { Show-GuiHandlerError -Contexto 'Salvar preferencias' -ErroObj $_ }
    }.GetNewClosure())
    $btnCancelar.Add_Click({
        try { $win.Close() } catch { Show-GuiHandlerError -Contexto 'Cancelar preferencias' -ErroObj $_ }
    }.GetNewClosure())

    [void]$win.ShowDialog()
    return $result.Salvou
}

# ----------------------------------------------------------------------------
# Monta e exibe a janela principal (deve rodar em thread STA).
# ----------------------------------------------------------------------------
function Invoke-MaintenanceGuiWindow {
    # Catalogo em ordem alfabetica (categoria, depois titulo).
    $catalogo = Get-GuiActionCatalog | Sort-Object Cat, Titulo
    $prefs = Get-GuiPrefs

    $window = [Windows.Markup.XamlReader]::Parse($script:GuiXaml)
    $F = { param($n) $window.FindName($n) }
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
    $txtLog     = & $F 'TxtLog'
    $btnCopiarLog = & $F 'BtnCopiarLog'

    $tema = Set-GuiAppearance -Window $window -Prefs $prefs

    # NOVO: identidade da janela -- titulo com o nome do colegio (+ versao, se o script
    # principal expuser algum campo reconhecido em ScriptConfig) e icone gerado na hora
    # (sem depender de arquivo .ico externo nem de internet).
    $versaoTxt = if ($global:ScriptConfig -and $global:ScriptConfig.Versao) { " v$($global:ScriptConfig.Versao)" }
                 elseif ($global:ScriptConfig -and $global:ScriptConfig.Version) { " v$($global:ScriptConfig.Version)" }
                 else { '' }
    $window.Title = "Script Supremo de Manutencao$versaoTxt — Colegio Mundo do Saber"
    try {
        $iconPath = Get-GuiAppIconPath -AccentHex $tema.Accent
        if ($iconPath -and (Test-Path $iconPath)) {
            $bmpIcone = New-Object System.Windows.Media.Imaging.BitmapImage
            $bmpIcone.BeginInit()
            $bmpIcone.CacheOption = 'OnLoad'
            $bmpIcone.UriSource = New-Object System.Uri($iconPath, [System.UriKind]::Absolute)
            $bmpIcone.EndInit()
            $bmpIcone.Freeze()
            $window.Icon = $bmpIcone
        }
    } catch { }

    # NOVO: restaura tamanho/posicao da janela salvos da ultima vez, com limites minimos
    # e sem deixar a janela "perdida" fora da tela (ex.: depois de desconectar um monitor).
    if ($prefs.JanelaLargura -and $prefs.JanelaAltura) {
        try {
            $areaUtil = [System.Windows.SystemParameters]::WorkArea
            $w = [Math]::Min([double]$prefs.JanelaLargura, $areaUtil.Width)
            $h = [Math]::Min([double]$prefs.JanelaAltura, $areaUtil.Height)
            $window.Width = [Math]::Max(700, $w)
            $window.Height = [Math]::Max(400, $h)
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

    $st = @{ Worker=$null; PS=$null; Handle=$null; LogPath=$null; LogPos=0; Selecao=$null; ParamControls=@{}; InkHex=$tema.Ink; TemaAtual=$tema; Prefs=$prefs; Cronometro=$null; StatusBase='' }
    $st.LogPath = "C:\ScriptsLogs\$env:COMPUTERNAME-ScriptLog.log"
    if ((Get-Variable -Name ScriptConfig -Scope Global -ErrorAction SilentlyContinue) -and $global:ScriptConfig.LogFilePath) {
        $st.LogPath = $global:ScriptConfig.LogFilePath
    }

    # Categorias (Todas + distintas, ja alfabeticas)
    $preencherCategorias = {
        $sel = '' + $lstCat.SelectedItem
        $lstCat.Items.Clear()
        [void]$lstCat.Items.Add('Todas')
        $ocultas = @($st.Prefs.CategoriasOcultas)
        foreach ($c in ($catalogo | Select-Object -ExpandProperty Cat -Unique | Sort-Object)) {
            if ($ocultas -contains $c) { continue }  # NOVO: categoria inteira ocultada em Personalizar
            [void]$lstCat.Items.Add($c)
        }
        $lstCat.SelectedItem = if ($sel -and $lstCat.Items.Contains($sel)) {
            $sel
        } elseif (-not $sel -and $st.Prefs.UltimaCategoria -and $lstCat.Items.Contains($st.Prefs.UltimaCategoria)) {
            $st.Prefs.UltimaCategoria  # NOVO: primeira abertura -- volta pra ultima categoria usada
        } else {
            'Todas'
        }
        if (-not $lstCat.SelectedItem) { $lstCat.SelectedIndex = 0 }
    }
    & $preencherCategorias

    # Filtro/renderizacao da lista de acoes (ja alfabetica)
    $Refiltrar = {
        try {
            $termo = ('' + $txtBusca.Text).Trim().ToLower()
            $cat = '' + $lstCat.SelectedItem
            $lstAcoes.Items.Clear()
            foreach ($a in $catalogo) {
                if ($cat -ne 'Todas' -and $a.Cat -ne $cat) { continue }
                if (@($st.Prefs.CategoriasOcultas) -contains $a.Cat) { continue }  # NOVO: categoria inteira ocultada
                if ($st.Prefs.OcultarDestrutivas -and $a.Destr) { continue }
                if ($termo -and -not (
                        ($a.Titulo.ToLower().Contains($termo)) -or
                        ($a.Desc.ToLower().Contains($termo)) -or
                        ($a.Func.ToLower().Contains($termo)) -or
                        ($a.Cat.ToLower().Contains($termo)))) { continue }
                $cor = if ($a.Destr) { '#f85149' } else { $st.InkHex }
                $marca = if ($a.Destr) { [char]0x26A0 } else { [char]0x2022 }
                [void]$lstAcoes.Items.Add([pscustomobject]@{ Titulo=$a.Titulo; Marca=$marca; Cor=$cor; Acao=$a })
            }
            $txtStatus.Text = "$($lstAcoes.Items.Count) acao(oes) listada(s)."
        } catch { Show-GuiHandlerError -Contexto 'Filtrar acoes' -ErroObj $_ }
    }

    $txtBusca.Add_TextChanged($Refiltrar)
    $lstCat.Add_SelectionChanged($Refiltrar)

    # Renderiza os parametros da acao selecionada
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
                $c.SetResourceReference([System.Windows.Controls.CheckBox]::ForegroundProperty, 'Ink')
                [void]$pnlParams.Children.Add($c)
            } else {
                $lbl = New-Object System.Windows.Controls.TextBlock
                $lbl.Text = $p.Rotulo
                $lbl.Margin = '0,6,0,2'
                $lbl.TextWrapping = 'Wrap'
                $lbl.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, 'Muted')
                [void]$pnlParams.Children.Add($lbl)
                switch ($p.Tipo) {
                    'choice' {
                        $c = New-Object System.Windows.Controls.ComboBox
                        foreach ($o in $p.Opcoes) { [void]$c.Items.Add($o) }
                        if ($p.Default) { $c.SelectedItem = $p.Default } elseif ($c.Items.Count) { $c.SelectedIndex = 0 }
                    }
                    'password' {
                        # Campo mascarado (ex.: senha de Wi-Fi) — nao ecoa o valor na tela.
                        $c = New-Object System.Windows.Controls.PasswordBox
                        $c.Padding = '6,3'
                        $c.SetResourceReference([System.Windows.Controls.PasswordBox]::BackgroundProperty, 'PanelDark')
                        $c.SetResourceReference([System.Windows.Controls.PasswordBox]::ForegroundProperty, 'Ink')
                        $c.SetResourceReference([System.Windows.Controls.PasswordBox]::BorderBrushProperty, 'Border')
                    }
                    default {
                        $c = New-Object System.Windows.Controls.TextBox
                        $c.Text = [string]$p.Default
                        $c.Padding = '6,3'
                        $c.SetResourceReference([System.Windows.Controls.TextBox]::BackgroundProperty, 'PanelDark')
                        $c.SetResourceReference([System.Windows.Controls.TextBox]::ForegroundProperty, 'Ink')
                        $c.SetResourceReference([System.Windows.Controls.TextBox]::BorderBrushProperty, 'Border')
                    }
                }
                $c.Margin = '0,0,0,0'

                # NOVO: campos marcados com Pasta=$true no catalogo ganham um botao "Procurar
                # pasta..." ao lado, que abre o dialogo nativo do Windows. So se aplica a
                # TextBox (nao mexe em ComboBox/PasswordBox nem em campos sem a flag).
                # NOTA: $p e' Hashtable (nao PSCustomObject) -- .PSObject.Properties so' expoe
                # os membros da classe Hashtable (Count/Keys/...), nunca as proprias chaves.
                # Acesso direto ($p.Pasta) funciona normalmente e retorna $null se a chave
                # nao existir, entao dispensa checagem de existencia.
                $temBotaoPasta = [bool]$p.Pasta -and ($c -is [System.Windows.Controls.TextBox])
                # NOVO: campos marcados com Arquivo=$true no catalogo ganham um botao "Procurar
                # arquivo(s)..." que abre um OpenFileDialog (com Multiselect) em vez do
                # FolderBrowserDialog -- mesmo padrao do botao de pasta, so muda o dialogo.
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
                    $btnPasta.Content = if ($temBotaoArquivo) { '📄' } else { '📂' }
                    $btnPasta.Width = 34
                    $btnPasta.Margin = '4,0,0,0'
                    $btnPasta.ToolTip = if ($temBotaoArquivo) { 'Procurar arquivo(s)...' } else { 'Procurar pasta...' }
                    [System.Windows.Controls.Grid]::SetColumn($btnPasta, 1)

                    # Referencias fechadas no clique via GetNewClosure (mesmo padrao ja usado
                    # no resto do arquivo para botoes criados em loop/dinamicamente).
                    $txtRef = $c
                    $ehListaDePastas = ($p.Tipo -eq 'paths')  # 'paths' aceita varias pastas separadas por ; (soma); os demais tipos substituem o valor
                    $ehListaDeArquivos = ($p.Tipo -eq 'files') # 'files' aceita varios arquivos separados por ; (soma), igual 'paths'
                    $ehArquivo = $temBotaoArquivo
                    $btnPasta.Add_Click({
                        try {
                            if ($ehArquivo) {
                                $dlg = New-Object System.Windows.Forms.OpenFileDialog
                                $dlg.Title = 'Selecione o(s) arquivo(s)'
                                $dlg.Multiselect = $true
                                $dlg.Filter = 'Videos (*.mp4;*.mkv;*.avi;*.mov)|*.mp4;*.mkv;*.avi;*.mov|Todos os arquivos (*.*)|*.*'
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
                        } catch { Show-GuiHandlerError -Contexto 'Procurar pasta/arquivo' -ErroObj $_ }
                    }.GetNewClosure())

                    [void]$gridPasta.Children.Add($btnPasta)
                    [void]$pnlParams.Children.Add($gridPasta)
                } else {
                    [void]$pnlParams.Children.Add($c)
                }
            }
            # AppObj (so' presente nos checkboxes gerados p/ "Instalar Aplicativos") marca
            # esse controle como item de uma lista de apps -- MontarSplatExtra junta todos
            # os marcados num unico -Apps em vez de mandar cada um como parametro proprio.
            $st.ParamControls[$p.Nome] = @{ Ctrl=$c; Tipo=$p.Tipo; AppObj=$p.AppObj }

            # Exemplo (dica curta) logo abaixo do campo, quando definido no catalogo.
            # FIX: $p e' Hashtable -- PSObject.Properties.Name nunca contem 'Exemplo' (mesma
            # causa do bug do botao de pasta); a dica nunca aparecia. Acesso direto resolve.
            if ($p.Exemplo) {
                $hint = New-Object System.Windows.Controls.TextBlock
                $hint.Text = $p.Exemplo
                $hint.FontSize = 11
                $hint.FontStyle = 'Italic'
                $hint.TextWrapping = 'Wrap'
                $hint.Margin = '0,2,0,4'
                $hint.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, 'Muted')
                [void]$pnlParams.Children.Add($hint)
            }
        }
    }

    # NOVO: atualiza o combo de presets salvos para a acao atualmente selecionada.
    $AtualizarPresetsCombo = {
        param($a)
        $cboPresets.Items.Clear()
        if (-not $a) { return }
        $presetsDaAcao = @($st.Prefs.Presets | Where-Object { $_.Func -eq $a.Func })
        foreach ($ps in ($presetsDaAcao | Sort-Object Nome)) { [void]$cboPresets.Items.Add($ps.Nome) }
        if ($cboPresets.Items.Count) { $cboPresets.SelectedIndex = 0 }
    }

    # NOVO: monta { Splat; Extra } a partir dos controles dinamicos de parametros + campo
    # de argumentos extras -- compartilhado por Executar, "Ver comando equivalente" e
    # "Salvar preset..." (evita 3 copias da mesma logica de montagem).
    $MontarSplatExtra = {
        $splat = @{}
        $appsMarcados = @()
        foreach ($nome in $st.ParamControls.Keys) {
            $pc = $st.ParamControls[$nome]
            if ($pc.AppObj) {
                # Checkbox de app (gerado em Get-GuiActionCatalog p/ "Instalar Aplicativos"):
                # nao vira parametro proprio -- todos os marcados somam num unico -Apps.
                if ([bool]$pc.Ctrl.IsChecked) { $appsMarcados += $pc.AppObj }
                continue
            }
            switch ($pc.Tipo) {
                'switch'   { $splat[$nome] = [bool]$pc.Ctrl.IsChecked }
                'choice'   { $v = '' + $pc.Ctrl.SelectedItem; if ($v) { $splat[$nome] = $v } }
                'paths'    { $v = ('' + $pc.Ctrl.Text).Trim(); if ($v) { $splat[$nome] = @($v -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) } }
                'files'    { $v = ('' + $pc.Ctrl.Text).Trim(); if ($v) { $splat[$nome] = @($v -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) } }
                'password' { $v = $pc.Ctrl.Password; if ($v) { $splat[$nome] = $v } }
                default    { $v = ('' + $pc.Ctrl.Text).Trim(); if ($v) { $splat[$nome] = $v } }
            }
        }
        if ($appsMarcados.Count) { $splat['Apps'] = $appsMarcados }
        $extra = @()
        $rawExtra = ('' + $txtExtra.Text).Trim()
        if ($rawExtra) { $extra = @($rawExtra -split '\s+') }
        return @{ Splat = $splat; Extra = $extra }
    }

    $lstAcoes.Add_SelectionChanged({
      try {
        $sel = $lstAcoes.SelectedItem
        if (-not $sel) {
            $btnExec.IsEnabled = $false
            $txtAcaoResumo.Text = 'Selecione uma ação à esquerda pra ver o que ela faz.'
            return
        }
        $a = $sel.Acao
        $st.Selecao = $a
        $detTitulo.Text = $a.Titulo
        $detCat.Text = "Categoria: $($a.Cat)"
        $detFunc.Text = $a.Func + '()'
        $detDesc.Text = if ($a.Desc) { $a.Desc } else { 'Sem descrição disponível.' }
        # NOVO: mesmo resumo tambem aparece embaixo da propria lista de acoes (nao so no
        # painel de Detalhe a direita) -- pedido do usuario pra ver de cara o que a acao
        # selecionada faz, sem precisar olhar pro outro lado da tela.
        $txtAcaoResumo.Text = if ($a.Desc) { "$($a.Titulo) — $($a.Desc)" } else { "$($a.Titulo) — sem descrição disponível." }
        $detAviso.Text = if ($a.Destr) { 'Ação destrutiva/irreversível. Confira antes de executar.' } else { '' }
        $txtExtra.Text = ''
        & $renderParams $a
        & $AtualizarPresetsCombo $a
        $temParams = ($a.PSObject.Properties.Name -contains 'Params') -and $a.Params
        $txtArgDica.Text = if ($temParams) {
            'Use os campos acima (mais simples) ou digite parâmetros extras aqui, se souber a sintaxe.'
        } else {
            'Deixe em branco, a menos que saiba os parâmetros aceitos por esta função.'
        }
        $txtStatus.Text = ''
        $txtStatus.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, 'Muted')
        $btnExec.IsEnabled = $true
      } catch { Show-GuiHandlerError -Contexto 'Selecionar acao' -ErroObj $_ }
    })

    # NOVO: duplo-clique numa acao SEM parametros (nao precisa escolher pasta/arquivo/
    # opcao antes) executa direto, sem precisar clicar em "Executar" depois. Acoes COM
    # parametros (ex.: pasta, ou os checkboxes de "Instalar Aplicativos") ignoram o
    # duplo-clique -- exigem preencher os campos e clicar em Executar, como ja fazem.
    # WPF nao tem um evento "MouseDoubleClick" pronto (isso e' coisa do WinForms); o jeito
    # certo e' checar ClickCount no MouseLeftButtonDown, que ja reflete a selecao atual
    # porque o ListBoxItem processa o clique (e atualiza SelectedItem) antes de borbulhar
    # ate o ListBox.
    $lstAcoes.Add_MouseLeftButtonDown({
        try {
            if ($_.ClickCount -ne 2) { return }
            # Confere se o clique caiu de fato em cima de um item (nao na area vazia
            # abaixo do ultimo item, que herdaria a selecao anterior por engano).
            $origem = $_.OriginalSource
            while ($origem -and -not ($origem -is [System.Windows.Controls.ListBoxItem])) {
                $origem = [System.Windows.Media.VisualTreeHelper]::GetParent($origem)
            }
            if (-not $origem) { return }
            $sel = $lstAcoes.SelectedItem
            if (-not $sel) { return }
            $a = $sel.Acao
            $temParams = ($a.PSObject.Properties.Name -contains 'Params') -and $a.Params
            if (-not $temParams -and $btnExec.IsEnabled) {
                $btnExec.RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Button]::ClickEvent)))
            }
        } catch { Show-GuiHandlerError -Contexto 'Duplo-clique em acao' -ErroObj $_ }
    })

    # Timer: tail do log + fim da execucao
    $timer = New-Object System.Windows.Threading.DispatcherTimer
    $timer.Interval = [TimeSpan]::FromMilliseconds(700)
    $timer.Add_Tick({
        try {
            if (Test-Path $st.LogPath) {
                $fs = [System.IO.File]::Open($st.LogPath, 'Open', 'Read', 'ReadWrite')
                try {
                    if ($fs.Length -lt $st.LogPos) { $st.LogPos = 0 }
                    if ($fs.Length -gt $st.LogPos) {
                        $fs.Seek($st.LogPos, 'Begin') | Out-Null
                        $sr = New-Object System.IO.StreamReader($fs)
                        $novo = $sr.ReadToEnd()
                        $st.LogPos = $fs.Length
                        if ($novo) {
                            $txtLog.AppendText($novo)
                            if ($st.Prefs.AutoScrollLog) { $txtLog.ScrollToEnd() }
                        }
                    }
                } finally { $fs.Close() }
            }
        } catch { }

        # NOVO: enquanto a acao roda, mostra tempo decorrido no status (nao e' % real de
        # progresso -- as funcoes de manutencao nao reportam isso -- mas da' uma nocao viva
        # de "ainda esta trabalhando", junto com a barra indeterminada.
        if ($st.Handle -and -not $st.Handle.IsCompleted -and $st.Cronometro) {
            $txtStatus.Text = $st.StatusBase + ' (' + $st.Cronometro.Elapsed.ToString('mm\:ss') + ')'
        }

        if ($st.Handle -and $st.Handle.IsCompleted) {
            $teveErro = $false
            try { $st.PS.EndInvoke($st.Handle) } catch { $txtLog.AppendText("`n[ERRO] " + $_.Exception.Message + "`n"); $teveErro = $true }
            if ($st.PS.HadErrors) { $teveErro = $true }
            try { $st.PS.Dispose() } catch { }
            $st.PS = $null; $st.Handle = $null
            if ($st.Cronometro) { $st.Cronometro.Stop() }
            $prgExec.IsIndeterminate = $false
            $prgExec.Visibility = 'Collapsed'
            $btnExec.IsEnabled = ($null -ne $lstAcoes.SelectedItem)
            $btnExec.Content = 'Executar'
            $tempoTxt = if ($st.Cronometro) { ' (' + $st.Cronometro.Elapsed.ToString('mm\:ss') + ')' } else { '' }
            if ($teveErro) {
                $txtStatus.Text = "Concluido com erro.$tempoTxt Veja o log."
                $txtStatus.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, 'Danger')
            } else {
                $txtStatus.Text = "Concluido.$tempoTxt"
                $txtStatus.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, 'Ink')
            }
        }
    })
    $timer.Start()

    # Personalizar
    $btnPers.Add_Click({
        try {
            if (Show-GuiPreferences -Owner $window -Prefs $st.Prefs -Catalogo $catalogo) {
                Save-GuiPrefs -Prefs $st.Prefs
                $novoTema = Set-GuiAppearance -Window $window -Prefs $st.Prefs
                $st.InkHex = $novoTema.Ink
                $st.TemaAtual = $novoTema
                & $preencherCategorias  # NOVO: categorias recem-ocultadas/reexibidas somem/voltam na lista da esquerda
                & $Refiltrar            # recolore os itens da lista conforme o tema + aplica categorias/destrutivas ocultas
                $txtStatus.Text = 'Preferencias aplicadas.'
            }
        } catch { Show-GuiHandlerError -Contexto 'Abrir Personalizar' -ErroObj $_ }
    })

    # NOVO: Presets -- carregar/salvar/excluir um conjunto de parametros pre-preenchidos
    # para a acao selecionada.
    $btnCarregarPreset.Add_Click({
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
                    # Checkbox de app: nao existe uma chave propria no preset (todos os
                    # marcados foram salvos juntos em .Apps) -- restaura comparando por Id.
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
                    'password' { $pc.Ctrl.Password = [string]$valor }
                    default    { $pc.Ctrl.Text = [string]$valor }
                }
            }
            $txtExtra.Text = [string]$preset.Extra
            $chkWhatIf.IsChecked = [bool]$preset.Simular
            $txtStatus.Text = "Preset '$nomePreset' carregado."
        } catch { Show-GuiHandlerError -Contexto 'Carregar preset' -ErroObj $_ }
    })

    $btnSalvarPreset.Add_Click({
        try {
            $a = $st.Selecao
            if (-not $a) { return }
            $nome = [Microsoft.VisualBasic.Interaction]::InputBox('Nome do preset (ex.: "Fotos - so JPG"):', 'Salvar preset', '')
            $nome = ('' + $nome).Trim()
            if (-not $nome) { return }

            $montado = & $MontarSplatExtra
            $jaExiste = $st.Prefs.Presets | Where-Object { $_.Func -eq $a.Func -and $_.Nome -eq $nome }
            if ($jaExiste) {
                $r = [System.Windows.MessageBox]::Show("Ja existe um preset '$nome' para esta acao. Sobrescrever?", 'Preset existente', 'YesNo', 'Question')
                if ($r -ne 'Yes') { return }
                $st.Prefs.Presets = @($st.Prefs.Presets | Where-Object { -not ($_.Func -eq $a.Func -and $_.Nome -eq $nome) })
            }
            $novoPreset = [pscustomobject]@{ Func=$a.Func; Nome=$nome; Splat=$montado.Splat; Extra=($montado.Extra -join ' '); Simular=[bool]$chkWhatIf.IsChecked }
            $st.Prefs.Presets = @($st.Prefs.Presets) + $novoPreset
            Save-GuiPrefs -Prefs $st.Prefs
            & $AtualizarPresetsCombo $a
            $cboPresets.SelectedItem = $nome
            $txtStatus.Text = "Preset '$nome' salvo."
        } catch { Show-GuiHandlerError -Contexto 'Salvar preset' -ErroObj $_ }
    })

    $btnExcluirPreset.Add_Click({
        try {
            $a = $st.Selecao
            if (-not $a) { return }
            $nomePreset = '' + $cboPresets.SelectedItem
            if (-not $nomePreset) { return }
            $r = [System.Windows.MessageBox]::Show("Excluir o preset '$nomePreset'?", 'Confirmar exclusao', 'YesNo', 'Warning')
            if ($r -ne 'Yes') { return }
            $st.Prefs.Presets = @($st.Prefs.Presets | Where-Object { -not ($_.Func -eq $a.Func -and $_.Nome -eq $nomePreset) })
            Save-GuiPrefs -Prefs $st.Prefs
            & $AtualizarPresetsCombo $a
            $txtStatus.Text = "Preset '$nomePreset' excluido."
        } catch { Show-GuiHandlerError -Contexto 'Excluir preset' -ErroObj $_ }
    })

    # NOVO: mostra o comando PowerShell equivalente ao que "Executar" vai rodar, sem executar nada.
    $btnVerComando.Add_Click({
        try {
            $a = $st.Selecao
            if (-not $a) { return }
            $montado = & $MontarSplatExtra
            $cmd = ConvertTo-GuiCommandPreview -FuncName $a.Func -Splat $montado.Splat -Extra $montado.Extra -Simular ([bool]$chkWhatIf.IsChecked)
            [System.Windows.MessageBox]::Show($cmd, 'Comando equivalente (Ctrl+C para copiar)', 'OK', 'Information') | Out-Null
        } catch { Show-GuiHandlerError -Contexto 'Ver comando equivalente' -ErroObj $_ }
    })

    # NOVO: copia o log ao vivo inteiro pra area de transferencia.
    $btnCopiarLog.Add_Click({
        try {
            if ($txtLog.Text) {
                [System.Windows.Clipboard]::SetText($txtLog.Text)
                $txtStatus.Text = 'Log copiado para a area de transferencia.'
            }
        } catch { Show-GuiHandlerError -Contexto 'Copiar log' -ErroObj $_ }
    })

    # Executar
    $btnExec.Add_Click({
      try {
        $a = $st.Selecao
        if (-not $a) { return }
        if ($st.Handle) { return }

        if ($a.Destr -and $st.Prefs.ConfirmarDestrutivas) {
            $r = [System.Windows.MessageBox]::Show("Confirmar a acao destrutiva:`n`n$($a.Titulo)`n`nDeseja continuar?", 'Confirmacao', 'YesNo', 'Warning')
            if ($r -ne 'Yes') { return }
        }

        # Monta o splat de parametros a partir dos controles dinamicos (mesma logica usada
        # por "Ver comando equivalente" e "Salvar preset...")
        $montado = & $MontarSplatExtra
        $splat = $montado.Splat
        $extra = $montado.Extra

        $simular = [bool]$chkWhatIf.IsChecked
        if (-not $st.Worker) { $st.Worker = New-GuiWorkerRunspace }

        $script = {
            param($FuncName, $Simular, $Splat, $Extra)
            # CORREÇÃO: sempre define os dois (nas duas direções) -- o runspace de fundo é
            # reaproveitado entre cliques, então só setar quando $Simular=true "vazava" pro
            # próximo clique sem Simular marcado (ficava preso em modo simulação até fechar
            # a janela e abrir de novo).
            $global:WhatIf = [bool]$Simular
            $WhatIfPreference = [bool]$Simular
            try { & $FuncName @Splat @Extra }
            catch { Write-Log "ERRO na GUI ao executar $FuncName : $($_.Exception.Message)" -Type Error }
        }
        $st.PS = [powershell]::Create()
        $st.PS.Runspace = $st.Worker
        [void]$st.PS.AddScript($script).AddArgument($a.Func).AddArgument($simular).AddArgument($splat).AddArgument($extra)
        $st.Handle = $st.PS.BeginInvoke()

        # NOVO: indicador de progresso (indeterminado -- as funcoes de manutencao nao
        # reportam % real internamente) + cronometro pro status mostrar tempo decorrido.
        $st.Cronometro = [System.Diagnostics.Stopwatch]::StartNew()
        $prgExec.Visibility = 'Visible'
        $prgExec.IsIndeterminate = $true

        $btnExec.IsEnabled = $false
        $btnExec.Content = 'Executando...'
        $modo = if ($simular) { ' (SIMULACAO)' } else { '' }
        $extraTxt = if ($splat.Count -or $extra.Count) { ' [parametros]' } else { '' }
        $st.StatusBase = "Executando $($a.Titulo)$modo..."
        $txtStatus.Text = $st.StatusBase
        $txtStatus.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, 'Muted')
        $txtLog.AppendText("`n>>> $($a.Titulo) -> $($a.Func)$modo$extraTxt`n")
        if ($st.Prefs.AutoScrollLog) { $txtLog.ScrollToEnd() }
      } catch { Show-GuiHandlerError -Contexto 'Executar acao' -ErroObj $_ }
    })

    # NOVO: atalhos de teclado -- Ctrl+F foca a busca, Ctrl+Enter executa a acao
    # selecionada (Enter puro fica de fora de proposito, pra nao disparar sozinho
    # enquanto o usuario digita em algum campo de parametro), Esc fecha a janela.
    $window.Add_KeyDown({
        try {
            $ctrl = (([int][System.Windows.Input.Keyboard]::Modifiers) -band ([int][System.Windows.Input.ModifierKeys]::Control)) -ne 0
            if ($ctrl -and $_.Key -eq 'F') {
                $txtBusca.Focus() | Out-Null
                $txtBusca.SelectAll()
                $_.Handled = $true
            } elseif ($ctrl -and $_.Key -eq 'Return') {
                if ($btnExec.IsEnabled) { $btnExec.RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Button]::ClickEvent))) }
                $_.Handled = $true
            } elseif ($_.Key -eq 'Escape') {
                $window.Close()
                $_.Handled = $true
            }
        } catch { Show-GuiHandlerError -Contexto 'Atalho de teclado' -ErroObj $_ }
    })

    $window.Add_Closed({
        try { $timer.Stop() } catch { }
        try { if ($st.PS) { $st.PS.Dispose() } } catch { }
        try { if ($st.Worker) { $st.Worker.Close(); $st.Worker.Dispose() } } catch { }
        # NOVO: lembra tamanho/posicao da janela e a ultima categoria/acao selecionadas
        # para a proxima abertura.
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

    & $Refiltrar

    # NOVO: reabre na mesma acao usada da ultima vez, se ela ainda existir no catalogo
    # e nao estiver oculta pelos filtros atuais.
    if ($prefs.UltimaAcao) {
        foreach ($item in $lstAcoes.Items) {
            if ($item.Acao.Func -eq $prefs.UltimaAcao) { $lstAcoes.SelectedItem = $item; break }
        }
    }

    $txtLog.AppendText("Interface grafica iniciada. Selecione uma acao a esquerda.`n")
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

    Write-Log "Abrindo a interface grafica em thread STA..." -Type Info
    if (-not $GuiPath -or -not (Test-Path $GuiPath)) {
        Write-Log "Caminho do Gui.ps1 nao encontrado para o modo STA. Abortando GUI." -Type Error
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
