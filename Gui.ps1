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
# PARAMETROS por acao (campos dinamicos) + "argumentos extras", checkbox
# "Simular (WhatIf)", confirmacao/destaque p/ acoes destrutivas, execucao em
# runspace de fundo (nao trava a janela), log ao vivo (tail do log) e botao
# "Personalizar" (tema, fonte, confirmacoes) com preferencias salvas em JSON.
# ============================================================================

Add-Type -AssemblyName PresentationFramework -ErrorAction SilentlyContinue
Add-Type -AssemblyName PresentationCore      -ErrorAction SilentlyContinue
Add-Type -AssemblyName WindowsBase           -ErrorAction SilentlyContinue

# ----------------------------------------------------------------------------
# Paletas de tema
# ----------------------------------------------------------------------------
$script:GuiTemas = @{
    Escuro = @{ Bg='#0f1419'; Panel='#161b22'; PanelDark='#0d1117'; Ink='#e6edf3'; Muted='#8b949e'; Border='#30363d'; Accent='#0f5c56'; Danger='#f85149'; Func='#58a6ff' }
    Claro  = @{ Bg='#f6f8fa'; Panel='#ffffff'; PanelDark='#f0f2f5'; Ink='#1f2328'; Muted='#57606a'; Border='#d0d7de'; Accent='#0f5c56'; Danger='#cf222e'; Func='#0969da' }
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
    $padrao = [pscustomobject]@{ Tema='Escuro'; Fonte=13; ConfirmarDestrutivas=$true; AutoScrollLog=$true; OcultarDestrutivas=$false }
    try {
        $p = Get-GuiPrefsPath
        if (Test-Path $p) {
            $j = Get-Content $p -Raw -Encoding UTF8 | ConvertFrom-Json
            foreach ($k in 'Tema','Fonte','ConfirmarDestrutivas','AutoScrollLog','OcultarDestrutivas') {
                if ($null -ne $j.$k) { $padrao.$k = $j.$k }
            }
        }
    } catch { }
    return $padrao
}

function Save-GuiPrefs {
    param($Prefs)
    try { $Prefs | ConvertTo-Json | Set-Content -Path (Get-GuiPrefsPath) -Encoding UTF8 } catch { }
}

# ----------------------------------------------------------------------------
# Catalogo de acoes (fonte de verdade). Todas as Funcoes existem no script.
# Destr = $true marca acoes destrutivas. Params (opcional) = parametros da acao.
#   Param: @{ Nome; Rotulo; Tipo='text'|'paths'|'switch'|'choice'; Default; Opcoes }
# ----------------------------------------------------------------------------
function Get-GuiActionCatalog {
    @(
        # --- Limpeza e Otimizacao ---
        [pscustomobject]@{ Cat='Limpeza'; Titulo='Agendar ChkDsk no Reboot';           Func='New-ChkDsk';                  Desc='Agenda verificacao de disco (chkdsk) na proxima reinicializacao.'; Destr=$false }
        [pscustomobject]@{ Cat='Limpeza'; Titulo='Limpar Arquivos e Pastas Vazias';    Func='Clear-EmptyFilesAndFolders';  Desc='Remove arquivos de 0 byte e pastas vazias (protege .gitkeep/desktop.ini). Suporta -WhatIf.'; Destr=$true; Params=@(
                                            @{ Nome='Path';             Rotulo='Pastas-raiz (vazio = %TEMP% padrao)'; Tipo='paths';  Default=''; Exemplo='Ex.: D:\Outra Pasta;E:\Downloads (separe varias pastas por ;)' }
                                            @{ Nome='IncludeEmptyFiles'; Rotulo='Tambem remover arquivos de 0 byte';    Tipo='switch'; Default=$true }
                                          ) }
        [pscustomobject]@{ Cat='Limpeza'; Titulo='Limpar Arquivos Temporarios';        Func='Clear-TemporaryFiles';        Desc='Remove arquivos temporarios do usuario e do sistema (%TEMP%, Windows\Temp).'; Destr=$true }
        [pscustomobject]@{ Cat='Limpeza'; Titulo='Limpar Cache do Windows Update';     Func='Clear-WUCache';               Desc='Limpa o cache de downloads do Windows Update (SoftwareDistribution).'; Destr=$true }
        [pscustomobject]@{ Cat='Limpeza'; Titulo='Limpar Prefetch';                    Func='Clear-Prefetch';              Desc='Limpa a pasta Prefetch do Windows.'; Destr=$true }
        [pscustomobject]@{ Cat='Limpeza'; Titulo='Limpar WinSxS (Componentes)';        Func='Clear-WinSxS';                Desc='Limpeza de componentes do WinSxS via DISM (StartComponentCleanup).'; Destr=$true }
        [pscustomobject]@{ Cat='Limpeza'; Titulo='Limpeza Profunda do Sistema';        Func='Clear-DeepSystemCleanup';     Desc='Rotina de limpeza profunda (cleanmgr /sagerun + caches diversos).'; Destr=$true }
        [pscustomobject]@{ Cat='Limpeza'; Titulo='Otimizar Volumes (Desfrag/ReTrim)';  Func='Optimize-Volumes';            Desc='Desfragmenta (HDD) ou faz ReTrim (SSD) dos volumes.'; Destr=$false }
        [pscustomobject]@{ Cat='Limpeza'; Titulo='Remover Pasta Windows.old';          Func='Remove-WindowsOld';           Desc='Remove a pasta Windows.old (versao anterior do Windows). Libera bastante espaco.'; Destr=$true }
        [pscustomobject]@{ Cat='Limpeza'; Titulo='Rotina Completa de Limpeza';         Func='Invoke-Cleanup';              Desc='Executa todas as tarefas de limpeza em sequencia.'; Destr=$true }
        [pscustomobject]@{ Cat='Limpeza'; Titulo='Verificacao DISM';                   Func='Invoke-DISM-Scan';            Desc='DISM /RestoreHealth — repara a imagem de componentes do Windows.'; Destr=$false }
        [pscustomobject]@{ Cat='Limpeza'; Titulo='Verificacao SFC';                    Func='Invoke-SFC-Scan';             Desc='sfc /scannow — verifica e repara arquivos de sistema.'; Destr=$false }

        # --- Privacidade e Seguranca ---
        [pscustomobject]@{ Cat='Privacidade'; Titulo='Desativar Cortana e Pesquisa Online'; Func='Disable-Cortana-AndSearch'; Desc='Desativa a Cortana e a pesquisa online na barra de tarefas.'; Destr=$false }
        [pscustomobject]@{ Cat='Privacidade'; Titulo='Desativar Servicos Desnecessarios';   Func='Disable-UnnecessaryServices'; Desc='Desativa servicos de telemetria/Xbox/fax etc.'; Destr=$true }
        [pscustomobject]@{ Cat='Privacidade'; Titulo='Desativar Windows Recall';            Func='Disable-WindowsRecall';     Desc='Desativa o recurso Windows Recall.'; Destr=$false }
        [pscustomobject]@{ Cat='Privacidade'; Titulo='Endurecimento de Privacidade';        Func='Enable-PrivacyHardening';   Desc='Aplica ajustes agressivos de privacidade (telemetria, ID de publicidade, coleta de entrada).'; Destr=$false }
        [pscustomobject]@{ Cat='Privacidade'; Titulo='Forcar Remocao do OneDrive';          Func='Remove-OneDrive-AndRestoreFolders'; Desc='Remove o OneDrive e restaura as pastas de usuario locais.'; Destr=$true }
        [pscustomobject]@{ Cat='Privacidade'; Titulo='Prevencao de Bloatware e Privacidade';Func='Grant-PrivacyAndBloatwarePrevention'; Desc='Aplica ajustes de privacidade e previne reinstalacao de bloatware (config global).'; Destr=$false }
        [pscustomobject]@{ Cat='Privacidade'; Titulo='Reforco de Seguranca (Defender)';     Func='Enable-WindowsHardening';   Desc='Aplica configuracoes de seguranca do Windows Defender (ASR, cloud block, PUA...).'; Destr=$false }
        [pscustomobject]@{ Cat='Privacidade'; Titulo='Remover Bloatware';                   Func='Remove-SystemBloatware';    Desc='Remove aplicativos pre-instalados (bloatware) do Windows.'; Destr=$true }
        [pscustomobject]@{ Cat='Privacidade'; Titulo='Rotina Completa de Bloatware';        Func='Invoke-Bloatware';          Desc='Executa toda a remocao de bloatware/privacidade em sequencia.'; Destr=$true }
        [pscustomobject]@{ Cat='Privacidade'; Titulo='Seguranca de Macros do Office';       Func='Grant-HardenOfficeMacros';  Desc='Desabilita macros perigosos do Office (Word/Excel/PowerPoint).'; Destr=$false }

        # --- Rede ---
        [pscustomobject]@{ Cat='Rede'; Titulo='Adicionar Rede Wi-Fi';          Func='Add-WiFiNetwork';             Desc='Adiciona o perfil de rede Wi-Fi "VemProMundo - Adm". A senha vem de CMS_WIFI_KEY / WiFi.local.json; use o campo abaixo so se quiser informar outra.'; Destr=$false; Params=@(
                                            @{ Nome='WifiKey'; Rotulo='Senha do Wi-Fi (opcional — deixe em branco p/ usar a configurada)'; Tipo='password'; Default=''; Exemplo='So preencha se quiser sobrescrever a senha ja configurada.' }
                                          ) }
        [pscustomobject]@{ Cat='Rede'; Titulo='Configurar DNS Google/Cloudflare'; Func='Set-DnsGoogleCloudflare';  Desc='Configura DNS para 8.8.8.8 / 1.1.1.1.'; Destr=$false }
        [pscustomobject]@{ Cat='Rede'; Titulo='Desativar IPv6';               Func='Disable-IPv6';                Desc='Desativa o IPv6 nas interfaces.'; Destr=$false }
        [pscustomobject]@{ Cat='Rede'; Titulo='Instalar Impressoras de Rede';  Func='Install-NetworkPrinters';     Desc='Instala as impressoras de rede configuradas.'; Destr=$false }
        [pscustomobject]@{ Cat='Rede'; Titulo='Limpar Cache ARP';             Func='Clear-ARP';                   Desc='Limpa a tabela ARP.'; Destr=$false }
        [pscustomobject]@{ Cat='Rede'; Titulo='Limpar Cache DNS';             Func='Clear-DNS';                   Desc='ipconfig /flushdns — limpa o cache de resolucao DNS.'; Destr=$false }
        [pscustomobject]@{ Cat='Rede'; Titulo='Limpar Spooler de Impressao';  Func='Clear-PrintSpooler';          Desc='Limpa a fila de impressao travada.'; Destr=$false }
        [pscustomobject]@{ Cat='Rede'; Titulo='Mostrar Informacoes de Rede';  Func='Show-NetworkInfo';            Desc='Exibe informacoes das interfaces de rede.'; Destr=$false }
        [pscustomobject]@{ Cat='Rede'; Titulo='Otimizar Desempenho de Rede';  Func='Optimize-NetworkPerformance'; Desc='Aplica ajustes de desempenho de rede.'; Destr=$false }
        [pscustomobject]@{ Cat='Rede'; Titulo='Rotina Completa de Rede';      Func='Invoke-NetworkUtilities';     Desc='Executa todos os ajustes de rede em sequencia.'; Destr=$false }
        [pscustomobject]@{ Cat='Rede'; Titulo='Testar Velocidade da Internet';Func='Test-InternetSpeed';          Desc='Mede a velocidade da conexao.'; Destr=$false }

        # --- Sistema e Desempenho ---
        [pscustomobject]@{ Cat='Sistema'; Titulo='Criar Ponto de Restauracao';      Func='New-SystemRestorePoint';      Desc='Habilita a Protecao do Sistema e cria um ponto de restauracao.'; Destr=$false }
        [pscustomobject]@{ Cat='Sistema'; Titulo='Efeitos Visuais para Desempenho'; Func='Set-VisualPerformance';       Desc='Ajusta efeitos visuais priorizando desempenho.'; Destr=$false }
        [pscustomobject]@{ Cat='Sistema'; Titulo='Otimizacoes Gerais do Sistema';   Func='Grant-SystemOptimizations';   Desc='Aplica um conjunto de otimizacoes gerais.'; Destr=$false }
        [pscustomobject]@{ Cat='Sistema'; Titulo='Otimizar Desempenho do Explorer'; Func='Optimize-ExplorerPerformance';Desc='Ajustes de desempenho do Windows Explorer.'; Destr=$false }
        [pscustomobject]@{ Cat='Sistema'; Titulo='Plano de Energia Otimizado';      Func='Set-OptimizedPowerPlan';      Desc='Aplica um plano de energia otimizado.'; Destr=$false }
        [pscustomobject]@{ Cat='Sistema'; Titulo='Renomear Notebook';               Func='Rename-Notebook';             Desc='Renomeia o computador. Requer reinicio para aplicar.'; Destr=$false; Params=@(
                                            @{ Nome='NovoNome'; Rotulo='Novo nome do notebook'; Tipo='text'; Default=''; Exemplo='Ex.: CMS-NOTE-14 (sem espacos/acentos, max ~15 caracteres)' }
                                          ) }

        # --- Personalizacao ---
        [pscustomobject]@{ Cat='Personalizacao'; Titulo='Ajustes de UI (Widgets/Barra)';   Func='Grant-UITweaks';              Desc='Aplica ajustes de UI conforme a config global (widgets, alinhamento, pesquisa).'; Destr=$false }
        [pscustomobject]@{ Cat='Personalizacao'; Titulo='Ativar Tema Escuro';              Func='Enable-DarkTheme';            Desc='Ativa o modo escuro do Windows.'; Destr=$false }
        [pscustomobject]@{ Cat='Personalizacao'; Titulo='Finalizar Tarefa na Barra';       Func='Enable-TaskbarEndTask';       Desc='Adiciona "Finalizar tarefa" no menu da barra de tarefas.'; Destr=$false }
        [pscustomobject]@{ Cat='Personalizacao'; Titulo='Habilitar Sudo';                  Func='Enable-Sudo';                 Desc='Ativa o sudo embutido (Windows 11 24H2+).'; Destr=$false }
        [pscustomobject]@{ Cat='Personalizacao'; Titulo='Historico da Area de Transferencia'; Func='Enable-ClipboardHistory';  Desc='Ativa o historico da area de transferencia (Win+V).'; Destr=$false }
        [pscustomobject]@{ Cat='Personalizacao'; Titulo='Menu de Contexto Classico';       Func='Enable-ClassicContextMenu';   Desc='Restaura o menu de contexto classico (Windows 11).'; Destr=$false }
        [pscustomobject]@{ Cat='Personalizacao'; Titulo='Restaurar Apps apos Reinicio';    Func='Enable-RestartAppsAfterReboot';Desc='Reabre apps apos reiniciar.'; Destr=$false }
        [pscustomobject]@{ Cat='Personalizacao'; Titulo='Segundos no Relogio';             Func='Enable-TaskbarSeconds';       Desc='Mostra os segundos no relogio da barra de tarefas.'; Destr=$false }
        [pscustomobject]@{ Cat='Personalizacao'; Titulo='Updates de Outros Produtos MS';   Func='Enable-OtherMicrosoftUpdates';Desc='Recebe updates de outros produtos Microsoft.'; Destr=$false }
        [pscustomobject]@{ Cat='Personalizacao'; Titulo='Windows Update Antecipado';       Func='Enable-WindowsUpdateFast';    Desc='Ativa atualizacoes antecipadas do Windows Update.'; Destr=$false }

        # --- Diagnosticos ---
        [pscustomobject]@{ Cat='Diagnosticos'; Titulo='Diagnosticos Avancados';   Func='Invoke-All-DiagnosticsAdvanced'; Desc='Executa todos os diagnosticos avancados.'; Destr=$false }
        [pscustomobject]@{ Cat='Diagnosticos'; Titulo='Informacoes do Sistema';   Func='Show-SystemInfo';             Desc='Exibe informacoes gerais do sistema.'; Destr=$false }
        [pscustomobject]@{ Cat='Diagnosticos'; Titulo='Testar Memoria';           Func='Test-Memory';                 Desc='Agenda/executa o diagnostico de memoria.'; Destr=$false }
        [pscustomobject]@{ Cat='Diagnosticos'; Titulo='Uso de Disco';             Func='Show-DiskUsage';              Desc='Exibe o uso de disco por unidade.'; Destr=$false }

        # --- Restauracao ---
        [pscustomobject]@{ Cat='Restauracao'; Titulo='Backup do Registro';              Func='Backup-Registry';        Desc='Faz backup do registro do Windows.'; Destr=$false }
        [pscustomobject]@{ Cat='Restauracao'; Titulo='Desfazer Reforco de Privacidade'; Func='Undo-PrivacyHardening';  Desc='Desfaz os ajustes agressivos de privacidade.'; Destr=$false }
        [pscustomobject]@{ Cat='Restauracao'; Titulo='Desfazer Tudo (Rotina)';          Func='Invoke-Undo';            Desc='Executa toda a rotina de restauracao/reversao.'; Destr=$true }
        [pscustomobject]@{ Cat='Restauracao'; Titulo='Reinstalar OneDrive';             Func='Restore-OneDrive';       Desc='Reinstala o OneDrive.'; Destr=$false }
        [pscustomobject]@{ Cat='Restauracao'; Titulo='Restaurar Registro';              Func='Restore-Registry';       Desc='Restaura o registro (HKLM\SOFTWARE, HKLM\SYSTEM, HKCU) a partir de uma pasta de backup gerada por "Backup do Registro".'; Destr=$true; Params=@(
                                            @{ Nome='BkpPath'; Rotulo='Pasta do backup do registro'; Tipo='text'; Default=''; Exemplo='Ex.: C:\Users\SeuUsuario\Documents\reg_backup_20260814_140000' }
                                          ) }
        [pscustomobject]@{ Cat='Restauracao'; Titulo='Restaurar TODOS os Padroes';      Func='Restore-SystemDefaults'; Desc='Reverte os tweaks aplicados, voltando o sistema ao padrao.'; Destr=$true }

        # --- Instalacao e Ferramentas ---
        [pscustomobject]@{ Cat='Instalacao'; Titulo='Atualizar PowerShell';        Func='Update-PowerShell';        Desc='Instala/atualiza o PowerShell (aka.ms/install-powershell).'; Destr=$false }
        [pscustomobject]@{ Cat='Instalacao'; Titulo='Atualizar Windows e Drivers';  Func='Update-WindowsAndDrivers'; Desc='Atualiza o Windows (PSWindowsUpdate) e drivers (winget).'; Destr=$false }
        [pscustomobject]@{ Cat='Instalacao'; Titulo='Instalar Aplicativos';         Func='Install-Applications';     Desc='Instala os aplicativos definidos (winget; usa Apps.json se existir).'; Destr=$false }

        # --- Avancado ---
        [pscustomobject]@{ Cat='Avancado'; Titulo='Configuracoes de GPO e Registro'; Func='Grant-GPORegistrySettings'; Desc='Aplica configuracoes de GPO via registro (Edge/Chrome/driver search...).'; Destr=$false }
        [pscustomobject]@{ Cat='Avancado'; Titulo='Desativar UAC';                   Func='Disable-UAC';               Desc='Desativa o Controle de Conta de Usuario (UAC).'; Destr=$false }
        [pscustomobject]@{ Cat='Avancado'; Titulo='Tweaks de Painel de Controle';    Func='Grant-ControlPanelTweaks';  Desc='Aplica ajustes de Painel de Controle/Explorer.'; Destr=$false }
        [pscustomobject]@{ Cat='Avancado'; Titulo='Tweaks de Privacidade';           Func='Grant-PrivacyTweaks';       Desc='Aplica os tweaks de privacidade no registro.'; Destr=$false }
        [pscustomobject]@{ Cat='Avancado'; Titulo='Tweaks Extras';                   Func='Grant-ExtraTweaks';         Desc='Aplica tweaks extras de otimizacao/seguranca.'; Destr=$false }

        # --- Rotinas ---
        [pscustomobject]@{ Cat='Rotinas'; Titulo='Manutencao Completa';       Func='Show-FullMaintenance'; Desc='Executa a manutencao completa (todos os grupos em sequencia).'; Destr=$true }
        [pscustomobject]@{ Cat='Rotinas'; Titulo='Rotina Colegio (completa)'; Func='Invoke-Colegio';       Desc='Rotina completa de manutencao do Colegio (checkpoint + backup + limpeza + tweaks + apps).'; Destr=$true }
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
  </Window.Resources>

  <Grid Margin="12">
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="*"/>
      <RowDefinition Height="170"/>
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

    <!-- Meio: categorias | acoes | detalhe -->
    <Grid Grid.Row="1">
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="200"/>
        <ColumnDefinition Width="*"/>
        <ColumnDefinition Width="340"/>
      </Grid.ColumnDefinitions>

      <ListBox x:Name="LstCategorias" Grid.Column="0" Background="{DynamicResource Panel}"
               Foreground="{DynamicResource Ink}" BorderBrush="{DynamicResource Border}" FontSize="{DynamicResource FSBody}"/>

      <ListBox x:Name="LstAcoes" Grid.Column="1" Margin="10,0" Background="{DynamicResource Panel}"
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

      <Border Grid.Column="2" Background="{DynamicResource Panel}" BorderBrush="{DynamicResource Border}" BorderThickness="1" CornerRadius="6">
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

            <TextBlock Text="ARGUMENTOS EXTRAS (AVANÇADO)" Foreground="{DynamicResource Muted}" FontSize="11" FontWeight="SemiBold" Margin="0,10,0,2"/>
            <TextBox x:Name="TxtExtra" Height="28" Background="{DynamicResource PanelDark}" Foreground="{DynamicResource Ink}"
                     BorderBrush="{DynamicResource Border}" Padding="6,3" VerticalContentAlignment="Center"/>
            <TextBlock x:Name="TxtArgDica" Foreground="{DynamicResource Muted}" FontSize="11" FontStyle="Italic" TextWrapping="Wrap" Margin="0,3,0,0"/>

            <Button x:Name="BtnExecutar" Content="Executar" Style="{StaticResource AccentButton}" Height="40" IsEnabled="False" Margin="0,14,0,0"/>
            <TextBlock x:Name="TxtStatus" Margin="0,10,0,0" Foreground="{DynamicResource Muted}" TextWrapping="Wrap"/>
          </StackPanel>
        </ScrollViewer>
      </Border>
    </Grid>

    <!-- Rodape: log ao vivo -->
    <Border Grid.Row="2" Margin="0,10,0,0" Background="{DynamicResource PanelDark}" BorderBrush="{DynamicResource Border}" BorderThickness="1" CornerRadius="6">
      <Grid Margin="8">
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="*"/>
        </Grid.RowDefinitions>
        <TextBlock Grid.Row="0" Text="Log ao vivo" Foreground="{DynamicResource Muted}" Margin="2,0,0,4"/>
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
        Title="Personalizar" Height="360" Width="380" WindowStartupLocation="CenterOwner"
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
  <StackPanel Margin="18">
    <TextBlock Text="Tema" Foreground="{DynamicResource Ink}" FontWeight="SemiBold"/>
    <ComboBox x:Name="CboTema" Margin="0,4,0,12">
      <ComboBoxItem Content="Escuro"/>
      <ComboBoxItem Content="Claro"/>
    </ComboBox>

    <TextBlock Text="Tamanho da fonte" Foreground="{DynamicResource Ink}" FontWeight="SemiBold"/>
    <ComboBox x:Name="CboFonte" Margin="0,4,0,12">
      <ComboBoxItem Content="Pequeno"/>
      <ComboBoxItem Content="Medio"/>
      <ComboBoxItem Content="Grande"/>
    </ComboBox>

    <CheckBox x:Name="ChkConfirmar" Content="Confirmar antes de acoes destrutivas" Foreground="{DynamicResource Ink}" Margin="0,4"/>
    <CheckBox x:Name="ChkAutoScroll" Content="Rolar o log automaticamente" Foreground="{DynamicResource Ink}" Margin="0,4"/>
    <CheckBox x:Name="ChkOcultarDestr" Content="Ocultar acoes destrutivas da lista" Foreground="{DynamicResource Ink}" Margin="0,4"/>

    <StackPanel Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,18,0,0">
      <Button x:Name="BtnCancelar" Content="Cancelar" Style="{StaticResource GhostButton}" Margin="0,0,8,0"/>
      <Button x:Name="BtnOk" Content="Salvar" Style="{StaticResource AccentButton}"/>
    </StackPanel>
  </StackPanel>
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
# Janela de preferencias (modal). Retorna $true se salvou.
# ----------------------------------------------------------------------------
function Show-GuiPreferences {
    param($Owner, $Prefs)
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
    $btnOk          = $win.FindName('BtnOk')
    $btnCancelar    = $win.FindName('BtnCancelar')

    $cboTema.SelectedIndex  = if ($Prefs.Tema -eq 'Claro') { 1 } else { 0 }
    $cboFonte.SelectedIndex = switch ([int]$Prefs.Fonte) { 12 {0} 16 {2} default {1} }
    $chkConfirmar.IsChecked    = [bool]$Prefs.ConfirmarDestrutivas
    $chkAutoScroll.IsChecked   = [bool]$Prefs.AutoScrollLog
    $chkOcultarDestr.IsChecked = [bool]$Prefs.OcultarDestrutivas

    $result = @{ Salvou = $false }
    $btnOk.Add_Click({
        try {
            $Prefs.Tema = if ($cboTema.SelectedIndex -eq 1) { 'Claro' } else { 'Escuro' }
            $Prefs.Fonte = switch ($cboFonte.SelectedIndex) { 0 {12} 2 {16} default {14} }
            $Prefs.ConfirmarDestrutivas = [bool]$chkConfirmar.IsChecked
            $Prefs.AutoScrollLog        = [bool]$chkAutoScroll.IsChecked
            $Prefs.OcultarDestrutivas   = [bool]$chkOcultarDestr.IsChecked
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
    $detTitulo  = & $F 'TxtDetTitulo'
    $detCat     = & $F 'TxtDetCat'
    $detFunc    = & $F 'TxtDetFunc'
    $detDesc    = & $F 'TxtDetDesc'
    $detAviso   = & $F 'TxtDetAviso'
    $paramsTit  = & $F 'TxtParamsTitulo'
    $pnlParams  = & $F 'PnlParams'
    $txtExtra   = & $F 'TxtExtra'
    $txtArgDica = & $F 'TxtArgDica'
    $btnExec    = & $F 'BtnExecutar'
    $txtStatus  = & $F 'TxtStatus'
    $txtLog     = & $F 'TxtLog'

    $tema = Set-GuiAppearance -Window $window -Prefs $prefs

    $st = @{ Worker=$null; PS=$null; Handle=$null; LogPath=$null; LogPos=0; Selecao=$null; ParamControls=@{}; InkHex=$tema.Ink; Prefs=$prefs }
    $st.LogPath = "C:\ScriptsLogs\$env:COMPUTERNAME-ScriptLog.log"
    if ((Get-Variable -Name ScriptConfig -Scope Global -ErrorAction SilentlyContinue) -and $global:ScriptConfig.LogFilePath) {
        $st.LogPath = $global:ScriptConfig.LogFilePath
    }

    # Categorias (Todas + distintas, ja alfabeticas)
    $preencherCategorias = {
        $sel = '' + $lstCat.SelectedItem
        $lstCat.Items.Clear()
        [void]$lstCat.Items.Add('Todas')
        foreach ($c in ($catalogo | Select-Object -ExpandProperty Cat -Unique | Sort-Object)) { [void]$lstCat.Items.Add($c) }
        $lstCat.SelectedItem = if ($sel) { $sel } else { 'Todas' }
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
                [void]$pnlParams.Children.Add($c)
            }
            $st.ParamControls[$p.Nome] = @{ Ctrl=$c; Tipo=$p.Tipo }

            # Exemplo (dica curta) logo abaixo do campo, quando definido no catalogo.
            if ($p.PSObject.Properties.Name -contains 'Exemplo' -and $p.Exemplo) {
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

    $lstAcoes.Add_SelectionChanged({
      try {
        $sel = $lstAcoes.SelectedItem
        if (-not $sel) { $btnExec.IsEnabled = $false; return }
        $a = $sel.Acao
        $st.Selecao = $a
        $detTitulo.Text = $a.Titulo
        $detCat.Text = "Categoria: $($a.Cat)"
        $detFunc.Text = $a.Func + '()'
        $detDesc.Text = if ($a.Desc) { $a.Desc } else { 'Sem descrição disponível.' }
        $detAviso.Text = if ($a.Destr) { 'Ação destrutiva/irreversível. Confira antes de executar.' } else { '' }
        $txtExtra.Text = ''
        & $renderParams $a
        $temParams = ($a.PSObject.Properties.Name -contains 'Params') -and $a.Params
        $txtArgDica.Text = if ($temParams) {
            'Use os campos acima (mais simples) ou digite parâmetros extras aqui, se souber a sintaxe.'
        } else {
            'Deixe em branco, a menos que saiba os parâmetros aceitos por esta função.'
        }
        $btnExec.IsEnabled = $true
      } catch { Show-GuiHandlerError -Contexto 'Selecionar acao' -ErroObj $_ }
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

        if ($st.Handle -and $st.Handle.IsCompleted) {
            try { $st.PS.EndInvoke($st.Handle) } catch { $txtLog.AppendText("`n[ERRO] " + $_.Exception.Message + "`n") }
            try { $st.PS.Dispose() } catch { }
            $st.PS = $null; $st.Handle = $null
            $btnExec.IsEnabled = ($null -ne $lstAcoes.SelectedItem)
            $btnExec.Content = 'Executar'
            $txtStatus.Text = 'Concluido.'
        }
    })
    $timer.Start()

    # Personalizar
    $btnPers.Add_Click({
        try {
            if (Show-GuiPreferences -Owner $window -Prefs $st.Prefs) {
                Save-GuiPrefs -Prefs $st.Prefs
                $novoTema = Set-GuiAppearance -Window $window -Prefs $st.Prefs
                $st.InkHex = $novoTema.Ink
                & $Refiltrar   # recolore os itens da lista conforme o tema
                $txtStatus.Text = 'Preferencias aplicadas.'
            }
        } catch { Show-GuiHandlerError -Contexto 'Abrir Personalizar' -ErroObj $_ }
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

        # Monta o splat de parametros a partir dos controles dinamicos
        $splat = @{}
        foreach ($nome in $st.ParamControls.Keys) {
            $pc = $st.ParamControls[$nome]
            switch ($pc.Tipo) {
                'switch'   { $splat[$nome] = [bool]$pc.Ctrl.IsChecked }
                'choice'   { $v = '' + $pc.Ctrl.SelectedItem; if ($v) { $splat[$nome] = $v } }
                'paths'    { $v = ('' + $pc.Ctrl.Text).Trim(); if ($v) { $splat[$nome] = @($v -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) } }
                'password' { $v = $pc.Ctrl.Password; if ($v) { $splat[$nome] = $v } }  # so envia se preenchido (senao usa o fallback interno da funcao)
                default    { $v = ('' + $pc.Ctrl.Text).Trim(); if ($v) { $splat[$nome] = $v } }
            }
        }
        $extra = @()
        $rawExtra = ('' + $txtExtra.Text).Trim()
        if ($rawExtra) { $extra = @($rawExtra -split '\s+') }

        $simular = [bool]$chkWhatIf.IsChecked
        if (-not $st.Worker) { $st.Worker = New-GuiWorkerRunspace }

        $script = {
            param($FuncName, $Simular, $Splat, $Extra)
            if ($Simular) { $global:WhatIf = $true; $WhatIfPreference = $true } else { $global:WhatIf = $false }
            try { & $FuncName @Splat @Extra }
            catch { Write-Log "ERRO na GUI ao executar $FuncName : $($_.Exception.Message)" -Type Error }
        }
        $st.PS = [powershell]::Create()
        $st.PS.Runspace = $st.Worker
        [void]$st.PS.AddScript($script).AddArgument($a.Func).AddArgument($simular).AddArgument($splat).AddArgument($extra)
        $st.Handle = $st.PS.BeginInvoke()

        $btnExec.IsEnabled = $false
        $btnExec.Content = 'Executando...'
        $modo = if ($simular) { ' (SIMULACAO)' } else { '' }
        $extraTxt = if ($splat.Count -or $extra.Count) { ' [parametros]' } else { '' }
        $txtStatus.Text = "Executando $($a.Titulo)$modo..."
        $txtLog.AppendText("`n>>> $($a.Titulo) -> $($a.Func)$modo$extraTxt`n")
        if ($st.Prefs.AutoScrollLog) { $txtLog.ScrollToEnd() }
      } catch { Show-GuiHandlerError -Contexto 'Executar acao' -ErroObj $_ }
    })

    $window.Add_Closed({
        try { $timer.Stop() } catch { }
        try { if ($st.PS) { $st.PS.Dispose() } } catch { }
        try { if ($st.Worker) { $st.Worker.Close(); $st.Worker.Dispose() } } catch { }
    })

    & $Refiltrar
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
