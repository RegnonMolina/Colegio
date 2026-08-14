# ============================================================================
# Gui.ps1 — Interface grafica (WPF) do Script Supremo de Manutencao
# ============================================================================
# Orientada a dados: Get-GuiActionCatalog e a fonte unica de verdade das acoes
# (Categoria/Titulo/Funcao/Descricao/Destrutivo). A janela so renderiza o catalogo.
#
# Dot-sourced pelo MaintenanceColegio.ps1 via Show-Gui. As funcoes reais ja
# estao no escopo quando este arquivo roda. Requer WPF (Windows + .NET).
#
# Recursos: busca em tempo real, filtro por categoria, painel de descricao,
# botao Executar + checkbox "Simular (WhatIf)", destaque vermelho p/ acoes
# destrutivas (com confirmacao), execucao em runspace de fundo (nao trava a
# janela) e log ao vivo (tail do arquivo de log do Write-Log).
# ============================================================================

Add-Type -AssemblyName PresentationFramework -ErrorAction SilentlyContinue
Add-Type -AssemblyName PresentationCore      -ErrorAction SilentlyContinue
Add-Type -AssemblyName WindowsBase           -ErrorAction SilentlyContinue

# ----------------------------------------------------------------------------
# Catalogo de acoes (fonte de verdade). Todas as Funcoes existem no script.
# Destr = $true marca acoes destrutivas (confirmacao + destaque vermelho).
# ----------------------------------------------------------------------------
function Get-GuiActionCatalog {
    @(
        # --- Limpeza e Otimizacao ---
        [pscustomobject]@{ Cat='Limpeza';       Titulo='Limpar Arquivos Temporarios';        Func='Clear-TemporaryFiles';        Desc='Remove arquivos temporarios do usuario e do sistema (%TEMP%, Windows\Temp).'; Destr=$true }
        [pscustomobject]@{ Cat='Limpeza';       Titulo='Limpar Arquivos e Pastas Vazias';    Func='Clear-EmptyFilesAndFolders';  Desc='Remove arquivos de 0 byte e pastas vazias em %TEMP% (protege marcadores como .gitkeep/desktop.ini).'; Destr=$true }
        [pscustomobject]@{ Cat='Limpeza';       Titulo='Limpar Prefetch';                    Func='Clear-Prefetch';              Desc='Limpa a pasta Prefetch do Windows.'; Destr=$true }
        [pscustomobject]@{ Cat='Limpeza';       Titulo='Limpar Cache do Windows Update';     Func='Clear-WUCache';               Desc='Limpa o cache de downloads do Windows Update (SoftwareDistribution).'; Destr=$true }
        [pscustomobject]@{ Cat='Limpeza';       Titulo='Limpar WinSxS (Componentes)';        Func='Clear-WinSxS';                Desc='Limpeza de componentes do WinSxS via DISM (StartComponentCleanup).'; Destr=$true }
        [pscustomobject]@{ Cat='Limpeza';       Titulo='Limpeza Profunda do Sistema';        Func='Clear-DeepSystemCleanup';     Desc='Rotina de limpeza profunda (cleanmgr /sagerun + caches diversos).'; Destr=$true }
        [pscustomobject]@{ Cat='Limpeza';       Titulo='Remover Pasta Windows.old';          Func='Remove-WindowsOld';           Desc='Remove a pasta Windows.old (versao anterior do Windows). Libera bastante espaco.'; Destr=$true }
        [pscustomobject]@{ Cat='Limpeza';       Titulo='Otimizar Volumes (Desfrag/ReTrim)';  Func='Optimize-Volumes';            Desc='Desfragmenta (HDD) ou faz ReTrim (SSD) dos volumes.'; Destr=$false }
        [pscustomobject]@{ Cat='Limpeza';       Titulo='Agendar ChkDsk no Reboot';           Func='New-ChkDsk';                  Desc='Agenda verificacao de disco (chkdsk) na proxima reinicializacao.'; Destr=$false }
        [pscustomobject]@{ Cat='Limpeza';       Titulo='Verificacao SFC';                    Func='Invoke-SFC-Scan';             Desc='sfc /scannow — verifica e repara arquivos de sistema.'; Destr=$false }
        [pscustomobject]@{ Cat='Limpeza';       Titulo='Verificacao DISM';                   Func='Invoke-DISM-Scan';            Desc='DISM /RestoreHealth — repara a imagem de componentes do Windows.'; Destr=$false }
        [pscustomobject]@{ Cat='Limpeza';       Titulo='Rotina Completa de Limpeza';         Func='Invoke-Cleanup';              Desc='Executa todas as tarefas de limpeza em sequencia.'; Destr=$true }

        # --- Privacidade e Seguranca ---
        [pscustomobject]@{ Cat='Privacidade';   Titulo='Remover Bloatware';                  Func='Remove-SystemBloatware';      Desc='Remove aplicativos pre-instalados (bloatware) do Windows.'; Destr=$true }
        [pscustomobject]@{ Cat='Privacidade';   Titulo='Forcar Remocao do OneDrive';         Func='Remove-OneDrive-AndRestoreFolders'; Desc='Remove o OneDrive e restaura as pastas de usuario locais.'; Destr=$true }
        [pscustomobject]@{ Cat='Privacidade';   Titulo='Desativar Windows Recall';           Func='Disable-WindowsRecall';       Desc='Desativa o recurso Windows Recall.'; Destr=$false }
        [pscustomobject]@{ Cat='Privacidade';   Titulo='Desativar Servicos Desnecessarios';  Func='Disable-UnnecessaryServices'; Desc='Desativa servicos de telemetria/Xbox/fax etc.'; Destr=$true }
        [pscustomobject]@{ Cat='Privacidade';   Titulo='Prevencao de Bloatware e Privacidade';Func='Grant-PrivacyAndBloatwarePrevention'; Desc='Aplica ajustes de privacidade e previne reinstalacao de bloatware (config global).'; Destr=$false }
        [pscustomobject]@{ Cat='Privacidade';   Titulo='Endurecimento de Privacidade';       Func='Enable-PrivacyHardening';     Desc='Aplica ajustes agressivos de privacidade (telemetria, ID de publicidade, coleta de entrada).'; Destr=$false }
        [pscustomobject]@{ Cat='Privacidade';   Titulo='Seguranca de Macros do Office';      Func='Grant-HardenOfficeMacros';    Desc='Desabilita macros perigosos do Office (Word/Excel/PowerPoint).'; Destr=$false }
        [pscustomobject]@{ Cat='Privacidade';   Titulo='Reforco de Seguranca (Defender)';    Func='Enable-WindowsHardening';     Desc='Aplica configuracoes de seguranca do Windows Defender (ASR, cloud block, PUA...).'; Destr=$false }
        [pscustomobject]@{ Cat='Privacidade';   Titulo='Desativar Cortana e Pesquisa Online';Func='Disable-Cortana-AndSearch';   Desc='Desativa a Cortana e a pesquisa online na barra de tarefas.'; Destr=$false }
        [pscustomobject]@{ Cat='Privacidade';   Titulo='Rotina Completa de Bloatware';       Func='Invoke-Bloatware';            Desc='Executa toda a remocao de bloatware/privacidade em sequencia.'; Destr=$true }

        # --- Rede ---
        [pscustomobject]@{ Cat='Rede';          Titulo='Adicionar Rede Wi-Fi';               Func='Add-WiFiNetwork';             Desc='Adiciona um perfil de rede Wi-Fi.'; Destr=$false }
        [pscustomobject]@{ Cat='Rede';          Titulo='Limpar Cache DNS';                   Func='Clear-DNS';                   Desc='ipconfig /flushdns — limpa o cache de resolucao DNS.'; Destr=$false }
        [pscustomobject]@{ Cat='Rede';          Titulo='Limpar Cache ARP';                   Func='Clear-ARP';                   Desc='Limpa a tabela ARP.'; Destr=$false }
        [pscustomobject]@{ Cat='Rede';          Titulo='Limpar Spooler de Impressao';        Func='Clear-PrintSpooler';          Desc='Limpa a fila de impressao travada.'; Destr=$false }
        [pscustomobject]@{ Cat='Rede';          Titulo='DNS Google/Cloudflare';              Func='Set-DnsGoogleCloudflare';     Desc='Configura DNS para 8.8.8.8 / 1.1.1.1.'; Destr=$false }
        [pscustomobject]@{ Cat='Rede';          Titulo='Desativar IPv6';                     Func='Disable-IPv6';                Desc='Desativa o IPv6 nas interfaces.'; Destr=$false }
        [pscustomobject]@{ Cat='Rede';          Titulo='Instalar Impressoras de Rede';       Func='Install-NetworkPrinters';     Desc='Instala as impressoras de rede configuradas.'; Destr=$false }
        [pscustomobject]@{ Cat='Rede';          Titulo='Testar Velocidade da Internet';      Func='Test-InternetSpeed';          Desc='Mede a velocidade da conexao.'; Destr=$false }
        [pscustomobject]@{ Cat='Rede';          Titulo='Mostrar Informacoes de Rede';        Func='Show-NetworkInfo';            Desc='Exibe informacoes das interfaces de rede.'; Destr=$false }
        [pscustomobject]@{ Cat='Rede';          Titulo='Otimizar Desempenho de Rede';        Func='Optimize-NetworkPerformance'; Desc='Aplica ajustes de desempenho de rede.'; Destr=$false }
        [pscustomobject]@{ Cat='Rede';          Titulo='Rotina Completa de Rede';            Func='Invoke-NetworkUtilities';     Desc='Executa todos os ajustes de rede em sequencia.'; Destr=$false }

        # --- Sistema e Desempenho ---
        [pscustomobject]@{ Cat='Sistema';       Titulo='Otimizar Desempenho do Explorer';    Func='Optimize-ExplorerPerformance';Desc='Ajustes de desempenho do Windows Explorer.'; Destr=$false }
        [pscustomobject]@{ Cat='Sistema';       Titulo='Plano de Energia Otimizado';         Func='Set-OptimizedPowerPlan';      Desc='Aplica um plano de energia otimizado.'; Destr=$false }
        [pscustomobject]@{ Cat='Sistema';       Titulo='Efeitos Visuais para Desempenho';    Func='Set-VisualPerformance';       Desc='Ajusta efeitos visuais priorizando desempenho.'; Destr=$false }
        [pscustomobject]@{ Cat='Sistema';       Titulo='Otimizacoes Gerais do Sistema';      Func='Grant-SystemOptimizations';   Desc='Aplica um conjunto de otimizacoes gerais.'; Destr=$false }
        [pscustomobject]@{ Cat='Sistema';       Titulo='Criar Ponto de Restauracao';         Func='New-SystemRestorePoint';      Desc='Habilita a Protecao do Sistema e cria um ponto de restauracao.'; Destr=$false }
        [pscustomobject]@{ Cat='Sistema';       Titulo='Renomear Notebook';                  Func='Rename-Notebook';             Desc='Renomeia o computador (pede o novo nome).'; Destr=$false }

        # --- Personalizacao ---
        [pscustomobject]@{ Cat='Personalizacao';Titulo='Ativar Tema Escuro';                 Func='Enable-DarkTheme';            Desc='Ativa o modo escuro do Windows.'; Destr=$false }
        [pscustomobject]@{ Cat='Personalizacao';Titulo='Historico da Area de Transferencia'; Func='Enable-ClipboardHistory';     Desc='Ativa o historico da area de transferencia (Win+V).'; Destr=$false }
        [pscustomobject]@{ Cat='Personalizacao';Titulo='Menu de Contexto Classico';          Func='Enable-ClassicContextMenu';   Desc='Restaura o menu de contexto classico (Windows 11).'; Destr=$false }
        [pscustomobject]@{ Cat='Personalizacao';Titulo='Segundos no Relogio';                Func='Enable-TaskbarSeconds';       Desc='Mostra os segundos no relogio da barra de tarefas.'; Destr=$false }
        [pscustomobject]@{ Cat='Personalizacao';Titulo='Finalizar Tarefa na Barra';          Func='Enable-TaskbarEndTask';       Desc='Adiciona "Finalizar tarefa" no menu da barra de tarefas.'; Destr=$false }
        [pscustomobject]@{ Cat='Personalizacao';Titulo='Windows Update Antecipado';          Func='Enable-WindowsUpdateFast';    Desc='Ativa atualizacoes antecipadas do Windows Update.'; Destr=$false }
        [pscustomobject]@{ Cat='Personalizacao';Titulo='Restaurar Apps apos Reinicio';       Func='Enable-RestartAppsAfterReboot';Desc='Reabre apps apos reiniciar.'; Destr=$false }
        [pscustomobject]@{ Cat='Personalizacao';Titulo='Updates de Outros Produtos MS';      Func='Enable-OtherMicrosoftUpdates';Desc='Recebe updates de outros produtos Microsoft.'; Destr=$false }
        [pscustomobject]@{ Cat='Personalizacao';Titulo='Habilitar Sudo';                     Func='Enable-Sudo';                 Desc='Ativa o sudo embutido (Windows 11 24H2+).'; Destr=$false }
        [pscustomobject]@{ Cat='Personalizacao';Titulo='Ajustes de UI (Widgets/Barra)';      Func='Grant-UITweaks';              Desc='Aplica ajustes de UI conforme a config global (widgets, alinhamento, pesquisa).'; Destr=$false }

        # --- Diagnosticos ---
        [pscustomobject]@{ Cat='Diagnosticos';  Titulo='Informacoes do Sistema';             Func='Show-SystemInfo';             Desc='Exibe informacoes gerais do sistema.'; Destr=$false }
        [pscustomobject]@{ Cat='Diagnosticos';  Titulo='Uso de Disco';                       Func='Show-DiskUsage';              Desc='Exibe o uso de disco por unidade.'; Destr=$false }
        [pscustomobject]@{ Cat='Diagnosticos';  Titulo='Testar Memoria';                     Func='Test-Memory';                 Desc='Agenda/executa o diagnostico de memoria.'; Destr=$false }
        [pscustomobject]@{ Cat='Diagnosticos';  Titulo='Diagnosticos Avancados';             Func='Invoke-All-DiagnosticsAdvanced'; Desc='Executa todos os diagnosticos avancados.'; Destr=$false }

        # --- Restauracao ---
        [pscustomobject]@{ Cat='Restauracao';   Titulo='Backup do Registro';                 Func='Backup-Registry';             Desc='Faz backup do registro do Windows.'; Destr=$false }
        [pscustomobject]@{ Cat='Restauracao';   Titulo='Restaurar Registro';                 Func='Restore-Registry';            Desc='Restaura o registro a partir do backup mais recente.'; Destr=$true }
        [pscustomobject]@{ Cat='Restauracao';   Titulo='Restaurar TODOS os Padroes';         Func='Restore-SystemDefaults';      Desc='Reverte os tweaks aplicados, voltando o sistema ao padrao.'; Destr=$true }
        [pscustomobject]@{ Cat='Restauracao';   Titulo='Desfazer Reforco de Privacidade';    Func='Undo-PrivacyHardening';       Desc='Desfaz os ajustes agressivos de privacidade.'; Destr=$false }
        [pscustomobject]@{ Cat='Restauracao';   Titulo='Reinstalar OneDrive';                Func='Restore-OneDrive';            Desc='Reinstala o OneDrive.'; Destr=$false }
        [pscustomobject]@{ Cat='Restauracao';   Titulo='Desfazer Tudo (Rotina)';             Func='Invoke-Undo';                 Desc='Executa toda a rotina de restauracao/reversao.'; Destr=$true }

        # --- Instalacao e Ferramentas ---
        [pscustomobject]@{ Cat='Instalacao';    Titulo='Instalar Aplicativos';               Func='Install-Applications';        Desc='Instala os aplicativos definidos (winget; usa Apps.json se existir).'; Destr=$false }
        [pscustomobject]@{ Cat='Instalacao';    Titulo='Atualizar Windows e Drivers';        Func='Update-WindowsAndDrivers';    Desc='Atualiza o Windows (PSWindowsUpdate) e drivers (winget).'; Destr=$false }
        [pscustomobject]@{ Cat='Instalacao';    Titulo='Atualizar PowerShell';               Func='Update-PowerShell';           Desc='Instala/atualiza o PowerShell (aka.ms/install-powershell).'; Destr=$false }

        # --- Avancado ---
        [pscustomobject]@{ Cat='Avancado';      Titulo='Configuracoes de GPO e Registro';    Func='Grant-GPORegistrySettings';   Desc='Aplica configuracoes de GPO via registro (Edge/Chrome/driver search...).'; Destr=$false }
        [pscustomobject]@{ Cat='Avancado';      Titulo='Desativar UAC';                      Func='Disable-UAC';                 Desc='Desativa o Controle de Conta de Usuario (UAC).'; Destr=$false }
        [pscustomobject]@{ Cat='Avancado';      Titulo='Tweaks de Privacidade';              Func='Grant-PrivacyTweaks';         Desc='Aplica os tweaks de privacidade no registro.'; Destr=$false }
        [pscustomobject]@{ Cat='Avancado';      Titulo='Tweaks de Painel de Controle';       Func='Grant-ControlPanelTweaks';    Desc='Aplica ajustes de Painel de Controle/Explorer.'; Destr=$false }
        [pscustomobject]@{ Cat='Avancado';      Titulo='Tweaks Extras';                      Func='Grant-ExtraTweaks';           Desc='Aplica tweaks extras de otimizacao/seguranca.'; Destr=$false }

        # --- Rotinas ---
        [pscustomobject]@{ Cat='Rotinas';       Titulo='Rotina Colegio (completa)';          Func='Invoke-Colegio';              Desc='Rotina completa de manutencao do Colegio (checkpoint + backup + limpeza + tweaks + apps).'; Destr=$true }
        [pscustomobject]@{ Cat='Rotinas';       Titulo='Manutencao Completa';                Func='Show-FullMaintenance';        Desc='Executa a manutencao completa (todos os grupos em sequencia).'; Destr=$true }
    )
}

# ----------------------------------------------------------------------------
# XAML da janela
# ----------------------------------------------------------------------------
$script:GuiXaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Script Supremo de Manutencao" Height="680" Width="1040"
        WindowStartupLocation="CenterScreen" Background="#0f1419">
  <Window.Resources>
    <Style TargetType="TextBlock"><Setter Property="Foreground" Value="#e6edf3"/></Style>
    <Style TargetType="Label"><Setter Property="Foreground" Value="#e6edf3"/></Style>
    <Style x:Key="AccentButton" TargetType="Button">
      <Setter Property="Background" Value="#0f5c56"/>
      <Setter Property="Foreground" Value="White"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="BorderThickness" Value="0"/>
      <Setter Property="Padding" Value="14,8"/>
      <Setter Property="Cursor" Value="Hand"/>
    </Style>
  </Window.Resources>

  <Grid Margin="12">
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="*"/>
      <RowDefinition Height="170"/>
    </Grid.RowDefinitions>

    <!-- Topo: busca + WhatIf -->
    <Grid Grid.Row="0" Margin="0,0,0,10">
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="*"/>
        <ColumnDefinition Width="Auto"/>
      </Grid.ColumnDefinitions>
      <TextBox x:Name="TxtBusca" Grid.Column="0" Height="34" FontSize="14"
               Background="#161b22" Foreground="#e6edf3" BorderBrush="#30363d"
               Padding="8,6" VerticalContentAlignment="Center"/>
      <CheckBox x:Name="ChkWhatIf" Grid.Column="1" Content="Simular (WhatIf)" Margin="12,0,0,0"
                VerticalAlignment="Center" Foreground="#e6edf3"/>
    </Grid>

    <!-- Meio: categorias | acoes | detalhe -->
    <Grid Grid.Row="1">
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="190"/>
        <ColumnDefinition Width="*"/>
        <ColumnDefinition Width="300"/>
      </Grid.ColumnDefinitions>

      <ListBox x:Name="LstCategorias" Grid.Column="0" Background="#161b22" Foreground="#e6edf3"
               BorderBrush="#30363d" FontSize="13"/>

      <ListBox x:Name="LstAcoes" Grid.Column="1" Margin="10,0" Background="#161b22"
               Foreground="#e6edf3" BorderBrush="#30363d" FontSize="13">
        <ListBox.ItemTemplate>
          <DataTemplate>
            <StackPanel Orientation="Horizontal" Margin="2">
              <TextBlock Text="{Binding Marca}" Width="18" Foreground="{Binding Cor}" FontWeight="Bold"/>
              <TextBlock Text="{Binding Titulo}" Foreground="{Binding Cor}"/>
            </StackPanel>
          </DataTemplate>
        </ListBox.ItemTemplate>
      </ListBox>

      <Border Grid.Column="2" Background="#161b22" BorderBrush="#30363d" BorderThickness="1" CornerRadius="6">
        <StackPanel Margin="14">
          <TextBlock x:Name="TxtDetTitulo" FontSize="16" FontWeight="Bold" TextWrapping="Wrap"/>
          <TextBlock x:Name="TxtDetCat" Foreground="#8b949e" Margin="0,4,0,0"/>
          <TextBlock x:Name="TxtDetFunc" Foreground="#58a6ff" FontFamily="Consolas" Margin="0,2,0,10"/>
          <TextBlock x:Name="TxtDetDesc" TextWrapping="Wrap" Margin="0,0,0,12"/>
          <TextBlock x:Name="TxtDetAviso" Foreground="#f85149" TextWrapping="Wrap" FontWeight="SemiBold" Margin="0,0,0,12"/>
          <Button x:Name="BtnExecutar" Content="Executar" Style="{StaticResource AccentButton}" Height="40" IsEnabled="False"/>
          <TextBlock x:Name="TxtStatus" Margin="0,10,0,0" Foreground="#8b949e" TextWrapping="Wrap"/>
        </StackPanel>
      </Border>
    </Grid>

    <!-- Rodape: log ao vivo -->
    <Border Grid.Row="2" Margin="0,10,0,0" Background="#0d1117" BorderBrush="#30363d" BorderThickness="1" CornerRadius="6">
      <Grid Margin="8">
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="*"/>
        </Grid.RowDefinitions>
        <TextBlock Grid.Row="0" Text="Log ao vivo" Foreground="#8b949e" Margin="2,0,0,4"/>
        <TextBox x:Name="TxtLog" Grid.Row="1" IsReadOnly="True" TextWrapping="NoWrap"
                 VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto"
                 Background="#0d1117" Foreground="#adbac7" FontFamily="Consolas" FontSize="12" BorderThickness="0"/>
      </Grid>
    </Border>
  </Grid>
</Window>
'@

# ----------------------------------------------------------------------------
# Constroi um runspace de fundo com as funcoes do script + globais essenciais,
# para executar as acoes sem travar a janela.
# ----------------------------------------------------------------------------
function New-GuiWorkerRunspace {
    $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault2()
    # Copia as funcoes do script (Verb-Substantivo) para o runspace de fundo.
    Get-ChildItem Function:\ | Where-Object { $_.Name -match '-' } | ForEach-Object {
        try {
            $entry = New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry($_.Name, $_.Definition)
            $iss.Commands.Add($entry)
        } catch { }
    }
    # Copia globais essenciais usados pelas funcoes.
    foreach ($vn in 'ScriptConfig','IsWindows11','defaultColors') {
        $v = Get-Variable -Name $vn -Scope Global -ErrorAction SilentlyContinue
        if ($v) {
            $iss.Variables.Add((New-Object System.Management.Automation.Runspaces.SessionStateVariableEntry($vn, $v.Value, '')))
        }
    }
    $rs = [runspacefactory]::CreateRunspace($iss)
    $rs.ApartmentState = 'STA'
    $rs.ThreadOptions  = 'ReuseThread'
    $rs.Open()
    return $rs
}

# ----------------------------------------------------------------------------
# Monta e exibe a janela (deve rodar em thread STA).
# ----------------------------------------------------------------------------
function Invoke-MaintenanceGuiWindow {
    $catalogo = Get-GuiActionCatalog

    $window = [Windows.Markup.XamlReader]::Parse($script:GuiXaml)
    $Txt   = { param($n) $window.FindName($n) }
    $txtBusca   = & $Txt 'TxtBusca'
    $chkWhatIf  = & $Txt 'ChkWhatIf'
    $lstCat     = & $Txt 'LstCategorias'
    $lstAcoes   = & $Txt 'LstAcoes'
    $detTitulo  = & $Txt 'TxtDetTitulo'
    $detCat     = & $Txt 'TxtDetCat'
    $detFunc    = & $Txt 'TxtDetFunc'
    $detDesc    = & $Txt 'TxtDetDesc'
    $detAviso   = & $Txt 'TxtDetAviso'
    $btnExec    = & $Txt 'BtnExecutar'
    $txtStatus  = & $Txt 'TxtStatus'
    $txtLog     = & $Txt 'TxtLog'

    # Estado compartilhado (hashtable p/ closures)
    $st = @{
        Worker    = $null
        PS        = $null
        Handle    = $null
        LogPath   = $null
        LogPos    = 0
        Selecao   = $null
    }
    # Caminho do log (mesma logica do Write-Log)
    $st.LogPath = "C:\ScriptsLogs\$env:COMPUTERNAME-ScriptLog.log"
    if ((Get-Variable -Name ScriptConfig -Scope Global -ErrorAction SilentlyContinue) -and $global:ScriptConfig.LogFilePath) {
        $st.LogPath = $global:ScriptConfig.LogFilePath
    }

    # Categorias (Todas + distintas)
    $cats = @('Todas') + ($catalogo | Select-Object -ExpandProperty Cat -Unique)
    foreach ($c in $cats) { [void]$lstCat.Items.Add($c) }
    $lstCat.SelectedIndex = 0

    # Filtro/renderizacao da lista de acoes
    $Refiltrar = {
        $termo = ('' + $txtBusca.Text).Trim().ToLower()
        $cat = '' + $lstCat.SelectedItem
        $lstAcoes.Items.Clear()
        foreach ($a in $catalogo) {
            if ($cat -ne 'Todas' -and $a.Cat -ne $cat) { continue }
            if ($termo -and -not (
                    ($a.Titulo.ToLower().Contains($termo)) -or
                    ($a.Desc.ToLower().Contains($termo)) -or
                    ($a.Func.ToLower().Contains($termo)) -or
                    ($a.Cat.ToLower().Contains($termo)))) { continue }
            $item = [pscustomobject]@{
                Titulo = $a.Titulo
                Marca  = if ($a.Destr) { [char]0x26A0 } else { [char]0x2022 }
                Cor    = if ($a.Destr) { '#f85149' } else { '#e6edf3' }
                Acao   = $a
            }
            [void]$lstAcoes.Items.Add($item)
        }
        $txtStatus.Text = "$($lstAcoes.Items.Count) acao(oes) listada(s)."
    }

    $txtBusca.Add_TextChanged($Refiltrar)
    $lstCat.Add_SelectionChanged($Refiltrar)

    $lstAcoes.Add_SelectionChanged({
        $sel = $lstAcoes.SelectedItem
        if (-not $sel) { $btnExec.IsEnabled = $false; return }
        $a = $sel.Acao
        $st.Selecao = $a
        $detTitulo.Text = $a.Titulo
        $detCat.Text = "Categoria: $($a.Cat)"
        $detFunc.Text = $a.Func + '()'
        $detDesc.Text = $a.Desc
        if ($a.Destr) { $detAviso.Text = 'Acao destrutiva/irreversivel. Confira antes de executar.' }
        else { $detAviso.Text = '' }
        $btnExec.IsEnabled = $true
    })

    # Timer p/ tail do log + deteccao de fim da execucao
    $timer = New-Object System.Windows.Threading.DispatcherTimer
    $timer.Interval = [TimeSpan]::FromMilliseconds(700)
    $timer.Add_Tick({
        # tail do log
        try {
            if (Test-Path $st.LogPath) {
                $fs = [System.IO.File]::Open($st.LogPath, 'Open', 'Read', 'ReadWrite')
                try {
                    if ($fs.Length -lt $st.LogPos) { $st.LogPos = 0 }  # log foi truncado
                    if ($fs.Length -gt $st.LogPos) {
                        $fs.Seek($st.LogPos, 'Begin') | Out-Null
                        $sr = New-Object System.IO.StreamReader($fs)
                        $novo = $sr.ReadToEnd()
                        $st.LogPos = $fs.Length
                        if ($novo) {
                            $txtLog.AppendText($novo)
                            $txtLog.ScrollToEnd()
                        }
                    }
                } finally { $fs.Close() }
            }
        } catch { }

        # fim da execucao?
        if ($st.Handle -and $st.Handle.IsCompleted) {
            try { $st.PS.EndInvoke($st.Handle) } catch {
                $txtLog.AppendText("`n[ERRO] " + $_.Exception.Message + "`n")
            }
            try { $st.PS.Dispose() } catch { }
            $st.PS = $null; $st.Handle = $null
            $btnExec.IsEnabled = ($null -ne $lstAcoes.SelectedItem)
            $btnExec.Content = 'Executar'
            $txtStatus.Text = 'Concluido.'
        }
    })
    $timer.Start()

    # Executar acao selecionada (em runspace de fundo)
    $btnExec.Add_Click({
        $a = $st.Selecao
        if (-not $a) { return }
        if ($st.Handle) { return }  # ja executando

        if ($a.Destr) {
            $r = [System.Windows.MessageBox]::Show(
                "Confirmar a acao destrutiva:`n`n$($a.Titulo)`n`nDeseja continuar?",
                'Confirmacao', 'YesNo', 'Warning')
            if ($r -ne 'Yes') { return }
        }

        $simular = [bool]$chkWhatIf.IsChecked
        if (-not $st.Worker) { $st.Worker = New-GuiWorkerRunspace }

        $script = {
            param($FuncName, $Simular)
            if ($Simular) { $global:WhatIf = $true; $WhatIfPreference = $true }
            else { $global:WhatIf = $false }
            try { & $FuncName } catch { Write-Log "ERRO na GUI ao executar $FuncName : $($_.Exception.Message)" -Type Error }
        }
        $st.PS = [powershell]::Create()
        $st.PS.Runspace = $st.Worker
        [void]$st.PS.AddScript($script).AddArgument($a.Func).AddArgument($simular)
        $st.Handle = $st.PS.BeginInvoke()

        $btnExec.IsEnabled = $false
        $btnExec.Content = 'Executando...'
        $modo = if ($simular) { ' (SIMULACAO)' } else { '' }
        $txtStatus.Text = "Executando $($a.Titulo)$modo..."
        $txtLog.AppendText("`n>>> $($a.Titulo) -> $($a.Func)$modo`n")
        $txtLog.ScrollToEnd()
    })

    # Limpeza ao fechar
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
    param(
        # Caminho do proprio Gui.ps1 (para recarregar as funcoes da GUI dentro do
        # runspace STA no caso MTA). Passado por Show-Gui.
        [string]$GuiPath
    )
    $staAtual = [System.Threading.Thread]::CurrentThread.GetApartmentState()
    if ($staAtual -eq [System.Threading.ApartmentState]::STA) {
        Invoke-MaintenanceGuiWindow
        return
    }

    # Thread MTA (pwsh 7): WPF exige STA. Hospeda a janela num runspace STA que
    # recebe as funcoes do script (via InitialSessionState) e recarrega este
    # Gui.ps1 por caminho (as funcoes da GUI ficam em escopo local de Show-Gui,
    # entao nao estao no Function:\ global para copiar).
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
    # Recarrega as funcoes da GUI no runspace STA e abre a janela.
    [void]$ps.AddScript('param($p) . $p; Invoke-MaintenanceGuiWindow').AddArgument($GuiPath)
    $ps.Invoke()
    $ps.Dispose(); $rs.Close(); $rs.Dispose()
}
