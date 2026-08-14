# Changelog — Script Supremo de Manutenção

Formato baseado em [Keep a Changelog](https://keepachangelog.com/pt-BR/).

## [2.1.0] - 2026-08-14

### Adicionado
- **Interface gráfica (WPF)** — `Gui.ps1`, aberta por `-Gui`, pelo item `K) Interface Gráfica` do menu, ou pela função `Show-Gui`. O menu de texto continua intacto (aditivo).
  - Orientada a dados: `Get-GuiActionCatalog` é a fonte única de ~69 ações (Categoria/Título/Função/Descrição/Destrutivo).
  - Busca em tempo real, filtro por categoria, painel de descrição, checkbox **Simular (WhatIf)**, destaque vermelho + confirmação para ações destrutivas, **log ao vivo** (tail do arquivo do `Write-Log`).
  - Execução em **runspace de fundo** (não trava a janela); trata thread **STA** (funciona em Windows PowerShell 5.1 e pwsh 7).
  - `Show-Gui` carrega o `Gui.ps1` do lado do script ou baixa do repositório (caminho `irm | iex`).
- CI passa a lintar `Gui.ps1` também (PSScriptAnalyzer); a checagem anti-fantasma segue no arquivo self-contained.

## [2.0.0] - 2026-08-13

### Corrigido
- **`$IsWindows11` nunca era definido** → agora `$global:IsWindows11 = build >= 22000`; destrava os tweaks de Win11 em `Grant-UITweaks`.
- **Config global sombreada**: `Grant-PrivacyAndBloatwarePrevention` e `Grant-UITweaks` declaravam `param([hashtable]$ScriptConfig)` e viravam no-op silencioso quando chamadas sem argumento — parâmetro removido, passam a usar o `$ScriptConfig` global.
- **`$WhatIf` nunca era setado** → novo parâmetro `[switch]$WhatIf`, ativando de fato os blocos `if (-not $WhatIf)`.
- **Checagem de Administrador** chamava `Write-Log` antes dele existir (load time) → trocado por `Write-Host`.
- **Dois caminhos de log divergentes** (`$ScriptConfig.LogFilePath` morto x hardcoded) → `Write-Log` agora deriva de `$ScriptConfig.LogFilePath` (fonte única).
- **Chamadas duplicadas** em `Invoke-Colegio` (`Backup-Registry`, `Clear-DeepSystemCleanup`) e `Invoke-Bloatware` (`Remove-SystemBloatware`) removidas.

### Implementado (antes eram funções-fantasma, chamadas mas nunca definidas)
- `Grant-PrivacyTweaks`, `Grant-ControlPanelTweaks`, `Grant-ExtraTweaks` (wrappers sobre `Set-SystemTweaks`).
- `Invoke-AppsAndTools` (orquestrador de Instalação e Ferramentas).
- `Restore-ControlPanelTweaks` (restore focada de Painel de Controle/Explorer).

### Adicionado
- **Menu principal**: `I) Limpeza e Otimização`, `J) Diagnósticos`; `G) Restaurações` passou a abrir o menu completo (`Invoke-Undo` virou opção `Z` interna).
- **Funções órfãs** organizadas nos menus: `Clear-EmptyFilesAndFolders`, `Remove-WindowsOld`, `Restore-Registry-FromBackup`, `Undo-PrivacyHardening`, `Restore-SystemDefaults`, `Update-WindowsAndDrivers`, `Update-PowerShell`, `Enable-PrivacyHardening`, `Grant-HardenOfficeMacros`, submenu `Show-PersonalizationTweaksMenu`.
- **Pré-flight** (`Show-EnvironmentCheck`): admin, build do SO, winget, PSWindowsUpdate, Proteção do Sistema, reboot pendente, espaço livre.
- **Relatório final** (`Show-CleanupReport`): GB liberados após a limpeza.
- **Modo desatendido** (`-Unattended`): roda a Rotina Colégio sem menu e encerra.
- **Lista de apps externalizável** (`Apps.json`; ver `Apps.example.json`) com fallback embutido.
- **`#Requires -Version 5.1` / `-RunAsAdministrator`**.
- **`Read-MenuKey`**: leitor único de tecla de menu (padroniza a leitura antes dispersa entre enum e char).
- **CI de lint** (GitHub Actions): PSScriptAnalyzer + verificação AST de funções chamadas-mas-não-definidas.

### Robustez
- `New-SystemRestorePoint` agora habilita a Proteção do Sistema e remove o throttle de 24h antes do checkpoint.
- `Update-WindowsAndDrivers` guarda `winget`/`PSWindowsUpdate` ausentes sem derrubar a rotina.

## [1.x] - até 2026-08-13
- Versão de auditoria com scrub de Wi-Fi (ver histórico do git). Correções numeradas (#2, #3, #6, #12, #13) embutidas como comentários no código.
