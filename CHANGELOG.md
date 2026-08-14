# Changelog — Script Supremo de Manutenção

Formato baseado em [Keep a Changelog](https://keepachangelog.com/pt-BR/).

## [2.3.1] - 2026-08-14

### Adicionado
- **Painéis redimensionáveis na GUI** (`GridSplitter`, como o Explorer do Windows): agora dá pra arrastar a barra entre Categorias/Ações, entre Ações/Detalhe, e entre a área do meio e o Log ao vivo. Barras destacam em verde ao passar o mouse; cada painel tem um tamanho mínimo (não dá pra arrastar até sumir).

## [2.3.0] - 2026-08-14

### Adicionado
- **`Remove-DuplicateFiles`** — nova função de limpeza: procura arquivos duplicados em pastas e subpastas por **duas formas complementares**:
  - **Hash (SHA256)** — conteúdo idêntico, sempre confiável. Só calcula hash dentro de grupos do mesmo tamanho (otimização).
  - **Nome semelhante** — padrões clássicos do Windows/navegador (`arquivo (1).ext`, `arquivo - Cópia.ext`, `arquivo - Copy.ext`, `arquivo_copy.ext`...), exigindo também o mesmo tamanho. Como o conteúdo pode diferir (hash não bate), esse grupo fica **só no relatório por padrão** — não remove nada sozinho; `-IncluirCandidatosPorNome` habilita a remoção também desse grupo.
  - Mantém **sempre 1 cópia** por grupo (a mais antiga por padrão, `-Manter MaisNovo` inverte) — nunca remove todas as cópias.
  - Protege nomes de sistema (`desktop.ini`, `Thumbs.db`, `.gitkeep`...) e ignora arquivos abaixo de `-TamanhoMinimoKB` (padrão 1 KB).
  - Pastas padrão: Downloads, Documentos, Área de Trabalho, Imagens, Vídeos, Música do usuário.
  - Suporta `-WhatIf`/`-Confirm`; `ConfirmImpact=High` pede confirmação por padrão (mesmo padrão de `Restore-SystemDefaults`).
  - **Deliberadamente fora da Rotina Completa de Limpeza (`Z`)** — requer revisão humana antes de rodar, não é acionada automaticamente por nenhuma rotina desatendida.
  - Menu: `⚙️ Limpeza e Otimização → N`. GUI: categoria Limpeza, com parâmetros estruturados (pastas, método, qual manter, tamanho mínimo, incluir candidatos por nome).
  - **Testado ao vivo** contra arquivos reais (não só sintaxe): grupos de hash reduzidos a 1 cópia, candidatos por nome preservados por padrão, arquivos protegidos e únicos intocados, `-WhatIf` não apaga nada, `-IncluirCandidatosPorNome` remove o grupo de revisão quando pedido.

### Corrigido
- **GUI: "Simular (WhatIf)" vazava para as próximas execuções** — o runspace de fundo é reaproveitado entre cliques; `$WhatIfPreference` só era setado quando o checkbox estava marcado, nunca resetado no `else`, então uma ação rodada com Simular deixava TODAS as ações seguintes em modo simulação (mesmo sem marcar) até fechar a janela. Corrigido: agora sempre define `$global:WhatIf`/`$WhatIfPreference` nas duas direções a cada execução.

## [2.2.2] - 2026-08-14

### Corrigido (bug real: "cliquei em Personalizar, travou o app")
- **Causa raiz:** a janela de preferências (`PrefsXaml`) referenciava `Style="{StaticResource GhostButton}"` e `{StaticResource AccentButton}`, definidos **apenas** nos recursos da janela principal. `StaticResource` é resolvido **na hora do parse**, dentro do próprio documento XAML — `PrefsXaml` não tinha esses estilos no seu próprio `<Window.Resources>`, então `XamlReader.Parse()` lançava exceção assim que o botão "Personalizar" era clicado. Uma exceção não tratada dentro de um `Add_Click` do WPF trava o `Dispatcher` da UI em vez de falhar visivelmente — daí o "travou o app".
- **Fix:** `PrefsXaml` ganhou seu próprio `<Window.Resources>` completo e autocontido (cores/fontes padrão + os dois estilos de botão), não depende mais de recursos externos pra fazer o parse.
- **Blindagem geral:** todo `Add_Click`/`Add_SelectionChanged`/`Add_TextChanged` da GUI agora está envolto em try/catch com `Show-GuiHandlerError` (log + MessageBox de erro visível), pra qualquer exceção futura nunca mais travar a janela silenciosamente.
- **Validado desta vez com o parser WPF real** (`[Windows.Markup.XamlReader]::Parse`, disponível neste ambiente Windows): as duas janelas parseiam sem erro, todos os controles nomeados resolvem via `FindName`, `Set-GuiAppearance` funciona nos dois temas, round-trip de preferências grava certo.

## [2.2.1] - 2026-08-14

### Corrigido (achado testando a GUI ao vivo)
- **Descrição pouco visível no painel de detalhe** — ganhou cabeçalho "DESCRIÇÃO" + divisor, igual ao de "PARÂMETROS", além de um texto de fallback ("Sem descrição disponível.") caso algum item fique sem uma no futuro.
- **`Restore-Registry`, `Restore-Registry-FromBackup` e `Rename-Notebook` usavam `Read-Host`** — travariam se chamadas pela GUI (o runspace de fundo não tem console pra digitar). Cada uma ganhou um parâmetro opcional (`-BkpPath` / `-NovoNome`) que pula o prompt quando fornecido; sem ele, o comportamento interativo do menu de texto continua idêntico.
- **`Add-WiFiNetwork`** ganhou `-WifiKey` opcional (prioridade sobre env/arquivo) pelo mesmo motivo, evitando o `Read-Host -AsSecureString` em background.

### Adicionado
- **Sugestões de argumentos**: parâmetros do catálogo podem ter um `Exemplo` (dica curta exibida abaixo do campo). Ex.: "Limpar Arquivos e Pastas Vazias" mostra `Ex.: D:\Outra Pasta;E:\Downloads`.
- **Novos parâmetros estruturados na GUI**: "Restaurar Registro" (pasta do backup), "Renomear Notebook" (novo nome), "Adicionar Rede Wi-Fi" (senha — campo **mascarado**, tipo `password`/`PasswordBox`).
- Dica dinâmica abaixo de "Argumentos extras" (muda conforme a ação tem ou não parâmetros estruturados).

## [2.2.0] - 2026-08-14

### Adicionado (GUI mais profissional)
- **Parâmetros por ação** na GUI: ações com `Params` no catálogo renderizam campos dinâmicos (texto/pastas/switch/escolha) — ex.: `Clear-Arquivos e Pastas Vazias` expõe `Path` e `IncludeEmptyFiles`. Campo **"Argumentos extras (avançado)"** disponível para qualquer ação (ex.: `-Verbose`), passado direto para a função (splat + args).
- **Botão ⚙ Personalizar**: janela de preferências com **tema (Escuro/Claro)**, **tamanho da fonte** (Pequeno/Médio/Grande), **confirmar ações destrutivas**, **auto-scroll do log** e **ocultar ações destrutivas**. Preferências persistidas em `%APPDATA%\ScriptSupremo\gui-prefs.json` e aplicadas ao vivo (tema/fonte via `DynamicResource`).
- **Ordem alfabética** em toda a GUI: categorias e ações ordenadas (`Sort-Object Cat, Titulo`).

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
