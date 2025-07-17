# ====================================================================================
# BOOTSTRAPPER PARA SCRIPT SUPREMO DE MANUTENÇÃO
# Este script é otimizado para execução via IRM | IEX
# Ele baixa o script principal e o executa localmente para evitar problemas de parsing.
# ====================================================================================

# Certifique-se de que estamos rodando como Administrador
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Este script precisa ser executado como Administrador. Por favor, feche e execute o PowerShell como Administrador." -ForegroundColor Red
    Start-Sleep 5
    exit
}

Write-Host "Iniciando o processo de configuração e execução do Script Supremo..." -ForegroundColor Cyan

# 1. Define o diretório de destino
$ScriptDownloadDir = "C:\ScriptSupremo"
Write-Host "Diretório de destino definido como: $ScriptDownloadDir" -ForegroundColor DarkCyan

# 2. Verifica se a pasta existe e a cria se necessário
if (-not (Test-Path $ScriptDownloadDir)) {
    Write-Host "A pasta '$ScriptDownloadDir' não existe. Criando..." -ForegroundColor Yellow
    try {
        New-Item -Path $ScriptDownloadDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
        Write-Host "Pasta '$ScriptDownloadDir' criada com sucesso!" -ForegroundColor Green
    } catch {
        Write-Host "ERRO: Não foi possível criar a pasta '$ScriptDownloadDir'. Verifique suas permissões." -ForegroundColor Red
        Write-Host "Detalhes do Erro: $($_.Exception.Message)" -ForegroundColor Red
        Pause
    }
} else {
    Write-Host "A pasta '$ScriptDownloadDir' já existe." -ForegroundColor DarkYellow
}

# 3. Define a URL do SEU SCRIPT PRINCIPAL ScriptSupremo.ps1 no GitHub
# Esta URL foi fornecida por você:
$MainScriptUrl = "https://raw.githubusercontent.com/RegnonMolina/Colegio/refs/heads/main/ScriptSupremo.ps1"
$OutputFileName = "ScriptSupremo.ps1"
$OutputFilePath = Join-Path $ScriptDownloadDir $OutputFileName

Write-Host "Baixando o script principal do GitHub..." -ForegroundColor DarkCyan

# 4. Baixa o script principal para o diretório de destino
try {
    Invoke-WebRequest -Uri $MainScriptUrl -OutFile $OutputFilePath -ErrorAction Stop
    Write-Host "Script principal baixado com sucesso para: $OutputFilePath" -ForegroundColor Green
} catch {
    Write-Host "ERRO: Não foi possível baixar o script principal da URL '$MainScriptUrl'." -ForegroundColor Red
    Write-Host "Verifique a URL ou sua conexão com a internet." -ForegroundColor Red
    Write-Host "Detalhes do Erro: $($_.Exception.Message)" -ForegroundColor Red
Pause
}

Write-Host "Preparando para executar o script principal..." -ForegroundColor DarkCyan

# 5. Navega até o diretório e executa o script principal
try {
    cd $ScriptDownloadDir -ErrorAction Stop
    Write-Host "Diretório atual: $(Get-Location)" -ForegroundColor Green

    Write-Host "Executando ScriptSupremo.ps1..." -ForegroundColor Cyan
    # O './' é crucial para executar scripts no diretório atual
    .\$OutputFileName # Executa o script principal
} catch {
    Write-Host "ERRO: Não foi possível executar o script '$OutputFileName'." -ForegroundColor Red
    Write-Host "Detalhes do Erro: $($_.Exception.Message)" -ForegroundColor Red
pause
}

Write-Host "Processo de inicialização do Bootstrapper concluído." -ForegroundColor Green
# ====================================================================================
