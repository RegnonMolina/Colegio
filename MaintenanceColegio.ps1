# ===============================
# SCRIPT SUPREMO DE MANUTENÇÃO 🛠️
# ===============================
# Iniciado em: $(Get-Date)
# Desenvolvido com sangue, café e PowerShell 💪

#clear-host
Write-Host "-------------------------------------------------------------------------"
Write-Host "| Script pra ajustes de notebooks do ambiente do Colégio Mundo do Saber |"
Write-Host "-------------------------------------------------------------------------"

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
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" = @{"Is-CortanaConsent" = 0}; # Chave corrigida: entre aspas

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
        "XboxNetApiSvc",                            # Xbox Live Networking Service
        "ndu"                                       # Windows Network Data Usage Monitor
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
    Write-Log "Aplicando tweaks extras de sistema..." Yellow

    $registryChanges = @{
        # Desabilitar o serviço de impressão (se não usar impressora)
        "HKLM:\SYSTEM\CurrentControlSet\Services\Spooler" = @{Start = 4}; # 4 = Desabilitado
        # Desabilitar a hibernação (economiza espaço em disco)
        # Nota: powercfg é um executável, mantido aqui, pois não há cmdlet direto para isso.
        "HKLM:\SYSTEM\CurrentControlSet\Control\Power" = @{HibernateEnabled = 0};
        # Desabilitar 'Last Access Timestamp' em arquivos (melhora performance de disco)
        "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" = @{NtfsDisableLastAccessUpdate = 1};
        # Aumentar a cache de I/O de disco
        "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" = @{LargeSystemCache = 1};
        # Desativar o Superfetch/SysMain (pode ser útil para SSDs antigos ou pouca RAM)
        "HKLM:\SYSTEM\CurrentControlSet\Services\SysMain" = @{Start = 4}; # 4 = Desabilitado
        # Desativar a otimização de entrega (Delivery Optimization)
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" = @{DODownloadMode = 0; DORestrictPeerSelectionBy = 1; DODisplayCacheSizeBytes = 0};
        # Desativar feedback de animação de inicialização do Windows
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" = @{DisableBootAnimation = 1};
        # Desativar o log de erros do Windows
        "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" = @{Disabled = 1};
        # Desativar o Windows Defender (se você tem um AV de terceiros)
        # ATENÇÃO: Desativar o Defender sem outro AV é um risco de segurança!
        # "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" = @{DisableAntiSpyware = 1};
        # "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" = @{DisableRealtimeMonitoring = 1};
        # Desativar acesso a USB (CUIDADO! Bloqueia pendrives, etc.)
        # "HKLM:\SYSTEM\CurrentControlSet\Services\UsbStor" = @{Start = 4};

        # Desabilitar o Serviço de Fax (se não usar)
        "HKLM:\SYSTEM\CurrentControlSet\Services\Fax" = @{Start = 4};
        # Desabilitar o Serviço de Desktop Remoto (se não usar)
        "HKLM:\SYSTEM\CurrentControlSet\Services\TermService" = @{Start = 4};

        # Ajustes para o Explorador de Arquivos
        # Desabilitar auto-rearranjar ícones no desktop (se não feito no Grant-ControlPanelTweaks)
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" = @{AutoArrange = 0};
        # Remover a seta de atalhos
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons" = @{29 = "%windir%\System32\shell32.dll,-50"};
        # Remover 'Atalho para' do nome de novos atalhos
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" = @{Link = 0};

        # Ajustes de performance da CPU
        "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82ca-49dd-9a64-d7ee62bfb990\5d76a2ca-e8c0-4067-9883-cd57e3f54ce4" = @{Value = 0; Value2 = 0; Value3 = 0}; # Processor idle disable - CUIDADO, pode aumentar consumo.
        "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82ca-49dd-9a64-d7ee62bfb990\0cc5b647-c1df-4637-891a-edc335ee7e0c" = @{Value = 0; Value2 = 0; Value3 = 0}; # Processor idle promotion disable

        # Desabilitar a limitação da largura de banda reservada (QoS)
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched" = @{NonBestEffortLimit = 0};

        # Remover botão do Teams da barra de tarefas
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" = @{TaskbarMn = 0}; # Valor 0 remove o ícone do Meet Now / Teams da barra de tarefas

        # Desabilitar o Meet Now na barra de tarefas (Windows 10)
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds" = @{ShellFeedsTaskbarViewMode = 2};
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds" = @{EnableFeeds = 0};

        # Desabilitar OneDrive Shell Extension (apenas o ícone na barra lateral do Explorer, se não foi feito em privacidade)
        "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" = @{"System.IsPinnedToNameSpaceTree" = 0};
        "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" = @{"System.IsPinnedToNameSpaceTree" = 0};
    }

    try {
        foreach ($path in $registryChanges.Keys) {
            foreach ($name in $registryChanges.$path.Keys) {
                $value = $registryChanges.$path.$name
                Write-Log "Configurando registro: $path - $name = $value" Cyan
                Set-ItemProperty -Path $path -Name $name -Value $value -Force -ErrorAction SilentlyContinue | Out-Null
            }
        }
        Write-Log "Tweaks extras de sistema aplicados com sucesso." Green

        # Cmdlets para serviços
        Write-Log "Ajustando serviços..." Cyan
        # Desabilitar Spooler
        try {
            Get-Service -Name "Spooler" -ErrorAction SilentlyContinue | Set-Service -StartupType Disabled -ErrorAction Stop | Out-Null
            Write-Log "Serviço Spooler desabilitado." Green
        } catch {
            Write-Log "Não foi possível desabilitar o serviço Spooler: $_" Yellow
        }
        # Desabilitar SysMain (Superfetch)
        try {
            Get-Service -Name "SysMain" -ErrorAction SilentlyContinue | Set-Service -StartupType Disabled -ErrorAction Stop | Out-Null
            Write-Log "Serviço SysMain (Superfetch) desabilitado." Green
        } catch {
            Write-Log "Não foi possível desabilitar o serviço SysMain: $_" Yellow
        }
        # Desabilitar Fax
        try {
            Get-Service -Name "Fax" -ErrorAction SilentlyContinue | Set-Service -StartupType Disabled -ErrorAction Stop | Out-Null
            Write-Log "Serviço Fax desabilitado." Green
        } catch {
            Write-Log "Não foi possível desabilitar o serviço Fax: $_" Yellow
        }
        # Desabilitar Serviço de Área de Trabalho Remota
        try {
            Get-Service -Name "TermService" -ErrorAction SilentlyContinue | Set-Service -StartupType Disabled -ErrorAction Stop | Out-Null
            Write-Log "Serviço de Área de Trabalho Remota desabilitado." Green
        } catch {
            Write-Log "Não foi possível desabilitar o serviço de Área de Trabalho Remota: $_" Yellow
        }

        # Comandos que ainda precisam de executáveis externos (sem cmdlet PowerShell direto equivalente simples)
        Write-Log "Executando comandos externos (powercfg, gpupdate)..." Cyan
        # Desabilitar Hibernação
        try {
            powercfg.exe /hibernate off | Out-Null
            Write-Log "Hibernação desabilitada." Green
        } catch {
            Write-Log "Não foi possível desabilitar a hibernação: $_" Yellow
        }

        # Atualizar políticas de grupo (útil após algumas mudanças de registro em HKLM)
        try {
            gpupdate.exe /force | Out-Null
            Write-Log "Políticas de grupo atualizadas." Green
        } catch {
            Write-Log "Não foi possível atualizar as políticas de grupo: $_" Yellow
        }

    } catch {
        Write-Log "Erro geral ao aplicar tweaks extras: $_" Red
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
    Write-Log "Restaurando configurações padrão do Painel de Controle e Explorer..." Yellow

    $registryChanges = @{
        # Restaurar visibilidade de itens no Painel de Controle
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" = @{NoControlPanel = 0; NoViewContextMenu = 0; NoDesktop = 0; NoFind = 0}; # Certifica-se de que não há política desabilitando
        # Restaurar atalhos na barra de tarefas (Jump Lists)
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" = @{Start_JumpListsItems = 10}; # Valor padrão é 10
        # Restaurar pré-visualização de miniaturas (Thumbnails)
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" = @{IconsOnly = 0}; # Valor padrão para mostrar miniaturas
        # Restaurar 'Verificar programas ao iniciar'
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" = @{ScanNetDrives = 1};
        # Ocultar extensões de arquivos (padrão)
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" = @{HideFileExt = 1}; # Padrão é ocultar extensões
        # Ocultar arquivos do sistema (padrão)
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" = @{ShowSuperHidden = 0}; # Padrão é ocultar arquivos de sistema
        # Desabilitar o 'shake to minimize'
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" = @{DisableShake = 0}; # Valor padrão é 0 (habilitado)
        # Restaurar notificações de novos programas instalados
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" = @{DontShowNewInstall = 0};
        # Restaurar 'Recente' e 'Fixado' do Quick Access
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" = @{HubMode = 0; ShowRecent = 1; ShowFrequent = 1}; # HubMode = 0 é o padrão.
        # Restaurar o recurso "Quick Access" completamente
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Ribbon" = @{QatExclude = 0}; # Habilita Quick Access no ribbon
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" = @{LaunchTo = 1}; # Abre Quick Access por padrão
        # Restaurar o auto-organizar ícones
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" = @{AutoArrange = 1}; # Valor para ativar o auto-organizar
        # Restaurar o snap para janelas
        "HKCU:\Control Panel\Desktop" = @{WindowArrangementActive = 1};
        # Restaurar a rolagem de janelas inativas
        "HKCU:\Control Panel\Desktop" = @{MouseWheelRouting = 1};
        # Restaurar o FadeEffect no menu iniciar e tooltips (valor padrão)
        "HKCU:\Control Panel\Desktop" = @{UserPreferencesMask = 0x9E3E0380}; # Valor padrão para UserPreferencesMask
        # Restaurar Animações do Windows (Minimize/Maximize)
        "HKCU:\Control Panel\Desktop\WindowMetrics" = @{MinAnimate = 1}; # Restaurar animação de minimizar/maximizar
    }

    try {
        foreach ($path in $registryChanges.Keys) {
            foreach ($name in $registryChanges.$path.Keys) {
                $value = $registryChanges.$path.$name
                Write-Log "Restaurando registro: $path - $name = $value" Cyan
                Set-ItemProperty -Path $path -Name $name -Value $value -Force -ErrorAction SilentlyContinue | Out-Null
            }
        }
        Write-Log "Configurações padrão do Painel de Controle e Explorer restauradas com sucesso." Green
    } catch {
        Write-Log "Erro ao restaurar configurações do Painel de Controle e Explorer: $_" Red
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

function Show-FullMaintenance {
    do {
        Clear-Host
        Write-Host "=========== MENU: MANUTENÇÃO COMPLETA ===========" -ForegroundColor Cyan
        Write-Host " A. Executar TODAS as tarefas de manutenção" -ForegroundColor Green
        Write-Host " B. Desempenho e Sistema"
        Write-Host " C. Limpeza e Otimização"
        Write-Host " D. Privacidade e Hardening"
        Write-Host " X. Voltar ao menu principal" -ForegroundColor Green
        Write-Host "===============================================" -ForegroundColor Cyan

        $key = [Console]::ReadKey($true).Key
        switch ($key) {
            'A' {
                # Execução TOTAL
                Enable-PrivacyHardening
                Grant-ExtraTweaks
                Set-VisualPerformance
                Disable-UAC
                Disable-Cortana-AndSearch
                Disable-ActionCenter-Notifications
                Disable-BloatwareScheduledTasks
                Stop-BloatwareProcesses
                Remove-Bloatware
                Remove-Copilot
                Remove-OneDrive-AndRestoreFolders
                Remove-StartAndTaskbarPins
                Remove-ScheduledTasksAggressive
                Disable-SMBv1
                New-ChkDsk
                Clear-WUCache
                Clear-TemporaryFiles
                Clear-Prefetch
                Clear-PrintSpooler
                Clear-DeepSystemCleanup
                Optimize-Volumes
                Remove-WindowsOld
                Clear-WinSxS
                Grant-ControlPanelTweaks
                Set-PerformanceTheme
                Disable-UnnecessaryServices
                Optimize-ExplorerPerformance
                Rename-Notebook
                Show-SuccessMessage
            }
            'B' { Show-PerformanceSubmenu }
            'C' { Show-CleanupSubmenu }
            'D' { Show-PrivacyHardeningMenu }
            'X' { return }
            default { Write-Host "`nOpção inválida!" -ForegroundColor Red; Start-Sleep 1 }
        }
    } while ($true)
}


# === FUNÇÕES DE MENU ===

function Show-AdvancedSettingsMenu {
    do {
        Clear-Host
        Write-Host "==== MENU: CONFIGURAÇÕES AVANÇADAS ====" -ForegroundColor Cyan
        Write-Host " A. Executar todos os ajustes deste menu" -ForegroundColor Green
        Write-Host " B. Ajustes do Painel de Controle/Configurações"
        Write-Host " C. Configurar Autologin"
        Write-Host " D. Scripts externos (Ativador e Chris Titus)"
        Write-Host " E. Tweaks de interface do Explorer"
        Write-Host " X. Voltar ao menu principal" -ForegroundColor Green

        $key = [Console]::ReadKey($true).Key
        switch ($key) {
            'A' {
                Grant-ControlPanelTweaks
                Show-AutoLoginMenu
                Show-ExternalScriptsMenu
                Grant-ExtraTweaks
            }
            'B' { Grant-ControlPanelTweaks }
            'C' { Show-AutoLoginMenu }
            'D' { Show-ExternalScriptsMenu }
            'E' { Grant-ExtraTweaks }
            'X' { return }
            default {
                Write-Host "`nOpção inválida!" -ForegroundColor Red
                Start-Sleep -Seconds 1
            }
        }
    } while ($true)
}

function Show-DiagnosticsMenu {
    do {
        Clear-Host
        Write-Host "==== MENU: DIAGNÓSTICO E INFORMAÇÕES ====" -ForegroundColor Cyan
        Write-Host " A. Executar todos os diagnósticos" -ForegroundColor Green
        Write-Host " B. Exibir informações de rede"
        Write-Host " C. Exibir informações do sistema"
        Write-Host " D. Exibir uso do disco"
        Write-Host " E. Testar memória RAM"
        Write-Host " F. Verificar arquivos do sistema (SFC)"
        Write-Host " G. Verificar integridade do sistema (DISM)"
        Write-Host " H. Verificar saúde dos discos (SMART)"
        Write-Host " X. Voltar ao menu principal" -ForegroundColor Green

        $key = [Console]::ReadKey($true).Key
        switch ($key) {
            'A' {
                Invoke-DISM-Scan
                Invoke-SFC-Scan
                Test-SMART-Drives
                Test-Memory
                Show-SystemInfo
                Show-NetworkInfo
                Show-DiskUsage
                Show-SuccessMessage
            }
            'B' { Show-NetworkInfo; Show-SuccessMessage }
            'C' { Show-SystemInfo; Show-SuccessMessage }
            'D' { Show-DiskUsage; Show-SuccessMessage }
            'E' { Test-Memory; Show-SuccessMessage }
            'F' { Invoke-SFC-Scan; Show-SuccessMessage }
            'G' { Invoke-DISM-Scan; Show-SuccessMessage }
            'H' { Test-SMART-Drives; Show-SuccessMessage }
            'X' { return }
            default {
                Write-Host "`nOpção inválida!" -ForegroundColor Red
                Start-Sleep 1
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
        Write-Host "==== MENU: REDE E IMPRESSORAS ====" -ForegroundColor Cyan
        Write-Host " A. Executar todas as tarefas deste menu" -ForegroundColor Green
        Write-Host " B. Adicionar rede Wi-Fi administrativa"
        Write-Host " C. Aplicar DNS (TCP/Cloudflare)"
        Write-Host " D. Definir DNS (Google/Cloudflare)"
        Write-Host " E. Desabilitar IPv6"
        Write-Host " F. Instalar impressoras de rede"
        Write-Host " G. Limpar cache ARP"
        Write-Host " H. Limpar cache DNS"
        Write-Host " X. Voltar ao menu principal" -ForegroundColor Green

        $key = [Console]::ReadKey($true).Key
        switch ($key) {
            'A' {
                try {
                    Add-WiFiNetwork
                    Optimize-NetworkPerformance
                    Set-DnsGoogleCloudflare
                    Disable-IPv6
                    Install-NetworkPrinters
                    Clear-ARP
                    Clear-DNS
                    Show-SuccessMessage
                } catch {
                    Write-Log "❌ Erro durante execução de tarefas de rede: $_" Red
                }
            }
            'B' { Add-WiFiNetwork; Show-SuccessMessage }
            'C' { Optimize-NetworkPerformance; Show-SuccessMessage }
            'D' { Set-DnsGoogleCloudflare; Show-SuccessMessage }
            'E' { Disable-IPv6; Show-SuccessMessage }
            'F' { Install-NetworkPrinters; Show-SuccessMessage }
            'G' { Clear-ARP; Show-SuccessMessage }
            'H' { Clear-DNS; Show-SuccessMessage }
            'X' { return }
            default {
                Write-Host "`nOpção inválida!" -ForegroundColor Red
                Start-Sleep 1
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
        Write-Host "==== MENU: REVERTER AJUSTES / RESTAURAR APLICATIVOS ====" -ForegroundColor Magenta
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
        Write-Host "==== MENU: UTILITÁRIOS DO SISTEMA ====" -ForegroundColor Cyan
        Write-Host " A. Executar todas as tarefas deste menu" -ForegroundColor Green
        Write-Host " B. Limpeza e Otimização"
        Write-Host " C. Remoção de Bloatware"
        Write-Host " D. Desempenho do Sistema"
        Write-Host " X. Voltar ao menu principal" -ForegroundColor Green

        $key = [Console]::ReadKey($true).Key
        switch ($key) {
            'A' {
                # Limpeza
                Clear-TemporaryFiles
                Clear-WUCache
                Clear-DNS
                Clear-Prefetch
                Clear-PrintSpooler
                Clear-DeepSystemCleanup
                Clear-WinSxS
                Remove-WindowsOld
                
                # Bloatware
                Remove-Bloatware
                Remove-Copilot
                Remove-OneDrive-AndRestoreFolders
                Stop-BloatwareProcesses
                Disable-BloatwareScheduledTasks
                
                # Desempenho
                Set-PerformanceTheme
                Optimize-ExplorerPerformance
                Disable-UnnecessaryServices
                Optimize-Volumes
                
                Show-SuccessMessage
            }
            'B' { Show-CleanupMenu }
            'C' { Show-BloatwareMenu }
            'D' { Show-SystemPerformanceMenu }
            'X' { return }
            default {
                Write-Host "`nOpção inválida!" -ForegroundColor Red
                Start-Sleep 1
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
    do {
        Clear-Host
        Write-Host "=============================================" -ForegroundColor Cyan
        Write-Host " SCRIPT DE MANUTENÇÃO WINDOWS - MENU PRINCIPAL" -ForegroundColor Cyan
        Write-Host "=============================================" -ForegroundColor Cyan
        Write-Host " B. Configurações Avançadas" -ForegroundColor Yellow
        Write-Host " C. Diagnóstico e Informações" -ForegroundColor Yellow
        Write-Host " D. Instalação de Programas" -ForegroundColor Yellow
        Write-Host " F. Rede e Impressoras" -ForegroundColor Yellow
        Write-Host " G. Restauração e Segurança (Undo)" -ForegroundColor Yellow
        Write-Host " H. Scripts Externos e Ativadores" -ForegroundColor Yellow
        Write-Host " U. Utilitários do Sistema (Bloat, Limpeza e Desempenho)" -ForegroundColor Yellow
        Write-Host " M. Manutenção Completa (Tudo em um)" -ForegroundColor Green
        Write-Host " Z. Colégio (Sequência Completa)" -ForegroundColor Magenta
        Write-Host " R. Reiniciar o PC" -ForegroundColor Red
        Write-Host " 0. Sair" -ForegroundColor Magenta
        Write-Host "=============================================" -ForegroundColor Cyan

        $key = [Console]::ReadKey($true).Key
        switch ($key) {
            'B' { Show-AdvancedSettingsMenu }
            'C' { Show-DiagnosticsMenu }
            'D' { Show-InstallationMenu }
            'F' { Show-NetworkMenu }
            'G' { Show-RestoreUndoMenu }
            'H' { Show-ExternalScriptsMenu }
            'U' { Show-UtilitiesMenu }  # 🔧 Novo menu combinado
            'M' { Show-FullMaintenance } 
            'Z' { Invoke-Colégio }
            'R' {
                Write-Log "Reiniciando o computador..." Cyan
                Restart-Computer -Force
            }
            '0' {
                $duration = (Get-Date) - $startTime
                Write-Log "Script concluído. Tempo total: $($duration.ToString('hh\:mm\:ss'))" Cyan
                Write-Log "Log salvo em: $logFile" Cyan
                return
            }
            default {
                Write-Host "`nOpção inválida!" -ForegroundColor Red
                Start-Sleep 1
            }
        }
    } while ($true)
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
    'Show-BloatwareMenu',
    'Show-CleanupMenu',
    'Show-DiagnosticsMenu',
    'Show-ExternalScriptsMenu',
    'Show-SuccessMessage',
    'Show-SystemPerformanceMenu',
    'Undo-PrivacyHardening'
)

Test-RequiredFunctions -FunctionList $FuncoesCriticas

# === EXECUÇÃO COM SEGURANÇA ===
try {
    Show-MainMenu
}
catch {
    Write-Host "❌ Erro fatal: $_" -ForegroundColor Red
    Write-Host "Consulte o log em: `"$logFile`"" -ForegroundColor Yellow
}
finally {
    # Cleanup se necessário
}
