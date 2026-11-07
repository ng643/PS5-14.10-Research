# Restart the two WebKit probe servers with the current code.
#   443  console-facing (TLS + DNS), corpus state: results/webkit/state.json
#   8080 local headless checks,  corpus state: results/webkit/state_local.json
$ErrorActionPreference = 'Stop'
$root = 'C:\PS5contrib'
$py = 'C:\Users\box12\AppData\Local\Programs\Python\Python311\python.exe'
Set-Location $root

Get-CimInstance Win32_Process -Filter "Name='python.exe'" |
    Where-Object { $_.CommandLine -like '*tools/webkit_server.py*' } |
    ForEach-Object { Write-Host "stopping pid $($_.ProcessId)"; Stop-Process -Id $_.ProcessId -Force }
Start-Sleep -Seconds 2

$block = '*.sonyentertainmentnetwork.com,ps5.np.playstation.net,feature.api.playstation.com,smetrics.aem.playstation.com,takedown.api.playstation.com,*.rnps.dl.playstation.net'

$console = @('-u', 'tools/webkit_server.py', '--port', '443', '--tls',
    '--cert', 'ug_cert.pem', '--key', 'ug_key.pem',
    '--dns', '--dns-log-queries', '--dns-block', $block,
    '--corpus', 'results/webkit/corpus', '--default', 'p172-jsc-corpus-runner.js')
Start-Process -FilePath $py -ArgumentList $console -WorkingDirectory $root `
    -RedirectStandardOutput "$root\results\webkit\serve_443.out" `
    -RedirectStandardError "$root\results\webkit\serve_443.err" -WindowStyle Hidden

$local = @('-u', 'tools/webkit_server.py', '--port', '8080', '--no-log',
    '--corpus', 'results/webkit/corpus', '--default', 'p172-jsc-corpus-runner.js',
    '--state', 'results/webkit/state_local.json')
Start-Process -FilePath $py -ArgumentList $local -WorkingDirectory $root `
    -RedirectStandardOutput "$root\results\webkit\serve_8080.out" `
    -RedirectStandardError "$root\results\webkit\serve_8080.err" -WindowStyle Hidden

Start-Sleep -Seconds 3
Get-CimInstance Win32_Process -Filter "Name='python.exe'" |
    Where-Object { $_.CommandLine -like '*tools/webkit_server.py*' } |
    ForEach-Object { Write-Host "running pid $($_.ProcessId)" }
