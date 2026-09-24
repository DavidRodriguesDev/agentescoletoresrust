$bytes = [System.IO.File]::ReadAllBytes("$env:USERPROFILE\update_priv.der")
$seed = $bytes[16..47]
$env:UPDATE_PRIV_KEY_HEX = -join ($seed | ForEach-Object { $_.ToString("x2") })

if ($env:UPDATE_PRIV_KEY_HEX.Length -ne 64) {
    Write-Error "UPDATE_PRIV_KEY_HEX com tamanho errado, abortando"
    exit 1
}

.\target\debug\server-bin.exe --config-path config_server_public.toml