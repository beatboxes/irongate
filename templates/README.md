# Templates

These files are **not directly usable**. They are extracted from the unquoted heredocs in
`irongate-install.sh`, which means the installer expands shell variables into them at install
time. They are committed so the generated configuration can be reviewed and diffed.

Variables the installer substitutes:

| Variable | Meaning |
|---|---|
| `$INTERFACE` | primary network interface (e.g. `eth0`) |
| `$CURRENT_IP` / `$LOCAL_MAC` | the host's address and MAC on that interface |
| `$CURRENT_GATEWAY` / `$GATEWAY_MAC` | upstream gateway address and MAC |
| `$WEBUI_PORT` | port the dashboard listens on |
| `$PHP_SOCK` | php-fpm socket path, detected from the installed PHP version |
| `$DEVICES_YAML` | the generated device list |
| `$MAINPID` | expanded by systemd, not by the installer |

To change any of these files, edit the corresponding heredoc in `irongate-install.sh`, then run
`python3 tools/heredoc_sync.py --extract`. Editing a template alone has no effect on a real
install and will be reported as drift by `tools/check-sync.sh`.
