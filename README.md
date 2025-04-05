# windivertredirect

Redirect outbound TCP connection to local proxy based on WinDivert
(https://github.com/basil00/WinDivert).

Will stablish two connections:
- `stratumproxy.exe`, `PROXY_IP`, `PROXY_PORT`, `TARGET_IP`, `LOCAL_PORT`, `tcp`, `Established`
- `target.exe`, `LOCAL_IP`, `LOCAL_PORT`, `TARGET_IP`, `TARGET_PORT`, `tcp`, `Established`

## Usage:

windivertredirect.exe EXCLUDE_IP TARGET_PORT PROXY_IP PROXY_PORT

### Parameters:
- **EXCLUDE_IP**: Whitelist remote IP that should not match.
- **TARGET_PORT**: Remote port to match.
- **PROXY_IP**: Proxy IP to divert to.
- **PROXY_PORT**: Proxy port to divert to.
