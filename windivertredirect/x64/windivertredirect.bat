cd /d %~dp0
setlocal enableDelayedExpansion
<!-- : ---Self-Elevating Batch Script----------------------------
@whoami /groups | find "S-1-16-12288" > nul && goto :admin
set "ELEVATE_CMDLINE=cd /d "%~dp0" & call "%~f0" %*"
cscript //nologo "%~f0?.wsf" //job:Elevate & exit /b

-->
<job id="Elevate"><script language="VBScript">
  Set objShell = CreateObject("Shell.Application")
  Set objWshShell = WScript.CreateObject("WScript.Shell")
  Set objWshProcessEnv = objWshShell.Environment("PROCESS")
  strCommandLine = Trim(objWshProcessEnv("ELEVATE_CMDLINE"))
  objShell.ShellExecute "cmd", "/c " & strCommandLine, "", "runas"
</script></job>
:admin -----------------------------------------------------------

set EXCLUDE_IP=123.123.123.123
set TARGET_PORT=10250
set PROXY_IP=192.168.8.114
set PROXY_PORT=34010

:while
windivertredirect.exe %EXCLUDE_IP% %TARGET_PORT% %PROXY_IP% %PROXY_PORT%
goto while
pause