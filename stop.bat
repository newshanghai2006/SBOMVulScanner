@echo off
setlocal EnableExtensions EnableDelayedExpansion

if "%~1"=="" (
    set /P "PORT=Enter port number to stop: "
) else (
    set "PORT=%~1"
)

if not defined PORT goto :invalid
echo(%PORT%| findstr /R /X "[0-9][0-9]*" >nul || goto :invalid
if "%PORT:~0,1%"=="0" goto :invalid
set /A PORT_NUMBER=%PORT% 2>nul
if %PORT_NUMBER% LSS 1 goto :invalid
if %PORT_NUMBER% GTR 65535 goto :invalid

title Stop Server port %PORT_NUMBER%
echo ========================================
echo   Stop service (port %PORT_NUMBER%)
echo ========================================
echo.

set "FOUND=0"
set "KILLED_PIDS= "

REM The trailing space prevents port 8000 from matching 80001 or 18000.
for /F "tokens=5" %%P in ('netstat -ano -p tcp ^| findstr /C:":%PORT_NUMBER% " ^| findstr "LISTENING"') do (
    echo(!KILLED_PIDS!| findstr /C:" %%P " >nul
    if errorlevel 1 (
        set "FOUND=1"
        echo Process listening on port %PORT_NUMBER%:
        tasklist /FI "PID eq %%P"
        echo.
        echo Stopping PID %%P ...
        taskkill /F /PID %%P >nul 2>&1
        if errorlevel 1 (
            echo ERROR: Failed to stop PID %%P. Try running this script as Administrator.
        ) else (
            echo Stopped PID %%P.
        )
        set "KILLED_PIDS=!KILLED_PIDS!%%P "
    )
)

if "%FOUND%"=="0" (
    echo No TCP service is listening on port %PORT_NUMBER%.
)

endlocal
exit /B 0

:invalid
echo ERROR: Port must be an integer from 1 to 65535.
echo Usage: %~nx0 ^<port^>
echo Or run %~nx0 without arguments and enter the port when prompted.
exit /B 2
