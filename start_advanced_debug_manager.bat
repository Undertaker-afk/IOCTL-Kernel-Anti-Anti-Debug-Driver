@echo off
echo Advanced Debug Manager - Installation und Start
echo ===============================================
echo.

:: Überprüfe Administrator-Rechte
net session >nul 2>&1
if %errorLevel% == 0 (
    echo Administrator-Rechte erkannt.
) else (
    echo FEHLER: Diese Batch-Datei muss als Administrator ausgeführt werden!
    echo Rechtsklick -> "Als Administrator ausführen"
    pause
    exit /b 1
)

:: Überprüfe ob Test-Signing aktiviert ist
bcdedit /enum | findstr /i testsigning | findstr /i yes >nul
if %errorLevel% == 0 (
    echo Test-Signing ist bereits aktiviert.
) else (
    echo Test-Signing wird aktiviert...
    bcdedit /set testsigning on
    echo HINWEIS: Neustart erforderlich für Test-Signing!
    echo Starte diese Datei nach dem Neustart erneut.
    pause
    shutdown /r /t 60 /c "Neustart für Test-Signing in 60 Sekunden..."
    exit /b 0
)

echo.
echo Installiere Kernel-Treiber...

:: Stoppe eventuell laufenden Treiber
sc stop IOCTLKernelCheat >nul 2>&1
sc delete IOCTLKernelCheat >nul 2>&1

:: Finde Treiber-Datei
set DRIVER_PATH=""
if exist "x64\Debug\kernel_mode.sys" (
    set DRIVER_PATH="%CD%\x64\Debug\kernel_mode.sys"
) else if exist "x64\Release\kernel_mode.sys" (
    set DRIVER_PATH="%CD%\x64\Release\kernel_mode.sys"
) else if exist "kernel_mode\x64\Debug\kernel_mode.sys" (
    set DRIVER_PATH="%CD%\kernel_mode\x64\Debug\kernel_mode.sys"
) else if exist "kernel_mode\x64\Release\kernel_mode.sys" (
    set DRIVER_PATH="%CD%\kernel_mode\x64\Release\kernel_mode.sys"
) else (
    echo FEHLER: Kernel-Treiber nicht gefunden!
    echo Bitte kompiliere das Projekt zuerst in Visual Studio.
    pause
    exit /b 1
)

echo Treiber-Pfad: %DRIVER_PATH%

:: Erstelle und starte Service
sc create IOCTLKernelCheat binpath=%DRIVER_PATH% type=kernel
if %errorLevel% neq 0 (
    echo FEHLER: Konnte Treiber-Service nicht erstellen!
    pause
    exit /b 1
)

sc start IOCTLKernelCheat
if %errorLevel% neq 0 (
    echo FEHLER: Konnte Treiber nicht starten!
    echo Überprüfe Windows Event Log für Details.
    pause
    exit /b 1
)

echo Treiber erfolgreich gestartet!
echo.

:: Starte Usermode-Anwendung
echo Starte Usermode-Anwendung...

set APP_PATH=""
if exist "x64\Debug\user_mode.exe" (
    set APP_PATH="%CD%\x64\Debug\user_mode.exe"
) else if exist "x64\Release\user_mode.exe" (
    set APP_PATH="%CD%\x64\Release\user_mode.exe"
) else if exist "user_mode\x64\Debug\user_mode.exe" (
    set APP_PATH="%CD%\user_mode\x64\Debug\user_mode.exe"
) else if exist "user_mode\x64\Release\user_mode.exe" (
    set APP_PATH="%CD%\user_mode\x64\Release\user_mode.exe"
) else (
    echo WARNUNG: Usermode-Anwendung nicht gefunden!
    echo Bitte kompiliere das Projekt zuerst in Visual Studio.
    echo Treiber ist trotzdem geladen und bereit.
    pause
    exit /b 0
)

echo Anwendungs-Pfad: %APP_PATH%
start "" %APP_PATH%

echo.
echo Installation und Start abgeschlossen!
echo.
echo Hinweise:
echo - Der Treiber läuft jetzt im Hintergrund
echo - Die GUI-Anwendung sollte sich öffnen
echo - Bei Problemen prüfe das Windows Event Log
echo.
echo Zum Stoppen des Treibers verwende: stop_driver.bat
echo.
pause
