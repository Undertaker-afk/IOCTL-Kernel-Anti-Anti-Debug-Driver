@echo off
echo Advanced Debug Manager - Treiber Stoppen
echo ========================================
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

echo Stoppe Kernel-Treiber...

:: Stoppe und entferne Service
sc stop IOCTLKernelCheat
if %errorLevel% == 0 (
    echo Treiber erfolgreich gestoppt.
) else (
    echo Treiber war bereits gestoppt oder nicht vorhanden.
)

sc delete IOCTLKernelCheat
if %errorLevel% == 0 (
    echo Treiber-Service erfolgreich entfernt.
) else (
    echo Treiber-Service war bereits entfernt oder nicht vorhanden.
)

echo.
echo Beende eventuell laufende Usermode-Anwendungen...
taskkill /f /im user_mode.exe >nul 2>&1
taskkill /f /im x64dbg.exe >nul 2>&1

echo.
echo Cleanup abgeschlossen!
echo Der Treiber ist jetzt gestoppt und entfernt.
echo.
pause
