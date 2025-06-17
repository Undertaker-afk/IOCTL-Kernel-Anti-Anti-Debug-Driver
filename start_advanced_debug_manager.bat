@echo off
echo Advanced Debug Manager - Automated Setup with kdmapper
echo ======================================================
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

:: Überprüfe ob Test-Signing aktiviert ist (für manuellen Driver-Load Fallback)
bcdedit /enum | findstr /i testsigning | findstr /i yes >nul
if %errorLevel% == 0 (
    echo Test-Signing ist bereits aktiviert.
) else (
    echo Test-Signing wird aktiviert (für Fallback)...
    bcdedit /set testsigning on
    echo HINWEIS: Test-Signing aktiviert für manuellen Driver-Load Fallback
)

echo.
echo ====================================================
echo WICHTIGE INFORMATIONEN:
echo ====================================================
echo.
echo Diese Anwendung verwendet kdmapper zum automatischen
echo Laden des Kernel-Treibers ohne Signatur-Anforderungen.
echo.
echo Folgende Schritte werden automatisch ausgeführt:
echo 1. Download von kdmapper (falls nicht vorhanden)
echo 2. Suche nach kernel_mode.sys
echo 3. Mapping des Treibers mit kdmapper
echo 4. Start der Debug-Umgebung
echo.
echo WICHTIG:
echo - Antivirus Real-Time Protection sollte deaktiviert sein
echo - Windows Defender Ausnahme für kdmapper empfohlen
echo - HVCI (Hypervisor-protected Code Integrity) kann Probleme verursachen
echo.
echo ====================================================
pause

echo.
echo Suche nach kompiliertem Treiber...

:: Finde Treiber-Datei
set DRIVER_PATH=""
if exist "x64\Debug\kernel_mode.sys" (
    set DRIVER_PATH="%CD%\x64\Debug\kernel_mode.sys"
    echo Treiber gefunden: Debug-Version
) else if exist "x64\Release\kernel_mode.sys" (
    set DRIVER_PATH="%CD%\x64\Release\kernel_mode.sys"
    echo Treiber gefunden: Release-Version
) else if exist "kernel_mode\x64\Debug\kernel_mode.sys" (
    set DRIVER_PATH="%CD%\kernel_mode\x64\Debug\kernel_mode.sys"
    echo Treiber gefunden: Debug-Version (Unterordner)
) else if exist "kernel_mode\x64\Release\kernel_mode.sys" (
    set DRIVER_PATH="%CD%\kernel_mode\x64\Release\kernel_mode.sys"
    echo Treiber gefunden: Release-Version (Unterordner)
) else (
    echo.
    echo WARNUNG: Kernel-Treiber nicht gefunden!
    echo.
    echo Erwartete Pfade:
    echo - x64\Debug\kernel_mode.sys
    echo - x64\Release\kernel_mode.sys
    echo - kernel_mode\x64\Debug\kernel_mode.sys
    echo - kernel_mode\x64\Release\kernel_mode.sys
    echo.
    echo Bitte kompiliere das kernel_mode Projekt zuerst in Visual Studio.
    echo Die Anwendung wird trotzdem gestartet und versucht den Treiber zu finden.
    echo.
)

if not %DRIVER_PATH%=="" (
    echo Treiber-Pfad: %DRIVER_PATH%
)

echo.
echo Starte Advanced Debug Manager...
echo Die Anwendung wird kdmapper automatisch herunterladen und verwenden.

:: Finde und starte Usermode-Anwendung
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
    echo.
    echo FEHLER: Usermode-Anwendung nicht gefunden!
    echo Bitte kompiliere das user_mode Projekt zuerst in Visual Studio.
    echo.
    pause
    exit /b 1
)

echo Anwendungs-Pfad: %APP_PATH%
echo.
echo Starte Anwendung...
echo (Die Anwendung wird kdmapper und Treiber automatisch verwalten)

start "" %APP_PATH%

echo.
echo ====================================================
echo Setup-Information:
echo ====================================================
echo.
echo Die Anwendung läuft jetzt und wird:
echo ✓ kdmapper automatisch herunterladen
echo ✓ Den Kernel-Treiber mit kdmapper mappen
echo ✓ Die Debug-Umgebung initialisieren
echo.
echo Bei Problemen:
echo - Prüfe Antivirus-Einstellungen
echo - Stelle sicher, dass Administrator-Rechte vorhanden sind
echo - Deaktiviere Windows Defender Real-Time Protection temporär
echo - Prüfe ob HVCI deaktiviert ist (msinfo32.exe -> System Summary)
echo.
echo Logfiles werden in der Anwendung angezeigt.
echo.
pause
