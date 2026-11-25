@echo off
chcp 65001 > nul
title CYBERSEC RADAR - Panel de Control de Ciberseguridad y CVEs

echo ======================================================================
echo    CYBERSEC RADAR // Control Center
echo    Iniciando Panel de Control de Ciberseguridad y Nuevos CVEs...
echo ======================================================================
echo.

where python >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] No se encontro Python en el sistema.
    echo Por favor instala Python 3.9 o superior y agregalo al PATH.
    pause
    exit /b 1
)

echo [*] Verificando dependencias...
python -c "import flask, feedparser, requests" >nul 2>nul
if %errorlevel% neq 0 (
    echo [*] Instalando dependencias necesarias: flask, feedparser, requests...
    pip install -r requirements.txt
    if %errorlevel% neq 0 (
        echo [ERROR] Fallo la instalacion de dependencias.
        pause
        exit /b 1
    )
)

echo [*] Iniciando servidor y abriendo navegador en http://127.0.0.1:5000 ...
echo.
echo ======================================================================
echo  Panel activo en segundo plano. Para cerrar el servidor pulsa CTRL+C.
echo ======================================================================
echo.

python app.py
pause
