@echo off
title Gestion de Tickets - Servidor
echo.
echo  ==============================
echo   GESTION DE TICKETS
echo   Area de Sistemas
echo  ==============================
echo.

:: Verificar si Python esta instalado
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python no esta instalado o no esta en el PATH.
    echo Instala Python desde https://python.org
    pause
    exit /b 1
)

:: Instalar dependencias / entorno virtual
if not exist "venv\" (
    echo Creando entorno virtual...
    python -m venv venv
)

echo Activando entorno virtual...
call venv\Scripts\activate.bat

echo Instalando dependencias...
pip install -r requirements.txt --quiet

:: Obtener IP de red local
for /f "tokens=2 delims=:" %%a in ('ipconfig ^| findstr /i "IPv4" ^| findstr /v "127.0.0.1"') do (
    set IP=%%a
    goto :found_ip
)
:found_ip
set IP=%IP: =%

echo.
echo  ============================================
echo   Servidor iniciado. Accesos disponibles:
echo.
echo   Este equipo  : http://localhost:5000
echo   Red local    : http://%IP%:5000
echo.
echo   Compartí la direccion de red con los
echo   demas usuarios de la empresa.
echo  ============================================
echo.
echo  Presiona Ctrl+C para detener el servidor.
echo.

python app.py
pause
