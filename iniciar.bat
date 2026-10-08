@echo off
rem Abre la app. Con Python usa un servidor SOLO local (127.0.0.1); si no, o si el puerto esta ocupado, abre el archivo directamente.
cd /d "%~dp0"
netstat -ano | findstr /R /C:":8765 .*LISTENING" >nul
if not errorlevel 1 (
  echo El puerto 8765 ya esta en uso por otro servidor ^(una ventana anterior^). Abriendo index.html directamente...
  start "" "%~dp0index.html"
  goto :eof
)
py -3 --version >nul 2>&1
if not errorlevel 1 ( start "" http://127.0.0.1:8765/index.html & py -3 serve.py 8765 & goto :eof )
python --version >nul 2>&1
if not errorlevel 1 ( start "" http://127.0.0.1:8765/index.html & python serve.py 8765 & goto :eof )
echo No se encontro Python. Abriendo index.html directamente...
start "" "%~dp0index.html"
