@echo off
set PYTHONPATH=%~dp0secops-cli;%~dp0secops-core;%~dp0secops-offense;%~dp0secops-defense;%~dp0secops
python -m secops_cli
pause
