@echo off
py -3 "%~dp0run_regression.py" %*
exit /b %errorlevel%
