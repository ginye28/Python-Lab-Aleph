@echo off
cd /d "%~dp0"
python privilege_revoke_bot.py >> revoke_bot.log 2>&1
