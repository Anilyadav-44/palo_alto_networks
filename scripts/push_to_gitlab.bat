@echo off
REM Project Unit42-FirmwareX — GitLab Push & Synchronization Script
REM Palo Alto Networks // Unit 42

echo ==============================================================================
echo [Unit42-FirmwareX] Synchronizing repository to GitLab origin...
echo Remote: https://gitlab.com/cjwrits/palo_alto_networks.git
echo ==============================================================================

git remote set-url origin https://gitlab.com/cjwrits/palo_alto_networks.git
git add -A
git commit -m "feat(deploy): complete PRD specifications, Docker containerization, and GitLab CI/CD"
echo.
echo Pushing branch 'main' to GitLab origin...
git push -u origin main

if %ERRORLEVEL% EQU 0 (
    echo.
    echo [SUCCESS] Project Unit42-FirmwareX pushed successfully to GitLab!
    echo URL: https://gitlab.com/cjwrits/palo_alto_networks
) else (
    echo.
    echo [NOTICE] If prompted for credentials, please provide your GitLab Personal Access Token (PAT)
    echo or authenticate via your browser.
)
pause
