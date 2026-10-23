# Project Unit42-FirmwareX — GitLab Push & Synchronization Script (PowerShell)
# Palo Alto Networks // Unit 42

Write-Host "==============================================================================" -ForegroundColor Cyan
Write-Host "[Unit42-FirmwareX] Synchronizing repository to GitLab origin..." -ForegroundColor Green
Write-Host "Remote URL: https://gitlab.com/cjwrits/palo_alto_networks.git" -ForegroundColor Yellow
Write-Host "==============================================================================" -ForegroundColor Cyan

git remote set-url origin https://gitlab.com/cjwrits/palo_alto_networks.git
git add -A
git commit -m "feat(deploy): complete PRD specifications, Docker containerization, and GitLab CI/CD" -q
Write-Host "`nPushing branch 'main' to GitLab origin..." -ForegroundColor Cyan
git push -u origin main

if ($LASTEXITCODE -eq 0) {
    Write-Host "`n[SUCCESS] Successfully pushed to GitLab: https://gitlab.com/cjwrits/palo_alto_networks" -ForegroundColor Green
} else {
    Write-Host "`n[NOTICE] Git authentication required. Please enter your GitLab username and Personal Access Token (PAT) when prompted." -ForegroundColor Yellow
}
