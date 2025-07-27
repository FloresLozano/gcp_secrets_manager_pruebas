param([string]$target)

switch ($target) {
    "format" {
        Write-Host "Formateando código con Black e isort..."
        black gcp_secrets_manager tests
        isort gcp_secrets_manager tests
    }
    "lint" {
        Write-Host "Verificando estilo con flake8..."
        flake8 gcp_secrets_manager tests
    }
    "typecheck" {
        Write-Host "Verificando tipos con mypy..."
        mypy gcp_secrets_manager
    }
    "test" {
        Write-Host "Ejecutando tests con pytest..."
        pytest -v --cov=gcp_secrets_manager --cov-report=term-missing
    }
    "all" {
        & "$PSCommandPath" format
        & "$PSCommandPath" lint
        & "$PSCommandPath" typecheck
        & "$PSCommandPath" test
    }
    default {
        Write-Host "Uso: .\make.ps1 [format|lint|typecheck|test|all]"
    }
} # ← ESTA LLAVE CERRABA E
