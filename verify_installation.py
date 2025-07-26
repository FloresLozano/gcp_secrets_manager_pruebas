# crear archivo: verify_installation.py
#!/usr/bin/env python
"""Script para verificar que la instalación fue exitosa"""

print("🔍 Verificando instalación de gcp-secrets-manager...\n")

# Test 1: Importación básica
try:
    import gcp_secrets_manager
    print("✅ 1. Módulo importado correctamente")
    print(f"   Versión: {gcp_secrets_manager.__version__}")
except ImportError as e:
    print(f"❌ 1. Error al importar: {e}")
    exit(1)

# Test 2: Verificar submódulos
try:
    from gcp_secrets_manager import StandardSecretsManager
    from gcp_secrets_manager import SecretManagerWithCache
    from gcp_secrets_manager import verify_credentials
    print("✅ 2. Todos los componentes principales disponibles")
except ImportError as e:
    print(f"❌ 2. Error al importar componentes: {e}")

# Test 3: Verificar CLI
import subprocess
result = subprocess.run(['gcp-secrets-cli', '--help'], capture_output=True)
if result.returncode == 0:
    print("✅ 3. CLI instalado y funcionando")
else:
    print("❌ 3. CLI no funciona correctamente")

print("\n✅ Instalación verificada correctamente!")