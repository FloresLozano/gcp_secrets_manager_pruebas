"""
Ejemplo básico de uso del gestor de secretos de GCP
"""
import os
import logging
from gcp_secrets_manager import StandardSecretsManager, verify_credentials

# Configurar logging
logging.basicConfig(level=logging.INFO)


def main():
    """Ejemplo de uso básico del gestor de secretos."""
    
    # 1. Verificar autenticación (opcional pero recomendado)
    print("1. Verificando autenticación con Google Cloud...")
    try:
        verify_credentials()
        print("   ✅ Autenticación verificada\n")
    except Exception as e:
        print(f"   ❌ Error de autenticación: {e}")
        return
    
    # 2. Inicializar el gestor
    project_id = os.environ.get('GCP_PROJECT_ID', 'tu-proyecto-gcp')
    print(f"2. Inicializando gestor para proyecto: {project_id}")
    secrets_manager = StandardSecretsManager(project_id)
    print("   ✅ Gestor inicializado\n")
    
    # 3. Ejemplos de obtención de secretos individuales
    print("3. Obteniendo secretos individuales:")
    
    # API Key
    api_key = secrets_manager.get_api_key("google")
    if api_key:
        print(f"   ✅ Google API Key: ***{api_key[-4:]}")
    else:
        print("   ❌ Google API Key no encontrada")
    
    # Database URL
    db_url = secrets_manager.get_db_url("postgres")
    if db_url:
        print(f"   ✅ PostgreSQL URL obtenida")
    else:
        print("   ❌ PostgreSQL URL no encontrada")
    
    # 4. Obtener grupos de credenciales
    print("\n4. Obteniendo grupos de credenciales:")
    
    # Todas las credenciales de una API
    api_creds = secrets_manager.get_api_credentials("stripe")
    if api_creds:
        print(f"   ✅ Credenciales de Stripe: {list(api_creds.keys())}")
    
    # Todas las credenciales de base de datos
    db_creds = secrets_manager.get_db_credentials("mysql")
    if db_creds:
        print(f"   ✅ Credenciales de MySQL: {list(db_creds.keys())}")
    
    # 5. Trabajar con el caché
    print("\n5. Información del caché:")
    cache_info = secrets_manager.get_cache_status()
    print(f"   - Secretos en caché: {cache_info['total_secrets']}")
    print(f"   - TTL configurado: {cache_info['ttl_seconds']} segundos")
    
    # 6. Secretos personalizados y legacy
    print("\n6. Secretos personalizados:")
    
    # Secreto que sigue la convención
    custom = secrets_manager.get_custom_secret("api-custom-key")
    if custom:
        print("   ✅ Secreto personalizado obtenido")
    
    # Secreto legacy (no sigue convención)
    env = secrets_manager.get_environment()
    if env:
        print(f"   ✅ Entorno: {env}")
    
    # 7. Manejo de errores
    print("\n7. Manejo de errores:")
    try:
        # Intenta obtener un secreto que probablemente no existe
        result = secrets_manager.get_api_key("servicio-inexistente")
        if result is None:
            print("   ℹ️  El secreto no existe (comportamiento esperado)")
    except Exception as e:
        print(f"   ❌ Error inesperado: {e}")
    
    print("\n✅ Ejemplo completado!")


if __name__ == "__main__":
    main()