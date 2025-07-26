"""
Ejemplos avanzados de uso del gestor de secretos
"""
import asyncio
import time
from concurrent.futures import ThreadPoolExecutor
from gcp_secrets_manager import StandardSecretsManager, SecretManagerWithCache


def example_custom_cache_ttl():
    """Ejemplo con TTL de caché personalizado."""
    print("=== Ejemplo: TTL de Caché Personalizado ===\n")
    
    # Crear gestor con caché de 10 segundos
    manager = StandardSecretsManager('tu-proyecto', cache_ttl_seconds=10)
    
    # Primera llamada - desde GCP
    print("1. Primera llamada (desde GCP):")
    start = time.time()
    secret = manager.get_api_key("test")
    print(f"   Tiempo: {time.time() - start:.2f}s")
    
    # Segunda llamada inmediata - desde caché
    print("2. Segunda llamada (desde caché):")
    start = time.time()
    secret = manager.get_api_key("test")
    print(f"   Tiempo: {time.time() - start:.2f}s")
    
    # Esperar a que expire el caché
    print("3. Esperando 11 segundos para que expire el caché...")
    time.sleep(11)
    
    # Tercera llamada - desde GCP nuevamente
    print("4. Tercera llamada (desde GCP nuevamente):")
    start = time.time()
    secret = manager.get_api_key("test")
    print(f"   Tiempo: {time.time() - start:.2f}s\n")


def example_bulk_operations():
    """Ejemplo de operaciones masivas."""
    print("=== Ejemplo: Operaciones Masivas ===\n")
    
    manager = StandardSecretsManager('tu-proyecto')
    
    # Lista de servicios para obtener credenciales
    services = ['google', 'aws', 'azure', 'stripe', 'twilio']
    
    print("Obteniendo API keys para múltiples servicios:")
    for service in services:
        key = manager.get_api_key(service)
        status = "✅ Encontrada" if key else "❌ No encontrada"
        print(f"   {service}: {status}")
    
    # Obtener múltiples secretos personalizados de una vez
    print("\nObteniendo múltiples secretos personalizados:")
    custom_secrets = [
        'ENVIRONMENT',
        'LOG_LEVEL',
        'GCP_PROJECT_ID',
        'GCP_REGION'
    ]
    
    results = manager.get_multiple_custom_secrets(custom_secrets, validate_format=False)
    for name, value in results.items():
        status = "✅" if value else "❌"
        print(f"   {status} {name}: {value or 'No encontrado'}")
    print()


def example_concurrent_access():
    """Ejemplo de acceso concurrente con threads."""
    print("=== Ejemplo: Acceso Concurrente ===\n")
    
    manager = StandardSecretsManager('tu-proyecto')
    
    def get_secret_info(secret_type, identifier):
        """Función para obtener información de un secreto."""
        start = time.time()
        if secret_type == 'api':
            result = manager.get_api_credentials(identifier)
        elif secret_type == 'db':
            result = manager.get_db_credentials(identifier)
        else:
            result = manager.get_auth_credentials(identifier)
        
        elapsed = time.time() - start
        return f"{secret_type}-{identifier}", len(result) if result else 0, elapsed
    
    # Lista de secretos a obtener concurrentemente
    tasks = [
        ('api', 'google'),
        ('api', 'stripe'),
        ('db', 'postgres'),
        ('db', 'mysql'),
        ('auth', 'main'),
        ('auth', 'admin')
    ]
    
    print("Obteniendo 6 grupos de credenciales concurrentemente:")
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(get_secret_info, t, i) for t, i in tasks]
        
        for future in futures:
            name, count, elapsed = future.result()
            print(f"   {name}: {count} credenciales en {elapsed:.2f}s")
    print()


def example_cache_management():
    """Ejemplo de gestión del caché."""
    print("=== Ejemplo: Gestión del Caché ===\n")
    
    manager = StandardSecretsManager('tu-proyecto')
    
    # Llenar el caché con algunos secretos
    print("1. Llenando el caché:")
    secrets_to_cache = [
        ('api', 'google'),
        ('db', 'postgres'),
        ('auth', 'main')
    ]
    
    for secret_type, identifier in secrets_to_cache:
        if secret_type == 'api':
            manager.get_api_key(identifier)
        elif secret_type == 'db':
            manager.get_db_user(identifier)
        else:
            manager.get_auth_user(identifier)
        print(f"   Cacheado: {secret_type}-{identifier}-*")
    
    # Ver estado del caché
    print("\n2. Estado del caché:")
    cache_info = manager.get_cache_status()
    print(f"   Total secretos: {cache_info['total_secrets']}")
    print(f"   Detalles:")
    for secret, info in list(cache_info['secrets'].items())[:5]:  # Mostrar solo 5
        print(f"     - {secret}: edad={info['age_seconds']:.1f}s, "
              f"expira en {info['expires_in']:.1f}s")
    
    # Limpiar un secreto específico
    print("\n3. Limpiando secreto específico del caché:")
    manager.clear_cache('api-google-key')
    print("   ✅ Limpiado: api-google-key")
    
    # Limpiar todo el caché
    print("\n4. Limpiando todo el caché:")
    manager.clear_cache()
    cache_info = manager.get_cache_status()
    print(f"   ✅ Caché limpiado. Secretos en caché: {cache_info['total_secrets']}\n")


def example_error_handling():
    """Ejemplo de manejo de errores."""
    print("=== Ejemplo: Manejo de Errores ===\n")
    
    # Usar un proyecto que probablemente no existe
    try:
        manager = StandardSecretsManager('proyecto-inexistente-12345')
        
        # Intentar obtener un secreto
        print("1. Intentando obtener secreto de proyecto inexistente:")
        result = manager.get_api_key("test")
        if result is None:
            print("   ℹ️  Secreto no encontrado (puede ser permiso denegado)")
        
    except Exception as e:
        print(f"   ❌ Error: {e}")
    
    # Validación de nombres
    print("\n2. Validación de nombres de secretos:")
    manager = StandardSecretsManager('tu-proyecto')
    
    # Nombre inválido (con validación)
    invalid_secret = "formato_invalido_secreto"
    print(f"   Intentando obtener '{invalid_secret}' con validación:")
    result = manager.get_custom_secret(invalid_secret, validate_format=True)
    print(f"   Resultado: {result} (None esperado)")
    
    # Mismo nombre sin validación
    print(f"   Intentando obtener '{invalid_secret}' sin validación:")
    result = manager.get_custom_secret(invalid_secret, validate_format=False)
    print(f"   Resultado: {result or 'No encontrado'}\n")


def example_using_low_level_api():
    """Ejemplo usando la API de bajo nivel directamente."""
    print("=== Ejemplo: API de Bajo Nivel ===\n")
    
    # Usar SecretManagerWithCache directamente
    cache_manager = SecretManagerWithCache('tu-proyecto', cache_ttl_seconds=60)
    
    # Obtener secreto individual
    print("1. Obteniendo secreto individual:")
    secret = cache_manager.get_secret('api-google-key')
    print(f"   Resultado: {'✅ Obtenido' if secret else '❌ No encontrado'}")
    
    # Obtener múltiples secretos
    print("\n2. Obteniendo múltiples secretos:")
    secrets = cache_manager.get_multiple_secrets([
        'api-google-key',
        'api-stripe-key',
        'db-postgres-password'
    ])
    
    for name, value in secrets.items():
        status = "✅" if value else "❌"
        print(f"   {status} {name}")
    
    # Información detallada del caché
    print("\n3. Información detallada del caché:")
    info = cache_manager.get_cache_info()
    print(f"   TTL: {info['ttl_seconds']}s")
    print(f"   Secretos cacheados: {info['total_secrets']}")


def main():
    """Ejecutar todos los ejemplos."""
    examples = [
        example_custom_cache_ttl,
        example_bulk_operations,
        example_concurrent_access,
        example_cache_management,
        example_error_handling,
        example_using_low_level_api
    ]
    
    for example in examples:
        try:
            example()
            print("\n" + "="*50 + "\n")
        except Exception as e:
            print(f"Error en ejemplo {example.__name__}: {e}\n")


if __name__ == "__main__":
    main()