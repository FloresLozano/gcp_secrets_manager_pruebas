"""CLI para el gestor de secretos de GCP"""
import argparse
import json
import logging
import sys
from typing import Optional
from .auth import verify_credentials
from .manager import StandardSecretsManager

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def setup_parser() -> argparse.ArgumentParser:
    """Configura el parser de argumentos CLI."""
    parser = argparse.ArgumentParser(
        description='GCP Secrets Manager CLI - Gestiona secretos en Google Cloud',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos de uso:
  # Verificar autenticación
  gcp-secrets-cli --verify-auth
  
  # Obtener una API key
  gcp-secrets-cli -p mi-proyecto --get-api-key google
  
  # Obtener credenciales de base de datos
  gcp-secrets-cli -p mi-proyecto --get-db-creds postgres
  
  # Ver estado del caché
  gcp-secrets-cli -p mi-proyecto --cache-status
  
  # Ejecutar demo completa
  gcp-secrets-cli -p mi-proyecto --demo
        """
    )
    
    # Argumentos principales
    parser.add_argument('--project', '-p', 
                       help='ID del proyecto GCP (o usa GCP_PROJECT_ID env var)')
    parser.add_argument('--verify-auth', action='store_true',
                       help='Verificar autenticación con GCP')
    parser.add_argument('--cache-ttl', type=int, default=300,
                       help='TTL del caché en segundos (default: 300)')
    
    # Comandos para obtener secretos
    secret_group = parser.add_argument_group('comandos de secretos')
    secret_group.add_argument('--get-api-key', metavar='SERVICE',
                            help='Obtener API key para un servicio')
    secret_group.add_argument('--get-api-creds', metavar='SERVICE',
                            help='Obtener todas las credenciales API')
    secret_group.add_argument('--get-db-creds', metavar='DB_NAME',
                            help='Obtener credenciales de base de datos')
    secret_group.add_argument('--get-auth-creds', metavar='SERVICE',
                            help='Obtener credenciales de autenticación')
    secret_group.add_argument('--get-custom', metavar='SECRET_NAME',
                            help='Obtener un secreto personalizado')
    
    # Comandos de utilidad
    util_group = parser.add_argument_group('comandos de utilidad')
    util_group.add_argument('--cache-status', action='store_true',
                          help='Ver estado del caché')
    util_group.add_argument('--clear-cache', action='store_true',
                          help='Limpiar todo el caché')
    util_group.add_argument('--list-legacy', action='store_true',
                          help='Listar secretos legacy disponibles')
    util_group.add_argument('--demo', action='store_true',
                          help='Ejecutar demostración completa')
    
    # Formato de salida
    parser.add_argument('--json', action='store_true',
                       help='Salida en formato JSON')
    parser.add_argument('--quiet', '-q', action='store_true',
                       help='Solo mostrar valores, sin mensajes adicionales')
    
    return parser


def get_project_id(args) -> Optional[str]:
    """Obtiene el project ID de los argumentos o variables de entorno."""
    import os
    project_id = args.project or os.environ.get('GCP_PROJECT_ID') or os.environ.get('GOOGLE_CLOUD_PROJECT')
    if not project_id and not args.verify_auth:
        logger.error("Error: Se requiere --project o la variable GCP_PROJECT_ID")
        sys.exit(1)
    return project_id


def print_result(result, args, label: str = ""):
    """Imprime resultados según las opciones especificadas."""
    if args.quiet and isinstance(result, str):
        print(result)
    elif args.json:
        if isinstance(result, str):
            print(json.dumps({label or "value": result}))
        else:
            print(json.dumps(result, indent=2))
    else:
        if label:
            print(f"\n{label}:")
        if isinstance(result, dict):
            for key, value in result.items():
                if value:
                    print(f"  {key}: {value}")
                else:
                    print(f"  {key}: [No encontrado]")
        else:
            print(f"  {result}")


def run_demo(manager: StandardSecretsManager):
    """Ejecuta una demostración completa del gestor."""
    print("\n" + "="*60)
    print("  DEMOSTRACIÓN DEL GESTOR DE SECRETOS")
    print("="*60 + "\n")
    
    demos = [
        ("API Keys", [
            ("Google API Key", lambda: manager.get_api_key("google")),
            ("Qdrant Credentials", lambda: manager.get_api_credentials("qdrant")),
        ]),
        ("Database Credentials", [
            ("Agents API URL", lambda: manager.get_db_url("agents_api")),
            ("Fin Agent DB", lambda: manager.get_db_credentials("fin_agent")),
        ]),
        ("Auth Credentials", [
            ("Main Auth", lambda: manager.get_auth_credentials("main")),
            ("WhatsApp Auth", lambda: manager.get_auth_credentials("whatsapp_app")),
        ]),
        ("Tokens", [
            ("WhatsApp Verify Token", lambda: manager.get_refresh_token("whatsapp_verify")),
            ("MTS API Token", lambda: manager.get_token_credentials("mts_agents_api")),
        ]),
        ("Encryption Keys", [
            ("Fernet Key", lambda: manager.get_encryption_key("fernet")),
            ("Main Encryption", lambda: manager.get_encryption_credentials("main")),
        ]),
    ]
    
    for category, tests in demos:
        print(f"\n{category}:")
        print("-" * len(category))
        for test_name, test_func in tests:
            try:
                result = test_func()
                if result:
                    if isinstance(result, dict):
                        print(f"✅ {test_name}: {list(result.keys())}")
                    else:
                        print(f"✅ {test_name}: Obtenido")
                else:
                    print(f"❌ {test_name}: No encontrado")
            except Exception as e:
                print(f"❌ {test_name}: Error - {e}")
    
    print("\n\nEstado del Caché:")
    print("-" * 16)
    cache_info = manager.get_cache_status()
    print(f"Total de secretos en caché: {cache_info['total_secrets']}")
    print(f"TTL configurado: {cache_info['ttl_seconds']} segundos")


def main():
    """Función principal del CLI."""
    parser = setup_parser()
    args = parser.parse_args()
    
    # Configurar nivel de logging
    if args.quiet:
        logging.getLogger().setLevel(logging.ERROR)
    
    try:
        # Verificar autenticación
        if args.verify_auth:
            print("Verificando autenticación con Google Cloud...")
            verify_credentials()
            print("\n✅ Autenticación verificada exitosamente!")
            return
        
        # Obtener project ID
        project_id = get_project_id(args)
        
        # Crear manager
        manager = StandardSecretsManager(project_id, cache_ttl_seconds=args.cache_ttl)
        
        # Ejecutar comandos
        if args.demo:
            run_demo(manager)
        
        elif args.get_api_key:
            result = manager.get_api_key(args.get_api_key)
            print_result(result, args, f"API Key para {args.get_api_key}")
        
        elif args.get_api_creds:
            result = manager.get_api_credentials(args.get_api_creds)
            print_result(result, args, f"Credenciales API para {args.get_api_creds}")
        
        elif args.get_db_creds:
            result = manager.get_db_credentials(args.get_db_creds)
            print_result(result, args, f"Credenciales DB para {args.get_db_creds}")
        
        elif args.get_auth_creds:
            result = manager.get_auth_credentials(args.get_auth_creds)
            print_result(result, args, f"Credenciales Auth para {args.get_auth_creds}")
        
        elif args.get_custom:
            result = manager.get_custom_secret(args.get_custom, validate_format=False)
            print_result(result, args, f"Secreto {args.get_custom}")
        
        elif args.cache_status:
            result = manager.get_cache_status()
            print_result(result, args, "Estado del Caché")
        
        elif args.clear_cache:
            manager.clear_cache()
            print("✅ Caché limpiado exitosamente")
        
        elif args.list_legacy:
            result = manager.list_available_legacy_secrets()
            print_result(result, args, "Secretos Legacy Disponibles")
        
        else:
            parser.print_help()
            
    except KeyboardInterrupt:
        print("\n\nOperación cancelada por el usuario.")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Error: {e}")
        if not args.quiet:
            logger.debug("Traceback completo:", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()