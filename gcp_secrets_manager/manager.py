"""Gestor principal de secretos con interfaz de alto nivel"""
import logging
from typing import Dict, List, Optional
from .cache import SecretManagerWithCache

logger = logging.getLogger(__name__)


class StandardSecretsManager:
    """
    Gestor estandarizado de secretos con un diseño híbrido y consistente.
    Proporciona una interfaz de alto nivel para acceder a diferentes tipos de secretos.
    """
    
    def __init__(self, project_id: str, cache_ttl_seconds: int = 300):
        """
        Inicializa el gestor estándar de secretos.
        
        Args:
            project_id: ID del proyecto de Google Cloud
            cache_ttl_seconds: TTL del caché en segundos
            
        Raises:
            ValueError: Si no se proporciona un project_id
        """
        if not project_id:
            raise ValueError("Se requiere un ID de proyecto de Google Cloud.")
        
        self.project_id = project_id
        self.sm_client = SecretManagerWithCache(project_id, cache_ttl_seconds)
        logger.info(f"StandardSecretsManager inicializado para proyecto: {project_id}")
    
    def _get_credentials_by_type(self, secret_type: str, identifier: str, 
                                data_types: List[str]) -> Dict[str, str]:
        """
        Obtiene múltiples credenciales relacionadas por tipo.
        
        Args:
            secret_type: Tipo de secreto (api, db, auth, etc.)
            identifier: Identificador del servicio
            data_types: Lista de tipos de datos a obtener
            
        Returns:
            Diccionario con las credenciales obtenidas
        """
        credentials = {}
        for data_type in data_types:
            secret_name = f"{secret_type}-{identifier}-{data_type}"
            value = self.sm_client.get_secret(secret_name)
            if value:
                credentials[data_type] = value
        return credentials
    
    # === MÉTODOS PARA SECRETOS DE TIPO 'API' ===
    def get_api_key(self, service_name: str) -> Optional[str]:
        """Obtiene la API key para un servicio específico."""
        return self.sm_client.get_secret(f"api-{service_name}-key")
    
    def get_api_secret(self, service_name: str) -> Optional[str]:
        """Obtiene el API secret para un servicio específico."""
        return self.sm_client.get_secret(f"api-{service_name}-secret")
    
    def get_api_id(self, service_name: str) -> Optional[str]:
        """Obtiene el API ID para un servicio específico."""
        return self.sm_client.get_secret(f"api-{service_name}-id")
    
    def get_api_url(self, service_name: str) -> Optional[str]:
        """Obtiene la API URL para un servicio específico."""
        return self.sm_client.get_secret(f"api-{service_name}-url")
    
    def get_api_credentials(self, service_name: str) -> Dict[str, str]:
        """Obtiene todas las credenciales API para un servicio."""
        return self._get_credentials_by_type('api', service_name, 
                                           ['key', 'secret', 'id', 'url'])
    
    # === MÉTODOS PARA SECRETOS DE TIPO 'DB' ===
    def get_db_user(self, db_identifier: str) -> Optional[str]:
        """Obtiene el usuario de base de datos."""
        return self.sm_client.get_secret(f"db-{db_identifier}-user")
    
    def get_db_password(self, db_identifier: str) -> Optional[str]:
        """Obtiene la contraseña de base de datos."""
        return self.sm_client.get_secret(f"db-{db_identifier}-password")
    
    def get_db_url(self, db_identifier: str) -> Optional[str]:
        """Obtiene la URL de conexión a base de datos."""
        return self.sm_client.get_secret(f"db-{db_identifier}-url")
    
    def get_db_host(self, db_identifier: str) -> Optional[str]:
        """Obtiene el host de base de datos."""
        return self.sm_client.get_secret(f"db-{db_identifier}-host")
    
    def get_db_port(self, db_identifier: str) -> Optional[str]:
        """Obtiene el puerto de base de datos."""
        return self.sm_client.get_secret(f"db-{db_identifier}-port")
    
    def get_db_credentials(self, db_identifier: str) -> Dict[str, str]:
        """Obtiene todas las credenciales de base de datos."""
        return self._get_credentials_by_type('db', db_identifier, 
                                           ['user', 'password', 'url', 'host', 'port'])
    
    # === MÉTODOS PARA SECRETOS DE TIPO 'AUTH' ===
    def get_auth_user(self, service_name: str) -> Optional[str]:
        """Obtiene el usuario de autenticación."""
        return self.sm_client.get_secret(f"auth-{service_name}-user")
    
    def get_auth_password(self, service_name: str) -> Optional[str]:
        """Obtiene la contraseña de autenticación."""
        return self.sm_client.get_secret(f"auth-{service_name}-password")
    
    def get_auth_key(self, service_name: str) -> Optional[str]:
        """Obtiene la clave de autenticación."""
        return self.sm_client.get_secret(f"auth-{service_name}-key")
    
    def get_auth_secret(self, service_name: str) -> Optional[str]:
        """Obtiene el secreto de autenticación."""
        return self.sm_client.get_secret(f"auth-{service_name}-secret")
    
    def get_auth_id(self, service_name: str) -> Optional[str]:
        """Obtiene el ID de autenticación."""
        return self.sm_client.get_secret(f"auth-{service_name}-id")
    
    def get_auth_credentials(self, service_name: str) -> Dict[str, str]:
        """Obtiene todas las credenciales de autenticación."""
        return self._get_credentials_by_type('auth', service_name, 
                                           ['key', 'secret', 'id', 'user', 'password'])
    
    # === MÉTODOS PARA SECRETOS DE TIPO 'TOKEN' ===
    def get_token_key(self, service_name: str) -> Optional[str]:
        """Obtiene el token key."""
        return self.sm_client.get_secret(f"token-{service_name}-key")
    
    def get_refresh_token(self, service_name: str) -> Optional[str]:
        """Obtiene el refresh token."""
        return self.sm_client.get_secret(f"token-{service_name}-secret")
    
    def get_token_credentials(self, service_name: str) -> Dict[str, str]:
        """Obtiene todas las credenciales de token."""
        return self._get_credentials_by_type('token', service_name, 
                                           ['key', 'secret', 'id'])
    
    # === MÉTODOS PARA SECRETOS DE TIPO 'ENCRYPTION' ===
    def get_encryption_key(self, context: str) -> Optional[str]:
        """Obtiene la clave de encriptación."""
        return self.sm_client.get_secret(f"encryption-{context}-key")
    
    def get_encryption_secret(self, context: str) -> Optional[str]:
        """Obtiene el secreto de encriptación."""
        return self.sm_client.get_secret(f"encryption-{context}-secret")
    
    def get_encryption_credentials(self, context: str) -> Dict[str, str]:
        """Obtiene todas las credenciales de encriptación."""
        return self._get_credentials_by_type('encryption', context, 
                                           ['key', 'secret'])
    
    # === MÉTODOS PARA SECRETOS LEGACY ===
    def get_anthropic_api_key(self) -> Optional[str]:
        """Obtiene la API key de Anthropic (legacy)."""
        return self.get_custom_secret('AGENTS_API_ANTHROPIC_API_KEY', validate_format=False)
    
    def get_mts_agents_api_url(self) -> Optional[str]:
        """Obtiene la URL de MTS Agents API (legacy)."""
        return self.get_custom_secret('MTS_AGENTS_API_URL', validate_format=False)
    
    def get_whatsapp_webhook_url(self) -> Optional[str]:
        """Obtiene la URL del webhook de WhatsApp (legacy)."""
        return self.get_custom_secret('WHATSAPP_WEBHOOK_URL', validate_format=False)
    
    def get_dockerhub_auth(self) -> Optional[str]:
        """Obtiene la autenticación de DockerHub (legacy)."""
        return self.get_custom_secret('dockerhub-auth', validate_format=False)
    
    def get_mts_secrets_data(self) -> Optional[str]:
        """Obtiene los datos de secretos MTS (legacy)."""
        return self.get_custom_secret('mts-secrets-data', validate_format=False)
    
    def get_environment(self) -> Optional[str]:
        """Obtiene el entorno actual (legacy)."""
        return self.get_custom_secret('ENVIRONMENT', validate_format=False)
    
    def get_log_level(self) -> Optional[str]:
        """Obtiene el nivel de log configurado (legacy)."""
        return self.get_custom_secret('LOG_LEVEL', validate_format=False)
    
    # === MÉTODOS GENÉRICOS Y DE UTILIDAD ===
    def get_custom_secret(self, secret_name: str, validate_format: bool = True) -> Optional[str]:
        """
        Obtiene un secreto personalizado.
        
        Args:
            secret_name: Nombre del secreto
            validate_format: Si se debe validar el formato del nombre
            
        Returns:
            El valor del secreto o None
        """
        return self.sm_client.get_secret(secret_name, validate_name=validate_format)
    
    def get_multiple_custom_secrets(self, secret_names: List[str], 
                                  validate_format: bool = True) -> Dict[str, Optional[str]]:
        """Obtiene múltiples secretos personalizados."""
        return self.sm_client.get_multiple_secrets(secret_names, validate_names=validate_format)
    
    def get_all_gcp_config(self) -> Dict[str, Optional[str]]:
        """Obtiene toda la configuración de GCP."""
        config_keys = [
            'GCP_PROJECT_ID', 'GOOGLE_CLOUD_PROJECT', 'GOOGLE_PROJECT_ID',
            'GCP_REGION', 'GCP_SERVICE_NAME', 'GCS_BUCKET_NAME',
            'GOOGLE_DOCAI_PROCESSOR_ID'
        ]
        return self.get_multiple_custom_secrets(config_keys, validate_format=False)
    
    def list_available_legacy_secrets(self) -> List[str]:
        """Lista todos los secretos legacy disponibles."""
        return list(SecretManagerWithCache.LEGACY_SECRETS)
    
    def is_legacy_secret(self, secret_name: str) -> bool:
        """Verifica si un secreto es legacy."""
        return secret_name in SecretManagerWithCache.LEGACY_SECRETS
    
    def get_cache_status(self) -> Dict:
        """Obtiene el estado actual del caché."""
        return self.sm_client.get_cache_info()
    
    def clear_cache(self, secret_name: Optional[str] = None):
        """Limpia el caché de secretos."""
        self.sm_client.clear_cache(secret_name)