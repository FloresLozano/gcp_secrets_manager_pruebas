"""Gestor principal de secretos con interfaz de alto nivel"""

import logging
from typing import Dict, List, Optional, Union
from .secure_value import SecureSecret
from .cache import SecretManagerWithCache

logger = logging.getLogger(__name__)


class StandardSecretsManager:
    """
    Gestor estandarizado de secretos con un diseño híbrido y consistente.
    Proporciona una interfaz de alto nivel para acceder a diferentes tipos de secretos.
    """

    def __init__(self, project_id: str, cache_ttl_seconds: int = 300, secure_mode: bool = True): 
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
        self.secure_mode = secure_mode
        self.sm_client = SecretManagerWithCache(project_id, cache_ttl_seconds)
        logger.info(f"StandardSecretsManager inicializado para proyecto: {project_id}")
        if not secure_mode:
            logger.warning("  Modo inseguro activado - los secretos se retornarán como strings")

    def _wrap_secret(self, value: Optional[str], name: str = "secret") -> Union[Optional[str], SecureSecret]:
        """Envuelve el valor en SecureSecret si está en modo seguro, de lo contrario devuelve el valor."""
        if value is None:
            return None
        if self.secure_mode:
            return SecureSecret(value, name)
        return value


    def _get_credentials_by_type(
        self, secret_type: str, identifier: str, data_types: List[str]
    ) -> Dict[str, str]:
        """
        Método interno para obtener múltiples credenciales relacionadas por tipo como strings.
        El empaquetado en SecureSecret se realiza en los métodos públicos.

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
    def get_api_key(self, service_name: str) -> Union[Optional[str], SecureSecret]:
        """Obtiene la API key para un servicio específico."""
        secret_name = f"api-{service_name}-key"
        value = self.sm_client.get_secret(secret_name)
        return self._wrap_secret(value, secret_name)

    def get_api_secret(self, service_name: str) -> Union[Optional[str], SecureSecret]:
        """Obtiene el API secret para un servicio específico."""
        secret_name = f"api-{service_name}-secret"
        value = self.sm_client.get_secret(secret_name)
        return self._wrap_secret(value, secret_name)

    def get_api_id(self, service_name: str) -> Union[Optional[str], SecureSecret]:
        """Obtiene el API ID para un servicio específico."""
        secret_name = f"api-{service_name}-id"
        value = self.sm_client.get_secret(secret_name)
        return self._wrap_secret(value, secret_name)

    def get_api_url(self, service_name: str) -> Union[Optional[str], SecureSecret]:
        """Obtiene la API URL para un servicio específico."""
        secret_name = f"api-{service_name}-url"
        value = self.sm_client.get_secret(secret_name)
        return self._wrap_secret(value, secret_name)

    def get_api_credentials(self, service_name: str) -> Dict[str, Union[str, SecureSecret]]:
        """Obtiene todas las credenciales API para un servicio."""
        creds = self._get_credentials_by_type("api", service_name, ["key", "secret", "id", "url"])
        if self.secure_mode:
            return {k: SecureSecret(v, f"api-{service_name}-{k}") for k, v in creds.items()}
        return creds

    # === MÉTODOS PARA SECRETOS DE TIPO 'DB' ===
    def get_db_user(self, db_identifier: str) -> Union[Optional[str], SecureSecret]:
        """Obtiene el usuario de base de datos."""
        secret_name = f"db-{db_identifier}-user"
        value = self.sm_client.get_secret(secret_name)
        return self._wrap_secret(value, secret_name)

    def get_db_password(self, db_identifier: str) -> Union[Optional[str], SecureSecret]:
        """Obtiene la contraseña de base de datos."""
        secret_name = f"db-{db_identifier}-password"
        value = self.sm_client.get_secret(secret_name)
        return self._wrap_secret(value, secret_name)

    def get_db_url(self, db_identifier: str) -> Union[Optional[str], SecureSecret]:
        """Obtiene la URL de conexión a base de datos."""
        secret_name = f"db-{db_identifier}-url"
        value = self.sm_client.get_secret(secret_name)
        return self._wrap_secret(value, secret_name)

    def get_db_host(self, db_identifier: str) -> Union[Optional[str], SecureSecret]:
        """Obtiene el host de base de datos."""
        secret_name = f"db-{db_identifier}-host"
        value = self.sm_client.get_secret(secret_name)
        return self._wrap_secret(value, secret_name)

    def get_db_port(self, db_identifier: str) -> Union[Optional[str], SecureSecret]:
        """Obtiene el puerto de base de datos."""
        secret_name = f"db-{db_identifier}-port"
        value = self.sm_client.get_secret(secret_name)
        return self._wrap_secret(value, secret_name)

    def get_db_credentials(self, db_identifier: str) -> Dict[str, Union[str, SecureSecret]]:
        """Obtiene todas las credenciales de base de datos."""
        creds = self._get_credentials_by_type("db", db_identifier, ["user", "password", "url", "host", "port"])
        if self.secure_mode:
            return {k: SecureSecret(v, f"db-{db_identifier}-{k}") for k, v in creds.items()}
        return creds


    # === MÉTODOS PARA SECRETOS DE TIPO 'AUTH' ===
    def get_auth_user(self, service_name: str) -> Union[Optional[str], SecureSecret]:
        """Obtiene el usuario de autenticación."""
        secret_name = f"auth-{service_name}-user"
        value = self.sm_client.get_secret(secret_name)
        return self._wrap_secret(value, secret_name)

    def get_auth_password(self, service_name: str) -> Union[Optional[str], SecureSecret]:
        """Obtiene la contraseña de autenticación."""
        secret_name = f"auth-{service_name}-password"
        value = self.sm_client.get_secret(secret_name)
        return self._wrap_secret(value, secret_name)

    def get_auth_key(self, service_name: str) -> Union[Optional[str], SecureSecret]:
        """Obtiene la clave de autenticación."""
        secret_name = f"auth-{service_name}-key"
        value = self.sm_client.get_secret(secret_name)
        return self._wrap_secret(value, secret_name)

    def get_auth_secret(self, service_name: str) -> Union[Optional[str], SecureSecret]:
        """Obtiene el secreto de autenticación."""
        secret_name = f"auth-{service_name}-secret"
        value = self.sm_client.get_secret(secret_name)
        return self._wrap_secret(value, secret_name)

    def get_auth_id(self, service_name: str) -> Union[Optional[str], SecureSecret]:
        """Obtiene el ID de autenticación."""
        secret_name = f"auth-{service_name}-id"
        value = self.sm_client.get_secret(secret_name)
        return self._wrap_secret(value, secret_name)

    def get_auth_credentials(self, service_name: str) -> Dict[str, Union[str, SecureSecret]]:
        """Obtiene todas las credenciales de autenticación."""
        creds = self._get_credentials_by_type("auth", service_name, ["key", "secret", "id", "user", "password"])
        if self.secure_mode:
            return {k: SecureSecret(v, f"auth-{service_name}-{k}") for k, v in creds.items()}
        return creds

    # === MÉTODOS PARA SECRETOS DE TIPO 'TOKEN' ===
    def get_token_key(self, service_name: str) -> Union[Optional[str], SecureSecret]:
        """Obtiene el token key."""
        secret_name = f"token-{service_name}-key"
        value = self.sm_client.get_secret(secret_name)
        return self._wrap_secret(value, secret_name)

    def get_refresh_token(self, service_name: str) -> Union[Optional[str], SecureSecret]:
        """Obtiene el refresh token (usando 'secret' como tipo de dato)."""
        secret_name = f"token-{service_name}-secret"
        value = self.sm_client.get_secret(secret_name)
        return self._wrap_secret(value, secret_name)

    def get_token_credentials(self, service_name: str) -> Dict[str, Union[str, SecureSecret]]:
        """Obtiene todas las credenciales de token."""
        creds = self._get_credentials_by_type("token", service_name, ["key", "secret", "id"])
        if self.secure_mode:
            return {k: SecureSecret(v, f"token-{service_name}-{k}") for k, v in creds.items()}
        return creds

    # === MÉTODOS PARA SECRETOS DE TIPO 'ENCRYPTION' ===
    def get_encryption_key(self, context: str) -> Union[Optional[str], SecureSecret]:
        """Obtiene la clave de encriptación."""
        secret_name = f"encryption-{context}-key"
        value = self.sm_client.get_secret(secret_name)
        return self._wrap_secret(value, secret_name)

    def get_encryption_secret(self, context: str) -> Union[Optional[str], SecureSecret]:
        """Obtiene el secreto de encriptación."""
        secret_name = f"encryption-{context}-secret"
        value = self.sm_client.get_secret(secret_name)
        return self._wrap_secret(value, secret_name)

    def get_encryption_credentials(self, context: str) -> Dict[str, Union[str, SecureSecret]]:
        """Obtiene todas las credenciales de encriptación."""
        creds = self._get_credentials_by_type("encryption", context, ["key", "secret"])
        if self.secure_mode:
            return {k: SecureSecret(v, f"encryption-{context}-{k}") for k, v in creds.items()}
        return creds


    # === MÉTODOS PARA SECRETOS LEGACY ===
    def get_anthropic_api_key(self) -> Union[Optional[str], SecureSecret]:
        """Obtiene la API key de Anthropic (legacy)."""
        return self.get_custom_secret("AGENTS_API_ANTHROPIC_API_KEY", validate_format=False)

    def get_mts_agents_api_url(self) -> Union[Optional[str], SecureSecret]:
        """Obtiene la URL de MTS Agents API (legacy)."""
        return self.get_custom_secret("MTS_AGENTS_API_URL", validate_format=False)

    def get_whatsapp_webhook_url(self) -> Union[Optional[str], SecureSecret]:
        """Obtiene la URL del webhook de WhatsApp (legacy)."""
        return self.get_custom_secret("WHATSAPP_WEBHOOK_URL", validate_format=False)

    def get_dockerhub_auth(self) -> Union[Optional[str], SecureSecret]:
        """Obtiene la autenticación de DockerHub (legacy)."""
        return self.get_custom_secret("dockerhub-auth", validate_format=False)

    def get_mts_secrets_data(self) -> Union[Optional[str], SecureSecret]:
        """Obtiene los datos de secretos MTS (legacy)."""
        return self.get_custom_secret("mts-secrets-data", validate_format=False)

    def get_environment(self) -> Union[Optional[str], SecureSecret]:
        """Obtiene el entorno actual (legacy)."""
        return self.get_custom_secret("ENVIRONMENT", validate_format=False)

    def get_log_level(self) -> Union[Optional[str], SecureSecret]:
        """Obtiene el nivel de log configurado (legacy)."""
        return self.get_custom_secret("LOG_LEVEL", validate_format=False)

    # === MÉTODOS GENÉRICOS Y DE UTILIDAD ===
    def get_custom_secret(self, secret_name: str, validate_format: bool = True) -> Union[Optional[str], SecureSecret]:
        """
        Obtiene un secreto personalizado.

        Args:
            secret_name: Nombre del secreto.
            validate_format: Si se debe validar el formato del nombre.

        Returns:
            El valor del secreto (como SecureSecret o str) o None.
        """
        value = self.sm_client.get_secret(secret_name, validate_name=validate_format)
        return self._wrap_secret(value, secret_name)

    def get_secret(self, secret_name: str, validate_format: bool = True) -> Union[Optional[str], SecureSecret]:
        """Alias de conveniencia para get_custom_secret.

        Mantiene el mismo comportamiento respecto a validación y secure_mode.
        """
        return self.get_custom_secret(secret_name, validate_format=validate_format)

    def get_multiple_custom_secrets(
        self, secret_names: List[str], validate_format: bool = True
    ) -> Dict[str, Optional[Union[str, SecureSecret]]]:
        """Obtiene múltiples secretos personalizados."""
        secrets = self.sm_client.get_multiple_secrets(secret_names, validate_names=validate_format)
        if self.secure_mode:
            return {k: self._wrap_secret(v, k) for k, v in secrets.items()}
        return secrets


    def get_all_gcp_config(self) -> Dict[str, Optional[Union[str, SecureSecret]]]:
        """Obtiene toda la configuración de GCP."""
        config_keys = [
            "GCP_PROJECT_ID", "GOOGLE_CLOUD_PROJECT", "GOOGLE_PROJECT_ID",
            "GCP_REGION", "GCP_SERVICE_NAME", "GCS_BUCKET_NAME", "GOOGLE_DOCAI_PROCESSOR_ID",
        ]
        return self.get_multiple_custom_secrets(config_keys, validate_format=False)


# === Métodos de utilidad del gestor (no devuelven secretos) ===
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
        logger.info(f"Caché limpiado para: {'todos los secretos' if secret_name is None else secret_name}")
