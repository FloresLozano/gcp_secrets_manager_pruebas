"""Validadores para nombres de secretos según convenciones establecidas"""
import re
from typing import Set, List
import logging

logger = logging.getLogger(__name__)


class SecretNameValidator:
    """Validador de nombres de secretos según convenciones estándar."""
    
    VALID_TYPES = ['api', 'db', 'auth', 'token', 'encryption']
    VALID_DATA_TYPES = ['key', 'password', 'user', 'url', 'secret', 'id', 'host', 'port']
    LEGACY_SECRETS = {
        'AGENTS_API_ANTHROPIC_API_KEY', 'ENVIRONMENT', 'GCP_PROJECT_ID', 
        'GOOGLE_CLOUD_PROJECT', 'GOOGLE_PROJECT_ID', 'GCP_REGION', 
        'GCP_SERVICE_NAME', 'GCS_BUCKET_NAME', 'GOOGLE_DOCAI_PROCESSOR_ID',
        'LOG_LEVEL', 'MTS_AGENTS_API_URL', 'WHATSAPP_WEBHOOK_URL',
        'dockerhub-auth', 'mts-secrets-data'
    }
    
    @classmethod
    def validate(cls, secret_name: str) -> bool:
        """
        Valida que el nombre del secreto siga la convención establecida.
        
        Args:
            secret_name: Nombre del secreto a validar
            
        Returns:
            True si el nombre es válido, False en caso contrario
        """
        if secret_name in cls.LEGACY_SECRETS:
            logger.debug(f"Secreto '{secret_name}' es legacy. Validación omitida.")
            return True
        
        valid_types_re = '|'.join(cls.VALID_TYPES)
        valid_data_types_re = '|'.join(cls.VALID_DATA_TYPES)
        pattern = fr'^({valid_types_re})-([a-z0-9_-]+?)-({valid_data_types_re})$'
        
        if not re.match(pattern, secret_name):
            logger.error(f"ERROR DE FORMATO: El secreto '{secret_name}' no sigue la convención.")
            logger.error(f"Formato esperado: {{tipo}}-{{identificador}}-{{tipo_dato}}")
            logger.error(f"Tipos válidos: {cls.VALID_TYPES}")
            logger.error(f"Tipos de dato válidos: {cls.VALID_DATA_TYPES}")
            return False
            
        logger.debug(f"El formato del secreto '{secret_name}' es válido.")
        return True
    
    @classmethod
    def is_legacy(cls, secret_name: str) -> bool:
        """Verifica si es un secreto legacy."""
        return secret_name in cls.LEGACY_SECRETS
    
    @classmethod
    def get_valid_types(cls) -> List[str]:
        """Retorna los tipos válidos de secretos."""
        return cls.VALID_TYPES.copy()
    
    @classmethod
    def get_valid_data_types(cls) -> List[str]:
        """Retorna los tipos de datos válidos."""
        return cls.VALID_DATA_TYPES.copy()