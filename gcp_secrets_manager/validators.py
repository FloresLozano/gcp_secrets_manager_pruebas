"""Validadores para nombres de secretos según convenciones establecidas"""

import logging
import re
from typing import List, Set

logger = logging.getLogger(__name__)


class SecretNameValidator:
    """Validador de nombres de secretos según convenciones estándar."""

    VALID_TYPES = ["api", "db", "auth", "token", "encryption"]
    VALID_DATA_TYPES = ["key", "password", "user", "url", "secret", "id", "host", "port"]
    LEGACY_SECRETS = {
        "AGENTS_API_ANTHROPIC_API_KEY",
        "ENVIRONMENT",
        "GCP_PROJECT_ID",
        "GOOGLE_CLOUD_PROJECT",
        "GOOGLE_PROJECT_ID",
        "GCP_REGION",
        "GCP_SERVICE_NAME",
        "GCS_BUCKET_NAME",
        "GOOGLE_DOCAI_PROCESSOR_ID",
        "LOG_LEVEL",
        "MTS_AGENTS_API_URL",
        "WHATSAPP_WEBHOOK_URL",
        "dockerhub-auth",
        "mts-secrets-data",
    }

    # Precompilación del patrón para rendimiento y para evitar identificadores inválidos
    # Identificador: alfanumérico con segmentos separados por un solo '-' o '_',
    # sin comenzar ni terminar con separadores.
    _VALID_TYPES_RE = "|".join(VALID_TYPES)
    _VALID_DATA_TYPES_RE = "|".join(VALID_DATA_TYPES)
    _IDENTIFIER_RE = r"(?:[a-z0-9]+(?:[-_][a-z0-9]+)*)"
    _PATTERN = re.compile(rf"^({_VALID_TYPES_RE})-({_IDENTIFIER_RE})-({_VALID_DATA_TYPES_RE})$")

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

        if not cls._PATTERN.match(secret_name):
            # Para rendimiento evitamos log costoso en masa; solo en DEBUG
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug("ERROR DE FORMATO: El secreto '%s' no sigue la convención.", secret_name)
                logger.debug("Formato esperado: {tipo}-{identificador}-{tipo_dato}")
                logger.debug("Tipos válidos: %s", cls.VALID_TYPES)
                logger.debug("Tipos de dato válidos: %s", cls.VALID_DATA_TYPES)
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
