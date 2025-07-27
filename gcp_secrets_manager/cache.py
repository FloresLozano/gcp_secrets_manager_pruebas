"""Sistema de caché para el gestor de secretos"""

import logging
import time
from typing import Dict, List, Optional, Tuple

from google.api_core import exceptions
from google.cloud import secretmanager

from .validators import SecretNameValidator

logger = logging.getLogger(__name__)


class SecretManagerWithCache:
    """
    Gestor de secretos con caché y validación de nombres según convención estándar.
    """

    def __init__(self, project_id: str, cache_ttl_seconds: int = 300):
        """
        Inicializa el gestor de secretos con caché.

        Args:
            project_id: ID del proyecto de Google Cloud
            cache_ttl_seconds: Tiempo de vida del caché en segundos (default: 300)
        """
        self.project_id = project_id
        self.client = secretmanager.SecretManagerServiceClient()
        self.cache_ttl = cache_ttl_seconds
        self._cache: Dict[str, Tuple[str, float]] = {}
        self.validator = SecretNameValidator()
        logger.info(
            f"SecretManager inicializado para proyecto '{project_id}' con TTL de {cache_ttl_seconds}s"
        )

    def _validate_secret_name(self, secret_name: str) -> bool:
        """Valida el formato del nombre del secreto."""
        return self.validator.validate(secret_name)

    def get_secret(self, secret_name: str, validate_name: bool = True) -> Optional[str]:
        """
        Obtiene un secreto del gestor, usando caché si está disponible.

        Args:
            secret_name: Nombre del secreto
            validate_name: Si se debe validar el formato del nombre

        Returns:
            El valor del secreto o None si no se encuentra
        """
        if validate_name and not self._validate_secret_name(secret_name):
            return None

        current_time = time.time()

        # Verificar caché
        if secret_name in self._cache:
            cached_value, timestamp = self._cache[secret_name]
            if current_time - timestamp < self.cache_ttl:
                logger.info(f"Secreto '{secret_name}' obtenido del CACHÉ.")
                return cached_value

        # Obtener de GCP
        logger.info(
            f"Secreto '{secret_name}' NO encontrado en caché o expirado. Obteniendo de GCP..."
        )
        try:
            name = f"projects/{self.project_id}/secrets/{secret_name}/versions/latest"
            response = self.client.access_secret_version(request={"name": name})
            secret_value = response.payload.data.decode("UTF-8")

            # Guardar en caché
            self._cache[secret_name] = (secret_value, current_time)
            logger.info(f"Secreto '{secret_name}' obtenido exitosamente y guardado en caché.")
            return secret_value

        except exceptions.NotFound:
            logger.warning(
                f"El secreto '{secret_name}' no fue encontrado en el proyecto '{self.project_id}'."
            )
            return None
        except exceptions.PermissionDenied:
            logger.error(f"Permiso denegado para acceder al secreto '{secret_name}'.")
            logger.error("Verifica los permisos de la Service Account o de tu usuario.")
            return None
        except Exception as e:
            logger.critical(f"Error inesperado al obtener '{secret_name}': {e}", exc_info=True)
            return None

    def get_multiple_secrets(
        self, secret_names: List[str], validate_names: bool = True
    ) -> Dict[str, Optional[str]]:
        """
        Obtiene múltiples secretos de una vez.

        Args:
            secret_names: Lista de nombres de secretos
            validate_names: Si se debe validar el formato de los nombres

        Returns:
            Diccionario con los secretos obtenidos
        """
        results = {}
        for secret_name in secret_names:
            results[secret_name] = self.get_secret(secret_name, validate_name=validate_names)
        return results

    def clear_cache(self, secret_name: Optional[str] = None):
        """
        Limpia el caché de secretos.

        Args:
            secret_name: Nombre específico del secreto a limpiar.
                        Si es None, limpia todo el caché.
        """
        if secret_name:
            if secret_name in self._cache:
                del self._cache[secret_name]
                logger.info(f"Caché del secreto '{secret_name}' limpiado.")
        else:
            self._cache.clear()
            logger.info("Caché completo limpiado.")

    def get_cache_info(self) -> Dict:
        """
        Obtiene información sobre el estado del caché.

        Returns:
            Diccionario con información del caché
        """
        current_time = time.time()
        cache_info = {
            "total_secrets": len(self._cache),
            "ttl_seconds": self.cache_ttl,
            "secrets": {},
        }

        for secret_name, (_, timestamp) in self._cache.items():
            age = current_time - timestamp
            is_valid = age < self.cache_ttl
            cache_info["secrets"][secret_name] = {
                "age_seconds": round(age, 2),
                "is_valid": is_valid,
                "expires_in": round(self.cache_ttl - age, 2) if is_valid else 0,
            }

        return cache_info
