"""Módulo de autenticación para Google Cloud"""

import logging
import os
import sys

import google.auth
from google.auth import exceptions

logger = logging.getLogger(__name__)


def verify_credentials():
    """
    Verifica que las credenciales de Google Cloud estén disponibles a través de
    Application Default Credentials (ADC), el método recomendado por Google.
    """
    logger.info("Verificando credenciales de autenticación (método ADC)")

    try:
        # Intenta obtener las credenciales usando la misma lógica que las librerías de Google
        credentials, project_id = google.auth.default()

        logger.info("Credenciales de autenticación encontradas con éxito.")

        # Muestra cómo se está autenticando el script para mayor claridad
        if hasattr(credentials, "service_account_email"):
            logger.info(f"Modo: Service Account ({credentials.service_account_email})")
        elif os.environ.get("GOOGLE_APPLICATION_CREDENTIALS"):
            logger.info(f"Modo: Archivo de clave (via GOOGLE_APPLICATION_CREDENTIALS)")
        else:
            logger.info(
                "Modo: Credenciales de Usuario Local (via 'gcloud auth application-default login')"
            )

        return credentials, project_id

    except google.auth.exceptions.DefaultCredentialsError:
        logger.error(
            "¡ERROR CRÍTICO! No se pudieron encontrar las credenciales de autenticación por defecto."
        )
        logger.error("Soluciones posibles:")
        logger.error(
            "  1. (Para Desarrollo Local): Ejecuta en tu terminal -> gcloud auth application-default login"
        )
        logger.error(
            "  2. (Para Producción en GCP): Asegúrate de que el servicio tiene una Service Account con permisos."
        )
        raise
