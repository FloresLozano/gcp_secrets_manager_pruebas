"""
GCP Secrets Manager - Gestor de secretos para Google Cloud Platform
"""

__version__ = "0.1.0"
__author__ = "cloud department"
__email__ = "cloud department"

# Importaciones principales para facilitar el uso
from .auth import verify_credentials
from .cache import SecretManagerWithCache
from .manager import StandardSecretsManager

# Definir qué se exporta cuando se hace "from gcp_secrets_manager import *"
__all__ = ["verify_credentials", "StandardSecretsManager", "SecretManagerWithCache"]
