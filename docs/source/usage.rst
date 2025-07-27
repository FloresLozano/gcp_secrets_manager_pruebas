Guía de Uso
===========

Este documento proporciona ejemplos de cómo usar la biblioteca `gcp-secrets-manager`.

Uso básico
----------

.. code-block:: python

   from gcp_secrets_manager import StandardSecretsManager

   manager = StandardSecretsManager()
   secret = manager.get_secret("my/secret")
   print(secret)

Uso con caché
-------------

.. code-block:: python

   from gcp_secrets_manager import SecretManagerWithCache

   manager = SecretManagerWithCache(ttl_seconds=300)
   secret = manager.get_secret("my/secret")
