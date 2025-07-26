# Changelog

Todos los cambios notables de este proyecto serán documentados en este archivo.

El formato está basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.0.0/),
y este proyecto adhiere a [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Agregado
- Compatibilidad con Python 3.12
- Validación CLI extendida
- Configuración inicial vía variables de entorno

### Cambiado
- Mejorado el rendimiento del sistema de caché
- Estructura de CLI refactorizada para facilitar pruebas

---

## [0.1.0] - 2025-07-24

### Agregado
- Implementación inicial del gestor de secretos
- Sistema de caché con TTL configurable
- Validación de nombres según convenciones
- Soporte para secretos legacy
- CLI para operaciones rápidas (`gcp-secrets-cli`)
- Tests unitarios y de integración con cobertura
- Documentación técnica y ejemplos de uso
- Soporte para múltiples tipos de secretos (API, DB, Auth, Token, Encryption)

### Características principales
- Gestión inteligente del caché con fallback
- Logging detallado y configurable
- Manejo robusto de errores (con retry opcional)
- Compatible con `google-cloud-secret-manager`
- Tipado estricto (`type hints`) para facilitar integración en editores y CI

---

[Unreleased]: https://github.com/FloresLozano/gcp_secrets_manager_pruebas/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/FloresLozano/gcp_secrets_manager_pruebas/releases/tag/v0.1.0
