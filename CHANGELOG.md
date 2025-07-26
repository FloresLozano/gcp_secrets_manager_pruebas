# Changelog

Todos los cambios notables de este proyecto serán documentados en este archivo.

El formato está basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.0.0/),
y este proyecto adhiere a [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Agregado
- Soporte para Python 3.12

### Cambiado
- Mejorado el rendimiento del caché

## [0.1.0] - 2024-01-XX

### Agregado
- Implementación inicial del gestor de secretos
- Sistema de caché con TTL configurable
- Validación de nombres según convenciones
- Soporte para secretos legacy
- CLI para operaciones rápidas
- Tests unitarios y de integración
- Documentación completa
- Ejemplos de uso básico y avanzado

### Características principales
- Métodos específicos para cada tipo de secreto (API, DB, Auth, Token, Encryption)
- Gestión inteligente del caché
- Logging detallado para debugging
- Manejo robusto de errores
- Compatible con Google Cloud Secret Manager
- Type hints para mejor soporte de IDEs

[Unreleased]: https://github.com/tunombre/gcp-secrets-manager/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/tunombre/gcp-secrets-manager/releases/tag/v0.1.0