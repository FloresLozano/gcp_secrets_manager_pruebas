"""Tests para el módulo de validadores"""

import pytest

from gcp_secrets_manager.validators import SecretNameValidator


class TestSecretNameValidator:
    """Tests exhaustivos para el validador de nombres de secretos"""

    def test_valid_api_secrets(self):
        """Test nombres válidos de tipo API"""
        valid_names = [
            "api-google-key",
            "api-openai-key",
            "api-stripe-secret",
            "api-twilio-id",
            "api-sendgrid-url",
            "api-slack-key",
            "api-github-secret",
            "api-aws-id",
        ]

        for name in valid_names:
            assert SecretNameValidator.validate(name) is True, f"'{name}' debería ser válido"

    def test_valid_db_secrets(self):
        """Test nombres válidos de tipo DB"""
        valid_names = [
            "db-postgres-user",
            "db-mysql-password",
            "db-mongodb-url",
            "db-redis-host",
            "db-elasticsearch-port",
            "db-cassandra-user",
            "db-neo4j-password",
        ]

        for name in valid_names:
            assert SecretNameValidator.validate(name) is True, f"'{name}' debería ser válido"

    def test_valid_auth_secrets(self):
        """Test nombres válidos de tipo AUTH"""
        valid_names = [
            "auth-admin-user",
            "auth-main-password",
            "auth-jwt-key",
            "auth-oauth-secret",
            "auth-ldap-id",
            "auth-saml-key",
        ]

        for name in valid_names:
            assert SecretNameValidator.validate(name) is True, f"'{name}' debería ser válido"

    def test_valid_token_secrets(self):
        """Test nombres válidos de tipo TOKEN"""
        valid_names = [
            "token-access-key",
            "token-refresh-secret",
            "token-bearer-id",
            "token-api-key",
        ]

        for name in valid_names:
            assert SecretNameValidator.validate(name) is True, f"'{name}' debería ser válido"

    def test_valid_encryption_secrets(self):
        """Test nombres válidos de tipo ENCRYPTION"""
        valid_names = [
            "encryption-aes-key",
            "encryption-rsa-secret",
            "encryption-fernet-key",
            "encryption-master-key",
        ]

        for name in valid_names:
            assert SecretNameValidator.validate(name) is True, f"'{name}' debería ser válido"

    def test_invalid_formats(self):
        """Test formatos inválidos"""
        invalid_names = [
            "invalid-format",  # Falta tipo de dato
            "api_google_key",  # Guiones bajos en lugar de guiones
            "api-google",  # Falta tipo de dato
            "unknown-google-key",  # Tipo desconocido
            "api-Google-key",  # Mayúsculas en identificador
            "api-google-KEY",  # Mayúsculas en tipo de dato
            "API-google-key",  # Mayúsculas en tipo
            "api--google-key",  # Doble guión
            "api-google-key-extra",  # Partes extras
            "-api-google-key",  # Empieza con guión
            "api-google-key-",  # Termina con guión
            "",  # Vacío
            "api",  # Solo tipo
            "api-",  # Tipo con guión
            "api-google-",  # Sin tipo de dato
            "api--key",  # Sin identificador
        ]

        for name in invalid_names:
            assert SecretNameValidator.validate(name) is False, f"'{name}' debería ser inválido"

    def test_legacy_secrets(self):
        """Test todos los secretos legacy"""
        for legacy_secret in SecretNameValidator.LEGACY_SECRETS:
            assert SecretNameValidator.validate(legacy_secret) is True
            assert SecretNameValidator.is_legacy(legacy_secret) is True

    def test_non_legacy_secrets(self):
        """Test que secretos normales no son legacy"""
        normal_secrets = ["api-google-key", "db-postgres-password", "auth-main-user"]

        for secret in normal_secrets:
            assert SecretNameValidator.is_legacy(secret) is False

    def test_edge_cases(self):
        """Test casos extremos"""
        edge_cases = [
            ("api-a-key", True),  # Identificador de una letra
            ("api-123-key", True),  # Identificador numérico
            ("api-test123-key", True),  # Identificador alfanumérico
            ("api-test_123-key", True),  # Identificador con guión bajo
            ("api-test-123-key", True),  # Identificador con guión
            ("api-very_long_identifier_name_with_many_parts-key", True),  # Identificador largo
        ]

        for name, expected in edge_cases:
            assert SecretNameValidator.validate(name) == expected, f"'{name}' resultado inesperado"

    def test_get_valid_types(self):
        """Test obtener tipos válidos"""
        types = SecretNameValidator.get_valid_types()

        assert isinstance(types, list)
        assert "api" in types
        assert "db" in types
        assert "auth" in types
        assert "token" in types
        assert "encryption" in types
        assert len(types) == 5

        # Verificar que es una copia (no la lista original)
        types.append("custom")
        assert "custom" not in SecretNameValidator.VALID_TYPES

    def test_get_valid_data_types(self):
        """Test obtener tipos de datos válidos"""
        data_types = SecretNameValidator.get_valid_data_types()

        assert isinstance(data_types, list)
        assert "key" in data_types
        assert "password" in data_types
        assert "user" in data_types
        assert "url" in data_types
        assert "secret" in data_types
        assert "id" in data_types
        assert "host" in data_types
        assert "port" in data_types
        assert len(data_types) == 8

        # Verificar que es una copia
        data_types.append("custom")
        assert "custom" not in SecretNameValidator.VALID_DATA_TYPES

    def test_case_sensitivity(self):
        """Test sensibilidad a mayúsculas/minúsculas"""
        # Minúsculas válidas
        assert SecretNameValidator.validate("api-google-key") is True

        # Mayúsculas inválidas
        assert SecretNameValidator.validate("API-GOOGLE-KEY") is False
        assert SecretNameValidator.validate("Api-Google-Key") is False

        # Legacy puede tener mayúsculas
        assert SecretNameValidator.validate("ENVIRONMENT") is True
        assert SecretNameValidator.validate("GCP_PROJECT_ID") is True

    @pytest.mark.parametrize("secret_type", ["api", "db", "auth", "token", "encryption"])
    @pytest.mark.parametrize(
        "data_type", ["key", "password", "user", "url", "secret", "id", "host", "port"]
    )
    def test_all_valid_combinations(self, secret_type, data_type):
        """Test todas las combinaciones válidas de tipo y tipo de dato"""
        # No todas las combinaciones tienen sentido, pero todas deberían ser válidas según el patrón
        secret_name = f"{secret_type}-test-{data_type}"
        assert SecretNameValidator.validate(secret_name) is True

    def test_special_characters_in_identifier(self):
        """Test caracteres especiales en el identificador"""
        test_cases = [
            ("api-test_with_underscore-key", True),  # Guión bajo permitido
            ("api-test-with-dash-key", True),  # Guión permitido
            ("api-test123-key", True),  # Números permitidos
            ("api-test.com-key", False),  # Punto no permitido
            ("api-test@mail-key", False),  # @ no permitido
            ("api-test$money-key", False),  # $ no permitido
            ("api-test#hash-key", False),  # # no permitido
            ("api-test space-key", False),  # Espacio no permitido
        ]

        for name, expected in test_cases:
            result = SecretNameValidator.validate(name)
            assert (
                result == expected
            ), f"'{name}' debería ser {'válido' if expected else 'inválido'}"


class TestValidatorPerformance:
    """Tests de rendimiento para el validador"""

    def test_validation_performance(self):
        """Test que la validación es rápida"""
        import time

        # Preparar muchos nombres para validar
        names_to_validate = []
        for i in range(1000):
            names_to_validate.append(f"api-service{i}-key")
            names_to_validate.append(f"invalid_format_{i}")
            names_to_validate.append("LEGACY_SECRET")

        # Medir tiempo
        start_time = time.time()

        for name in names_to_validate:
            SecretNameValidator.validate(name)

        elapsed_time = time.time() - start_time

        # Debería validar 3000 nombres en menos de 0.1 segundos
        assert elapsed_time < 0.1, f"Validación muy lenta: {elapsed_time:.3f}s para 3000 nombres"

    def test_regex_compilation_caching(self):
        """Test que el regex se compile eficientemente"""
        # Este test verifica implícitamente que el regex no se recompile cada vez
        # al hacer múltiples validaciones

        for _ in range(100):
            assert SecretNameValidator.validate("api-test-key") is True
            assert SecretNameValidator.validate("invalid_format") is False
