"""Tests para el gestor de secretos"""
import pytest
from unittest.mock import Mock, patch, MagicMock
from gcp_secrets_manager import StandardSecretsManager
from gcp_secrets_manager.cache import SecretManagerWithCache
from gcp_secrets_manager.validators import SecretNameValidator


class TestSecretNameValidator:
    """Tests para el validador de nombres de secretos."""
    
    def test_valid_secret_names(self):
        """Test nombres válidos de secretos."""
        valid_names = [
            'api-google-key',
            'db-postgres-password',
            'auth-main-user',
            'token-jwt-secret',
            'encryption-fernet-key'
        ]
        
        for name in valid_names:
            assert SecretNameValidator.validate(name) is True
    
    def test_invalid_secret_names(self):
        """Test nombres inválidos de secretos."""
        invalid_names = [
            'invalid-format',
            'api_google_key',  # Guiones bajos en lugar de guiones
            'api-google',      # Falta tipo de dato
            'unknown-google-key',  # Tipo desconocido
        ]
        
        for name in invalid_names:
            assert SecretNameValidator.validate(name) is False
    
    def test_legacy_secrets(self):
        """Test secretos legacy siempre son válidos."""
        legacy_names = ['ENVIRONMENT', 'GCP_PROJECT_ID', 'dockerhub-auth']
        
        for name in legacy_names:
            assert SecretNameValidator.validate(name) is True
            assert SecretNameValidator.is_legacy(name) is True


class TestSecretManagerWithCache:
    """Tests para el gestor con caché."""
    
    @pytest.fixture
    def mock_client(self):
        """Mock del cliente de Secret Manager."""
        with patch('gcp_secrets_manager.cache.secretmanager.SecretManagerServiceClient') as mock:
            yield mock
    
    @pytest.fixture
    def cache_manager(self, mock_client):
        """Fixture para crear un gestor con caché."""
        return SecretManagerWithCache('test-project', cache_ttl_seconds=60)
    
    def test_get_secret_from_gcp(self, cache_manager, mock_client):
        """Test obtener secreto desde GCP."""
        # Configurar mock
        mock_response = Mock()
        mock_response.payload.data.decode.return_value = 'test-value'
        mock_client.return_value.access_secret_version.return_value = mock_response
        
        # Ejecutar
        result = cache_manager.get_secret('api-test-key')
        
        # Verificar
        assert result == 'test-value'
        mock_client.return_value.access_secret_version.assert_called_once()
    
    def test_get_secret_from_cache(self, cache_manager, mock_client):
        """Test obtener secreto desde caché."""
        # Agregar al caché manualmente
        import time
        cache_manager._cache['api-test-key'] = ('cached-value', time.time())
        
        # Ejecutar
        result = cache_manager.get_secret('api-test-key')
        
        # Verificar que no se llamó a GCP
        assert result == 'cached-value'
        mock_client.return_value.access_secret_version.assert_not_called()
    
    def test_cache_expiration(self, cache_manager, mock_client):
        """Test expiración del caché."""
        import time
        
        # Agregar al caché con timestamp antiguo
        old_timestamp = time.time() - 120  # 2 minutos atrás
        cache_manager._cache['api-test-key'] = ('old-value', old_timestamp)
        
        # Configurar mock para nueva llamada
        mock_response = Mock()
        mock_response.payload.data.decode.return_value = 'new-value'
        mock_client.return_value.access_secret_version.return_value = mock_response
        
        # Ejecutar
        result = cache_manager.get_secret('api-test-key')
        
        # Verificar que se obtuvo nuevo valor
        assert result == 'new-value'
        mock_client.return_value.access_secret_version.assert_called_once()


class TestStandardSecretsManager:
    """Tests para el gestor estándar."""
    
    @pytest.fixture
    def manager(self):
        """Fixture para crear un gestor estándar."""
        with patch('gcp_secrets_manager.cache.secretmanager.SecretManagerServiceClient'):
            return StandardSecretsManager('test-project')
    
    def test_get_api_key(self, manager):
        """Test obtener API key."""
        with patch.object(manager.sm_client, 'get_secret', return_value='test-api-key'):
            result = manager.get_api_key('google')
            assert result == 'test-api-key'
            manager.sm_client.get_secret.assert_called_with('api-google-key')
    
    def test_get_db_credentials(self, manager):
        """Test obtener credenciales de base de datos."""
        mock_values = {
            'db-postgres-user': 'admin',
            'db-postgres-password': 'secret123',
            'db-postgres-host': 'localhost',
            'db-postgres-port': '5432',
            'db-postgres-url': None  # No existe
        }
        
        with patch.object(manager.sm_client, 'get_secret', 
                         side_effect=lambda x: mock_values.get(x)):
            creds = manager.get_db_credentials('postgres')
            
            assert creds['user'] == 'admin'
            assert creds['password'] == 'secret123'
            assert creds['host'] == 'localhost'
            assert creds['port'] == '5432'
            assert 'url' not in creds  # No debe incluir valores None
    
    def test_get_custom_secret(self, manager):
        """Test obtener secreto personalizado."""
        with patch.object(manager.sm_client, 'get_secret', return_value='custom-value'):
            # Con validación
            result = manager.get_custom_secret('api-custom-key', validate_format=True)
            assert result == 'custom-value'
            
            # Sin validación (para legacy)
            result = manager.get_custom_secret('LEGACY_SECRET', validate_format=False)
            assert result == 'custom-value'
    
    def test_get_cache_status(self, manager):
        """Test obtener estado del caché."""
        mock_cache_info = {
            'total_secrets': 5,
            'ttl_seconds': 300,
            'secrets': {}
        }
        
        with patch.object(manager.sm_client, 'get_cache_info', 
                         return_value=mock_cache_info):
            status = manager.get_cache_status()
            assert status['total_secrets'] == 5
            assert status['ttl_seconds'] == 300
    
    def test_initialization_without_project_id(self):
        """Test que falla sin project_id."""
        with pytest.raises(ValueError, match="Se requiere un ID de proyecto"):
            StandardSecretsManager("")


@pytest.mark.integration
class TestIntegration:
    """Tests de integración (requieren configuración real de GCP)."""
    
    @pytest.mark.skip(reason="Requiere credenciales reales de GCP")
    def test_real_secret_retrieval(self):
        """Test real de obtención de secretos."""
        import os
        project_id = os.environ.get('GCP_PROJECT_ID', 'test-project')
        
        manager = StandardSecretsManager(project_id)
        # Intenta obtener un secreto conocido
        result = manager.get_environment()
        
        # Verifica que se obtuvo algo (o None si no existe)
        assert result is None or isinstance(result, str)