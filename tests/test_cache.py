"""Tests específicos para el módulo de caché"""
import time
import pytest
from unittest.mock import Mock, patch, MagicMock
from google.api_core import exceptions
from gcp_secrets_manager.cache import SecretManagerWithCache
from gcp_secrets_manager.validators import SecretNameValidator


class TestSecretManagerWithCache:
    """Tests detallados para SecretManagerWithCache"""
    
    @pytest.fixture
    def mock_client(self):
        """Mock del cliente de Secret Manager"""
        with patch('gcp_secrets_manager.cache.secretmanager.SecretManagerServiceClient') as mock:
            yield mock
    
    @pytest.fixture
    def cache_manager(self, mock_client):
        """Crea una instancia del gestor con caché para tests"""
        return SecretManagerWithCache('test-project', cache_ttl_seconds=60)
    
    def test_initialization(self, cache_manager):
        """Test de inicialización correcta"""
        assert cache_manager.project_id == 'test-project'
        assert cache_manager.cache_ttl == 60
        assert cache_manager._cache == {}
        assert isinstance(cache_manager.validator, SecretNameValidator)
    
    def test_get_secret_valid_name(self, cache_manager, mock_client):
        """Test obtener secreto con nombre válido"""
        # Configurar mock
        mock_response = Mock()
        mock_response.payload.data.decode.return_value = 'test-value'
        mock_client.return_value.access_secret_version.return_value = mock_response
        
        # Ejecutar
        result = cache_manager.get_secret('api-test-key')
        
        # Verificar
        assert result == 'test-value'
        assert 'api-test-key' in cache_manager._cache
        mock_client.return_value.access_secret_version.assert_called_once()
    
    def test_get_secret_invalid_name_with_validation(self, cache_manager):
        """Test obtener secreto con nombre inválido y validación activa"""
        result = cache_manager.get_secret('invalid_format_name', validate_name=True)
        assert result is None
    
    def test_get_secret_invalid_name_without_validation(self, cache_manager, mock_client):
        """Test obtener secreto con nombre inválido sin validación"""
        # Configurar mock
        mock_response = Mock()
        mock_response.payload.data.decode.return_value = 'legacy-value'
        mock_client.return_value.access_secret_version.return_value = mock_response
        
        # Ejecutar sin validación
        result = cache_manager.get_secret('LEGACY_SECRET', validate_name=False)
        
        # Verificar
        assert result == 'legacy-value'
    
    def test_cache_hit(self, cache_manager):
        """Test de acierto en caché"""
        # Agregar manualmente al caché
        current_time = time.time()
        cache_manager._cache['api-test-key'] = ('cached-value', current_time)
        
        # Obtener del caché
        with patch.object(cache_manager.client, 'access_secret_version') as mock_access:
            result = cache_manager.get_secret('api-test-key')
            
            # Verificar que no se llamó a la API
            assert result == 'cached-value'
            mock_access.assert_not_called()
    
    def test_cache_expiration(self, cache_manager, mock_client):
        """Test de expiración del caché"""
        # Agregar al caché con timestamp antiguo (más de 60 segundos)
        old_timestamp = time.time() - 120
        cache_manager._cache['api-test-key'] = ('old-value', old_timestamp)
        
        # Configurar nueva respuesta
        mock_response = Mock()
        mock_response.payload.data.decode.return_value = 'new-value'
        mock_client.return_value.access_secret_version.return_value = mock_response
        
        # Obtener secreto (debería llamar a la API)
        result = cache_manager.get_secret('api-test-key')
        
        # Verificar
        assert result == 'new-value'
        assert cache_manager._cache['api-test-key'][0] == 'new-value'
    
    def test_get_secret_not_found(self, cache_manager, mock_client):
        """Test cuando el secreto no existe"""
        mock_client.return_value.access_secret_version.side_effect = exceptions.NotFound('Not found')
        
        result = cache_manager.get_secret('api-nonexistent-key')
        
        assert result is None
        assert 'api-nonexistent-key' not in cache_manager._cache
    
    def test_get_secret_permission_denied(self, cache_manager, mock_client):
        """Test cuando no hay permisos"""
        mock_client.return_value.access_secret_version.side_effect = exceptions.PermissionDenied('Denied')
        
        result = cache_manager.get_secret('api-forbidden-key')
        
        assert result is None
        assert 'api-forbidden-key' not in cache_manager._cache
    
    def test_get_secret_generic_exception(self, cache_manager, mock_client):
        """Test con excepción genérica"""
        mock_client.return_value.access_secret_version.side_effect = Exception('Unknown error')
        
        result = cache_manager.get_secret('api-error-key')
        
        assert result is None
        assert 'api-error-key' not in cache_manager._cache
    
    def test_get_multiple_secrets(self, cache_manager, mock_client):
        """Test obtener múltiples secretos"""
        # Configurar respuestas
        responses = {
            'api-service1-key': 'value1',
            'api-service2-key': 'value2',
            'api-service3-key': None  # No existe
        }
        
        def mock_get_secret(name, validate_name=True):
            return responses.get(name)
        
        with patch.object(cache_manager, 'get_secret', side_effect=mock_get_secret):
            results = cache_manager.get_multiple_secrets([
                'api-service1-key',
                'api-service2-key',
                'api-service3-key'
            ])
            
            assert results['api-service1-key'] == 'value1'
            assert results['api-service2-key'] == 'value2'
            assert results['api-service3-key'] is None
    
    def test_clear_cache_specific_secret(self, cache_manager):
        """Test limpiar un secreto específico del caché"""
        # Agregar varios secretos al caché
        current_time = time.time()
        cache_manager._cache = {
            'api-test1-key': ('value1', current_time),
            'api-test2-key': ('value2', current_time),
            'api-test3-key': ('value3', current_time)
        }
        
        # Limpiar uno específico
        cache_manager.clear_cache('api-test2-key')
        
        # Verificar
        assert 'api-test1-key' in cache_manager._cache
        assert 'api-test2-key' not in cache_manager._cache
        assert 'api-test3-key' in cache_manager._cache
    
    def test_clear_cache_all(self, cache_manager):
        """Test limpiar todo el caché"""
        # Agregar secretos al caché
        current_time = time.time()
        cache_manager._cache = {
            'api-test1-key': ('value1', current_time),
            'api-test2-key': ('value2', current_time)
        }
        
        # Limpiar todo
        cache_manager.clear_cache()
        
        # Verificar
        assert cache_manager._cache == {}
    
    def test_clear_cache_nonexistent_secret(self, cache_manager):
        """Test limpiar secreto que no está en caché"""
        cache_manager._cache = {'api-test-key': ('value', time.time())}
        
        # No debe lanzar excepción
        cache_manager.clear_cache('api-nonexistent-key')
        
        # El caché existente debe permanecer
        assert 'api-test-key' in cache_manager._cache
    
    def test_get_cache_info_empty(self, cache_manager):
        """Test información de caché vacío"""
        info = cache_manager.get_cache_info()
        
        assert info['total_secrets'] == 0
        assert info['ttl_seconds'] == 60
        assert info['secrets'] == {}
    
    def test_get_cache_info_with_secrets(self, cache_manager):
        """Test información de caché con secretos"""
        current_time = time.time()
        
        # Agregar secretos con diferentes edades
        cache_manager._cache = {
            'api-new-key': ('value1', current_time - 10),      # 10 segundos
            'api-mid-key': ('value2', current_time - 30),      # 30 segundos
            'api-old-key': ('value3', current_time - 70)       # 70 segundos (expirado)
        }
        
        info = cache_manager.get_cache_info()
        
        # Verificaciones generales
        assert info['total_secrets'] == 3
        assert info['ttl_seconds'] == 60
        
        # Verificar secreto nuevo
        assert info['secrets']['api-new-key']['is_valid'] is True
        assert info['secrets']['api-new-key']['age_seconds'] >= 10
        assert info['secrets']['api-new-key']['expires_in'] <= 50
        
        # Verificar secreto medio
        assert info['secrets']['api-mid-key']['is_valid'] is True
        assert info['secrets']['api-mid-key']['age_seconds'] >= 30
        assert info['secrets']['api-mid-key']['expires_in'] <= 30
        
        # Verificar secreto expirado
        assert info['secrets']['api-old-key']['is_valid'] is False
        assert info['secrets']['api-old-key']['age_seconds'] >= 70
        assert info['secrets']['api-old-key']['expires_in'] == 0
    
    def test_concurrent_cache_access(self, cache_manager, mock_client):
        """Test de acceso concurrente al caché"""
        from concurrent.futures import ThreadPoolExecutor
        import threading
        
        # Configurar mock para simular demora
        call_count = threading.local()
        call_count.value = 0
        
        def mock_access_secret(*args, **kwargs):
            call_count.value = getattr(call_count, 'value', 0) + 1
            time.sleep(0.1)  # Simular latencia
            response = Mock()
            response.payload.data.decode.return_value = f'value-{call_count.value}'
            return response
        
        mock_client.return_value.access_secret_version.side_effect = mock_access_secret
        
        # Ejecutar múltiples hilos pidiendo el mismo secreto
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [
                executor.submit(cache_manager.get_secret, 'api-concurrent-key')
                for _ in range(10)
            ]
            
            results = [f.result() for f in futures]
        
        # Todos deberían obtener el mismo valor (del caché después de la primera llamada)
        assert all(r == results[0] for r in results)
        
    def test_cache_with_different_ttl(self):
        """Test con diferentes valores de TTL"""
        # TTL muy corto
        short_cache = SecretManagerWithCache('test-project', cache_ttl_seconds=1)
        short_cache._cache['api-test-key'] = ('value', time.time())
        
        # Esperar a que expire
        time.sleep(1.1)
        
        info = short_cache.get_cache_info()
        assert info['secrets']['api-test-key']['is_valid'] is False
        
        # TTL largo
        long_cache = SecretManagerWithCache('test-project', cache_ttl_seconds=3600)
        long_cache._cache['api-test-key'] = ('value', time.time())
        
        info = long_cache.get_cache_info()
        assert info['secrets']['api-test-key']['is_valid'] is True
        assert info['secrets']['api-test-key']['expires_in'] > 3500


@pytest.mark.parametrize("secret_name,expected", [
    ('api-test-key', True),
    ('db-postgres-password', True),
    ('auth-main-user', True),
    ('LEGACY_SECRET', True),
    ('invalid-format', False),
    ('api_underscore_key', False),
])
def test_validation_in_get_secret(mock_client, secret_name, expected):
    """Test parametrizado de validación en get_secret"""
    cache_manager = SecretManagerWithCache('test-project')
    
    # Configurar mock para retornar valor si es válido
    if expected:
        mock_response = Mock()
        mock_response.payload.data.decode.return_value = 'test-value'
        mock_client.return_value.access_secret_version.return_value = mock_response
    
    result = cache_manager.get_secret(secret_name, validate_name=True)
    
    if expected:
        assert result is not None
    else:
        assert result is None