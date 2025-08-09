import pytest
from unittest.mock import patch, MagicMock

from gcp_secrets_manager.manager import StandardSecretsManager


@patch("gcp_secrets_manager.cache.secretmanager.SecretManagerServiceClient")
def test_get_api_key_with_mocked_gcp_returns_secure_value(mock_client_cls):
    # Arrange: mock GCP Secret Manager client and its response
    mock_client = MagicMock()
    mock_client_cls.return_value = mock_client

    mock_response = MagicMock()
    mock_payload = MagicMock()
    mock_payload.data = b"my-api-key"
    mock_response.payload = mock_payload

    mock_client.access_secret_version.return_value = mock_response

    sm = StandardSecretsManager(project_id="test-project", secure_mode=True, cache_ttl_seconds=60)

    # Act
    secret = sm.get_api_key("google")

    # Assert
    assert secret  # truthy
    assert secret.get_value(confirm=True) == "my-api-key"
    mock_client.access_secret_version.assert_called_once()

    # Cache behavior: subsequent call should not hit the API again
    mock_client.access_secret_version.reset_mock()
    _ = sm.get_api_key("google")
    mock_client.access_secret_version.assert_not_called()


@patch("gcp_secrets_manager.cache.secretmanager.SecretManagerServiceClient")
def test_get_custom_secret_with_mocked_gcp(mock_client_cls):
    mock_client = MagicMock()
    mock_client_cls.return_value = mock_client

    mock_response = MagicMock()
    mock_payload = MagicMock()
    mock_payload.data = b"custom-value"
    mock_response.payload = mock_payload
    mock_client.access_secret_version.return_value = mock_response

    sm = StandardSecretsManager(project_id="test-project", secure_mode=False)

    # When secure_mode=False we should get a plain string
    value = sm.get_secret("my-custom-secret")
    assert value == "custom-value"

    # Validate call happened once
    mock_client.access_secret_version.assert_called_once()
