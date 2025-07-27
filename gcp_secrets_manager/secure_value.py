
"""Clase para manejar valores secretos de forma segura"""
import hashlib
from typing import Optional, Any


class SecureSecret:
    """
    Encapsula un valor secreto para prevenir su exposición accidental.
    Los valores solo pueden ser accedidos explícitamente.
    """
    
    def __init__(self, value: Optional[str], name: str = "secret"):
        self._value = value
        self._name = name
        self._accessed = False
        self._hash = None
        if value:
            self._hash = hashlib.sha256(value.encode()).hexdigest()[:8]
    
    def __str__(self) -> str:
        """Representación string segura - nunca muestra el valor real"""
        if self._value is None:
            return f"<SecureSecret: {self._name} (None)>"
        return f"<SecureSecret: {self._name} [****{self._hash}]>"
    
    def __repr__(self) -> str:
        """Representación para debugging - nunca muestra el valor real"""
        return self.__str__()
    
    def __bool__(self) -> bool:
        """Permite usar if secret: ..."""
        return self._value is not None
    
    def get_value(self, confirm: bool = False) -> Optional[str]:
        """
        Obtiene el valor real del secreto.
        
        Args:
            confirm: Debe ser True para confirmar que realmente quieres el valor
            
        Returns:
            El valor del secreto solo si confirm=True
            
        Raises:
            ValueError: Si no se confirma explícitamente
        """
        if not confirm:
            raise ValueError(
                "⚠️  Debes confirmar explícitamente que quieres acceder al valor del secreto. "
                "Usa: secret.get_value(confirm=True)"
            )
        self._accessed = True
        return self._value
    
    def get_masked_value(self, show_chars: int = 4) -> str:
        """
        Obtiene una versión enmascarada del secreto.
        
        Args:
            show_chars: Número de caracteres a mostrar al final
            
        Returns:
            Valor enmascarado como: ****1234
        """
        if not self._value:
            return "None"
        
        if len(self._value) <= show_chars:
            return "*" * len(self._value)
        
        masked_part = "*" * (len(self._value) - show_chars)
        visible_part = self._value[-show_chars:]
        return f"{masked_part}{visible_part}"
    
    def was_accessed(self) -> bool:
        """Indica si el valor fue accedido"""
        return self._accessed
    
    def length(self) -> int:
        """Retorna la longitud del secreto sin exponer el valor"""
        return len(self._value) if self._value else 0
    
    def starts_with(self, prefix: str) -> bool:
        """Verifica si el secreto empieza con un prefijo sin exponer el valor completo"""
        return self._value.startswith(prefix) if self._value else False
    
    def __eq__(self, other) -> bool:
        """Comparación segura sin exponer valores"""
        if isinstance(other, SecureSecret):
            return self._hash == other._hash
        return False