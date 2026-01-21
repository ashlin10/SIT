"""
Credential Manager - Handles encryption/decryption of stored credentials.

This module provides utilities for securely storing and retrieving credentials
using Fernet symmetric encryption.
"""

import os
import json
import base64
import hashlib
from pathlib import Path
from typing import Optional, Dict, Any, List
from cryptography.fernet import Fernet, InvalidToken

# Load environment variables
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


class CredentialManager:
    """Manages encryption and decryption of credentials."""
    
    def __init__(self, encryption_key: Optional[str] = None):
        """
        Initialize the credential manager.
        
        Args:
            encryption_key: Fernet encryption key. If not provided, reads from
                          CREDENTIAL_ENCRYPTION_KEY environment variable.
        """
        self._key = encryption_key or os.environ.get("CREDENTIAL_ENCRYPTION_KEY")
        self._cipher: Optional[Fernet] = None
        
        if self._key:
            try:
                self._cipher = Fernet(self._key.encode() if isinstance(self._key, str) else self._key)
            except Exception as e:
                print(f"Warning: Invalid encryption key, credentials will not be encrypted: {e}")
    
    @property
    def is_encryption_enabled(self) -> bool:
        """Check if encryption is properly configured."""
        return self._cipher is not None
    
    def encrypt(self, plaintext: str) -> str:
        """
        Encrypt a plaintext string.
        
        Args:
            plaintext: The string to encrypt.
            
        Returns:
            Base64-encoded encrypted string, or original if encryption disabled.
        """
        if not self._cipher or not plaintext:
            return plaintext
        
        try:
            encrypted = self._cipher.encrypt(plaintext.encode())
            return f"ENC:{encrypted.decode()}"
        except Exception as e:
            print(f"Warning: Encryption failed: {e}")
            return plaintext
    
    def decrypt(self, ciphertext: str) -> str:
        """
        Decrypt an encrypted string.
        
        Args:
            ciphertext: The encrypted string (prefixed with 'ENC:').
            
        Returns:
            Decrypted plaintext, or original if not encrypted or decryption fails.
        """
        if not self._cipher or not ciphertext:
            return ciphertext
        
        # Check if the value is encrypted (has ENC: prefix)
        if not ciphertext.startswith("ENC:"):
            return ciphertext
        
        try:
            encrypted_data = ciphertext[4:]  # Remove 'ENC:' prefix
            decrypted = self._cipher.decrypt(encrypted_data.encode())
            return decrypted.decode()
        except InvalidToken:
            print("Warning: Failed to decrypt - invalid token or wrong key")
            return ciphertext
        except Exception as e:
            print(f"Warning: Decryption failed: {e}")
            return ciphertext
    
    def encrypt_preset(self, preset: Dict[str, Any]) -> Dict[str, Any]:
        """
        Encrypt sensitive fields in an FMC preset.
        
        Args:
            preset: FMC preset dictionary with 'password' field.
            
        Returns:
            Preset with encrypted password.
        """
        encrypted = preset.copy()
        if "password" in encrypted:
            encrypted["password"] = self.encrypt(encrypted["password"])
        return encrypted
    
    def decrypt_preset(self, preset: Dict[str, Any]) -> Dict[str, Any]:
        """
        Decrypt sensitive fields in an FMC preset.
        
        Args:
            preset: FMC preset dictionary with potentially encrypted 'password'.
            
        Returns:
            Preset with decrypted password.
        """
        decrypted = preset.copy()
        if "password" in decrypted:
            decrypted["password"] = self.decrypt(decrypted["password"])
        return decrypted
    
    def encrypt_presets_file(self, presets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Encrypt all presets in a list."""
        return [self.encrypt_preset(p) for p in presets]
    
    def decrypt_presets_file(self, presets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Decrypt all presets in a list."""
        return [self.decrypt_preset(p) for p in presets]


# Global instance - initialized when module loads
_credential_manager: Optional[CredentialManager] = None


def get_credential_manager() -> CredentialManager:
    """Get or create the global credential manager instance."""
    global _credential_manager
    if _credential_manager is None:
        _credential_manager = CredentialManager()
    return _credential_manager


def encrypt_password(password: str) -> str:
    """Convenience function to encrypt a password."""
    return get_credential_manager().encrypt(password)


def decrypt_password(encrypted: str) -> str:
    """Convenience function to decrypt a password."""
    return get_credential_manager().decrypt(encrypted)


def generate_encryption_key() -> str:
    """Generate a new Fernet encryption key."""
    return Fernet.generate_key().decode()


# Migration utility
def migrate_presets_file(file_path: str) -> bool:
    """
    Migrate an existing presets file to use encrypted passwords.
    
    Args:
        file_path: Path to the presets JSON file.
        
    Returns:
        True if migration was successful, False otherwise.
    """
    cm = get_credential_manager()
    if not cm.is_encryption_enabled:
        print("Error: Encryption key not configured. Set CREDENTIAL_ENCRYPTION_KEY environment variable.")
        return False
    
    try:
        with open(file_path, 'r') as f:
            presets = json.load(f)
        
        # Check if already encrypted
        already_encrypted = all(
            p.get("password", "").startswith("ENC:") 
            for p in presets if p.get("password")
        )
        
        if already_encrypted:
            print(f"File {file_path} is already encrypted.")
            return True
        
        # Encrypt and save
        encrypted_presets = cm.encrypt_presets_file(presets)
        
        with open(file_path, 'w') as f:
            json.dump(encrypted_presets, f, indent=2)
        
        print(f"Successfully encrypted {len(presets)} presets in {file_path}")
        return True
        
    except Exception as e:
        print(f"Error migrating presets file: {e}")
        return False


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        if sys.argv[1] == "generate-key":
            print(f"New encryption key: {generate_encryption_key()}")
        elif sys.argv[1] == "migrate" and len(sys.argv) > 2:
            migrate_presets_file(sys.argv[2])
        else:
            print("Usage:")
            print("  python credential_manager.py generate-key")
            print("  python credential_manager.py migrate <path-to-presets.json>")
    else:
        print("Credential Manager Utility")
        print(f"Encryption enabled: {get_credential_manager().is_encryption_enabled}")
