#!/usr/bin/env python3
"""
Migration script to encrypt existing FMC config presets.

Usage:
    1. Ensure CREDENTIAL_ENCRYPTION_KEY is set in .env
    2. Run: python migrate_credentials.py

This will encrypt all plaintext passwords in FMC config preset files.
"""

import os
import sys
import glob

# Load environment variables
from dotenv import load_dotenv
load_dotenv()

from utils.credential_manager import get_credential_manager, migrate_presets_file

def main():
    cm = get_credential_manager()
    
    if not cm.is_encryption_enabled:
        print("=" * 60)
        print("ERROR: Encryption key not configured!")
        print("=" * 60)
        print("\nPlease create a .env file with:")
        print("  CREDENTIAL_ENCRYPTION_KEY=<your-key>")
        print("\nGenerate a key with:")
        print("  python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\"")
        print()
        sys.exit(1)
    
    print("=" * 60)
    print("FMC Credentials Migration Tool")
    print("=" * 60)
    print(f"Encryption enabled: {cm.is_encryption_enabled}")
    print()
    
    # Find all user preset files
    data_dir = os.path.join(os.path.dirname(__file__), "web_app", "data", "users")
    
    if not os.path.exists(data_dir):
        print(f"No user data directory found at: {data_dir}")
        sys.exit(0)
    
    preset_files = glob.glob(os.path.join(data_dir, "*", "fmc_config_presets.json"))
    
    if not preset_files:
        print("No FMC config preset files found.")
        sys.exit(0)
    
    print(f"Found {len(preset_files)} preset file(s) to migrate:\n")
    
    for preset_file in preset_files:
        user = os.path.basename(os.path.dirname(preset_file))
        print(f"  - User '{user}': {preset_file}")
    
    print()
    confirm = input("Proceed with migration? (yes/no): ").strip().lower()
    
    if confirm != "yes":
        print("Migration cancelled.")
        sys.exit(0)
    
    print()
    success_count = 0
    for preset_file in preset_files:
        user = os.path.basename(os.path.dirname(preset_file))
        print(f"Migrating {user}...", end=" ")
        if migrate_presets_file(preset_file):
            success_count += 1
            print("✓")
        else:
            print("✗")
    
    print()
    print(f"Migration complete: {success_count}/{len(preset_files)} files processed successfully.")


if __name__ == "__main__":
    main()
