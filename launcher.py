#!/usr/bin/env python3
"""
Telegram Desktop TData Decryptor Launcher
Easy-to-use launcher with automatic dependency installation
"""

import os
import sys
import subprocess
import platform


def install_requirements():
    """Install required packages"""
    print("Checking and installing dependencies...")
    
    requirements = [
        'pycryptodome',
        'pillow'
    ]
    
    for req in requirements:
        try:
            __import__(req.replace('-', '_').split('>=')[0])
        except ImportError:
            print(f"Installing {req}...")
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', req])
    
    print("All dependencies installed successfully!\n")


def main():
    """Main launcher"""
    print("=" * 60)
    print("  Telegram Desktop TData Decryptor v2.0")
    print("  Enhanced Edition with GUI & Auto-Search")
    print("=" * 60)
    print()
    
    # Install requirements if needed
    try:
        from Crypto.Cipher import AES
    except ImportError:
        install_requirements()
    
    # Import and run the main application
    try:
        from telegram_decryptor import TelegramDecryptorGUI
        
        print("Starting GUI application...")
        print()
        print("Features:")
        print("  ✓ Dark/Light theme toggle")
        print("  ✓ Automatic tdata folder search")
        print("  ✓ Password-protected data support")
        print("  ✓ Progress indicators")
        print("  ✓ Result export to JSON")
        print()
        
        app = TelegramDecryptorGUI()
        app.run()
        
    except Exception as e:
        print(f"\nError starting application: {e}")
        print("\nTrying command-line mode...")
        
        # Fallback to command line if GUI fails
        from tdata_crypto import FullTDataDecryptor
        
        print("\nCommand Line Mode")
        print("-" * 40)
        
        # Get tdata path
        tdata_path = input("Enter tdata folder path (or press Enter for auto-search): ").strip()
        
        if not tdata_path:
            # Auto-search
            print("Searching for tdata folders...")
            
            if platform.system() == 'Windows':
                search_paths = [
                    os.path.expandvars(r'%APPDATA%\Telegram Desktop\tdata'),
                    os.path.expandvars(r'%LOCALAPPDATA%\Telegram Desktop\tdata'),
                ]
            elif platform.system() == 'Linux':
                search_paths = [
                    os.path.expanduser('~/.local/share/TelegramDesktop/tdata'),
                    os.path.expanduser('~/.var/app/org.telegram.desktop/data/TelegramDesktop/tdata'),
                ]
            else:  # macOS
                search_paths = [
                    os.path.expanduser('~/Library/Application Support/Telegram Desktop/tdata'),
                ]
            
            for path in search_paths:
                if os.path.exists(path):
                    tdata_path = path
                    print(f"Found: {path}")
                    break
            
            if not tdata_path:
                print("No tdata folder found. Please enter path manually.")
                sys.exit(1)
        
        # Get password
        password = input("Enter password (or press Enter if none): ").strip()
        
        # Decrypt
        print("\nDecrypting...")
        decryptor = FullTDataDecryptor()
        
        if decryptor.decrypt_tdata_folder(tdata_path, password):
            print("\n✅ Decryption successful!")
            
            # Display results
            if decryptor.accounts:
                print(f"\nFound {len(decryptor.accounts)} account(s):")
                for acc in decryptor.accounts:
                    print(f"  - User ID: {acc.user_id}")
                    print(f"    Main DC: {acc.main_dc_id}")
                    print(f"    Auth Keys: {len(acc.auth_keys)}")
            
            if decryptor.settings:
                print(f"\nSettings: {len(decryptor.settings)} entries")
            
            # Export option
            export = input("\nExport results to JSON? (y/n): ").lower()
            if export == 'y':
                output_file = f"telegram_session_{os.getpid()}.json"
                if decryptor.export_session(output_file):
                    print(f"Exported to: {output_file}")
                else:
                    print("Export failed")
        else:
            print("\n❌ Decryption failed!")
            print("Possible reasons:")
            print("  - Incorrect password")
            print("  - Corrupted tdata files")
            print("  - Incompatible Telegram version")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        sys.exit(1)
