#!/usr/bin/env python3
"""
Telegram Desktop TData Decryptor - Enhanced Edition
Complete solution with all requested features
"""

import os
import sys
import json
import glob
import time
import struct
import hashlib
import binascii
import platform
import threading
import traceback
from pathlib import Path
from datetime import datetime
from typing import List, Optional, Dict, Tuple
from dataclasses import dataclass, asdict

# Try importing GUI libraries
try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox, scrolledtext
    GUI_AVAILABLE = True
except ImportError:
    GUI_AVAILABLE = False
    print("Warning: Tkinter not available. GUI features disabled.")

# Crypto imports with auto-install
try:
    from Crypto.Cipher import AES
    from Crypto.Protocol.KDF import PBKDF2
    from Crypto.Util.Padding import unpad, pad
except ImportError:
    print("Installing required cryptography library...")
    os.system(f"{sys.executable} -m pip install pycryptodome")
    from Crypto.Cipher import AES
    from Crypto.Protocol.KDF import PBKDF2
    from Crypto.Util.Padding import unpad, pad


class DecryptionStatus:
    """Status tracking for decryption process"""
    def __init__(self):
        self.current_step = ""
        self.progress = 0
        self.total_steps = 0
        self.files_processed = 0
        self.errors = []
        self.warnings = []
        
    def update(self, step: str, progress: int = None):
        self.current_step = step
        if progress is not None:
            self.progress = progress
            
    def add_error(self, error: str):
        self.errors.append(error)
        
    def add_warning(self, warning: str):
        self.warnings.append(warning)


@dataclass
class TelegramAccount:
    """Enhanced Telegram account data structure"""
    index: int
    user_id: Optional[int] = None
    phone: Optional[str] = None
    username: Optional[str] = None
    main_dc_id: Optional[int] = None
    auth_keys: Dict[int, str] = None
    
    def __post_init__(self):
        if self.auth_keys is None:
            self.auth_keys = {}
    
    def to_dict(self):
        return asdict(self)


class EnhancedTDataDecryptor:
    """Enhanced TData decryption with comprehensive features"""
    
    # Telegram Desktop constants
    LOCAL_ENCRYPT_SALT_SIZE = 32
    LOCAL_ENCRYPT_KEY_SIZE = 256
    LOCAL_ENCRYPT_ITER_COUNT = 4000
    LOCAL_ENCRYPT_NO_PWD_ITER_COUNT = 4
    
    # Known folder hashes
    KNOWN_FOLDERS = {
        'D877F783D5D3EF8C': 'data',
        'A7FDF864FBC10B77': 'data#2',
        '8B0C7D8C8C0C8D8C': 'data#3',
        'F8806DD0C461824F': 'cache',
    }
    
    def __init__(self, status_callback=None):
        self.status = DecryptionStatus()
        self.status_callback = status_callback
        self.accounts: List[TelegramAccount] = []
        self.settings: Dict = {}
        self.cache_data: Dict = {}
        self.decrypted_files: List[str] = []
        
    def update_status(self, message: str, progress: int = None):
        """Update status with callback"""
        self.status.update(message, progress)
        if self.status_callback:
            self.status_callback(message, progress)
    
    @staticmethod
    def compute_hashes(data: bytes) -> Dict[str, bytes]:
        """Compute various hashes for data"""
        return {
            'md5': hashlib.md5(data).digest(),
            'sha1': hashlib.sha1(data).digest(),
            'sha256': hashlib.sha256(data).digest(),
            'sha512': hashlib.sha512(data).digest()
        }
    
    def create_local_key(self, password: str, salt: bytes) -> bytes:
        """Create encryption key from password"""
        if not password:
            iterations = self.LOCAL_ENCRYPT_NO_PWD_ITER_COUNT
            self.update_status("Using no-password key derivation")
        else:
            iterations = self.LOCAL_ENCRYPT_ITER_COUNT
            self.update_status("Deriving key from password")
        
        password_bytes = password.encode('utf-8') if password else b''
        return PBKDF2(
            password_bytes, 
            salt,
            dkLen=self.LOCAL_ENCRYPT_KEY_SIZE,
            count=iterations,
            hmac_hash_module=hashlib.sha512
        )
    
    def prepare_aes_oldmtp(self, auth_key: bytes, msg_key: bytes, 
                          send: bool = False) -> Tuple[bytes, bytes]:
        """Prepare AES key and IV for old MTP protocol"""
        x = 0 if send else 8
        
        sha1_a = hashlib.sha1(msg_key + auth_key[x:x+32]).digest()
        sha1_b = hashlib.sha1(auth_key[x+32:x+48] + msg_key + auth_key[x+48:x+64]).digest()
        sha1_c = hashlib.sha1(auth_key[x+64:x+96] + msg_key).digest()
        sha1_d = hashlib.sha1(msg_key + auth_key[x+96:x+128]).digest()
        
        aes_key = sha1_a[:8] + sha1_b[8:20] + sha1_c[4:16]
        aes_iv = sha1_a[8:20] + sha1_b[:8] + sha1_c[16:20] + sha1_d[:8]
        
        return aes_key, aes_iv
    
    def decrypt_local(self, encrypted: bytes, key: bytes, 
                     msg_key: bytes) -> Optional[bytes]:
        """Decrypt local data with verification"""
        try:
            # Prepare AES
            aes_key, aes_iv = self.prepare_aes_oldmtp(key, msg_key, False)
            
            # Decrypt
            cipher = AES.new(aes_key, AES.MODE_CBC, aes_iv)
            decrypted = cipher.decrypt(encrypted)
            
            # Verify integrity
            if len(decrypted) < 16:
                return None
            
            data_with_padding = decrypted[:-16]
            sha1_hash = decrypted[-16:]
            
            # Check hash
            if hashlib.sha1(data_with_padding).digest()[:16] != sha1_hash:
                return None
            
            # Remove padding
            if len(data_with_padding) > 0:
                padding_len = data_with_padding[0]
                if padding_len <= len(data_with_padding):
                    return data_with_padding[padding_len:]
            
            return None
            
        except Exception as e:
            self.status.add_error(f"Decryption error: {str(e)}")
            return None
    
    def decrypt_file(self, file_path: str, password: str = '') -> Optional[bytes]:
        """Decrypt a single tdata file"""
        try:
            self.update_status(f"Reading {os.path.basename(file_path)}")
            
            with open(file_path, 'rb') as f:
                data = f.read()
            
            if len(data) < self.LOCAL_ENCRYPT_SALT_SIZE + 16:
                self.status.add_warning(f"File too small: {file_path}")
                return None
            
            # Extract components
            salt = data[:self.LOCAL_ENCRYPT_SALT_SIZE]
            msg_key = data[self.LOCAL_ENCRYPT_SALT_SIZE:self.LOCAL_ENCRYPT_SALT_SIZE + 16]
            encrypted = data[self.LOCAL_ENCRYPT_SALT_SIZE + 16:]
            
            # Generate key
            key = self.create_local_key(password, salt)
            
            # Decrypt
            decrypted = self.decrypt_local(encrypted, key, msg_key)
            
            if decrypted:
                self.decrypted_files.append(file_path)
                return decrypted
            
            return None
            
        except Exception as e:
            self.status.add_error(f"Failed to decrypt {file_path}: {str(e)}")
            return None
    
    def parse_account_data(self, data: bytes, index: int) -> Optional[TelegramAccount]:
        """Parse account information from decrypted data"""
        try:
            account = TelegramAccount(index=index)
            offset = 0
            
            # Read user ID
            if len(data) >= offset + 8:
                account.user_id = struct.unpack_from('<Q', data, offset)[0]
                offset += 8
            
            # Read DC ID
            if len(data) >= offset + 4:
                account.main_dc_id = struct.unpack_from('<I', data, offset)[0]
                offset += 4
            
            # Read auth keys count
            if len(data) >= offset + 4:
                key_count = struct.unpack_from('<I', data, offset)[0]
                offset += 4
                
                # Read each auth key
                for _ in range(min(key_count, 10)):  # Limit for safety
                    if len(data) >= offset + 4 + 256:
                        dc_id = struct.unpack_from('<I', data, offset)[0]
                        offset += 4
                        key = data[offset:offset + 256]
                        account.auth_keys[dc_id] = binascii.hexlify(key).decode()
                        offset += 256
            
            return account if account.user_id else None
            
        except Exception as e:
            self.status.add_error(f"Failed to parse account: {str(e)}")
            return None
    
    def find_tdata_folders(self, base_path: str, max_depth: int = 5) -> List[str]:
        """Recursively search for tdata folders with progress"""
        self.update_status("Searching for tdata folders...")
        tdata_folders = []
        visited = set()
        
        def search_recursive(path: str, depth: int):
            if depth > max_depth or path in visited:
                return
            
            visited.add(path)
            
            try:
                for entry in os.scandir(path):
                    if entry.is_dir():
                        entry_lower = entry.name.lower()
                        
                        # Check for tdata folder
                        if 'tdata' in entry_lower:
                            tdata_folders.append(entry.path)
                            self.update_status(f"Found: {entry.path}")
                        
                        # Check for known hash folders
                        elif entry.name.upper() in self.KNOWN_FOLDERS:
                            parent_tdata = os.path.dirname(entry.path)
                            if parent_tdata not in tdata_folders:
                                tdata_folders.append(parent_tdata)
                                self.update_status(f"Found: {parent_tdata}")
                        
                        # Check for key files
                        elif self._has_key_files(entry.path):
                            tdata_folders.append(entry.path)
                            self.update_status(f"Found: {entry.path}")
                        
                        # Continue search
                        if depth < max_depth:
                            search_recursive(entry.path, depth + 1)
                            
            except (PermissionError, OSError) as e:
                pass
        
        search_recursive(base_path, 0)
        return list(set(tdata_folders))
    
    def _has_key_files(self, path: str) -> bool:
        """Check if directory contains key files"""
        key_patterns = ['key_datas', 'key_data*', 'map0', 'map1', 'maps', 'settings*']
        
        try:
            files = os.listdir(path)
            for pattern in key_patterns:
                if any(f.startswith(pattern.replace('*', '')) for f in files):
                    return True
        except:
            pass
        
        return False
    
    def decrypt_tdata_folder(self, tdata_path: str, password: str = '') -> bool:
        """Decrypt entire tdata folder with comprehensive processing"""
        if not os.path.exists(tdata_path):
            self.status.add_error(f"Path does not exist: {tdata_path}")
            return False
        
        self.update_status("Starting decryption process...")
        self.accounts = []
        self.settings = {}
        self.cache_data = {}
        
        # Find all potential key files
        key_files = self._find_all_key_files(tdata_path)
        
        if not key_files:
            self.status.add_error("No key files found in tdata folder")
            return False
        
        self.status.total_steps = len(key_files)
        success_count = 0
        
        # Process each file
        for i, key_file in enumerate(key_files):
            progress = int((i / len(key_files)) * 100)
            self.update_status(f"Processing {os.path.basename(key_file)}...", progress)
            
            decrypted = self.decrypt_file(key_file, password)
            
            if decrypted:
                # Parse based on file type
                if 'key_data' in os.path.basename(key_file):
                    account = self.parse_account_data(decrypted, len(self.accounts))
                    if account:
                        self.accounts.append(account)
                        success_count += 1
                
                elif 'map' in os.path.basename(key_file) or 'settings' in os.path.basename(key_file):
                    settings = self._parse_settings(decrypted)
                    self.settings.update(settings)
                    success_count += 1
                
                elif 'cache' in os.path.basename(key_file):
                    cache_info = self._parse_cache_index(decrypted)
                    self.cache_data.update(cache_info)
                    success_count += 1
            
            self.status.files_processed = i + 1
        
        self.update_status(f"Decryption complete. {success_count}/{len(key_files)} files processed.", 100)
        
        return success_count > 0
    
    def _find_all_key_files(self, tdata_path: str) -> List[str]:
        """Find all potential key files in tdata"""
        key_files = []
        
        # File patterns to search
        patterns = [
            'key_datas', 'key_data*',
            'maps', 'map0', 'map1',
            'settings*', 'cache*', 
            'configs', 'config'
        ]
        
        # Search in main folder
        for pattern in patterns:
            key_files.extend(glob.glob(os.path.join(tdata_path, pattern)))
        
        # Search in known hash folders
        for folder_hash, folder_name in self.KNOWN_FOLDERS.items():
            folder_path = os.path.join(tdata_path, folder_hash)
            if os.path.exists(folder_path):
                for pattern in patterns:
                    key_files.extend(glob.glob(os.path.join(folder_path, pattern)))
        
        # Search one level deep in any subfolder
        try:
            for entry in os.scandir(tdata_path):
                if entry.is_dir():
                    for pattern in patterns:
                        key_files.extend(glob.glob(os.path.join(entry.path, pattern)))
        except:
            pass
        
        return list(set(key_files))
    
    def _parse_settings(self, data: bytes) -> Dict:
        """Parse settings from decrypted data"""
        settings = {}
        
        try:
            if len(data) >= 4:
                settings['version'] = struct.unpack('<I', data[:4])[0]
            
            # Add more parsing as needed
            
        except Exception as e:
            self.status.add_warning(f"Failed to parse settings: {str(e)}")
        
        return settings
    
    def _parse_cache_index(self, data: bytes) -> Dict:
        """Parse cache index"""
        cache_info = {}
        
        try:
            if len(data) >= 8:
                cache_info['size'] = len(data)
                cache_info['entries'] = []
                
                # Basic parsing
                offset = 0
                while offset + 16 <= len(data):
                    entry_hash = data[offset:offset + 16]
                    cache_info['entries'].append(binascii.hexlify(entry_hash).decode()[:8])
                    offset += 16
                    
                    if len(cache_info['entries']) >= 100:  # Limit
                        break
                        
        except Exception as e:
            self.status.add_warning(f"Failed to parse cache: {str(e)}")
        
        return cache_info
    
    def export_results(self, output_path: str) -> bool:
        """Export all results to JSON"""
        try:
            results = {
                'timestamp': datetime.now().isoformat(),
                'status': {
                    'files_processed': self.status.files_processed,
                    'errors': self.status.errors,
                    'warnings': self.status.warnings
                },
                'accounts': [acc.to_dict() for acc in self.accounts],
                'settings': self.settings,
                'cache_data': self.cache_data,
                'decrypted_files': self.decrypted_files
            }
            
            with open(output_path, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            
            return True
            
        except Exception as e:
            self.status.add_error(f"Failed to export: {str(e)}")
            return False
    
    def get_summary(self) -> str:
        """Get decryption summary"""
        summary = []
        summary.append(f"Decryption Summary")
        summary.append(f"{'=' * 50}")
        summary.append(f"Files Processed: {self.status.files_processed}")
        summary.append(f"Accounts Found: {len(self.accounts)}")
        summary.append(f"Settings Entries: {len(self.settings)}")
        summary.append(f"Cache Entries: {len(self.cache_data.get('entries', []))}")
        
        if self.accounts:
            summary.append(f"\nAccounts:")
            for acc in self.accounts:
                summary.append(f"  - User ID: {acc.user_id}")
                summary.append(f"    DC: {acc.main_dc_id}")
                summary.append(f"    Auth Keys: {len(acc.auth_keys)}")
        
        if self.status.errors:
            summary.append(f"\nErrors ({len(self.status.errors)}):")
            for err in self.status.errors[:5]:  # Show first 5
                summary.append(f"  - {err}")
        
        if self.status.warnings:
            summary.append(f"\nWarnings ({len(self.status.warnings)}):")
            for warn in self.status.warnings[:5]:
                summary.append(f"  - {warn}")
        
        return "\n".join(summary)


# Enhanced GUI Class
if GUI_AVAILABLE:
    class EnhancedTelegramGUI:
        """Enhanced GUI with all requested features"""
        
        def __init__(self):
            self.root = tk.Tk()
            self.root.title("Telegram TData Decryptor v2.0 - Enhanced Edition")
            self.root.geometry("1000x700")
            
            # Initialize decryptor
            self.decryptor = EnhancedTDataDecryptor(self.status_callback)
            
            # Variables
            self.dark_mode = tk.BooleanVar(value=True)
            self.search_running = False
            self.decryption_running = False
            
            # Create GUI
            self.setup_gui()
            self.apply_theme()
            self.center_window()
        
        def center_window(self):
            """Center window on screen"""
            self.root.update_idletasks()
            x = (self.root.winfo_screenwidth() // 2) - (self.root.winfo_width() // 2)
            y = (self.root.winfo_screenheight() // 2) - (self.root.winfo_height() // 2)
            self.root.geometry(f'+{x}+{y}')
        
        def setup_gui(self):
            """Setup all GUI components"""
            # Main container
            main_container = tk.Frame(self.root)
            main_container.pack(fill=tk.BOTH, expand=True)
            
            # Header
            header = tk.Frame(main_container, height=60)
            header.pack(fill=tk.X, padx=10, pady=5)
            
            tk.Label(header, text="Telegram TData Decryptor", 
                    font=('Arial', 18, 'bold')).pack(side=tk.LEFT, padx=10)
            
            self.theme_btn = tk.Button(header, text="🌙 Dark Mode", 
                                      command=self.toggle_theme,
                                      font=('Arial', 10))
            self.theme_btn.pack(side=tk.RIGHT, padx=10)
            
            # Input section
            input_frame = tk.LabelFrame(main_container, text="Input", 
                                       font=('Arial', 11, 'bold'))
            input_frame.pack(fill=tk.X, padx=10, pady=5)
            
            # Path row
            path_row = tk.Frame(input_frame)
            path_row.pack(fill=tk.X, padx=10, pady=5)
            
            tk.Label(path_row, text="TData Path:", width=12).pack(side=tk.LEFT)
            self.path_var = tk.StringVar()
            self.path_entry = tk.Entry(path_row, textvariable=self.path_var, width=50)
            self.path_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
            
            tk.Button(path_row, text="Browse", command=self.browse_folder,
                     width=10).pack(side=tk.LEFT, padx=2)
            
            tk.Button(path_row, text="Auto Search", command=self.auto_search,
                     width=12).pack(side=tk.LEFT, padx=2)
            
            # Password row
            pass_row = tk.Frame(input_frame)
            pass_row.pack(fill=tk.X, padx=10, pady=5)
            
            tk.Label(pass_row, text="Password:", width=12).pack(side=tk.LEFT)
            self.password_var = tk.StringVar()
            tk.Entry(pass_row, textvariable=self.password_var, show="*", 
                    width=30).pack(side=tk.LEFT, padx=5)
            
            tk.Label(pass_row, text="(Leave empty if none)", 
                    fg='gray').pack(side=tk.LEFT, padx=10)
            
            # Action buttons
            action_frame = tk.Frame(input_frame)
            action_frame.pack(fill=tk.X, padx=10, pady=10)
            
            self.decrypt_btn = tk.Button(action_frame, text="🔓 DECRYPT", 
                                        command=self.decrypt,
                                        font=('Arial', 12, 'bold'),
                                        bg='#4CAF50', fg='white',
                                        width=20, height=2)
            self.decrypt_btn.pack(side=tk.LEFT, padx=5)
            
            tk.Button(action_frame, text="Clear", command=self.clear_output,
                     width=10).pack(side=tk.LEFT, padx=5)
            
            tk.Button(action_frame, text="Export", command=self.export_results,
                     width=10).pack(side=tk.LEFT, padx=5)
            
            # Progress
            self.progress_var = tk.IntVar()
            self.progress = ttk.Progressbar(input_frame, variable=self.progress_var,
                                           mode='determinate', length=200)
            self.progress.pack(fill=tk.X, padx=10, pady=5)
            
            # Status label
            self.status_var = tk.StringVar(value="Ready")
            self.status_label = tk.Label(input_frame, textvariable=self.status_var,
                                        anchor=tk.W)
            self.status_label.pack(fill=tk.X, padx=10, pady=2)
            
            # Output section
            output_frame = tk.LabelFrame(main_container, text="Output", 
                                        font=('Arial', 11, 'bold'))
            output_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
            
            # Text output with scrollbar
            text_frame = tk.Frame(output_frame)
            text_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
            
            scrollbar = tk.Scrollbar(text_frame)
            scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
            
            self.output_text = tk.Text(text_frame, wrap=tk.WORD,
                                      yscrollcommand=scrollbar.set,
                                      font=('Consolas', 10))
            self.output_text.pack(fill=tk.BOTH, expand=True)
            scrollbar.config(command=self.output_text.yview)
            
            # Configure text tags
            self.output_text.tag_configure("header", font=('Consolas', 11, 'bold'))
            self.output_text.tag_configure("success", foreground='#4CAF50')
            self.output_text.tag_configure("error", foreground='#F44336')
            self.output_text.tag_configure("warning", foreground='#FF9800')
            self.output_text.tag_configure("info", foreground='#2196F3')
            
            # Set default path
            self.set_default_path()
        
        def apply_theme(self):
            """Apply dark/light theme"""
            if self.dark_mode.get():
                bg = '#1e1e1e'
                fg = '#ffffff'
                entry_bg = '#2d2d2d'
                text_bg = '#252525'
            else:
                bg = '#f0f0f0'
                fg = '#000000'
                entry_bg = '#ffffff'
                text_bg = '#ffffff'
            
            self.root.configure(bg=bg)
            
            # Update widgets
            for widget in [self.path_entry, self.output_text]:
                try:
                    widget.configure(bg=text_bg, fg=fg)
                except:
                    pass
            
            # Update theme button
            if self.dark_mode.get():
                self.theme_btn.config(text="☀️ Light Mode")
            else:
                self.theme_btn.config(text="🌙 Dark Mode")
        
        def toggle_theme(self):
            """Toggle theme"""
            self.dark_mode.set(not self.dark_mode.get())
            self.apply_theme()
        
        def set_default_path(self):
            """Set default tdata path"""
            if platform.system() == 'Windows':
                paths = [
                    os.path.expandvars(r'%APPDATA%\Telegram Desktop\tdata'),
                    os.path.expandvars(r'%LOCALAPPDATA%\Telegram Desktop\tdata'),
                ]
            elif platform.system() == 'Linux':
                paths = [
                    os.path.expanduser('~/.local/share/TelegramDesktop/tdata'),
                ]
            else:
                paths = [
                    os.path.expanduser('~/Library/Application Support/Telegram Desktop/tdata'),
                ]
            
            for path in paths:
                if os.path.exists(path):
                    self.path_var.set(path)
                    break
        
        def browse_folder(self):
            """Browse for folder"""
            folder = filedialog.askdirectory(title="Select TData Folder")
            if folder:
                self.path_var.set(folder)
        
        def status_callback(self, message: str, progress: int = None):
            """Callback for status updates"""
            self.status_var.set(message)
            if progress is not None:
                self.progress_var.set(progress)
            self.log(message, "info")
            self.root.update()
        
        def log(self, message: str, tag: str = None):
            """Log message to output"""
            timestamp = datetime.now().strftime("%H:%M:%S")
            self.output_text.insert(tk.END, f"[{timestamp}] ", "info")
            self.output_text.insert(tk.END, f"{message}\n", tag)
            self.output_text.see(tk.END)
        
        def clear_output(self):
            """Clear output text"""
            self.output_text.delete(1.0, tk.END)
            self.progress_var.set(0)
            self.status_var.set("Ready")
        
        def auto_search(self):
            """Auto search for tdata folders"""
            if self.search_running:
                return
            
            self.search_running = True
            self.log("Starting automatic search for tdata folders...", "info")
            
            def search_thread():
                try:
                    # Determine search paths
                    if platform.system() == 'Windows':
                        search_paths = [
                            os.path.expandvars(r'%USERPROFILE%'),
                            os.path.expandvars(r'%APPDATA%'),
                        ]
                    else:
                        search_paths = [os.path.expanduser('~')]
                    
                    found_folders = []
                    for base_path in search_paths:
                        if os.path.exists(base_path):
                            folders = self.decryptor.find_tdata_folders(base_path, max_depth=3)
                            found_folders.extend(folders)
                    
                    if found_folders:
                        self.log(f"\nFound {len(found_folders)} tdata folder(s):", "success")
                        for folder in found_folders:
                            self.log(f"  📁 {folder}", "info")
                        
                        self.path_var.set(found_folders[0])
                    else:
                        self.log("No tdata folders found", "warning")
                        
                except Exception as e:
                    self.log(f"Search error: {str(e)}", "error")
                finally:
                    self.search_running = False
            
            thread = threading.Thread(target=search_thread, daemon=True)
            thread.start()
        
        def decrypt(self):
            """Decrypt tdata folder"""
            if self.decryption_running:
                return
            
            path = self.path_var.get().strip()
            if not path:
                messagebox.showwarning("Warning", "Please select a tdata folder")
                return
            
            if not os.path.exists(path):
                messagebox.showerror("Error", f"Path does not exist: {path}")
                return
            
            self.decryption_running = True
            self.decrypt_btn.config(state=tk.DISABLED)
            
            def decrypt_thread():
                try:
                    self.log("\n" + "="*60, "header")
                    self.log("Starting Decryption Process", "header")
                    self.log("="*60 + "\n", "header")
                    
                    password = self.password_var.get()
                    
                    # Perform decryption
                    success = self.decryptor.decrypt_tdata_folder(path, password)
                    
                    if success:
                        self.log("\n✅ Decryption Successful!\n", "success")
                        
                        # Display summary
                        summary = self.decryptor.get_summary()
                        for line in summary.split('\n'):
                            if 'Error' in line:
                                tag = "error"
                            elif 'Warning' in line:
                                tag = "warning"
                            elif line.startswith('='):
                                tag = "header"
                            else:
                                tag = "info"
                            self.log(line, tag)
                        
                        # Auto-export
                        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                        output_file = os.path.join(
                            os.path.dirname(path),
                            f"telegram_decrypted_{timestamp}.json"
                        )
                        
                        if self.decryptor.export_results(output_file):
                            self.log(f"\n📁 Results saved to: {output_file}", "success")
                    else:
                        self.log("\n❌ Decryption Failed!", "error")
                        
                        if not password:
                            self.log("Try entering a password if data is protected", "warning")
                        
                except Exception as e:
                    self.log(f"\nError: {str(e)}", "error")
                    self.log(traceback.format_exc(), "error")
                finally:
                    self.decryption_running = False
                    self.decrypt_btn.config(state=tk.NORMAL)
                    self.progress_var.set(0)
            
            thread = threading.Thread(target=decrypt_thread, daemon=True)
            thread.start()
        
        def export_results(self):
            """Export results to file"""
            if not self.decryptor.accounts and not self.decryptor.settings:
                messagebox.showwarning("Warning", "No data to export")
                return
            
            file_path = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
            )
            
            if file_path:
                if self.decryptor.export_results(file_path):
                    self.log(f"Exported to: {file_path}", "success")
                    messagebox.showinfo("Success", f"Results exported to:\n{file_path}")
                else:
                    messagebox.showerror("Error", "Failed to export results")
        
        def run(self):
            """Start the GUI"""
            self.root.mainloop()


# Main execution
def main():
    """Main entry point"""
    if GUI_AVAILABLE:
        try:
            app = EnhancedTelegramGUI()
            app.run()
        except Exception as e:
            print(f"GUI Error: {e}")
            print("Falling back to command line mode...")
    else:
        print("GUI not available. Using command line mode.")
    
    # Command line fallback
    if not GUI_AVAILABLE or True:  # Always show CLI option
        print("\nCommand Line Mode")
        print("-" * 40)
        
        decryptor = EnhancedTDataDecryptor()
        
        # Get path
        path = input("Enter tdata path (or press Enter for auto-search): ").strip()
        
        if not path:
            print("Searching...")
            if platform.system() == 'Windows':
                base = os.path.expandvars(r'%USERPROFILE%')
            else:
                base = os.path.expanduser('~')
            
            folders = decryptor.find_tdata_folders(base, max_depth=3)
            
            if folders:
                print(f"\nFound {len(folders)} folder(s):")
                for i, folder in enumerate(folders, 1):
                    print(f"{i}. {folder}")
                
                choice = input("\nSelect folder number (default=1): ").strip()
                idx = int(choice) - 1 if choice.isdigit() else 0
                
                if 0 <= idx < len(folders):
                    path = folders[idx]
            else:
                print("No folders found")
                return
        
        # Get password
        password = input("Enter password (or press Enter if none): ").strip()
        
        # Decrypt
        print("\nDecrypting...")
        
        def status_callback(msg, progress):
            if progress:
                print(f"[{progress}%] {msg}")
            else:
                print(f"[*] {msg}")
        
        decryptor.status_callback = status_callback
        
        if decryptor.decrypt_tdata_folder(path, password):
            print("\n✅ Success!")
            print(decryptor.get_summary())
            
            # Export option
            export = input("\nExport to JSON? (y/n): ").lower()
            if export == 'y':
                output = f"telegram_decrypted_{int(time.time())}.json"
                if decryptor.export_results(output):
                    print(f"Exported to: {output}")
        else:
            print("\n❌ Failed!")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nCancelled by user")
    except Exception as e:
        print(f"\nError: {e}")
        traceback.print_exc()
