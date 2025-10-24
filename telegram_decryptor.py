#!/usr/bin/env python3
"""
Telegram Desktop TData Decryptor
Enhanced tool with GUI, dark mode, and automatic tdata folder search
"""

import os
import sys
import glob
import struct
import hashlib
import binascii
import json
import base64
import threading
from pathlib import Path
from typing import List, Optional, Tuple, Dict
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from datetime import datetime

# Crypto imports
try:
    from Crypto.Cipher import AES
    from Crypto.Protocol.KDF import PBKDF2
    from Crypto.Util.Padding import unpad
except ImportError:
    print("Installing required cryptography libraries...")
    os.system(f"{sys.executable} -m pip install pycryptodome")
    from Crypto.Cipher import AES
    from Crypto.Protocol.KDF import PBKDF2
    from Crypto.Util.Padding import unpad


class TDataDecryptor:
    """Core decryption functionality for Telegram Desktop tdata files"""
    
    # Constants from Telegram Desktop
    LOCAL_ENCRYPT_ITER_COUNT = 4000
    LOCAL_ENCRYPT_NO_PWD_ITER_COUNT = 4
    STRONG_ITERATIONS_COUNT = 100000
    LOCAL_ENCRYPT_SALT_SIZE = 32
    LOCAL_ENCRYPT_KEY_SIZE = 256
    
    def __init__(self):
        self.accounts = []
        self.settings = {}
        
    @staticmethod
    def md5(data):
        """Calculate MD5 hash"""
        return hashlib.md5(data).digest()
    
    @staticmethod
    def sha1(data):
        """Calculate SHA1 hash"""
        return hashlib.sha1(data).digest()
    
    @staticmethod
    def sha256(data):
        """Calculate SHA256 hash"""
        return hashlib.sha256(data).digest()
    
    @staticmethod
    def xor_bytes(a: bytes, b: bytes) -> bytes:
        """XOR two byte arrays"""
        return bytes(x ^ y for x, y in zip(a, b))
    
    def prepare_aes_oldmtp(self, auth_key: bytes, msg_key: bytes, send: bool = True) -> Tuple[bytes, bytes]:
        """Prepare AES key and IV for old MTP protocol"""
        x = 0 if send else 8
        
        sha1_a = self.sha1(msg_key + auth_key[x:x+32])
        sha1_b = self.sha1(auth_key[x+32:x+48] + msg_key + auth_key[x+48:x+64])
        sha1_c = self.sha1(auth_key[x+64:x+96] + msg_key)
        sha1_d = self.sha1(msg_key + auth_key[x+96:x+128])
        
        aes_key = sha1_a[:8] + sha1_b[8:20] + sha1_c[4:16]
        aes_iv = sha1_a[8:20] + sha1_b[:8] + sha1_c[16:20] + sha1_d[:8]
        
        return aes_key, aes_iv
    
    def decrypt_local(self, encrypted: bytes, key: bytes, msg_key: bytes) -> Optional[bytes]:
        """Decrypt local data using the provided key"""
        try:
            aes_key, aes_iv = self.prepare_aes_oldmtp(key, msg_key, False)
            cipher = AES.new(aes_key, AES.MODE_CBC, aes_iv)
            decrypted = cipher.decrypt(encrypted)
            
            # Verify SHA1
            data_len = len(decrypted) - 16
            if data_len < 0:
                return None
                
            data = decrypted[:data_len]
            sha1_data = decrypted[data_len:data_len + 16]
            
            if self.sha1(data)[:16] == sha1_data:
                # Remove padding
                padding_len = data[0] if len(data) > 0 else 0
                if padding_len <= len(data):
                    return data[padding_len:]
                    
        except Exception as e:
            pass
        return None
    
    def create_local_key(self, password: str, salt: bytes) -> bytes:
        """Create local key from password and salt"""
        if not password:
            # No password case
            iterations = self.LOCAL_ENCRYPT_NO_PWD_ITER_COUNT
        else:
            iterations = self.LOCAL_ENCRYPT_ITER_COUNT
            
        password_bytes = password.encode('utf-8') if password else b''
        return PBKDF2(password_bytes, salt, dkLen=self.LOCAL_ENCRYPT_KEY_SIZE, count=iterations, hmac_hash_module=hashlib.sha512)
    
    def decrypt_key_data(self, key_file: str, passcode: str = '') -> Optional[bytes]:
        """Decrypt key_datas file"""
        try:
            with open(key_file, 'rb') as f:
                data = f.read()
                
            if len(data) < 16 + self.LOCAL_ENCRYPT_SALT_SIZE:
                return None
                
            # Extract salt and encrypted data
            salt = data[:self.LOCAL_ENCRYPT_SALT_SIZE]
            msg_key = data[self.LOCAL_ENCRYPT_SALT_SIZE:self.LOCAL_ENCRYPT_SALT_SIZE + 16]
            encrypted = data[self.LOCAL_ENCRYPT_SALT_SIZE + 16:]
            
            # Generate key
            key = self.create_local_key(passcode, salt)
            
            # Decrypt
            return self.decrypt_local(encrypted, key, msg_key)
            
        except Exception as e:
            return None
    
    def parse_settings(self, data: bytes) -> Dict:
        """Parse decrypted settings data"""
        settings = {}
        try:
            # Basic parsing - extend as needed
            if len(data) > 4:
                version = struct.unpack('<I', data[:4])[0]
                settings['version'] = version
                
            # Parse more fields as needed
            # This is simplified - actual parsing is more complex
            
        except Exception:
            pass
        return settings
    
    def parse_account(self, data: bytes, index: int) -> Dict:
        """Parse account data"""
        account = {'index': index}
        try:
            if len(data) > 8:
                # Parse user ID (simplified)
                user_id = struct.unpack('<Q', data[:8])[0]
                account['user_id'] = user_id
                
            # Parse more fields as needed
            
        except Exception:
            pass
        return account
    
    def find_tdata_folders(self, base_path: str, max_depth: int = 5) -> List[str]:
        """Recursively search for tdata folders"""
        tdata_folders = []
        
        def search_recursive(path: str, depth: int):
            if depth > max_depth:
                return
                
            try:
                for entry in os.scandir(path):
                    if entry.is_dir():
                        # Check if this is a tdata folder
                        if 'tdata' in entry.name.lower():
                            tdata_folders.append(entry.path)
                        # Check for key files or map files
                        elif any(os.path.exists(os.path.join(entry.path, f)) 
                                for f in ['key_datas', 'map0', 'map1', 'maps']):
                            tdata_folders.append(entry.path)
                        # Continue searching
                        search_recursive(entry.path, depth + 1)
            except (PermissionError, OSError):
                pass
                
        search_recursive(base_path, 0)
        return tdata_folders
    
    def decrypt_tdata(self, tdata_path: str, passcode: str = '') -> bool:
        """Decrypt a tdata folder"""
        self.accounts = []
        self.settings = {}
        
        # Look for key files
        key_files = []
        for pattern in ['key_datas', 'key_data*', 'maps', 'map0', 'map1']:
            key_files.extend(glob.glob(os.path.join(tdata_path, pattern)))
            # Also check subfolders
            key_files.extend(glob.glob(os.path.join(tdata_path, '*', pattern)))
        
        if not key_files:
            return False
            
        success = False
        for key_file in key_files:
            decrypted = self.decrypt_key_data(key_file, passcode)
            if decrypted:
                # Parse based on file type
                if 'key_data' in os.path.basename(key_file):
                    # Account data
                    account = self.parse_account(decrypted, len(self.accounts))
                    self.accounts.append(account)
                    success = True
                elif 'map' in os.path.basename(key_file):
                    # Settings or cache
                    settings = self.parse_settings(decrypted)
                    self.settings.update(settings)
                    success = True
                    
        return success


class TelegramDecryptorGUI:
    """Enhanced GUI for Telegram Desktop data decryption"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Telegram Desktop Data Decryptor v2.0")
        self.root.geometry("900x650")
        
        # Initialize decryptor
        self.decryptor = TDataDecryptor()
        
        # Theme variables
        self.dark_mode = tk.BooleanVar(value=True)
        self.colors = {}
        self.update_theme()
        
        # Status variables
        self.current_status = tk.StringVar(value="Ready")
        self.search_running = False
        
        # Setup GUI
        self.setup_styles()
        self.create_widgets()
        self.apply_theme()
        
        # Center window
        self.center_window()
        
    def center_window(self):
        """Center the window on screen"""
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')
    
    def update_theme(self):
        """Update color scheme based on theme mode"""
        if self.dark_mode.get():
            self.colors = {
                'bg': '#1e1e1e',
                'fg': '#ffffff',
                'button_bg': '#0d7377',
                'button_fg': '#ffffff',
                'button_hover': '#14a1a5',
                'entry_bg': '#2d2d2d',
                'entry_fg': '#ffffff',
                'text_bg': '#252525',
                'text_fg': '#ffffff',
                'select_bg': '#0d7377',
                'status_bg': '#2d2d2d',
                'frame_bg': '#1e1e1e',
                'label_fg': '#cccccc',
                'success': '#4caf50',
                'warning': '#ff9800',
                'error': '#f44336'
            }
        else:
            self.colors = {
                'bg': '#f0f0f0',
                'fg': '#000000',
                'button_bg': '#2196f3',
                'button_fg': '#ffffff',
                'button_hover': '#42a5f5',
                'entry_bg': '#ffffff',
                'entry_fg': '#000000',
                'text_bg': '#ffffff',
                'text_fg': '#000000',
                'select_bg': '#2196f3',
                'status_bg': '#e0e0e0',
                'frame_bg': '#f0f0f0',
                'label_fg': '#333333',
                'success': '#4caf50',
                'warning': '#ff9800',
                'error': '#f44336'
            }
    
    def setup_styles(self):
        """Setup ttk styles"""
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
    def apply_theme(self):
        """Apply theme to all widgets"""
        self.update_theme()
        
        # Configure root
        self.root.configure(bg=self.colors['bg'])
        
        # Configure styles
        self.style.configure('Title.TLabel', 
                           background=self.colors['bg'],
                           foreground=self.colors['fg'],
                           font=('Arial', 16, 'bold'))
        
        self.style.configure('Status.TLabel',
                           background=self.colors['status_bg'],
                           foreground=self.colors['fg'],
                           font=('Consolas', 10))
        
        # Configure frames
        for frame in [self.header_frame, self.control_frame, self.output_frame, self.status_frame]:
            frame.configure(bg=self.colors['frame_bg'])
        
        # Configure text widget
        self.output_text.configure(
            bg=self.colors['text_bg'],
            fg=self.colors['text_fg'],
            insertbackground=self.colors['fg']
        )
        
        # Configure entries
        for entry in [self.path_entry, self.password_entry]:
            entry.configure(
                bg=self.colors['entry_bg'],
                fg=self.colors['entry_fg'],
                insertbackground=self.colors['fg']
            )
        
        # Configure buttons
        for button in [self.browse_button, self.search_button, self.decrypt_button, self.clear_button]:
            button.configure(
                bg=self.colors['button_bg'],
                fg=self.colors['button_fg'],
                activebackground=self.colors['button_hover'],
                activeforeground=self.colors['button_fg']
            )
        
        # Configure labels
        for label in [self.path_label, self.password_label]:
            label.configure(bg=self.colors['frame_bg'], fg=self.colors['label_fg'])
    
    def create_widgets(self):
        """Create all GUI widgets"""
        # Header Frame
        self.header_frame = tk.Frame(self.root)
        self.header_frame.pack(fill=tk.X, padx=10, pady=5)
        
        title = ttk.Label(self.header_frame, text="Telegram Desktop Data Decryptor", 
                         style='Title.TLabel')
        title.pack(side=tk.LEFT, padx=5)
        
        # Theme toggle
        self.theme_button = tk.Button(self.header_frame, text="☀️ Light",
                                     command=self.toggle_theme,
                                     font=('Arial', 10))
        self.theme_button.pack(side=tk.RIGHT, padx=5)
        self.update_theme_button()
        
        # Control Frame
        self.control_frame = tk.Frame(self.root)
        self.control_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Path selection
        path_frame = tk.Frame(self.control_frame)
        path_frame.pack(fill=tk.X, pady=5)
        
        self.path_label = tk.Label(path_frame, text="TData Path:", width=12, anchor=tk.W)
        self.path_label.pack(side=tk.LEFT, padx=5)
        
        self.path_entry = tk.Entry(path_frame, width=50)
        self.path_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        
        self.browse_button = tk.Button(path_frame, text="Browse", command=self.browse_folder,
                                      width=10, cursor="hand2")
        self.browse_button.pack(side=tk.LEFT, padx=5)
        
        self.search_button = tk.Button(path_frame, text="Auto Search", command=self.auto_search,
                                      width=12, cursor="hand2")
        self.search_button.pack(side=tk.LEFT, padx=5)
        
        # Password entry
        password_frame = tk.Frame(self.control_frame)
        password_frame.pack(fill=tk.X, pady=5)
        
        self.password_label = tk.Label(password_frame, text="Password:", width=12, anchor=tk.W)
        self.password_label.pack(side=tk.LEFT, padx=5)
        
        self.password_entry = tk.Entry(password_frame, show="*", width=30)
        self.password_entry.pack(side=tk.LEFT, padx=5)
        
        tk.Label(password_frame, text="(Leave empty if no password)", 
                fg='gray').pack(side=tk.LEFT, padx=5)
        
        # Action buttons
        button_frame = tk.Frame(self.control_frame)
        button_frame.pack(fill=tk.X, pady=10)
        
        self.decrypt_button = tk.Button(button_frame, text="🔓 Decrypt", 
                                       command=self.decrypt_data,
                                       font=('Arial', 11, 'bold'),
                                       width=15, height=2,
                                       cursor="hand2")
        self.decrypt_button.pack(side=tk.LEFT, padx=5)
        
        self.clear_button = tk.Button(button_frame, text="Clear Output",
                                     command=self.clear_output,
                                     width=12, cursor="hand2")
        self.clear_button.pack(side=tk.LEFT, padx=5)
        
        # Progress bar
        self.progress = ttk.Progressbar(self.control_frame, mode='indeterminate')
        self.progress.pack(fill=tk.X, padx=5, pady=5)
        
        # Output Frame
        self.output_frame = tk.Frame(self.root)
        self.output_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        output_label = tk.Label(self.output_frame, text="Output:", 
                              font=('Arial', 10, 'bold'))
        output_label.pack(anchor=tk.W)
        
        # Output text with scrollbar
        text_frame = tk.Frame(self.output_frame)
        text_frame.pack(fill=tk.BOTH, expand=True)
        
        scrollbar = tk.Scrollbar(text_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.output_text = tk.Text(text_frame, wrap=tk.WORD, 
                                  yscrollcommand=scrollbar.set,
                                  font=('Consolas', 10))
        self.output_text.pack(fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.output_text.yview)
        
        # Configure text tags for colored output
        self.output_text.tag_configure("success", foreground=self.colors['success'])
        self.output_text.tag_configure("warning", foreground=self.colors['warning'])
        self.output_text.tag_configure("error", foreground=self.colors['error'])
        self.output_text.tag_configure("info", foreground="#2196f3")
        self.output_text.tag_configure("header", font=('Consolas', 11, 'bold'))
        
        # Status Frame
        self.status_frame = tk.Frame(self.root)
        self.status_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.status_label = ttk.Label(self.status_frame, 
                                     textvariable=self.current_status,
                                     style='Status.TLabel')
        self.status_label.pack(side=tk.LEFT, padx=5)
        
        # Set default path
        self.set_default_path()
    
    def set_default_path(self):
        """Set default Telegram Desktop path based on OS"""
        default_paths = []
        
        if sys.platform == 'win32':
            default_paths = [
                os.path.expandvars(r'%APPDATA%\Telegram Desktop\tdata'),
                os.path.expandvars(r'%LOCALAPPDATA%\Telegram Desktop\tdata'),
            ]
        elif sys.platform == 'linux':
            default_paths = [
                os.path.expanduser('~/.local/share/TelegramDesktop/tdata'),
                os.path.expanduser('~/.var/app/org.telegram.desktop/data/TelegramDesktop/tdata'),
            ]
        elif sys.platform == 'darwin':
            default_paths = [
                os.path.expanduser('~/Library/Application Support/Telegram Desktop/tdata'),
            ]
        
        for path in default_paths:
            if os.path.exists(path):
                self.path_entry.insert(0, path)
                break
    
    def toggle_theme(self):
        """Toggle between dark and light theme"""
        self.dark_mode.set(not self.dark_mode.get())
        self.apply_theme()
        self.update_theme_button()
    
    def update_theme_button(self):
        """Update theme button text"""
        if self.dark_mode.get():
            self.theme_button.config(text="☀️ Light")
        else:
            self.theme_button.config(text="🌙 Dark")
    
    def browse_folder(self):
        """Browse for tdata folder"""
        folder = filedialog.askdirectory(title="Select TData Folder")
        if folder:
            self.path_entry.delete(0, tk.END)
            self.path_entry.insert(0, folder)
    
    def update_status(self, message: str, type: str = "info"):
        """Update status message"""
        self.current_status.set(message)
        self.log_message(message, type)
    
    def log_message(self, message: str, type: str = "info"):
        """Log message to output text"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.output_text.insert(tk.END, f"[{timestamp}] ", "info")
        self.output_text.insert(tk.END, f"{message}\n", type)
        self.output_text.see(tk.END)
        self.root.update()
    
    def clear_output(self):
        """Clear output text"""
        self.output_text.delete(1.0, tk.END)
    
    def auto_search(self):
        """Automatically search for tdata folders"""
        if self.search_running:
            self.log_message("Search already in progress...", "warning")
            return
        
        self.search_running = True
        self.progress.start()
        self.search_button.config(state=tk.DISABLED)
        
        def search_thread():
            try:
                self.update_status("Searching for TData folders...")
                
                # Determine search paths based on OS
                search_paths = []
                if sys.platform == 'win32':
                    search_paths = [
                        os.path.expandvars(r'%USERPROFILE%'),
                        os.path.expandvars(r'%APPDATA%'),
                        os.path.expandvars(r'%LOCALAPPDATA%'),
                    ]
                else:
                    search_paths = [
                        os.path.expanduser('~'),
                        os.path.expanduser('~/.local/share'),
                        os.path.expanduser('~/.var/app'),
                    ]
                
                found_folders = []
                for base_path in search_paths:
                    if os.path.exists(base_path):
                        self.update_status(f"Searching in {base_path}...")
                        folders = self.decryptor.find_tdata_folders(base_path, max_depth=4)
                        found_folders.extend(folders)
                
                # Remove duplicates
                found_folders = list(set(found_folders))
                
                if found_folders:
                    self.log_message(f"\n{'='*50}", "header")
                    self.log_message("Found TData Folders:", "header")
                    self.log_message(f"{'='*50}\n", "header")
                    
                    for i, folder in enumerate(found_folders, 1):
                        self.log_message(f"{i}. {folder}", "success")
                    
                    # Use the first found folder
                    self.path_entry.delete(0, tk.END)
                    self.path_entry.insert(0, found_folders[0])
                    
                    self.update_status(f"Found {len(found_folders)} folder(s)", "success")
                else:
                    self.update_status("No TData folders found", "warning")
                    self.log_message("\nNo TData folders found. Please browse manually.", "warning")
                    
            except Exception as e:
                self.update_status(f"Search error: {str(e)}", "error")
            finally:
                self.search_running = False
                self.progress.stop()
                self.search_button.config(state=tk.NORMAL)
        
        thread = threading.Thread(target=search_thread, daemon=True)
        thread.start()
    
    def decrypt_data(self):
        """Decrypt the selected tdata folder"""
        tdata_path = self.path_entry.get().strip()
        if not tdata_path:
            messagebox.showwarning("Warning", "Please select a TData folder first!")
            return
        
        if not os.path.exists(tdata_path):
            messagebox.showerror("Error", f"Path does not exist: {tdata_path}")
            return
        
        self.progress.start()
        self.decrypt_button.config(state=tk.DISABLED)
        
        def decrypt_thread():
            try:
                self.log_message(f"\n{'='*50}", "header")
                self.log_message("Starting Decryption Process", "header")
                self.log_message(f"{'='*50}\n", "header")
                
                self.update_status("Decrypting TData folder...")
                
                password = self.password_entry.get()
                
                # Perform decryption
                success = self.decryptor.decrypt_tdata(tdata_path, password)
                
                if success:
                    self.log_message("\n✅ Decryption successful!\n", "success")
                    
                    # Display accounts
                    if self.decryptor.accounts:
                        self.log_message(f"Found {len(self.decryptor.accounts)} account(s):\n", "info")
                        for account in self.decryptor.accounts:
                            self.log_message(f"  Account {account.get('index', 0)}:", "header")
                            if 'user_id' in account:
                                self.log_message(f"    User ID: {account['user_id']}", "info")
                            self.log_message("", "info")
                    
                    # Display settings
                    if self.decryptor.settings:
                        self.log_message("Settings:", "header")
                        for key, value in self.decryptor.settings.items():
                            self.log_message(f"  {key}: {value}", "info")
                    
                    # Save results
                    self.save_results()
                    
                    self.update_status("Decryption completed successfully", "success")
                else:
                    self.log_message("\n❌ Decryption failed!", "error")
                    self.log_message("Possible reasons:", "warning")
                    self.log_message("  • Incorrect password", "warning")
                    self.log_message("  • Corrupted tdata files", "warning")
                    self.log_message("  • Incompatible Telegram version", "warning")
                    
                    if not password:
                        self.log_message("\nTry entering a password if the data is protected", "info")
                    
                    self.update_status("Decryption failed", "error")
                    
            except Exception as e:
                self.log_message(f"\n❌ Error: {str(e)}", "error")
                self.update_status(f"Error: {str(e)}", "error")
            finally:
                self.progress.stop()
                self.decrypt_button.config(state=tk.NORMAL)
        
        thread = threading.Thread(target=decrypt_thread, daemon=True)
        thread.start()
    
    def save_results(self):
        """Save decryption results to file"""
        try:
            output_dir = os.path.dirname(self.path_entry.get())
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = os.path.join(output_dir, f"telegram_decrypted_{timestamp}.json")
            
            results = {
                'timestamp': timestamp,
                'accounts': self.decryptor.accounts,
                'settings': self.decryptor.settings
            }
            
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
            
            self.log_message(f"\n📁 Results saved to: {output_file}", "success")
            
        except Exception as e:
            self.log_message(f"Failed to save results: {str(e)}", "warning")
    
    def run(self):
        """Start the GUI application"""
        self.root.mainloop()


def main():
    """Main entry point"""
    try:
        app = TelegramDecryptorGUI()
        app.run()
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
