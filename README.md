# Telegram Desktop TData Decryptor v2.0

A powerful and user-friendly tool for decrypting Telegram Desktop's tdata folder with an enhanced GUI, dark mode support, and automatic folder search capabilities.

## 🌟 Features

- **🎨 Modern GUI** with dark/light theme toggle
- **🔍 Auto-Search**: Automatically finds tdata folders on your system
- **🔓 Full Decryption**: Supports all tdata file types (key_datas, maps, cache)
- **🔐 Password Support**: Handles password-protected data
- **📊 Real-time Progress**: Visual indicators showing decryption progress
- **💾 Export Options**: Save results as JSON for further analysis
- **🖥️ Cross-Platform**: Works on Windows, Linux, and macOS
- **🚀 No External Tools Required**: Built-in decryption implementation

## 📋 Requirements

- Python 3.7 or higher
- PyCryptodome library (automatically installed)
- Tkinter (usually included with Python)

## 🚀 Quick Start

### Method 1: Using the Launcher (Recommended)

Simply run the launcher script:

```bash
python launcher.py
```

The launcher will:
- Automatically install required dependencies
- Start the GUI application
- Provide fallback to command-line mode if GUI fails

### Method 2: Direct GUI Launch

```bash
python telegram_decryptor.py
```

### Method 3: Command Line Usage

```python
from tdata_crypto import FullTDataDecryptor

decryptor = FullTDataDecryptor()
success = decryptor.decrypt_tdata_folder('/path/to/tdata', 'optional_password')

if success:
    for account in decryptor.accounts:
        print(f"User ID: {account.user_id}")
```

## 📁 File Structure

- `telegram_decryptor.py` - Main GUI application
- `tdata_crypto.py` - Core decryption module
- `launcher.py` - Easy launcher with auto-setup
- `requirements.txt` - Python dependencies

## 🎮 GUI Usage Guide

### Main Window Components

1. **Theme Toggle**: Switch between dark and light modes
2. **Path Selection**: 
   - Enter tdata path manually
   - Use "Browse" to select folder
   - Click "Auto Search" to find folders automatically
3. **Password Field**: Enter password if data is protected
4. **Decrypt Button**: Start the decryption process
5. **Output Area**: View real-time progress and results

### Step-by-Step Instructions

1. **Launch the Application**
   ```bash
   python launcher.py
   ```

2. **Find Your TData Folder**
   - Click "Auto Search" to automatically find tdata folders
   - Or manually browse to your tdata location:
     - Windows: `%APPDATA%\Telegram Desktop\tdata`
     - Linux: `~/.local/share/TelegramDesktop/tdata`
     - macOS: `~/Library/Application Support/Telegram Desktop/tdata`

3. **Enter Password** (if applicable)
   - Leave empty if no local passcode was set
   - Enter your Telegram Desktop passcode if one was configured

4. **Click Decrypt**
   - Watch the progress bar and status updates
   - Results will appear in the output area

5. **View Results**
   - Account information (User ID, DC info)
   - Settings data
   - Results are automatically saved to a JSON file

## 🔍 Auto-Search Feature

The tool searches for tdata folders in common locations:

### Windows
- `%APPDATA%\Telegram Desktop\tdata`
- `%LOCALAPPDATA%\Telegram Desktop\tdata`
- User profile subdirectories

### Linux
- `~/.local/share/TelegramDesktop/tdata`
- `~/.var/app/org.telegram.desktop/data/TelegramDesktop/tdata`
- Snap and Flatpak locations

### macOS
- `~/Library/Application Support/Telegram Desktop/tdata`

## 📊 Output Format

The tool exports decryption results in JSON format:

```json
{
  "timestamp": "20240124_143022",
  "accounts": [
    {
      "index": 0,
      "user_id": 123456789,
      "main_dc_id": 2,
      "auth_keys": {
        "1": "hex_encoded_key...",
        "2": "hex_encoded_key..."
      }
    }
  ],
  "settings": {
    "version": 1,
    "auto_start": 0,
    "start_minimized": 0
  }
}
```

## 🛠️ Advanced Features

### Cache Decryption

The tool can decrypt cached media files:

```python
from tdata_crypto import FullTDataDecryptor

decryptor = FullTDataDecryptor()
decryptor.decrypt_tdata_folder('/path/to/tdata', 'password')
extracted_files = decryptor.decrypt_cache('/path/to/tdata', '/output/dir')
```

### Session Export

Export session data for use with other Telegram tools:

```python
decryptor.export_session('session.json')
```

## ⚙️ Supported File Types

- **key_datas**: Main account authentication data
- **map0/map1/maps**: Settings and configuration
- **cache**: Encrypted media cache
- **D877F783D5D3EF8C**: Legacy data folder (md5 of "data")
- **A7FDF864FBC10B77**: Secondary account folder (md5 of "data#2")

## 🔐 Security Notes

- The tool only works with local tdata files
- Requires proper authorization (password if set)
- Does not connect to Telegram servers
- All operations are performed locally
- Decrypted data should be handled securely

## 🐛 Troubleshooting

### "No tdata folders found"
- Ensure Telegram Desktop is installed
- Check if tdata folder exists in expected locations
- Try manual browse option

### "Decryption failed"
- Verify the correct password was entered
- Ensure tdata files are not corrupted
- Check Telegram Desktop version compatibility

### GUI doesn't start
- Ensure tkinter is installed: `pip install tk`
- Try command-line mode via launcher
- Check Python version (3.7+ required)

## 📈 Version History

### v2.0 (Current)
- Added modern GUI with themes
- Implemented auto-search functionality
- Built-in decryption (no external tools)
- Progress indicators and status updates
- Cache decryption support

### v1.0
- Initial command-line version
- Basic decryption support

## 📄 License

This tool is provided for educational and forensic purposes. Use responsibly and only on data you own or have permission to analyze.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## ⚠️ Disclaimer

This tool is for legitimate forensic analysis and data recovery purposes only. Users are responsible for complying with all applicable laws and regulations. The authors are not responsible for any misuse of this software.

## 💡 Tips

- Always backup your tdata folder before analysis
- Use the password field only if you set a local passcode in Telegram Desktop
- The auto-search feature may take a few moments on systems with many files
- Export results immediately after successful decryption for safekeeping

---

**Need help?** Check the troubleshooting section or file an issue on the project repository.
