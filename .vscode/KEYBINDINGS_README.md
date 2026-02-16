# ReSharper Shortcuts for VS Code

This file contains the ReSharper-style keyboard shortcuts configured for Visual Studio Code.

## How to Use

The `keybindings.json` file in this directory contains custom keybindings that mimic ReSharper shortcuts for developers who are familiar with JetBrains ReSharper.

### For Project-Level Shortcuts (Recommended)

To use these shortcuts for this project only:
1. The keybindings.json file is already in the `.vscode` directory
2. These shortcuts will automatically apply when you open this workspace in VS Code

### For User-Level Shortcuts

If you want these shortcuts to apply globally across all your VS Code projects:
1. Open VS Code Command Palette (`Ctrl+Shift+P`)
2. Type "Preferences: Open Keyboard Shortcuts (JSON)"
3. Copy the contents of `.vscode/keybindings.json` to your user keybindings file

## Shortcut Reference

### Navigation
- `Ctrl+N` - Quick Open (Go to File)
- `Ctrl+Shift+N` - New Untitled File
- `Ctrl+M` - Go to Definition
- `Ctrl+Shift+Alt+N` - Go to Symbol
- `Ctrl+-` - Navigate Back
- `Ctrl+Shift+-` - Navigate Forward
- `Alt+` ` - Show Editors in Active Group

### Editing
- `Ctrl+D` - Duplicate Line Down
- `Ctrl+L` - Delete Line
- `Ctrl+W` - Expand Selection
- `Ctrl+Shift+W` - Shrink Selection
- `Ctrl+/` - Comment Line
- `Ctrl+Shift+/` - Block Comment
- `Ctrl+Alt+Enter` - Insert Line Before
- `Ctrl+Shift+Enter` - Insert Line After
- `Ctrl+Alt+J` - Join Lines

### Code Actions & Refactoring
- `Ctrl+Shift+R` - Rename Symbol
- `Alt+Enter` - Quick Fix (Code Actions)
- `Ctrl+Alt+F` - Format Document

### File & Window Management
- `Ctrl+Shift+S` - Save All Files
- `Ctrl+Alt+L` - Show Active File in Explorer
- `Shift+Alt+L` - Reveal Active File in OS

### Search & Find
- `Ctrl+Shift+F` - Find in Files
- `Ctrl+Shift+H` - Replace in Files
- `Ctrl+F12` - Go to Implementation
- `Ctrl+Shift+F12` - Find References (References View)
- `Shift+F12` - Find All References

### Build & Debug
- `Ctrl+Shift+B` - Run Build Task
- `Shift+F9` - Start Debugging
- `Ctrl+F5` - Run Without Debugging

### Terminal
- `Ctrl+Alt+T` - Open New Terminal

## Notes

- These shortcuts are configured to work on Windows/Linux. For macOS, replace `Ctrl` with `Cmd` in most cases.
- Some shortcuts may conflict with default VS Code or system shortcuts. You can modify them in the `keybindings.json` file.
- VS Code's keybindings use JSON with Comments (JSONC) format, so comments are allowed in the file.

## Version

Latest version: 2026 (compatible with VS Code 1.85+)

## Alternative: Install ReSharper Extension

You can also install the official "Resharper 9 Keybindings" extension from the VS Code Marketplace:
1. Open Extensions view (`Ctrl+Shift+X`)
2. Search for "Resharper 9 Keybindings"
3. Install the extension by Microsoft

The extension provides similar shortcuts and is maintained by Microsoft.
