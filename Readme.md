# ClickFix Testing MCP Server

A Model Context Protocol (MCP) server for safely detonating and analyzing ClickFix
social engineering pages inside an isolated Windows 10 VirtualBox VM.

## Purpose

This MCP server provides a secure, sandboxed environment for security researchers
and students to analyze ClickFix-style attacks. ClickFix is a social engineering
technique where malicious web pages trick users into opening the Windows Run dialog
(Win+R), pasting a malicious command from their clipboard, and executing it.

This server automates the analysis by:
1. Loading suspicious URLs inside an isolated Windows 10 VM
2. Taking screenshots at each stage
3. Detecting known ClickFix patterns in page source
4. Capturing any commands injected into the clipboard
5. Optionally simulating the click-through interaction (stops before execution)
6. Saving captured commands with .virus extension for safe handling

## Features

### Current Implementation

- **`check_vm_status`** - Check if the analysis VM is running and accessible
- **`start_vm`** - Start the VM in headless mode
- **`restore_vm_snapshot`** - Restore VM to a clean snapshot between tests
- **`analyze_url`** - Load a URL, screenshot, detect patterns, capture commands
- **`get_screenshot`** - Retrieve a base64-encoded screenshot
- **`read_captured_command`** - Inspect captured malicious commands safely
- **`list_output_files`** - List all screenshots and captured command files
- **`close_browser_in_vm`** - Close Chrome between tests

## Prerequisites

- Docker Desktop with MCP Toolkit enabled
- Docker MCP CLI plugin (`docker mcp` command)
- VirtualBox 7.x installed on the host
- A Windows 10 VM in VirtualBox with:
  - Name matching CLICKFIX_VM_NAME (default: "ClickFixVM")
  - A clean snapshot named matching CLICKFIX_SNAPSHOT (default: "clean")
  - Google Chrome installed
  - Guest Additions installed (for guestcontrol)
  - A user account matching CLICKFIX_VM_USER / CLICKFIX_VM_PASS
  - Network configured (NAT or host-only as appropriate)

## VM Setup Guide

### Creating the Windows 10 Analysis VM

1. Create a new VM in VirtualBox:
   - Name: ClickFixVM
   - Type: Microsoft Windows / Windows 10 (64-bit)
   - RAM: 4096 MB minimum
   - Storage: 40 GB dynamic VDI

2. Install Windows 10 (evaluation ISO works fine)

3. Install VirtualBox Guest Additions (Insert Guest Additions CD from Devices menu)

4. Install Google Chrome

5. Create a user account:
   - Username: user
   - Password: password
   (or configure your own and set env vars)

6. Disable Windows Defender / real-time protection (so it doesn't interfere with analysis)

7. Take a snapshot named "clean":
   VBoxManage snapshot ClickFixVM take clean --description "Clean state for ClickFix testing"

8. Shut down the VM (the MCP server will start it as needed)

### Important Security Notes

- The VM should be on an ISOLATED network (NAT or host-only)
- NEVER use this VM for personal activities
- ALWAYS restore to clean snapshot after testing
- The .virus extension prevents accidental execution of captured commands
- The click-through simulation stops BEFORE pressing Enter (does not execute)

## Installation

See the step-by-step instructions provided with the files.

## Usage Examples

In Claude Desktop, you can ask:

- "Check if the ClickFix VM is running"
- "Start the analysis VM"
- "Analyze this URL for ClickFix patterns: http://suspicious-site.example.com"
- "Analyze this URL and click through: http://suspicious-site.example.com"
- "Show me the captured commands from the last analysis"
- "List all screenshots taken"
- "Restore the VM to clean state"

## Architecture

```
Claude Desktop -> MCP Gateway -> ClickFix MCP Server -> VBoxManage -> Windows 10 VM
                                       |                                    |
                                       v                                    v
                                 Output Directory                    Chrome Browser
                                 (screenshots .png)                  (loads URLs)
                                 (commands .virus)
```

## Environment Variables

| Variable                  | Default        | Description                          |
|--------------------------|----------------|--------------------------------------|
| CLICKFIX_VM_NAME         | ClickFixVM     | VirtualBox VM name                   |
| CLICKFIX_SNAPSHOT        | clean          | Snapshot name for clean restore      |
| CLICKFIX_VM_USER         | user           | Guest OS username                    |
| CLICKFIX_VM_PASS         | password       | Guest OS password                    |
| CLICKFIX_OUTPUT_DIR      | /app/output    | Directory for screenshots & commands |
| VBOXMANAGE_PATH          | VBoxManage     | Path to VBoxManage binary            |
| CLICKFIX_SCREENSHOT_TIMEOUT | 30          | Screenshot timeout in seconds        |
| CLICKFIX_PAGE_LOAD_WAIT  | 10             | Seconds to wait for page load        |

## Development

### Local Testing

```bash
# Set environment variables
export CLICKFIX_VM_NAME="ClickFixVM"
export CLICKFIX_SNAPSHOT="clean"
export CLICKFIX_VM_USER="user"
export CLICKFIX_VM_PASS="password"

# Run directly
python clickfix_server.py

# Test MCP protocol
echo '{"jsonrpc":"2.0","method":"tools/list","id":1}' | python clickfix_server.py
```

### Adding New Tools

1. Add the function to `clickfix_server.py`
2. Decorate with `@mcp.tool()`
3. Use SINGLE-LINE docstrings only
4. Default all parameters to empty strings
5. Return formatted strings
6. Update the catalog entry with the new tool name
7. Rebuild the Docker image

## Troubleshooting

### Tools Not Appearing
- Verify Docker image built successfully
- Check catalog and registry files
- Ensure Claude Desktop config includes custom catalog
- Restart Claude Desktop

### VM Not Starting
- Verify VM exists: `VBoxManage list vms`
- Check VM state: `VBoxManage showvminfo ClickFixVM`
- Ensure VBoxManage is accessible from the container

### Guest Control Not Working
- Verify Guest Additions are installed in the VM
- Check credentials match env vars
- Ensure VM is fully booted before running commands

### Screenshots Are Black
- Wait longer after VM start (increase PAGE_LOAD_WAIT)
- Verify Guest Additions are installed
- Check if display is locked (disable screen lock in VM)

## Security Considerations

- VM runs in isolated VirtualBox environment
- Commands saved with .virus extension to prevent accidental execution
- Click-through simulation stops before pressing Enter
- URL sanitization blocks localhost/private IPs
- All credentials stored via Docker secrets
- Running as non-root user in container
- Always restore to clean snapshot between analyses

## Disclaimer

This tool is for educational and security research purposes only.
Only test against systems and URLs you have permission to analyze.
The authors are not responsible for misuse of this tool.

## License

MIT License
