#!/usr/bin/env python3
"""Simple ClickFix Testing MCP Server - Detonate and analyze ClickFix pages in a safe VM sandbox."""
import os
import sys
import logging
import json
import re
import base64
import subprocess
import time
import hashlib
from datetime import datetime, timezone
from pathlib import Path

from mcp.server.fastmcp import FastMCP

# Configure logging to stderr
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stderr
)
logger = logging.getLogger("clickfix-server")

# Initialize MCP server
mcp = FastMCP("clickfix")

# Configuration from environment variables
VBOX_VM_NAME = os.environ.get("CLICKFIX_VM_NAME", "ClickFixVM")
VBOX_SNAPSHOT = os.environ.get("CLICKFIX_SNAPSHOT", "clean")
VBOX_USER = os.environ.get("CLICKFIX_VM_USER", "user")
VBOX_PASS = os.environ.get("CLICKFIX_VM_PASS", "password")
OUTPUT_DIR = os.environ.get("CLICKFIX_OUTPUT_DIR", "/app/output")
VBOXMANAGE = os.environ.get("VBOXMANAGE_PATH", "VBoxManage")
SCREENSHOT_TIMEOUT = int(os.environ.get("CLICKFIX_SCREENSHOT_TIMEOUT", "30"))
PAGE_LOAD_WAIT = int(os.environ.get("CLICKFIX_PAGE_LOAD_WAIT", "10"))


# === UTILITY FUNCTIONS ===

def _sanitize_url(url):
    """Basic URL validation and sanitization."""
    url = url.strip()
    if not url:
        return None, "URL is empty"
    if not re.match(r'^https?://', url, re.IGNORECASE):
        url = "http://" + url
    # Block local/private IPs to protect host (VM should be isolated anyway)
    blocked = ['127.0.0.1', 'localhost', '0.0.0.0', '::1']
    for b in blocked:
        if b in url.lower():
            return None, f"Blocked address in URL: {b}"
    return url, None


def _run_vbox(args, timeout=60):
    """Run a VBoxManage command and return stdout/stderr."""
    cmd = [VBOXMANAGE] + args
    logger.info(f"Running: {' '.join(cmd)}")
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"
    except FileNotFoundError:
        return -1, "", f"VBoxManage not found at {VBOXMANAGE}"
    except Exception as e:
        return -1, "", str(e)


def _run_guest_cmd(command, timeout=60):
    """Execute a command inside the guest VM via VBoxManage guestcontrol."""
    rc, out, err = _run_vbox([
        "guestcontrol", VBOX_VM_NAME, "run",
        "--exe", "cmd.exe",
        "--username", VBOX_USER,
        "--password", VBOX_PASS,
        "--wait-stdout", "--wait-stderr",
        "--", "cmd.exe", "/c", command
    ], timeout=timeout)
    return rc, out, err


def _take_screenshot_vbox(output_path):
    """Take a screenshot of the VM display via VBoxManage."""
    rc, out, err = _run_vbox([
        "controlvm", VBOX_VM_NAME, "screenshotpng", output_path
    ])
    return rc == 0, err


def _generate_safe_filename(url, extension):
    """Generate a safe filename from URL with timestamp."""
    url_hash = hashlib.md5(url.encode()).hexdigest()[:8]
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    safe_name = re.sub(r'[^a-zA-Z0-9]', '_', url)[:50]
    return f"{timestamp}_{safe_name}_{url_hash}{extension}"


def _save_command_safely(command_text, url, output_dir):
    """Save captured command text with .virus extension so it cannot be accidentally executed."""
    filename = _generate_safe_filename(url, ".virus")
    filepath = os.path.join(output_dir, filename)
    content = {
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "source_url": url,
        "warning": "THIS FILE CONTAINS A POTENTIALLY MALICIOUS COMMAND CAPTURED DURING CLICKFIX ANALYSIS. DO NOT EXECUTE.",
        "command_text": command_text
    }
    with open(filepath, 'w') as f:
        json.dump(content, f, indent=2)
    return filepath


def _detect_clickfix_patterns(page_source):
    """Analyze page source for common ClickFix social engineering patterns."""
    patterns = {
        "fake_captcha": [
            r'verify\s+you\s+are\s+human',
            r'i\s+am\s+not\s+a\s+robot',
            r'captcha\s+verification',
            r'prove\s+you\s+are\s+human',
            r'security\s+check',
            r'bot\s+verification'
        ],
        "clipboard_hijack": [
            r'navigator\.clipboard\.writeText',
            r'document\.execCommand\s*\(\s*["\']copy',
            r'clipboardData\.setData',
            r'copy\s+to\s+clipboard'
        ],
        "run_dialog_instruction": [
            r'press\s+win(dows)?\s*\+?\s*r',
            r'open\s+run\s+dialog',
            r'win\s*\+\s*r',
            r'windows\s+key\s*\+\s*r'
        ],
        "paste_instruction": [
            r'ctrl\s*\+\s*v',
            r'paste\s+(the|and|it)',
            r'right[\s-]click.*paste'
        ],
        "powershell_command": [
            r'powershell',
            r'iex\s*\(',
            r'invoke-expression',
            r'invoke-webrequest',
            r'downloadstring',
            r'start-process',
            r'hidden\s*window'
        ],
        "cmd_command": [
            r'cmd\.exe',
            r'mshta\s+',
            r'certutil\s+-',
            r'bitsadmin\s+',
            r'regsvr32\s+'
        ],
        "encoded_payload": [
            r'base64',
            r'frombase64string',
            r'atob\s*\(',
            r'btoa\s*\(',
            r'\\x[0-9a-fA-F]{2}'
        ]
    }

    findings = {}
    source_lower = page_source.lower() if page_source else ""
    for category, regexes in patterns.items():
        matches = []
        for pattern in regexes:
            found = re.findall(pattern, source_lower)
            if found:
                matches.extend(found[:3])
        if matches:
            findings[category] = matches

    return findings


# === MCP TOOLS ===

@mcp.tool()
async def check_vm_status(vm_name: str = "") -> str:
    """Check if the ClickFix analysis VM is running and accessible."""
    name = vm_name.strip() if vm_name.strip() else VBOX_VM_NAME
    logger.info(f"Checking VM status for: {name}")

    try:
        rc, out, err = _run_vbox(["showvminfo", name, "--machinereadable"])
        if rc != 0:
            return f"❌ Error: Could not get VM info for '{name}'. {err}"

        state_match = re.search(r'VMState="(\w+)"', out)
        state = state_match.group(1) if state_match else "unknown"
        os_match = re.search(r'ostype="([^"]+)"', out)
        os_type = os_match.group(1) if os_match else "unknown"
        mem_match = re.search(r'memory=(\d+)', out)
        memory = mem_match.group(1) if mem_match else "unknown"

        status_emoji = "🟢" if state == "running" else "🔴"
        return f"""{status_emoji} VM Status: {name}
- State: {state}
- OS: {os_type}
- Memory: {memory} MB
- Snapshot for reset: {VBOX_SNAPSHOT}
- Guest user: {VBOX_USER}"""

    except Exception as e:
        logger.error(f"Error checking VM: {e}")
        return f"❌ Error checking VM status: {str(e)}"


@mcp.tool()
async def start_vm(vm_name: str = "") -> str:
    """Start the ClickFix analysis VM if it is not already running."""
    name = vm_name.strip() if vm_name.strip() else VBOX_VM_NAME
    logger.info(f"Starting VM: {name}")

    try:
        rc, out, err = _run_vbox(["showvminfo", name, "--machinereadable"])
        if rc == 0 and 'VMState="running"' in out:
            return f"✅ VM '{name}' is already running."

        rc, out, err = _run_vbox(["startvm", name, "--type", "headless"], timeout=120)
        if rc != 0:
            return f"❌ Error starting VM: {err}"

        logger.info("Waiting for VM to boot...")
        time.sleep(30)
        return f"✅ VM '{name}' started successfully in headless mode. Please wait ~30s for full boot before testing."

    except Exception as e:
        logger.error(f"Error starting VM: {e}")
        return f"❌ Error starting VM: {str(e)}"


@mcp.tool()
async def restore_vm_snapshot(snapshot_name: str = "") -> str:
    """Restore the VM to a clean snapshot for safe repeated testing."""
    snap = snapshot_name.strip() if snapshot_name.strip() else VBOX_SNAPSHOT
    logger.info(f"Restoring snapshot '{snap}' on VM '{VBOX_VM_NAME}'")

    try:
        # Power off if running
        _run_vbox(["controlvm", VBOX_VM_NAME, "poweroff"], timeout=30)
        time.sleep(5)

        rc, out, err = _run_vbox(["snapshot", VBOX_VM_NAME, "restore", snap], timeout=120)
        if rc != 0:
            return f"❌ Error restoring snapshot '{snap}': {err}"

        return f"✅ VM restored to snapshot '{snap}'. Use start_vm to boot it."

    except Exception as e:
        logger.error(f"Error restoring snapshot: {e}")
        return f"❌ Error restoring snapshot: {str(e)}"


@mcp.tool()
async def analyze_url(url: str = "", click_through: str = "false") -> str:
    """Load a URL in the VM browser, screenshot it, detect ClickFix patterns, and optionally click through."""
    clean_url, error = _sanitize_url(url)
    if error:
        return f"❌ Error: {error}"

    do_click = click_through.strip().lower() in ("true", "yes", "1")
    logger.info(f"Analyzing URL: {clean_url} (click_through={do_click})")
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    results = {
        "url": clean_url,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "screenshots": [],
        "patterns_detected": {},
        "captured_commands": [],
        "clicked_through": do_click
    }

    try:
        # Step 1: Open URL in browser via guest control
        logger.info("Opening URL in VM browser...")
        open_cmd = f'start "" "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" --new-window --disable-popup-blocking "{clean_url}"'
        rc, out, err = _run_guest_cmd(open_cmd, timeout=30)
        # start command returns immediately, we wait for page load
        time.sleep(PAGE_LOAD_WAIT)

        # Step 2: Take initial screenshot
        logger.info("Taking initial screenshot...")
        screenshot_file = _generate_safe_filename(clean_url, "_initial.png")
        screenshot_path = os.path.join(OUTPUT_DIR, screenshot_file)
        success, scr_err = _take_screenshot_vbox(screenshot_path)
        if success:
            results["screenshots"].append(screenshot_path)
        else:
            logger.warning(f"Screenshot failed: {scr_err}")

        # Step 3: Get page source for pattern analysis
        logger.info("Extracting page source...")
        # Use PowerShell to grab the page source via Invoke-WebRequest
        ps_cmd = f'powershell -Command "(Invoke-WebRequest -Uri \'{clean_url}\' -UseBasicParsing).Content" 2>nul'
        rc, page_source, err = _run_guest_cmd(ps_cmd, timeout=30)

        if page_source:
            patterns = _detect_clickfix_patterns(page_source)
            results["patterns_detected"] = patterns

        # Step 4: Check clipboard content (ClickFix often copies commands to clipboard)
        logger.info("Checking clipboard for injected commands...")
        clip_cmd = 'powershell -Command "Get-Clipboard" 2>nul'
        rc, clipboard_content, err = _run_guest_cmd(clip_cmd, timeout=15)

        if clipboard_content and clipboard_content.strip():
            cmd_file = _save_command_safely(clipboard_content.strip(), clean_url, OUTPUT_DIR)
            results["captured_commands"].append({
                "source": "clipboard",
                "saved_to": cmd_file,
                "preview": clipboard_content.strip()[:200]
            })

        # Step 5: If click_through is enabled, simulate the ClickFix interaction
        if do_click:
            logger.info("Click-through enabled - simulating user interaction...")

            # Simulate Win+R (Run dialog)
            logger.info("Simulating Win+R...")
            _run_vbox(["controlvm", VBOX_VM_NAME, "keyboardputscancode",
                       "e0", "5b",  # Left Windows key down
                       "13",        # R down
                       "93",        # R up
                       "e0", "db"   # Left Windows key up
                       ])
            time.sleep(3)

            # Take screenshot of Run dialog
            run_screenshot = _generate_safe_filename(clean_url, "_run_dialog.png")
            run_screenshot_path = os.path.join(OUTPUT_DIR, run_screenshot)
            success, _ = _take_screenshot_vbox(run_screenshot_path)
            if success:
                results["screenshots"].append(run_screenshot_path)

            # Simulate Ctrl+V (paste clipboard content)
            logger.info("Simulating Ctrl+V paste...")
            _run_vbox(["controlvm", VBOX_VM_NAME, "keyboardputscancode",
                       "1d",  # Left Ctrl down
                       "2f",  # V down
                       "af",  # V up
                       "9d"   # Left Ctrl up
                       ])
            time.sleep(2)

            # Take screenshot showing pasted command
            paste_screenshot = _generate_safe_filename(clean_url, "_pasted.png")
            paste_screenshot_path = os.path.join(OUTPUT_DIR, paste_screenshot)
            success, _ = _take_screenshot_vbox(paste_screenshot_path)
            if success:
                results["screenshots"].append(paste_screenshot_path)

            # Re-check clipboard after interaction
            rc, clip2, err = _run_guest_cmd(clip_cmd, timeout=15)
            if clip2 and clip2.strip() and clip2.strip() != clipboard_content.strip():
                cmd_file2 = _save_command_safely(clip2.strip(), clean_url, OUTPUT_DIR)
                results["captured_commands"].append({
                    "source": "clipboard_after_click",
                    "saved_to": cmd_file2,
                    "preview": clip2.strip()[:200]
                })

            # NOTE: We do NOT press Enter - we stop before execution for safety
            logger.info("Stopped before execution (Enter not pressed) for safety.")

            # Take final screenshot
            final_screenshot = _generate_safe_filename(clean_url, "_final.png")
            final_screenshot_path = os.path.join(OUTPUT_DIR, final_screenshot)
            success, _ = _take_screenshot_vbox(final_screenshot_path)
            if success:
                results["screenshots"].append(final_screenshot_path)

        # Build report
        report = f"""🔍 ClickFix Analysis Report
━━━━━━━━━━━━━━━━━━━━━━━━━━━
🌐 URL: {clean_url}
⏱️ Analyzed: {results['timestamp']}

📸 Screenshots Captured: {len(results['screenshots'])}"""

        for i, s in enumerate(results["screenshots"]):
            report += f"\n  {i+1}. {s}"

        if results["patterns_detected"]:
            report += "\n\n⚠️ ClickFix Patterns Detected:"
            for category, matches in results["patterns_detected"].items():
                report += f"\n  🔴 {category}: {', '.join(str(m) for m in matches[:3])}"
        else:
            report += "\n\n✅ No obvious ClickFix patterns detected in page source."

        if results["captured_commands"]:
            report += "\n\n🔒 Captured Commands (saved as .virus files):"
            for cmd in results["captured_commands"]:
                report += f"\n  📁 Source: {cmd['source']}"
                report += f"\n  📁 File: {cmd['saved_to']}"
                report += f"\n  📋 Preview: {cmd['preview'][:100]}..."
        else:
            report += "\n\n📋 No commands found in clipboard."

        if do_click:
            report += "\n\n⚡ Click-through simulation completed (stopped before Enter/execution)."
        else:
            report += "\n\n💡 Tip: Set click_through='true' to simulate the full ClickFix interaction (stops before execution)."

        return report

    except Exception as e:
        logger.error(f"Error analyzing URL: {e}")
        return f"❌ Error during analysis: {str(e)}"


@mcp.tool()
async def get_screenshot(filename: str = "") -> str:
    """Get a base64-encoded screenshot from the output directory by filename."""
    if not filename.strip():
        return "❌ Error: filename is required"

    try:
        filepath = os.path.join(OUTPUT_DIR, filename.strip())
        if not os.path.exists(filepath):
            # Try listing available files
            files = [f for f in os.listdir(OUTPUT_DIR) if f.endswith('.png')]
            return f"❌ File not found: {filename}\n\n📁 Available screenshots:\n" + "\n".join(f"  - {f}" for f in files)

        with open(filepath, 'rb') as f:
            data = base64.b64encode(f.read()).decode('utf-8')
        size_kb = os.path.getsize(filepath) / 1024
        return f"📸 Screenshot: {filename} ({size_kb:.1f} KB)\n\nBase64 PNG data:\n{data[:200]}...\n\n(Full base64 data available - {len(data)} chars)"

    except Exception as e:
        logger.error(f"Error getting screenshot: {e}")
        return f"❌ Error: {str(e)}"


@mcp.tool()
async def read_captured_command(filename: str = "") -> str:
    """Read a captured .virus command file to inspect the malicious payload."""
    if not filename.strip():
        return "❌ Error: filename is required"

    try:
        filepath = os.path.join(OUTPUT_DIR, filename.strip())
        if not os.path.exists(filepath):
            files = [f for f in os.listdir(OUTPUT_DIR) if f.endswith('.virus')]
            return f"❌ File not found: {filename}\n\n📁 Available .virus files:\n" + "\n".join(f"  - {f}" for f in files)

        with open(filepath, 'r') as f:
            content = json.load(f)

        return f"""🔒 Captured Command Analysis
━━━━━━━━━━━━━━━━━━━━━━━━━━━
📁 File: {filename}
⏱️ Captured: {content.get('captured_at', 'unknown')}
🌐 Source URL: {content.get('source_url', 'unknown')}

⚠️ WARNING: {content.get('warning', 'N/A')}

📋 Command Text:
{content.get('command_text', 'No command text found')}"""

    except Exception as e:
        logger.error(f"Error reading command file: {e}")
        return f"❌ Error: {str(e)}"


@mcp.tool()
async def list_output_files(filter_type: str = "") -> str:
    """List all output files (screenshots and captured commands) from analyses."""
    logger.info(f"Listing output files (filter: {filter_type})")

    try:
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        all_files = sorted(os.listdir(OUTPUT_DIR))

        ft = filter_type.strip().lower()
        if ft == "screenshots":
            all_files = [f for f in all_files if f.endswith('.png')]
        elif ft == "commands":
            all_files = [f for f in all_files if f.endswith('.virus')]

        if not all_files:
            return "📁 No output files found. Run analyze_url first."

        report = f"📁 Output Files ({len(all_files)} total):\n"
        for f in all_files:
            fpath = os.path.join(OUTPUT_DIR, f)
            size = os.path.getsize(fpath)
            icon = "📸" if f.endswith('.png') else "🔒" if f.endswith('.virus') else "📄"
            report += f"\n  {icon} {f} ({size/1024:.1f} KB)"

        return report

    except Exception as e:
        logger.error(f"Error listing files: {e}")
        return f"❌ Error: {str(e)}"


@mcp.tool()
async def close_browser_in_vm() -> str:
    """Close Chrome in the VM to clean up between tests."""
    logger.info("Closing browser in VM")

    try:
        rc, out, err = _run_guest_cmd("taskkill /f /im chrome.exe", timeout=15)
        if rc == 0 or "not found" in err.lower():
            return "✅ Browser closed in VM."
        return f"⚠️ Browser close result: {err}"

    except Exception as e:
        logger.error(f"Error closing browser: {e}")
        return f"❌ Error: {str(e)}"


# === SERVER STARTUP ===
if __name__ == "__main__":
    logger.info("Starting ClickFix Testing MCP server...")
    logger.info(f"VM Name: {VBOX_VM_NAME}")
    logger.info(f"Snapshot: {VBOX_SNAPSHOT}")
    logger.info(f"Output Dir: {OUTPUT_DIR}")

    # Verify VBoxManage is accessible
    rc, out, err = _run_vbox(["--version"])
    if rc == 0:
        logger.info(f"VBoxManage version: {out}")
    else:
        logger.warning(f"VBoxManage not accessible: {err}")
        logger.warning("Make sure VBoxManage is mounted/available in the container")

    try:
        mcp.run(transport='stdio')
    except Exception as e:
        logger.error(f"Server error: {e}", exc_info=True)
        sys.exit(1)
