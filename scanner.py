#!/usr/bin/env python3
"""
Trivy IOC Scanner - TeamPCP Supply Chain Attack
Detects Indicators of Compromise from the March 19, 2026 Trivy compromise.
Reference: https://www.wiz.io/blog/trivy-compromised-supply-chain-attack

Usage:
    python scanner.py [OPTIONS]

Options:
    --dir DIR           Directory to scan for Trivy binaries (default: filesystem roots)
    --workflows DIR     Directory to scan for GitHub Actions YAML files
    --github-token PAT  GitHub PAT for org-level repository audit
    --github-org ORG    GitHub organization name to audit
    --network           Enable network log / history sweeping
    --json              Output results as JSON
    --quiet             Suppress informational output, only show findings
"""

import argparse
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# IOC Definitions
# ---------------------------------------------------------------------------

MALICIOUS_VERSION = "v0.69.4"

# All known malicious SHA256 hashes for backdoored Trivy v0.69.4 binaries
MALICIOUS_HASHES = {
    "887e1f5b5b50162a60bd03b66269e0ae545d0aef0583c1c5b00972152ad7e073": "FreeBSD-64bit",
    "f7084b0229dce605ccc5506b14acd4d954a496da4b6134a294844ca8d601970d": "Linux-32bit",
    "822dd269ec10459572dfaaefe163dae693c344249a0161953f0d5cdd110bd2a0": "Linux-64bit",
    "bef7e2c5a92c4fa4af17791efc1e46311c0f304796f1172fce192f5efc40f5d7": "Linux-ARM",
    "e64e152afe2c722d750f10259626f357cdea40420c5eedae37969fbf13abbecf": "Linux-ARM64 (unconfirmed)",
    "ecce7ae5ffc9f57bb70efd3ea136a2923f701334a8cd47d4fbf01a97fd22859c": "Linux-PPC64LE",
    "d5edd791021b966fb6af0ace09319ace7b97d6642363ef27b3d5056ca654a94c": "Linux-s390x",
    "e6310d8a003d7ac101a6b1cd39ff6c6a88ee454b767c1bdce143e04bc1113243": "macOS-64bit",
    "6328a34b26a63423b555a61f89a6a0525a534e9c88584c815d937910f1ddd538": "macOS-ARM64",
    "0880819ef821cff918960a39c1c1aada55a5593c61c608ea9215da858a86e349": "Windows-64bit",
}

# Malicious commit hashes for compromised GitHub Actions
MALICIOUS_ACTION_HASHES = {
    "setup-trivy": {
        "8afa9b9f9183b4e00c46e2b82d34047e3c177bd0",
        "386c0f18ac3d7f2ed33e2d884761119f4024ff8a",
        "384add36b52014a0f99c0ab3a3d58bd47e53d00f",
        "7a4b6f31edb8db48cc22a1d41e298b38c4a6417e",
        "6d8d730153d6151e03549f276faca0275ed9c7b2",
        "99b93c070aac11b52dfc3e41a55cbb24a331ae75",
        "f4436225d8a5fd1715d3c2290d8a50643e726031",
    },
    "trivy-action": {
        "f4f1785be270ae13f36f6a8cfbf6faaae50e660a",
        "0891663bc55073747be0eb864fbec3727840945d",
        "2e7964d59cd24d1fd2aa4d6a5f93b7f09ea96947",
        "ddb9da4475c1cef7d5389062bdfdfbdbd1394648",
        "4209dcadeaea6a7df69262fef1beeda940881d4d",
        "f5c9fd927027beaa3760d2a84daa8b00e6e5ee21",
        "18f01febc4c3cd70ce6b94b70e69ab866fc033f5",
        "bb75a9059c2d5803db49e6ed6c6f7e0b367f96be",
        "d488f4388ff4aa268906e25c2144f1433a4edec2",
        "3c615ac0f29e743eda8863377f9776619fd2db76",
        "a9bc513ea7989e3234b395cafb8ed5ccc3755636",
        "8519037888b189f13047371758f7aed2283c6b58",
        "8cfb9c31cc944da57458555aa398bb99336d5a1f",
        "9092287c0339a8102f91c5a257a7e27625d9d029",
        "7b955a5ece1e1b085c12dac7ac10e0eb1f5b0d4d",
        "19851bef764b57ff95b35e66589f31949eeb229d",
        "61fbe20b7589e6b61eedcd5fe1e958e1a95fbd13",
        "fa78e67c0df002c509bcdea88677fb5e2fe6a9b1",
        "b7befdc106c600585d3eec87d7e98e1c136839ae",
        "7f6f0ce52a59bdfc5757c3982aac2353b58f4c73",
        "ddb6697447a97198bdef9bae00215059eb5e8bc2",
        "3dffed04dc90cf1c548f40577d642c52241ec76c",
        "ad623e14ebdfe82b9627811d57b9a39e283d6128",
        "848d665ed24dc1a41f6b4b7c7ffac7693d6b37be",
        "ddb94181dcbc723d96ffc07fddd14d97e4849016",
        "b7252377a3d82c73d497bfafa3eabe84de1d02c4",
        "fa4209b6182a4c1609ce34d40b67f5cfd7f00f53",
        "2b1dac84ff12ba56158b3a97e2941a587cb20da9",
        "66c90331c8b991e7895d37796ac712b5895dda3b",
        "fd429cf86db999572f3d9ca7c54561fdf7d388a4",
        "8ae5a08aec3013ee8f6132b2a9012b45002f8eaa",
        "2a51c5c5bb1fd1f0e134c9754f1702cfa359c3dd",
        "9c000ba9d482773cbbc2c3544d61b109bc9eb832",
        "91e7c2c36dcad14149d8e455b960af62a2ffb275",
        "4bdcc5d9ef3ddb42ccc9126e6c07faa3df2807e3",
        "9e8968cb83234f0de0217aa8c934a68a317ee518",
        "c5967f85626795f647d4bf6eb67227f9b79e02f5",
        "b745a35bad072d93a9b83080e9920ec52c6b5a27",
        "38623bf26706d51c45647909dcfb669825442804",
        "555e7ad4c895c558c7214496df1cd56d1390c516",
        "2297a1b967ecc05ba2285eb6af56ab4da554ecae",
        "820428afeb64484d311211658383ce7f79d31a0a",
        "f77738448eec70113cf711656914b61905b3bd47",
        "252554b0e1130467f4301ba65c55a9c373508e35",
        "22e864e71155122e2834eb0c10d0e7e0b8f65aa3",
        "405e91f329294fb696f55793203abf1f6aba9b40",
        "506d7ff06abc509692c600b5b69b4dc6ceaa4b15",
        "276ca9680f6df9016db12f7c48571e5c4639451d",
        "aa3c46a9643b18125abb8aefc13219014e9c4be8",
        "ea56cd31d82b853932d50f1144e95b21817e52cf",
        "0d49ceb356f7d4735c63bd0d5c7e67665ec7f80c",
        "7550f14b64c1c724035a075b36e71423719a1f30",
        "da73ae0790e458e878b300b57ceb5f81ac573b46",
        "6ec7aaf336b7d2593d980908be9bc4fed6d407c6",
        "cf19d27c8a7fb7a8bbf1e1000e9318749bcd82cf",
        "ef3a510e3f94df3ea9fcd01621155ca5f2c3bf5b",
        "6fc874a1f9d65052d4c67a314da1dae914f1daff",
        "b9faa60f85f6f780a34b8d0faaf45b3e3966fdda",
        "ab6606b76e5a054be08cab3d07da323e90e751e8",
        "a5b4818debf2adbaba872aaffd6a0f64a26449fa",
        "e53b0483d08da44da9dfe8a84bf2837e5163699b",
        "8aa8af3ea1de8e968a3e49a40afb063692ab8eae",
        "91d5e0a13afab54533a95f8019dd7530bd38a071",
        "794b6d99daefd5e27ecb33e12691c4026739bf98",
        "9ba3c3cd3b23d033cd91253a9e61a4bf59c8a670",
        "e0198fd2b6e1679e36d32933941182d9afa82f6f",
        "9738180dd24427b8824445dbbc23c30ffc1cb0d8",
        "3201ddddd69a1419c6f1511a14c5945ba3217126",
        "985447b035c447c1ed45f38fad7ca7a4254cb668",
        "3d1b5be1589a83fc98b82781c263708b2eb3b47b",
        "fd090040b5f584f4fcbe466878cb204d0735dcf4",
        "85cb72f1e8ee5e6e44488cd6cbdbca94722f96ed",
        "cf1692a1fc7a47120e6508309765db7e33477946",
        "1d74e4cf63b7cf083cf92bf5923cf037f7011c6b",
        "c19401b2f58dc6d2632cb473d44be98dd8292a93",
    },
}

# Persistence artifact paths (expanded beyond the stated requirement)
PERSISTENCE_PATHS = [
    "~/.config/systemd/user/sysmon.py",          # Primary malicious script
    "~/.config/systemd/user/sysmon.service",      # Systemd unit that runs it
    "~/.config/systemd/user/sysmon.timer",        # Possible timer variant
    "/tmp/pglog",                                  # Downloaded dropper payload
    "~/tpcp.tar.gz",                              # Encrypted credential bundle
    "/tmp/tpcp.tar.gz",                           # Alternate bundle location
]

# C2 network indicators
C2_INDICATORS = [
    "scan.aquasecurtiy.org",                      # Typosquatted primary C2
    "aquasecurtiy.org",                           # Domain root
    "45.148.10.212",                              # C2 IP (TECHOFF SRV LIMITED)
    "plug-tab-protective-relay.trycloudflare.com", # Cloudflare tunnel C2
    "tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io",  # ICP-hosted fallback
    "tdtqy-oyaaa-aaaae-af2dq-cai",               # ICP canister short form
]

MALICIOUS_ACTIONS = [
    "aquasecurity/trivy-action",
    "aquasecurity/setup-trivy",
]

MALICIOUS_REPO_NAME = "tpcp-docs"


class Color:
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    GREEN  = "\033[92m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"

    @staticmethod
    def supported() -> bool:
        return sys.stdout.isatty() and platform.system() != "Windows" or (
            platform.system() == "Windows" and os.environ.get("WT_SESSION")
        )

def _c(color: str, text: str, use_color: bool) -> str:
    if use_color and Color.supported():
        return f"{color}{text}{Color.RESET}"
    return text

class Severity:
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    INFO     = "INFO"

class Finding:
    def __init__(self, check: str, severity: str, path: str, detail: str):
        self.check    = check
        self.severity = severity
        self.path     = path
        self.detail   = detail

    def to_dict(self) -> dict:
        return {
            "check":    self.check,
            "severity": self.severity,
            "path":     self.path,
            "detail":   self.detail,
        }

def sha256_file(path: str) -> Optional[str]:
    """Return SHA256 hex digest of a file, or None on read error."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError):
        return None


def get_binary_version(path: str) -> Optional[str]:
    """
    Attempt to extract the version string from a Trivy binary.
    Tries --version flag first, then scans raw bytes for version pattern.
    """
    try:
        result = subprocess.run(
            [path, "--version"],
            capture_output=True, text=True, timeout=5
        )
        output = result.stdout + result.stderr
        match = re.search(r"Version:\s*(v?\d+\.\d+\.\d+)", output)
        if match:
            v = match.group(1)
            return v if v.startswith("v") else f"v{v}"
    except Exception:
        pass

    try:
        with open(path, "rb") as f:
            content = f.read(1024 * 1024)  # read first 1 MB
        match = re.search(rb"v0\.\d{2}\.\d+", content)
        if match:
            return match.group(0).decode("utf-8", errors="replace")
    except (OSError, PermissionError):
        pass

    return None


def find_trivy_binaries(search_dirs: list[str], quiet: bool, use_color: bool) -> list[str]:
    """Walk directories to locate any executable named 'trivy' or 'trivy.exe'."""
    found = []
    trivy_names = {"trivy", "trivy.exe"}

    for root_dir in search_dirs:
        if not quiet:
            print(f"  Scanning: {root_dir}")
        try:
            for dirpath, dirnames, filenames in os.walk(root_dir, followlinks=False):
                # Skip common noisy directories to speed up scan
                dirnames[:] = [
                    d for d in dirnames
                    if d not in {
                        "proc", "sys", "dev", "run",
                        "node_modules", ".git", "__pycache__",
                    }
                ]
                for fname in filenames:
                    if fname.lower() in trivy_names:
                        found.append(os.path.join(dirpath, fname))
        except PermissionError:
            pass

    return found


def get_docker_images() -> list[dict]:
    """Return list of docker images as dicts with id/repository/tag."""
    try:
        result = subprocess.run(
            ["docker", "images", "--format", "{{.ID}}\t{{.Repository}}\t{{.Tag}}"],
            capture_output=True, text=True, timeout=10
        )
        images = []
        for line in result.stdout.strip().splitlines():
            parts = line.split("\t")
            if len(parts) == 3:
                images.append({"id": parts[0], "repository": parts[1], "tag": parts[2]})
        return images
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []


def scan_docker_image_for_trivy(image_id: str) -> list[str]:
    """
    Export a docker image layer filesystem and look for trivy binaries inside.
    Returns list of paths found within the image.
    """
    found = []
    try:
        result = subprocess.run(
            ["docker", "run", "--rm", "--entrypoint", "find",
             image_id, "/", "-name", "trivy", "-type", "f"],
            capture_output=True, text=True, timeout=30
        )
        for line in result.stdout.strip().splitlines():
            if line.strip():
                found.append(line.strip())
    except Exception:
        pass
    return found


def expand_path(p: str) -> str:
    return os.path.expanduser(os.path.expandvars(p))


def check_binaries(search_dirs: list[str], quiet: bool, use_color: bool) -> list[Finding]:
    findings = []

    if not quiet:
        print(_c(Color.BOLD, "\n[1] Binary & Hash Scanning", use_color))

    binaries = find_trivy_binaries(search_dirs, quiet, use_color)

    if not binaries and not quiet:
        print("  No Trivy binaries found on filesystem.")

    for path in binaries:
        if not quiet:
            print(f"  Found binary: {path}")

        digest = sha256_file(path)
        version = get_binary_version(path)

        if digest and digest in MALICIOUS_HASHES:
            platform_label = MALICIOUS_HASHES[digest]
            findings.append(Finding(
                check="binary_hash",
                severity=Severity.CRITICAL,
                path=path,
                detail=(
                    f"SHA256 matches known malicious Trivy {MALICIOUS_VERSION} binary "
                    f"({platform_label}). Hash: {digest}"
                ),
            ))
        elif digest and not quiet:
            print(f"    Hash {digest[:16]}... not in malicious hash list.")

        if version and version == MALICIOUS_VERSION:
            already_flagged = any(
                f.path == path and f.check == "binary_hash" for f in findings
            )
            if not already_flagged:
                findings.append(Finding(
                    check="binary_version",
                    severity=Severity.CRITICAL,
                    path=path,
                    detail=(
                        f"Binary reports version {MALICIOUS_VERSION} — the compromised release. "
                        f"Hash ({digest or 'unreadable'}) does not match known IOC hashes; "
                        f"treat as suspect until verified against official Aqua checksums."
                    ),
                ))
        elif version and not quiet:
            print(f"    Version: {version} (not {MALICIOUS_VERSION})")

    return findings


def check_docker_images(quiet: bool, use_color: bool) -> list[Finding]:
    findings = []

    if not quiet:
        print(_c(Color.BOLD, "\n[1b] Container Image Scanning", use_color))

    images = get_docker_images()
    if not images:
        if not quiet:
            print("  Docker not available or no images found.")
        return findings

    for image in images:
        label = f"{image['repository']}:{image['tag']}"
        if not quiet:
            print(f"  Checking image: {label}")

        # Flag images that appear to be Trivy itself
        if "trivy" in image["repository"].lower():
            if image["tag"] == "0.69.4":
                findings.append(Finding(
                    check="docker_image_version",
                    severity=Severity.CRITICAL,
                    path=label,
                    detail=(
                        f"Docker image tag matches malicious Trivy release {MALICIOUS_VERSION}. "
                        f"Image ID: {image['id']}"
                    ),
                ))
            elif not quiet:
                print(f"    Trivy image found with tag {image['tag']} — not malicious version.")

        # Scan image filesystem for embedded trivy binaries
        embedded = scan_docker_image_for_trivy(image["id"])
        for embedded_path in embedded:
            if not quiet:
                print(f"    Trivy binary found inside image at: {embedded_path}")
            findings.append(Finding(
                check="docker_embedded_binary",
                severity=Severity.HIGH,
                path=f"{label}::{embedded_path}",
                detail=(
                    f"Trivy binary found at '{embedded_path}' inside image '{label}'. "
                    f"Verify this binary's hash against known malicious hashes."
                ),
            ))

    return findings

def check_persistence(quiet: bool, use_color: bool) -> list[Finding]:
    findings = []

    if not quiet:
        print(_c(Color.BOLD, "\n[2] Persistence Mechanism Detection", use_color))

    for raw_path in PERSISTENCE_PATHS:
        full_path = expand_path(raw_path)
        if os.path.exists(full_path):
            severity = Severity.CRITICAL if "sysmon.py" in raw_path or "pglog" in raw_path else Severity.HIGH
            findings.append(Finding(
                check="persistence_artifact",
                severity=severity,
                path=full_path,
                detail=f"Malicious persistence artifact exists: {full_path}",
            ))
            if not quiet:
                print(f"  {_c(Color.RED, 'FOUND', use_color)}: {full_path}")
        else:
            if not quiet:
                print(f"  Not found: {full_path}")

    return findings

def check_workflows(workflows_dir: str, quiet: bool, use_color: bool) -> list[Finding]:
    findings = []

    if not quiet:
        print(_c(Color.BOLD, "\n[3] GitHub Actions Pipeline Audit", use_color))

    if not os.path.isdir(workflows_dir):
        if not quiet:
            print(f"  Directory not found: {workflows_dir}")
        return findings

    yaml_files = []
    for root, _, files in os.walk(workflows_dir):
        for f in files:
            if f.endswith((".yml", ".yaml")):
                yaml_files.append(os.path.join(root, f))

    if not yaml_files:
        if not quiet:
            print(f"  No YAML files found in {workflows_dir}")
        return findings

    uses_pattern = re.compile(
        r"uses:\s*(?P<action>aquasecurity/(?:trivy-action|setup-trivy))@(?P<ref>[a-f0-9]{40}|\S+)",
        re.IGNORECASE,
    )

    for yaml_path in yaml_files:
        if not quiet:
            print(f"  Scanning: {yaml_path}")
        try:
            with open(yaml_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except OSError:
            continue

        for lineno, line in enumerate(content.splitlines(), start=1):
            match = uses_pattern.search(line)
            if not match:
                continue

            action = match.group("action").lower()
            ref    = match.group("ref")

            action_key = None
            if "setup-trivy" in action:
                action_key = "setup-trivy"
            elif "trivy-action" in action:
                action_key = "trivy-action"

            if action_key is None:
                continue

            malicious_hashes = MALICIOUS_ACTION_HASHES.get(action_key, set())

            if ref in malicious_hashes:
                findings.append(Finding(
                    check="workflow_malicious_hash",
                    severity=Severity.CRITICAL,
                    path=f"{yaml_path}:{lineno}",
                    detail=(
                        f"Workflow references {action}@{ref} — this is a known malicious commit hash "
                        f"pushed by TeamPCP."
                    ),
                ))
            elif re.fullmatch(r"[a-f0-9]{40}", ref):

                findings.append(Finding(
                    check="workflow_action_ref",
                    severity=Severity.INFO,
                    path=f"{yaml_path}:{lineno}",
                    detail=(
                        f"Workflow uses {action}@{ref} (full SHA — not in malicious hash list). "
                        f"Verify this SHA was not affected during March 19-20, 2026 window."
                    ),
                ))
            else:

                findings.append(Finding(
                    check="workflow_unpinned_action",
                    severity=Severity.HIGH,
                    path=f"{yaml_path}:{lineno}",
                    detail=(
                        f"Workflow uses {action}@{ref} with a mutable tag reference. "
                        f"Tags were force-pushed to malicious commits by TeamPCP on March 19, 2026. "
                        f"Check workflow run logs from that date window."
                    ),
                ))

    return findings


def check_github_org(token: str, org: str, quiet: bool, use_color: bool) -> list[Finding]:
    findings = []

    if not quiet:
        print(_c(Color.BOLD, "\n[4] GitHub Organization Audit", use_color))

    try:
        import urllib.request
        import urllib.error

        url = f"https://api.github.com/orgs/{org}/repos?per_page=100&type=all"
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

        page = 1
        found_tpcp = False

        while True:
            paged_url = f"{url}&page={page}"
            req = urllib.request.Request(paged_url, headers=headers)

            try:
                with urllib.request.urlopen(req, timeout=15) as resp:
                    repos = json.loads(resp.read().decode())
            except urllib.error.HTTPError as e:
                findings.append(Finding(
                    check="github_api_error",
                    severity=Severity.INFO,
                    path=f"github.com/{org}",
                    detail=f"GitHub API request failed: HTTP {e.code} — {e.reason}",
                ))
                break

            if not repos:
                break

            for repo in repos:
                name = repo.get("name", "")
                if name == MALICIOUS_REPO_NAME:
                    found_tpcp = True
                    findings.append(Finding(
                        check="tpcp_docs_repo",
                        severity=Severity.CRITICAL,
                        path=f"github.com/{org}/{name}",
                        detail=(
                            f"Repository '{MALICIOUS_REPO_NAME}' found in org '{org}'. "
                            f"This is the fallback exfiltration repository created by TeamPCP malware "
                            f"to store encrypted stolen credentials. Created: {repo.get('created_at', 'unknown')}. "
                            f"Delete immediately and rotate all credentials."
                        ),
                    ))

            if len(repos) < 100:
                break
            page += 1

        if not found_tpcp and not quiet:
            print(f"  No '{MALICIOUS_REPO_NAME}' repository found in org '{org}'.")

    except ImportError:
        pass

    return findings

def check_network_logs(quiet: bool, use_color: bool) -> list[Finding]:
    findings = []

    if not quiet:
        print(_c(Color.BOLD, "\n[5] Network Log Sweeping", use_color))

    sources_checked = []

    def scan_text(source_label: str, text: str):
        for ioc in C2_INDICATORS:
            if ioc in text:
                findings.append(Finding(
                    check="network_c2_indicator",
                    severity=Severity.CRITICAL,
                    path=source_label,
                    detail=f"C2 indicator '{ioc}' found in {source_label}.",
                ))

    # --- /etc/hosts ---
    hosts_path = "/etc/hosts"
    if os.path.exists(hosts_path):
        sources_checked.append(hosts_path)
        try:
            with open(hosts_path, "r", errors="replace") as f:
                scan_text(hosts_path, f.read())
        except OSError:
            pass

    # --- Shell history files ---
    history_files = [
        "~/.bash_history",
        "~/.zsh_history",
        "~/.sh_history",
        "~/.history",
    ]
    for hf in history_files:
        expanded = expand_path(hf)
        if os.path.exists(expanded):
            sources_checked.append(expanded)
            try:
                with open(expanded, "r", errors="replace") as f:
                    scan_text(expanded, f.read())
            except OSError:
                pass

    # --- systemd journal (Linux only) ---
    if platform.system() == "Linux":
        try:
            result = subprocess.run(
                ["journalctl", "--no-pager", "-n", "5000", "--output=short"],
                capture_output=True, text=True, timeout=15,
            )
            if result.stdout:
                sources_checked.append("journalctl")
                scan_text("journalctl", result.stdout)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    # --- macOS: DNS cache via log stream (best-effort) ---
    if platform.system() == "Darwin":
        try:
            result = subprocess.run(
                ["log", "show", "--predicate",
                 'process == "mDNSResponder"', "--last", "24h", "--style", "compact"],
                capture_output=True, text=True, timeout=20,
            )
            if result.stdout:
                sources_checked.append("macOS mDNSResponder log")
                scan_text("macOS mDNSResponder log", result.stdout)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    # --- /var/log files (best-effort, common Linux locations) ---
    log_paths = [
        "/var/log/syslog",
        "/var/log/messages",
        "/var/log/auth.log",
    ]
    for lp in log_paths:
        if os.path.exists(lp):
            sources_checked.append(lp)
            try:
                # Only read last 50k characters to avoid huge files
                with open(lp, "r", errors="replace") as f:
                    f.seek(0, 2)
                    size = f.tell()
                    f.seek(max(0, size - 50000))
                    scan_text(lp, f.read())
            except OSError:
                pass

    # --- Windows: PowerShell DNS cache ---
    if platform.system() == "Windows":
        try:
            result = subprocess.run(
                ["powershell", "-NonInteractive", "-Command",
                 "Get-DnsClientCache | Select-Object -ExpandProperty Entry"],
                capture_output=True, text=True, timeout=10,
            )
            if result.stdout:
                sources_checked.append("Windows DNS cache")
                scan_text("Windows DNS cache", result.stdout)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    if not sources_checked and not quiet:
        print("  No network log sources accessible.")
    elif not quiet:
        print(f"  Checked {len(sources_checked)} source(s): {', '.join(sources_checked)}")

    return findings

# ---------------------------------------------------------------------------
# Check 6: GitHub Actions Run Log Audit
# ---------------------------------------------------------------------------

COMPROMISE_WINDOW_START = "2026-03-19T00:00:00Z"
COMPROMISE_WINDOW_END   = "2026-03-21T00:00:00Z"

# Step names injected by the compromised actions
AFFECTED_STEP_NAMES = [
    "run trivy",         # aquasecurity/trivy-action entrypoint step
    "setup environment", # aquasecurity/setup-trivy setup step
]

# Strings to search for inside downloaded run logs
LOG_IOC_PATTERNS = C2_INDICATORS + [
    "v0.69.4",
    "0.69.4",
    "tpcp.tar.gz",
    "tpcp-docs",
    "sysmon.py",
    "TeamPCP",
    "teamPCP",
]


def check_workflow_run_logs(
    token: str,
    repos: list[str],
    quiet: bool,
    use_color: bool,
) -> list[Finding]:
    """
    Query GitHub Actions run history for the compromise window and scan logs
    for C2 indicators, malicious version strings, and affected step names.
    Requires a PAT with repo/actions:read scope.
    """
    import io
    import urllib.error
    import urllib.request
    import zipfile

    findings = []

    if not quiet:
        print(_c(Color.BOLD, "\n[6] GitHub Actions Run Log Audit", use_color))
        print(f"  Compromise window: {COMPROMISE_WINDOW_START} -> {COMPROMISE_WINDOW_END}")

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    def gh_get(url: str) -> dict:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode())

    for repo in repos:
        if not quiet:
            print(f"\n  Repo: {repo}")

        # --- List runs created in the compromise window ---
        runs_url = (
            f"https://api.github.com/repos/{repo}/actions/runs"
            f"?created={COMPROMISE_WINDOW_START}..{COMPROMISE_WINDOW_END}&per_page=100"
        )

        try:
            data = gh_get(runs_url)
        except urllib.error.HTTPError as e:
            findings.append(Finding(
                check="github_api_error",
                severity=Severity.INFO,
                path=f"github.com/{repo}",
                detail=f"Could not list workflow runs: HTTP {e.code} — check token scope (needs repo/actions:read).",
            ))
            continue
        except Exception as e:
            findings.append(Finding(
                check="github_api_error",
                severity=Severity.INFO,
                path=f"github.com/{repo}",
                detail=f"Could not list workflow runs: {e}",
            ))
            continue

        runs = data.get("workflow_runs", [])
        if not runs:
            if not quiet:
                print("    No workflow runs found in the compromise window.")
            continue

        if not quiet:
            print(f"    {len(runs)} run(s) found in the March 19-20 window.")

        for run in runs:
            run_id       = run["id"]
            run_name     = run.get("name", "unknown")
            run_html_url = run.get("html_url", f"github.com/{repo}/actions/runs/{run_id}")
            triggered_at = run.get("created_at", "unknown")
            conclusion   = run.get("conclusion", "unknown")

            if not quiet:
                print(f"    Checking run: {run_name} ({triggered_at}, conclusion={conclusion})")

            # --- Check jobs/steps for affected action step names ---
            try:
                jobs_data = gh_get(
                    f"https://api.github.com/repos/{repo}/actions/runs/{run_id}/jobs"
                )
            except Exception:
                jobs_data = {"jobs": []}

            for job in jobs_data.get("jobs", []):
                job_name = job.get("name", str(job.get("id", "")))
                for step in job.get("steps", []):
                    step_name = step.get("name", "")
                    if any(s in step_name.lower() for s in AFFECTED_STEP_NAMES):
                        step_conclusion = step.get("conclusion", "unknown")
                        findings.append(Finding(
                            check="workflow_run_affected_step",
                            severity=Severity.HIGH,
                            path=f"{run_html_url} — job: {job_name}",
                            detail=(
                                f"Step '{step_name}' (conclusion: {step_conclusion}) matches a "
                                f"compromised action step name. Run '{run_name}' triggered at "
                                f"{triggered_at}. Review full logs for this run."
                            ),
                        ))

            # --- Download and scan full run logs ---
            logs_url = f"https://api.github.com/repos/{repo}/actions/runs/{run_id}/logs"
            req = urllib.request.Request(logs_url, headers=headers)
            try:
                with urllib.request.urlopen(req, timeout=30) as resp:
                    zip_bytes = resp.read()

                with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
                    for log_name in zf.namelist():
                        try:
                            with zf.open(log_name) as lf:
                                log_text = lf.read().decode("utf-8", errors="replace")
                        except Exception:
                            continue

                        seen_in_this_log: set[str] = set()
                        for indicator in LOG_IOC_PATTERNS:
                            if indicator in log_text and indicator not in seen_in_this_log:
                                seen_in_this_log.add(indicator)
                                findings.append(Finding(
                                    check="workflow_log_ioc",
                                    severity=Severity.CRITICAL,
                                    path=f"{run_html_url} — log: {log_name}",
                                    detail=(
                                        f"IOC '{indicator}' found in run logs for '{run_name}' "
                                        f"(triggered {triggered_at}). This run likely executed "
                                        f"malicious code from the compromised action."
                                    ),
                                ))

            except urllib.error.HTTPError as e:
                if e.code == 410:
                    # Logs expired (GitHub retains them for 90 days)
                    findings.append(Finding(
                        check="workflow_log_expired",
                        severity=Severity.INFO,
                        path=run_html_url,
                        detail=(
                            f"Logs for run '{run_name}' ({triggered_at}) are no longer available "
                            f"(HTTP 410 Gone). Cannot confirm or rule out compromise for this run."
                        ),
                    ))
            except Exception:
                pass

    return findings


# ---------------------------------------------------------------------------
SEVERITY_COLOR = {
    Severity.CRITICAL: Color.RED,
    Severity.HIGH:     Color.YELLOW,
    Severity.INFO:     Color.CYAN,
}

def print_findings(findings: list[Finding], use_color: bool):
    if not findings:
        print(_c(Color.GREEN, "\nNo IOCs detected.", use_color))
        return

    critical = [f for f in findings if f.severity == Severity.CRITICAL]
    high     = [f for f in findings if f.severity == Severity.HIGH]
    info     = [f for f in findings if f.severity == Severity.INFO]

    print(_c(Color.BOLD, f"\n{'='*60}", use_color))
    print(_c(Color.BOLD, " FINDINGS SUMMARY", use_color))
    print(_c(Color.BOLD, f"{'='*60}", use_color))
    print(f"  {_c(Color.RED,    f'CRITICAL : {len(critical)}', use_color)}")
    print(f"  {_c(Color.YELLOW, f'HIGH     : {len(high)}',     use_color)}")
    print(f"  {_c(Color.CYAN,   f'INFO     : {len(info)}',     use_color)}")
    print()

    for f in findings:
        color = SEVERITY_COLOR.get(f.severity, Color.RESET)
        severity_label = _c(color, f"[{f.severity}]", use_color)
        print(f"  {severity_label} {_c(Color.BOLD, f.check, use_color)}")
        print(f"    Path   : {f.path}")
        print(f"    Detail : {f.detail}")
        print()


def print_json(findings: list[Finding]):
    output = {
        "scanner": "trivy-ioc-scanner",
        "attack":  "TeamPCP Supply Chain Attack (March 19, 2026)",
        "total":   len(findings),
        "findings": [f.to_dict() for f in findings],
    }
    print(json.dumps(output, indent=2))

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="trivy-ioc-scanner",
        description=(
            "Scans the local environment for Indicators of Compromise from the "
            "TeamPCP Trivy supply chain attack (March 19, 2026)."
        ),
    )
    p.add_argument(
        "--dir", metavar="PATH", action="append", dest="scan_dirs",
        help=(
            "Directory to search for Trivy binaries. Can be specified multiple times. "
            "Defaults to filesystem roots if omitted."
        ),
    )
    p.add_argument(
        "--workflows", metavar="PATH", default=".github/workflows",
        help="Directory to scan for GitHub Actions YAML files (default: .github/workflows)",
    )
    p.add_argument(
        "--github-token", metavar="PAT", dest="github_token",
        help="GitHub Personal Access Token for org-level repository audit",
    )
    p.add_argument(
        "--github-org", metavar="ORG", dest="github_org",
        help="GitHub organization name to search for tpcp-docs repository",
    )
    p.add_argument(
        "--github-repo", metavar="OWNER/REPO", action="append", dest="github_repos",
        help=(
            "GitHub repo (owner/repo) to audit for Actions run logs during the compromise window. "
            "Can be specified multiple times. Requires --github-token."
        ),
    )
    p.add_argument(
        "--network", action="store_true",
        help="Enable network log and shell history sweeping for C2 indicators",
    )
    p.add_argument(
        "--skip-docker", action="store_true", dest="skip_docker",
        help="Skip container image scanning",
    )
    p.add_argument(
        "--json", action="store_true",
        help="Output results as JSON (suppresses all other output)",
    )
    p.add_argument(
        "--quiet", action="store_true",
        help="Suppress informational output; only print findings",
    )
    return p


def default_scan_dirs() -> list[str]:
    """Return sensible default directories to search for Trivy binaries."""
    dirs = []
    system = platform.system()
    if system == "Windows":
        dirs += [
            os.environ.get("ProgramFiles", "C:\\Program Files"),
            os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)"),
            os.environ.get("LOCALAPPDATA", ""),
            os.environ.get("USERPROFILE", ""),
            "C:\\Windows\\System32",
        ]
    else:
        dirs += [
            "/usr/local/bin",
            "/usr/bin",
            "/bin",
            "/opt",
            str(Path.home()),
            "/home",
        ]
    return [d for d in dirs if d and os.path.isdir(d)]


def main():
    parser = build_arg_parser()
    args   = parser.parse_args()

    use_color  = not args.json
    json_mode  = args.json
    quiet      = args.quiet or json_mode

    if not quiet:
        print(_c(Color.BOLD, "Trivy IOC Scanner — TeamPCP Supply Chain Attack", use_color))
        print("Reference: CVE Trivy compromise, March 19, 2026")
        print("-" * 60)

    scan_dirs = args.scan_dirs if args.scan_dirs else default_scan_dirs()

    all_findings: list[Finding] = []

    # Run all checks
    all_findings += check_binaries(scan_dirs, quiet, use_color)
    if not args.skip_docker:
        all_findings += check_docker_images(quiet, use_color)
    all_findings += check_persistence(quiet, use_color)
    all_findings += check_workflows(args.workflows, quiet, use_color)

    if args.github_token and args.github_org:
        all_findings += check_github_org(
            args.github_token, args.github_org, quiet, use_color
        )
    elif args.github_token or args.github_org:
        if not quiet:
            print("\n  [!] Both --github-token and --github-org are required for GitHub audit.")

    if args.network:
        all_findings += check_network_logs(quiet, use_color)
    elif not quiet:
        print(_c(Color.BOLD, "\n[5] Network Log Sweeping", use_color))
        print("  Skipped. Pass --network to enable.")

    if args.github_repos and args.github_token:
        all_findings += check_workflow_run_logs(
            args.github_token, args.github_repos, quiet, use_color
        )
    elif args.github_repos and not args.github_token:
        if not quiet:
            print("\n  [!] --github-repo requires --github-token to query run logs.")
    elif not quiet:
        print(_c(Color.BOLD, "\n[6] GitHub Actions Run Log Audit", use_color))
        print("  Skipped. Pass --github-token and --github-repo OWNER/REPO to enable.")

    # Output
    if json_mode:
        print_json(all_findings)
    else:
        print_findings(all_findings, use_color)

        # Exit code: 1 if any critical/high findings, 0 if clean
        critical_or_high = [
            f for f in all_findings
            if f.severity in (Severity.CRITICAL, Severity.HIGH)
        ]
        if critical_or_high:
            sys.exit(1)


if __name__ == "__main__":
    main()
