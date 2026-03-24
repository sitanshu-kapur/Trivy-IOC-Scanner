# Trivy IOC Scanner

A CLI tool to detect Indicators of Compromise (IOCs) from the TeamPCP supply chain attack that backdoored Aqua Security's Trivy scanner on March 19, 2026.

Reference: [Wiz Research — Trivy Compromised](https://www.wiz.io/blog/trivy-compromised-supply-chain-attack)

## What it detects

| Check | What it looks for |
|---|---|
| **Binary & hash scanning** | Trivy executables on the filesystem matching any of the 10 known malicious SHA256 hashes for `v0.69.4`, or binaries self-reporting that version |
| **Container image scanning** | Docker images tagged `0.69.4` and Trivy binaries embedded inside any local image |
| **Persistence artifacts** | `~/.config/systemd/user/sysmon.py`, the systemd unit/timer files, `/tmp/pglog` dropper, and `tpcp.tar.gz` credential bundles |
| **GitHub Actions audit** | Workflow YAML files referencing `aquasecurity/trivy-action` or `aquasecurity/setup-trivy`, cross-referenced against all 82 known malicious commit hashes |
| **GitHub org audit** | Searches a GitHub organization for a repository named `tpcp-docs` — the fallback exfiltration repo created by the malware |
| **Network log sweeping** | Shell history, `/etc/hosts`, systemd journal, macOS DNS logs, `/var/log/*`, and Windows DNS cache for C2 indicators |

### C2 indicators checked

- `scan.aquasecurtiy.org` (typosquatted primary C2)
- `45.148.10.212` (TECHOFF SRV LIMITED, Amsterdam)
- `plug-tab-protective-relay.trycloudflare.com` (Cloudflare tunnel used in GitHub Actions exfiltration)
- `tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io` (ICP-hosted fallback C2)

## Requirements

Python 3.9+ — no third-party dependencies.

## Installation

```bash
git clone https://github.com/sitanshu-kapur/Trivy-IOC-Scanner.git
cd Trivy-IOC-Scanner
python scanner.py --help
```

## Usage

### Basic — scan common binary paths and local workflows

```bash
python scanner.py
```

### Specify directories to search

```bash
python scanner.py --dir /usr/local/bin --dir /opt
```

### Scan a specific workflows directory

```bash
python scanner.py --workflows path/to/.github/workflows
```

### Include GitHub organization audit

```bash
python scanner.py --github-token ghp_yourtoken --github-org your-org-name
```

### Enable network log sweeping

```bash
python scanner.py --network
```

### Full scan

```bash
python scanner.py \
  --dir /usr/local/bin \
  --workflows .github/workflows \
  --github-token ghp_yourtoken \
  --github-org your-org-name \
  --network
```

### CI/CD usage (JSON output, non-zero exit on findings)

```bash
python scanner.py --json --skip-docker
```

Exits with code `1` if any CRITICAL or HIGH findings are present, `0` if clean.

## Options

| Flag | Description |
|---|---|
| `--dir PATH` | Directory to search for Trivy binaries. Repeatable. Defaults to common system paths. |
| `--workflows PATH` | Directory to scan for GitHub Actions YAML files. Default: `.github/workflows` |
| `--github-token PAT` | GitHub Personal Access Token for org-level audit |
| `--github-org ORG` | GitHub organization to search for `tpcp-docs` repository |
| `--network` | Enable network log and shell history sweeping |
| `--skip-docker` | Skip container image scanning |
| `--json` | Output results as JSON |
| `--quiet` | Suppress informational output; only show findings |

## Severity levels

| Level | Meaning |
|---|---|
| `CRITICAL` | Confirmed IOC — hash match, known malicious action commit, persistence artifact found, or `tpcp-docs` repo present |
| `HIGH` | Strong indicator — mutable action tag reference (force-pushable), or Trivy binary found inside container image |
| `INFO` | Informational — action pinned to full SHA not in malicious list; verify manually against the March 19–20, 2026 window |

## Recommended response steps

1. **If a malicious binary hash is found**: Remove the binary immediately. Assume any credentials accessible during its execution have been compromised — rotate SSH keys, cloud credentials (AWS, GCP, Azure), and Kubernetes tokens.

2. **If `sysmon.py` or the systemd unit is found**: The machine has an active backdoor. Disable and remove the unit, delete the script, and treat the machine as fully compromised. Re-image if possible.

3. **If `tpcp-docs` is found in your GitHub org**: The malware successfully exfiltrated encrypted credentials. Delete the repository, rotate all secrets accessible to your CI/CD runners, and audit GitHub Actions run logs from March 19–20, 2026.

4. **If a workflow uses a mutable action tag**: Check the workflow run logs from March 19–20, 2026 for the `Run Trivy` step (trivy-action) or `Setup environment` step (setup-trivy). Pin all actions to full SHA hashes going forward.

5. **If C2 traffic is found in logs**: Treat any secrets present in the environment at that time as compromised and rotate immediately.
