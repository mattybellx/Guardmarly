#!/usr/bin/env python3
"""One-click growth automation for ansede-static.
Usage:
  1. Create a GitHub Personal Access Token at https://github.com/settings/tokens
     (needs: repo, workflow, read:org scopes)
  2. Set it: $env:GITHUB_TOKEN = "ghp_..."
  3. Run: python benchmarks/growth_automation.py
"""
import urllib.request, json, os, sys, subprocess, tempfile, shutil
from pathlib import Path

TOKEN = os.environ.get("GITHUB_TOKEN", "").strip()
if not TOKEN:
    print("ERROR: Set GITHUB_TOKEN environment variable first.")
    print("  1. Go to https://github.com/settings/tokens")
    print("  2. Generate a new token with 'repo' and 'workflow' scopes")
    print("  3. Run: $env:GITHUB_TOKEN = 'ghp_...'")
    sys.exit(1)

HEADERS = {
    "Accept": "application/vnd.github+json",
    "Authorization": f"Bearer {TOKEN}",
    "User-Agent": "ansede-growth-automation",
}

def api(method, url, data=None):
    """Make a GitHub API call."""
    body = json.dumps(data).encode() if data else None
    req = urllib.request.Request(url, data=body, headers=HEADERS, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as e:
        body = e.read().decode()[:500]
        print(f"  API error {e.code}: {body}")
        return None

def api_get(url):
    return api("GET", url)

def api_post(url, data=None):
    return api("POST", url, data)

def api_patch(url, data):
    return api("PATCH", url, data)

def run(cmd, cwd=None):
    return subprocess.run(cmd, shell=True, cwd=cwd, capture_output=True, text=True)

# ── Step 1: Update repo settings ──────────────────────────────────────
print("=" * 60)
print("Step 1: Updating GitHub repo description and topics...")
result = api_patch("https://api.github.com/repos/mattybellx/Ansede", {
    "description": "Offline SAST that detects IDOR, missing authentication, and ownership bypass. OWASP recall 62%, CVE recall 96.3% across 5 languages. Beats Semgrep OSS on recall.",
    "topics": ["sast", "static-analysis", "security", "python", "owasp", "idor",
               "cwe", "security-scanner", "code-review", "devsecops", "offline",
               "authorization", "authentication", "javascript", "cli", "sarif"],
    "homepage": "https://pypi.org/project/ansede-static/"
})
if result:
    print(f"  Done. Description: {result.get('description', '')[:70]}...")
else:
    print("  Failed. Check your token has repo scope.")

# ── Step 2: Fork and PR to sbilly/awesome-security ────────────────────
print("\nStep 2: Preparing PR to sbilly/awesome-security (14.6k stars)...")

# Fork the repo
fork_result = api_post("https://api.github.com/repos/sbilly/awesome-security/forks")
if not fork_result:
    print("  Fork failed. You may already have a fork — continuing...")
else:
    print(f"  Forked: {fork_result.get('full_name', '?')}")

# Clone, edit, push
with tempfile.TemporaryDirectory() as tmp:
    clone_dir = Path(tmp) / "awesome-security"
    clone_url = f"https://x-access-token:{TOKEN}@github.com/mattybellx/awesome-security.git"
    
    r = run(f'git clone --depth 1 "{clone_url}" "{clone_dir}"')
    if r.returncode != 0:
        # Try existing fork
        clone_url = f"https://x-access-token:{TOKEN}@github.com/mattybellx/awesome-security.git"
        r = run(f'git clone "{clone_url}" "{clone_dir}"')
    if r.returncode != 0:
        print(f"  Clone failed: {r.stderr[:200]}")
    else:
        readme = clone_dir / "README.md"
        content = readme.read_text(encoding="utf-8", errors="replace")
        
        # Find Web > Development section and add entry
        new_entry = "* [Ansede Static](https://github.com/mattybellx/Ansede) - Offline SAST for Python/JS detecting IDOR, missing auth, and ownership bypass. 62% OWASP recall, 96.3% CVE recall. Free + Pro.\n"
        
        if "Ansede Static" not in content:
            # Insert after a known SAST entry
            insert_after = "* [Bearer]"
            if insert_after in content:
                content = content.replace(
                    insert_after,
                    insert_after + "\n" + new_entry.strip()
                )
                readme.write_text(content, encoding="utf-8")
                
                run('git add README.md', cwd=str(clone_dir))
                run('git commit -m "Add Ansede Static — offline SAST with IDOR/auth detection"', cwd=str(clone_dir))
                result = run('git push origin master', cwd=str(clone_dir))
                
                if result.returncode == 0:
                    # Create PR
                    pr = api_post("https://api.github.com/repos/sbilly/awesome-security/pulls", {
                        "title": "Add Ansede Static — offline SAST with IDOR/auth detection",
                        "head": "mattybellx:master",
                        "base": "master",
                        "body": "Ansede Static is an offline-first SAST tool that detects authorization flaws (CWE-639 IDOR, CWE-862 Missing Auth, CWE-285 Ownership Bypass) that every other free scanner misses by default.\n\n- OWASP Benchmark: 62.0% recall (beats Semgrep OSS at 59.4%)\n- CVE recall: 96.3% (158/164) across 5 languages\n- Zero external network dependencies\n- 1,234 tests, 100% quality gates\n- Free + Pro tiers"
                    })
                    if pr:
                        print(f"  PR created: {pr.get('html_url', '?')}")
                    else:
                        print("  PR creation failed — check permissions")
                else:
                    print(f"  Push failed: {result.stderr[:200]}")
            else:
                print(f"  Could not find insertion point in README")
        else:
            print("  Already in list — skipping")

# ── Step 3: Fork and PR to devsecops/awesome-devsecops ────────────────
print("\nStep 3: Preparing PR to devsecops/awesome-devsecops (5.4k stars)...")

fork_result = api_post("https://api.github.com/repos/devsecops/awesome-devsecops/forks")
if not fork_result:
    print("  Fork failed — may already exist, continuing...")
else:
    print(f"  Forked: {fork_result.get('full_name', '?')}")

with tempfile.TemporaryDirectory() as tmp:
    clone_dir = Path(tmp) / "awesome-devsecops"
    clone_url = f"https://x-access-token:{TOKEN}@github.com/mattybellx/awesome-devsecops.git"
    
    r = run(f'git clone --depth 1 "{clone_url}" "{clone_dir}"')
    if r.returncode != 0:
        print(f"  Clone failed: {r.stderr[:200]}")
    else:
        readme = clone_dir / "README.md"
        content = readme.read_text(encoding="utf-8", errors="replace")
        
        new_entry = "* [Ansede Static](https://github.com/mattybellx/Ansede) - Offline SAST for Python/JS detecting IDOR, auth bypass, and ownership flaws. 62% OWASP recall, 96.3% CVE recall.\n"
        
        if "Ansede Static" not in content:
            # Insert in Testing section
            insert_after = "* [RIPS]"
            if insert_after in content:
                content = content.replace(
                    insert_after,
                    insert_after + "\n" + new_entry.strip()
                )
                readme.write_text(content, encoding="utf-8")
                
                run('git add README.md', cwd=str(clone_dir))
                run('git commit -m "Add Ansede Static to Testing tools"', cwd=str(clone_dir))
                result = run('git push origin master', cwd=str(clone_dir))
                
                if result.returncode == 0:
                    pr = api_post("https://api.github.com/repos/devsecops/awesome-devsecops/pulls", {
                        "title": "Add Ansede Static to Testing tools",
                        "head": "mattybellx:master",
                        "base": "master",
                        "body": "Adds Ansede Static, an offline-first SAST scanner specialized in authorization vulnerability detection (CWE-639/862/285) that free alternatives miss by default.\n\n- 62% OWASP recall\n- 96.3% CVE recall\n- Free + Pro tiers"
                    })
                    if pr:
                        print(f"  PR created: {pr.get('html_url', '?')}")
                    else:
                        print("  PR creation failed")
                else:
                    print(f"  Push failed: {result.stderr[:200]}")
            else:
                print("  Could not find insertion point")
        else:
            print("  Already in list — skipping")

print("\n" + "=" * 60)
print("DONE. Check your GitHub notifications for PR status.")
print("=" * 60)
