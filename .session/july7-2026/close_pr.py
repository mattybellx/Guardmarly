"""Close duplicate PR #159 and check all PRs."""
import urllib.request, json, os

token = os.environ.get('GITHUB_TOKEN', '').strip()
if not token:
    token = "YOUR_GITHUB_TOKEN_HERE"  # Set GITHUB_TOKEN env var instead
headers = {'Accept': 'application/vnd.github+json', 'Authorization': 'Bearer ' + token, 'User-Agent': 'ansede'}

# Close duplicate PR
url = 'https://api.github.com/repos/devsecops/awesome-devsecops/pulls/159'
data = json.dumps({'state': 'closed'}).encode()
req = urllib.request.Request(url, data=data, headers=headers, method='PATCH')
try:
    with urllib.request.urlopen(req, timeout=10) as resp:
        result = json.load(resp)
    print('PR #159:', result.get('state', '?'))
except urllib.error.HTTPError as e:
    print('PR #159 error:', e.code, e.read().decode()[:200])

# Check status of all open PRs
print()
r = urllib.request.Request('https://api.github.com/search/issues?q=type:pr+author:mattybellx+is:open', headers=headers)
try:
    d = json.load(urllib.request.urlopen(r, timeout=10))
    prs = d.get('items', [])
    print(f'Open PRs: {len(prs)}')
    for pr in prs:
        repo_url = pr.get('repository_url', '')
        repo = repo_url.split('/repos/')[-1] if '/repos/' in repo_url else repo_url
        print(f'  {repo}#{pr["number"]} - {pr["title"][:80]}')
except Exception as e:
    print('Search error:', e)
