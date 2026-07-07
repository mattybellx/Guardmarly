"""Quick check: what worked from the growth automation run?"""
import urllib.request, json

headers = {'User-Agent': 'ansede', 'Accept': 'application/vnd.github+json'}

# Check repo
r = urllib.request.Request('https://api.github.com/repos/mattybellx/Ansede', headers=headers)
d = json.load(urllib.request.urlopen(r, timeout=10))
print('Repo state:')
print('  Description:', d.get('description', 'NOT SET'))
print('  Topics:', d.get('topics', []))
print('  Stars:', d.get('stargazers_count', 0))

# Check forks
print()
for repo in ['mattybellx/awesome-security', 'mattybellx/awesome-devsecops']:
    try:
        r2 = urllib.request.Request(f'https://api.github.com/repos/{repo}', headers=headers)
        d2 = json.load(urllib.request.urlopen(r2, timeout=10))
        print(f'Fork EXISTS: {repo}')
    except urllib.error.HTTPError as e:
        if e.code == 404:
            print(f'Fork MISSING: {repo}')

# Check open PRs
print()
try:
    r3 = urllib.request.Request(
        'https://api.github.com/search/issues?q=type:pr+author:mattybellx+is:open',
        headers=headers
    )
    d3 = json.load(urllib.request.urlopen(r3, timeout=10))
    prs = d3.get('items', [])
    print(f'Open PRs by mattybellx: {len(prs)}')
    for pr in prs:
        print(f'  {pr["html_url"]}')
        print(f'  {pr["title"][:100]}')
except Exception as e:
    print(f'PR check error: {e}')
