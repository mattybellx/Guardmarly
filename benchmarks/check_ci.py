import urllib.request, json, os
token = os.environ.get('GITHUB_TOKEN','').strip()
headers = {'Accept':'application/vnd.github+json','User-Agent':'ansede'}
if token: headers['Authorization'] = f'Bearer {token}'
url = 'https://api.github.com/repos/mattybellx/Ansede/actions/runs?per_page=10'
req = urllib.request.Request(url, headers=headers)
with urllib.request.urlopen(req, timeout=15) as resp:
    data = json.load(resp)
for r in data.get('workflow_runs',[]):
    name = r['name']
    status = r['status']
    conclusion = r.get('conclusion','-')
    icon = '+' if conclusion == 'success' else ('x' if conclusion == 'failure' else '~')
    print(f'  [{icon}] {name:<45} {status:<12} {conclusion}')
