"""Update GitHub repo settings: description, topics, website."""
import urllib.request, json, os

token = os.environ.get('GITHUB_TOKEN','').strip()
if not token:
    print('NO TOKEN')
    exit(1)

headers = {
    'Accept': 'application/vnd.github+json',
    'Authorization': 'Bearer ' + token,
    'User-Agent': 'ansede-release'
}

data = json.dumps({
    'description': 'Offline SAST that detects IDOR, missing authentication, and ownership bypass. OWASP recall 62%, CVE recall 96.3% across 5 languages. Beats Semgrep OSS on recall.',
    'topics': ['sast', 'static-analysis', 'security', 'python', 'owasp', 'idor', 'cwe', 'security-scanner', 'code-review', 'devsecops', 'offline', 'authorization', 'authentication', 'javascript', 'cli', 'sarif'],
    'homepage': 'https://pypi.org/project/ansede-static/'
}).encode()

url = 'https://api.github.com/repos/mattybellx/Ansede'
req = urllib.request.Request(url, data=data, headers=headers, method='PATCH')

try:
    with urllib.request.urlopen(req, timeout=15) as resp:
        result = json.load(resp)
    desc = result.get('description', '')
    topics = result.get('topics', [])
    print('OK: Repo updated')
    print('Description:', desc[:80])
    print('Topics:', topics)
except urllib.error.HTTPError as e:
    print('API Error:', e.code, e.reason)
    print(e.read().decode()[:500])
