"""Check all CI jobs with details."""
import urllib.request, json, os

token = os.environ.get('GITHUB_TOKEN','').strip()
headers = {'Accept':'application/vnd.github+json','User-Agent':'ansede-release'}
if token: headers['Authorization'] = 'Bearer ' + token

runs_url = 'https://api.github.com/repos/mattybellx/Ansede/actions/runs?per_page=10'
req = urllib.request.Request(runs_url, headers=headers)
with urllib.request.urlopen(req, timeout=15) as resp:
    data = json.load(resp)

for run in data.get('workflow_runs', []):
    name = run['name']
    status = run['status']
    conclusion = run.get('conclusion', '-')
    icon = '+' if conclusion == 'success' else ('x' if conclusion == 'failure' else '?')
    print(f'[{icon}] {name:<50} {status:<12} {conclusion}')

    if conclusion == 'failure' and status == 'completed':
        jobs_url = run['jobs_url']
        try:
            req2 = urllib.request.Request(jobs_url, headers=headers)
            with urllib.request.urlopen(req2, timeout=15) as resp2:
                jobs = json.load(resp2)
            for job in jobs.get('jobs', []):
                jc = job.get('conclusion', '-')
                ji = '+' if jc == 'success' else 'x'
                print(f'    [{ji}] {job["name"]:<40} {jc}')
                for step in job.get('steps', []):
                    if step.get('conclusion') not in ('success', 'skipped', None):
                        print(f'         FAILED STEP: {step["name"]}')
        except:
            pass

print("\n--- All recent runs above ---")
