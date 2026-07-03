"""Check CI job details."""
import urllib.request, json, os

token = os.environ.get('GITHUB_TOKEN','').strip()
headers = {'Accept':'application/vnd.github+json','User-Agent':'ansede'}
if token: headers['Authorization'] = f'Bearer {token}'

runs_url = 'https://api.github.com/repos/mattybellx/Ansede/actions/runs?per_page=5'
req = urllib.request.Request(runs_url, headers=headers)
with urllib.request.urlopen(req, timeout=15) as resp:
    data = json.load(resp)

# Find the CI workflow run
for run in data.get('workflow_runs', []):
    if run['name'] == 'CI' and run['status'] == 'completed':
        print(f"CI Workflow: conclusion={run.get('conclusion')}")
        jobs_url = run['jobs_url']
        req2 = urllib.request.Request(jobs_url, headers=headers)
        with urllib.request.urlopen(req2, timeout=15) as resp2:
            jobs = json.load(resp2)
        for job in jobs.get('jobs', []):
            icon = '+' if job.get('conclusion') == 'success' else 'x'
            steps = []
            for step in job.get('steps', []):
                if step.get('conclusion') != 'success':
                    steps.append(f"{step['name']} -> {step.get('conclusion')}")
            step_info = f" ({'; '.join(steps)})" if steps else ""
            print(f"  [{icon}] {job['name']:<35} {job.get('conclusion')}{step_info}")
        break
