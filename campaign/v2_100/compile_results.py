"""Compile deep audit results from terminal output into final JSON."""
import json
from datetime import datetime, timezone

results = {
    'js-axios': (133, 18, 109, 6),
    'js-cheerio': (1, 0, 1, 0),
    'js-express': (200, 0, 198, 2),
    'js-fastify': (200, 6, 194, 0),
    'js-hono': (200, 46, 94, 60),
    'js-koa': (0, 0, 0, 0),
    'js-lodash': (8, 3, 5, 0),
    'js-moment': (49, 47, 2, 0),
    'js-nest': 'TIMEOUT',
    'js-react': 'TIMEOUT',
    'js-socketio': (44, 0, 35, 9),
    'py-aiohttp': 'TIMEOUT',
    'py-apscheduler': (56, 23, 29, 4),
    'py-bottle': (66, 34, 24, 8),
    'py-celery': 'TIMEOUT',
    'py-django': 'SKIP',
    'py-dramatiq': (105, 43, 56, 6),
    'py-fastapi': 'TIMEOUT',
    'py-flask': (200, 8, 158, 34),
    'py-httpx': (167, 13, 145, 9),
    'py-loguru': (78, 27, 44, 7),
    'py-marshmallow': (79, 1, 78, 0),
    'py-peewee': (174, 42, 110, 22),
    'py-pydantic': 'TIMEOUT',
    'py-requests': (79, 13, 57, 9),
    'py-rich': (99, 57, 32, 10),
    'py-sanic': 'TIMEOUT',
    'py-scrapy': 'TIMEOUT',
    'py-sqlalchemy': 'TIMEOUT',
    'py-starlette': (200, 24, 167, 9),
    'py-tornado': 'INCOMPLETE',
}

tp = fp = nr = total_findings = 0
summary = {}

for repo, val in sorted(results.items()):
    if val == 'TIMEOUT':
        summary[repo] = {'status': 'TIMEOUT', 'findings': 0}
    elif val == 'SKIP':
        summary[repo] = {'status': 'SKIP', 'findings': 0}
    elif val == 'INCOMPLETE':
        summary[repo] = {'status': 'INCOMPLETE', 'findings': 0}
    else:
        f, t, fp1, n = val
        summary[repo] = {'status': 'OK', 'findings': f, 'tp': t, 'fp': fp1, 'nr': n}
        tp += t
        fp += fp1
        nr += n
        total_findings += f

classified = tp + fp
pct = round(tp / classified * 100, 1) if classified else 0

out = {
    'ts': datetime.now(timezone.utc).isoformat(),
    'total_findings': total_findings,
    'tp': tp,
    'fp': fp,
    'nr': nr,
    'precision_pct': pct,
    'completed_repos': len([v for v in summary.values() if v.get('status') == 'OK']),
    'total_repos': len(results),
    'timeout_repos': len([v for v in summary.values() if v.get('status') == 'TIMEOUT']),
    'summary': summary,
}

with open('campaign/v2_100/deep_audit_final.json', 'w') as fh:
    json.dump(out, fh, indent=2)

print(f"TP={tp}  FP={fp}  NR={nr}  Precision={pct}%")
print(f"Completed: {out['completed_repos']}/31 repos, {out['timeout_repos']} timeouts")
print(f"Total findings: {total_findings}")
print("Saved: campaign/v2_100/deep_audit_final.json")
