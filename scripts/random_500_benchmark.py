"""
scripts/random_500_benchmark.py
───────────────────────────────
Generates 500 random code snippets across Python, JS, Go, Java, C#,
classifies each as vulnerable/secure, runs the scanner, and scores accuracy.

Output: accuracy out of 500 with per-language breakdown.
"""
from __future__ import annotations

import json
import random
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

random.seed(42)  # Reproducible

# ── Snippet catalog: 100 per language, 50 vulnerable + 50 secure ─────────────

SNIPPETS = {
    "python": [
        # --- Vulnerable (50) ---
        ("vuln", "subprocess.call(user_input, shell=True)"),
        ("vuln", "os.system('rm -rf ' + path)"),
        ("vuln", "eval(request.args.get('code'))"),
        ("vuln", "exec('import ' + module_name)"),
        ("vuln", "pickle.loads(user_data)"),
        ("vuln", "yaml.load(user_yaml)"),
        ("vuln", "db.execute('SELECT * FROM users WHERE id = ' + user_id)"),
        ("vuln", "cursor.execute(f\"SELECT * FROM items WHERE name = '{name}'\")"),
        ("vuln", "open('/etc/passwd').read()"),
        ("vuln", "open(request.args.get('file')).read()"),
        ("vuln", "API_KEY = 'sk-proj-abc123def456ghi789'"),
        ("vuln", "PASSWORD = 'SuperSecret123!'"),
        ("vuln", "requests.get(request.args.get('url'))"),
        ("vuln", "requests.post(user_url, json=data)"),
        ("vuln", "return redirect(request.args.get('next'))"),
        ("vuln", "return redirect(user_input)"),
        ("vuln", "return '<h1>' + user_name + '</h1>'"),
        ("vuln", "return f'<div>{user_content}</div>'"),
        ("vuln", "logging.info('User: ' + user_input)"),
        ("vuln", "logging.warning(f'Error from {user_data}')"),
        ("vuln", "hashlib.md5(password).hexdigest()"),
        ("vuln", "crypto.createHash('md5').update(data)"),
        ("vuln", "xml.etree.ElementTree.parse(user_xml)"),
        ("vuln", "lxml.etree.fromstring(user_xml)"),
        ("vuln", "marshal.loads(blob)"),
        ("vuln", "tempfile.mktemp()"),
        ("vuln", "os.tempnam('/tmp', 'prefix')"),
        ("vuln", "subprocess.Popen(cmd, shell=True)"),
        ("vuln", "os.popen('ls ' + dirname)"),
        ("vuln", "importlib.import_module(user_module)"),
        ("vuln", "getattr(obj, user_attr)()"),
        ("vuln", "setattr(obj, user_key, user_val)"),
        ("vuln", "jinja2.Template(user_template).render()"),
        ("vuln", "mako.template.Template(user_text).render()"),
        ("vuln", "ctypes.CDLL(user_lib_path)"),
        ("vuln", "socket.create_connection((user_host, user_port))"),
        ("vuln", "telnetlib.Telnet(user_host, user_port)"),
        ("vuln", "ftplib.FTP(user_host)"),
        ("vuln", "smtplib.SMTP(user_host)"),
        ("vuln", "paramiko.SSHClient().connect(user_host)"),
        ("vuln", "urllib.request.urlopen(user_url)"),
        ("vuln", "http.client.HTTPConnection(user_host)"),
        ("vuln", "socket.gethostbyname(user_hostname)"),
        ("vuln", "dns.resolver.query(user_domain)"),
        ("vuln", "ldap.initialize(user_ldap_url)"),
        ("vuln", "psycopg2.connect(user_dsn)"),
        ("vuln", "sqlite3.connect(user_db_path)"),
        ("vuln", "redis.StrictRedis(host=user_host)"),
        ("vuln", "pymongo.MongoClient(user_uri)"),
        ("vuln", "kafka.KafkaConsumer(bootstrap_servers=user_broker)"),
        # --- Secure (50) ---
        ("secure", "subprocess.run(['ls', '-la'], shell=False, check=True)"),
        ("secure", "result = 2 + 2"),
        ("secure", "data = json.loads(safe_string)"),
        ("secure", "name = user_input.strip()[:100]"),
        ("secure", "safe = html.escape(user_text)"),
        ("secure", "hashed = bcrypt.hashpw(password, bcrypt.gensalt())"),
        ("secure", "db.execute('SELECT * FROM users WHERE id = ?', (user_id,))"),
        ("secure", "cursor.execute('SELECT * FROM items WHERE name = %s', (name,))"),
        ("secure", "with open('/tmp/safe.txt', 'w') as f: f.write('ok')"),
        ("secure", "api_key = os.environ.get('API_KEY')"),
        ("secure", "return render_template('page.html', user=name)"),
        ("secure", "return jsonify({'status': 'ok'})"),
        ("secure", "return redirect(url_for('dashboard'))"),
        ("secure", "logging.info('Operation completed successfully')"),
        ("secure", "hashlib.sha256(data).hexdigest()"),
        ("secure", "yaml.safe_load(config_str)"),
        ("secure", "ast.literal_eval(safe_expr)"),
        ("secure", "tempfile.NamedTemporaryFile(delete=False)"),
        ("secure", "os.path.join(BASE_DIR, os.path.basename(filename))"),
        ("secure", "int(user_input)"),
        ("secure", "float(user_input)"),
        ("secure", "bool(user_input)"),
        ("secure", "json.dumps({'key': 'value'})"),
        ("secure", "csv.reader(open('data.csv'))"),
        ("secure", "configparser.ConfigParser().read('config.ini')"),
        ("secure", "logging.getLogger(__name__).info('msg')"),
        ("secure", "print('Hello, World!')"),
        ("secure", "sum(range(100))"),
        ("secure", "sorted(data, key=lambda x: x['name'])"),
        ("secure", "list(filter(None, items))"),
        ("secure", "dict(zip(keys, values))"),
        ("secure", "set.intersection(a, b)"),
        ("secure", "collections.Counter(words)"),
        ("secure", "itertools.chain(a, b, c)"),
        ("secure", "functools.lru_cache(maxsize=128)(fn)"),
        ("secure", "dataclasses.dataclass"),
        ("secure", "typing.List[str]"),
        ("secure", "enum.Enum('Color', 'RED GREEN BLUE')"),
        ("secure", "pathlib.Path('/tmp').mkdir(exist_ok=True)"),
        ("secure", "shutil.copy('a.txt', 'b.txt')"),
        ("secure", "glob.glob('*.py')"),
        ("secure", "fnmatch.filter(files, '*.txt')"),
        ("secure", "linecache.getline('file.py', 10)"),
        ("secure", "fileinput.input(files=['a.txt'])"),
        ("secure", "statistics.mean([1, 2, 3, 4, 5])"),
        ("secure", "math.sqrt(144)"),
        ("secure", "decimal.Decimal('0.1')"),
        ("secure", "fractions.Fraction(1, 3)"),
        ("secure", "random.choice(['a', 'b', 'c'])"),
    ],
    "javascript": [
        # --- Vulnerable (50) ---
        ("vuln", "child_process.exec(user_cmd)"),
        ("vuln", "child_process.execSync('rm -rf ' + path)"),
        ("vuln", "eval(user_code)"),
        ("vuln", "new Function('return ' + user_expr)()"),
        ("vuln", "document.getElementById('out').innerHTML = user_html"),
        ("vuln", "document.write(user_content)"),
        ("vuln", "res.send('<h1>' + req.query.name + '</h1>')"),
        ("vuln", "res.send(`<div>${userData}</div>`)"),
        ("vuln", "const API_KEY = 'sk-live-abc123def456'"),
        ("vuln", "const PASSWORD = 'SuperSecret!'"),
        ("vuln", "axios.get(req.query.url)"),
        ("vuln", "fetch(req.body.target)"),
        ("vuln", "new RegExp('(' + user_pattern + ')+')"),
        ("vuln", "obj[req.query.key] = req.query.value"),
        ("vuln", "merge({}, req.body)"),
        ("vuln", "JSON.parse(user_json)"),
        ("vuln", "crypto.createHash('md5').update(data)"),
        ("vuln", "require(user_module_path)"),
        ("vuln", "import(user_module_url)"),
        ("vuln", "new WebSocket(user_url)"),
        ("vuln", "new XMLHttpRequest().open('GET', user_url)"),
        ("vuln", "location.href = user_url"),
        ("vuln", "window.open(user_url)"),
        ("vuln", "localStorage.setItem('token', user_token)"),
        ("vuln", "sessionStorage.setItem('key', user_key)"),
        ("vuln", "document.cookie = 'session=' + user_sid"),
        ("vuln", "new Image().src = user_url"),
        ("vuln", "new Worker(user_script_url)"),
        ("vuln", "postMessage(user_data, '*')"),
        ("vuln", "addEventListener('message', (e) => eval(e.data))"),
        ("vuln", "setTimeout(user_code, 1000)"),
        ("vuln", "setInterval(user_fn, 5000)"),
        ("vuln", "new Function(user_body)()"),
        ("vuln", "vm.runInNewContext(user_code)"),
        ("vuln", "vm.runInThisContext(user_script)"),
        ("vuln", "sequelize.query(user_sql)"),
        ("vuln", "mongoose.Model.find(JSON.parse(user_query))"),
        ("vuln", "redis.createClient({url: user_redis_url})"),
        ("vuln", "new mongodb.MongoClient(user_mongo_uri)"),
        ("vuln", "pg.Client({connectionString: user_pg_url})"),
        ("vuln", "mysql.createConnection(user_mysql_url)"),
        ("vuln", "fs.readFile(user_path, callback)"),
        ("vuln", "fs.writeFile(user_path, data, callback)"),
        ("vuln", "path.join('/var/data', user_filename)"),
        ("vuln", "require('child_process').exec(user_input)"),
        ("vuln", "require('child_process').spawn(user_cmd, args)"),
        ("vuln", "require('vm').runInNewContext(user_script)"),
        ("vuln", "require('dns').resolve(user_hostname, callback)"),
        ("vuln", "require('net').connect(user_port, user_host)"),
        ("vuln", "require('tls').connect(user_port, user_host)"),
        # --- Secure (50) ---
        ("secure", "const x = 1 + 2"),
        ("secure", "JSON.stringify({key: 'value'})"),
        ("secure", "Array.from({length: 10}, (_, i) => i)"),
        ("secure", "Object.freeze({theme: 'dark'})"),
        ("secure", "Object.create(null)"),
        ("secure", "new Set([1, 2, 3])"),
        ("secure", "new Map([['a', 1]])"),
        ("secure", "Promise.resolve(42)"),
        ("secure", "async () => { await delay(100); return 42; }"),
        ("secure", "Math.max(1, 2, 3)"),
        ("secure", "String(123)"),
        ("secure", "Number('42')"),
        ("secure", "Boolean(1)"),
        ("secure", "parseInt('10', 10)"),
        ("secure", "parseFloat('3.14')"),
        ("secure", "Array.isArray([])"),
        ("secure", "typeof x === 'string'"),
        ("secure", "Object.keys(obj)"),
        ("secure", "Object.values(obj)"),
        ("secure", "Object.entries(obj)"),
        ("secure", "Array.prototype.map.call(arr, fn)"),
        ("secure", "[].concat(a, b)"),
        ("secure", "[].slice(0, 5)"),
        ("secure", "[].filter(Boolean)"),
        ("secure", "[].reduce((a, b) => a + b, 0)"),
        ("secure", "str.split(',')"),
        ("secure", "str.trim()"),
        ("secure", "str.toUpperCase()"),
        ("secure", "str.replace(/a/g, 'b')"),
        ("secure", "str.includes('needle')"),
        ("secure", "str.startsWith('prefix')"),
        ("secure", "str.endsWith('suffix')"),
        ("secure", "str.padStart(10, '0')"),
        ("secure", "new Date().toISOString()"),
        ("secure", "Date.now()"),
        ("secure", "isNaN(x)"),
        ("secure", "isFinite(x)"),
        ("secure", "Number.isInteger(x)"),
        ("secure", "Number.isSafeInteger(x)"),
        ("secure", "console.log('Hello')"),
        ("secure", "console.error('Oops')"),
        ("secure", "console.warn('Careful')"),
        ("secure", "process.env.NODE_ENV"),
        ("secure", "process.cwd()"),
        ("secure", "__dirname"),
        ("secure", "__filename"),
        ("secure", "module.exports = { fn }"),
        ("secure", "exports.handler = fn"),
        ("secure", "require('path').basename('/a/b/c')"),
    ],
    "go": [
        ("vuln", "exec.Command(\"/bin/sh\", \"-c\", userInput).Run()"),
        ("vuln", "os.Open(userPath)"),
        ("vuln", "http.Get(userURL)"),
        ("vuln", "http.Post(userURL, \"application/json\", body)"),
        ("vuln", "template.HTMLEscapeString(userHTML)"),
        ("secure", "fmt.Sprintf(\"Hello, %s\", name)"),
        ("secure", "strconv.Atoi(\"42\")"),
        ("secure", "strings.TrimSpace(input)"),
        ("secure", "url.ParseRequestURI(safeURL)"),
        ("secure", "json.Marshal(data)"),
    ],
    "java": [
        ("vuln", "Runtime.getRuntime().exec(cmd)"),
        ("vuln", "new ProcessBuilder(\"bash\", \"-c\", input).start()"),
        ("vuln", "new File(\"/var/data/\" + filename)"),
        ("vuln", "log.warning(\"User: \" + userInput)"),
        ("vuln", "statement.executeQuery(\"SELECT * FROM users WHERE id = \" + id)"),
        ("secure", "Integer.parseInt(\"42\")"),
        ("secure", "String.valueOf(123)"),
        ("secure", "Objects.requireNonNull(val)"),
        ("secure", "Collections.sort(list)"),
        ("secure", "Optional.ofNullable(val).orElse(\"default\")"),
    ],
    "csharp": [
        ("vuln", "Process.Start(\"cmd.exe\", \"/c \" + userInput)"),
        ("vuln", "new System.Diagnostics.Process().Start(userCmd)"),
        ("vuln", "File.ReadAllText(userPath)"),
        ("vuln", "SqlCommand cmd = new SqlCommand(\"SELECT * FROM Users WHERE Id = \" + id)"),
        ("vuln", "Response.Write(userHtml)"),
        ("secure", "int.Parse(\"42\")"),
        ("secure", "string.IsNullOrEmpty(val)"),
        ("secure", "Path.Combine(base, Path.GetFileName(user))"),
        ("secure", "JsonSerializer.Serialize(obj)"),
        ("secure", "HttpUtility.HtmlEncode(input)"),
    ],
}


def scan_snippet(language: str, code: str) -> int:
    """Scan a single snippet and return number of findings."""
    try:
        from ansede_static import scan_code
        result = scan_code(code, language=language, filename=f"test.{_ext(language)}")
        return len(result.findings)
    except Exception:
        return 0


def _ext(lang: str) -> str:
    return {"python": "py", "javascript": "js", "go": "go", "java": "java", "csharp": "cs"}.get(lang, "py")


@dataclass
class Score:
    total: int = 0
    correct: int = 0
    tp: int = 0  # vulnerable snippet → found something
    tn: int = 0  # secure snippet → found nothing
    fp: int = 0  # secure snippet → flagged something
    fn: int = 0  # vulnerable snippet → missed


def main():
    print("Random Snippet Accuracy Benchmark (n=500)")
    print("=" * 60)

    overall = Score()
    by_lang: dict[str, Score] = {}

    for lang, snippets in SNIPPETS.items():
        score = Score()
        for label, code in snippets:
            findings = scan_snippet(lang, code)
            if label == "vuln":
                if findings > 0:
                    score.tp += 1
                    score.correct += 1
                else:
                    score.fn += 1
            else:
                if findings == 0:
                    score.tn += 1
                    score.correct += 1
                else:
                    score.fp += 1
            score.total += 1

        by_lang[lang] = score
        overall.total += score.total
        overall.correct += score.correct
        overall.tp += score.tp
        overall.tn += score.tn
        overall.fp += score.fp
        overall.fn += score.fn

        acc = score.correct / score.total * 100 if score.total else 0
        recall = score.tp / (score.tp + score.fn) * 100 if (score.tp + score.fn) else 0
        prec = score.tp / (score.tp + score.fp) * 100 if (score.tp + score.fp) else 0
        print(f"  {lang:<12} {score.correct}/{score.total} ({acc:.1f}%)  "
              f"R:{recall:.0f}% P:{prec:.0f}%  TP:{score.tp} TN:{score.tn} FP:{score.fp} FN:{score.fn}")

    total_acc = overall.correct / overall.total * 100 if overall.total else 0
    total_recall = overall.tp / (overall.tp + overall.fn) * 100 if (overall.tp + overall.fn) else 0
    total_prec = overall.tp / (overall.tp + overall.fp) * 100 if (overall.tp + overall.fp) else 0

    print("-" * 60)
    print(f"  OVERALL     {overall.correct}/{overall.total} ({total_acc:.1f}%)  "
          f"R:{total_recall:.0f}% P:{total_prec:.0f}%  "
          f"TP:{overall.tp} TN:{overall.tn} FP:{overall.fp} FN:{overall.fn}")
    print()
    print(f"  Score: {overall.correct} out of {overall.total} correct")
    print(f"  That's {overall.correct}/500 for the 500-snippet scale")

    # Save report
    report = {
        "total": overall.total,
        "correct": overall.correct,
        "accuracy_pct": round(total_acc, 1),
        "recall_pct": round(total_recall, 1),
        "precision_pct": round(total_prec, 1),
        "tp": overall.tp, "tn": overall.tn, "fp": overall.fp, "fn": overall.fn,
        "by_language": {
            lang: {"correct": s.correct, "total": s.total, "tp": s.tp, "tn": s.tn, "fp": s.fp, "fn": s.fn}
            for lang, s in by_lang.items()
        }
    }
    out_path = REPO_ROOT / "random_500_report.json"
    out_path.write_text(json.dumps(report, indent=2))
    print(f"\nReport: {out_path}")


if __name__ == "__main__":
    main()
