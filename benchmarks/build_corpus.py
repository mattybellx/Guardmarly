"""Generate the labelled benchmark corpus used by ``run_benchmark.py``.

Every entry is a minimal, canonically-vulnerable (or canonically-safe) snippet
whose expected CWE set is declared here and nowhere else.  The corpus is
written out as real files under ``benchmarks/corpus/`` so that the scanner is
exercised through its normal file-discovery path and so that a reviewer can
read exactly what was scanned.

Ground-truth rules
------------------
* ``positives``  — the snippet is genuinely vulnerable; the declared CWEs are
  what a competent human auditor would report.  A scan that reports any of the
  declared CWEs at the declared line is a true positive; a scan that reports
  nothing is a miss.
* ``negatives``  — the snippet is safe.  *Any* security finding at all is a
  false positive.  These are written to look superficially like their
  vulnerable twins (same callee, same shape, hardened argument or guard) so
  that pattern-only matchers are penalised.

Run ``python benchmarks/build_corpus.py`` to (re)generate the tree.
"""
from __future__ import annotations

import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
CORPUS = HERE / "corpus"


# --------------------------------------------------------------------------
# POSITIVES — (expected CWEs, source)
# --------------------------------------------------------------------------
POSITIVES: dict[str, tuple[list[str], str]] = {
    # ---------------------------------------------------------------- python
    "python/sqli_concat.py": (["CWE-89"], '''
from flask import Flask, request
import sqlite3

app = Flask(__name__)


@app.route("/user")
def user():
    name = request.args.get("name")
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = '" + name + "'")
    return str(cur.fetchall())
'''),
    "python/sqli_fstring.py": (["CWE-89"], '''
from flask import Flask, request

app = Flask(__name__)


@app.route("/order")
def order():
    oid = request.args.get("id")
    cursor = get_cursor()
    cursor.execute(f"SELECT * FROM orders WHERE id = {oid}")
    return "ok"
'''),
    "python/cmdi_os_system.py": (["CWE-78"], '''
from flask import Flask, request
import os

app = Flask(__name__)


@app.route("/ping")
def ping():
    host = request.args.get("host")
    os.system("ping -c 1 " + host)
    return "pong"
'''),
    "python/cmdi_subprocess_shell.py": (["CWE-78"], '''
import subprocess
from flask import request, Flask

app = Flask(__name__)


@app.route("/convert")
def convert():
    src = request.args.get("src")
    subprocess.run("convert " + src + " out.png", shell=True)
    return "done"
'''),
    "python/pathtraversal.py": (["CWE-22"], '''
import os
from flask import Flask, request

app = Flask(__name__)


@app.route("/download")
def download():
    name = request.args.get("file")
    with open(os.path.join("/srv/files", name)) as fh:
        return fh.read()
'''),
    "python/ssrf.py": (["CWE-918"], '''
import requests
from flask import Flask, request

app = Flask(__name__)


@app.route("/fetch")
def fetch():
    url = request.args.get("url")
    return requests.get(url).text
'''),
    "python/deserialization_pickle.py": (["CWE-502"], '''
import pickle
from flask import Flask, request

app = Flask(__name__)


@app.route("/load", methods=["POST"])
def load():
    blob = request.get_data()
    obj = pickle.loads(blob)
    return str(obj)
'''),
    "python/deserialization_yaml.py": (["CWE-502"], '''
import yaml
from flask import Flask, request

app = Flask(__name__)


@app.route("/config", methods=["POST"])
def config():
    doc = yaml.load(request.get_data())
    return str(doc)
'''),
    "python/weak_hash_md5.py": (["CWE-327"], '''
import hashlib


def fingerprint(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()
'''),
    "python/hardcoded_secret.py": (["CWE-798"], '''
AWS_ACCESS_KEY_ID = "QM4H7T2K9XRPLZR2MWVD"
AWS_SECRET_ACCESS_KEY = "K8vQ2mZxR7pT4nL9dW3yH6bC1gF5jS0a"
'''),
    "python/xss_render.py": (["CWE-79"], '''
from flask import Flask, request, render_template_string

app = Flask(__name__)


@app.route("/hello")
def hello():
    name = request.args.get("name")
    return render_template_string("<h1>Hello " + name + "</h1>")
'''),
    "python/idor_django.py": (["CWE-639"], '''
from django.http import JsonResponse
from .models import Invoice


def invoice_detail(request, invoice_id):
    invoice = Invoice.objects.get(pk=invoice_id)
    return JsonResponse({"total": invoice.total})
'''),
    "python/open_redirect.py": (["CWE-601"], '''
from flask import Flask, request, redirect

app = Flask(__name__)


@app.route("/go")
def go():
    return redirect(request.args.get("next"))
'''),
    "python/xxe.py": (["CWE-611"], '''
from flask import Flask, request
from lxml import etree

app = Flask(__name__)


@app.route("/parse", methods=["POST"])
def parse():
    parser = etree.XMLParser(resolve_entities=True)
    tree = etree.fromstring(request.get_data(), parser)
    return etree.tostring(tree)
'''),
    # ------------------------------------------------------------ javascript
    "javascript/sqli_concat.js": (["CWE-89"], '''
const express = require("express");
const app = express();

app.get("/user", function (req, res) {
  const name = req.query.name;
  db.query("SELECT * FROM users WHERE name = '" + name + "'", function (err, rows) {
    res.json(rows);
  });
});
'''),
    "javascript/sqli_template.js": (["CWE-89"], '''
const app = require("express").Router();

app.get("/order", async (req, res) => {
  const id = req.query.id;
  const rows = await pool.query(`SELECT * FROM orders WHERE id = ${id}`);
  res.json(rows);
});
'''),
    "javascript/cmdi_exec.js": (["CWE-78"], '''
const express = require("express");
const { exec } = require("child_process");
const app = express();

app.get("/ping", function (req, res) {
  const host = req.query.host;
  exec("ping -c 1 " + host, function (err, stdout) {
    res.send(stdout);
  });
});
'''),
    "javascript/pathtraversal.js": (["CWE-22"], '''
const express = require("express");
const fs = require("fs");
const path = require("path");
const app = express();

app.get("/download", function (req, res) {
  const file = req.query.file;
  res.send(fs.readFileSync(path.join("/srv/files", file)));
});
'''),
    "javascript/ssrf_axios.js": (["CWE-918"], '''
const express = require("express");
const axios = require("axios");
const app = express();

app.get("/proxy", async function (req, res) {
  const url = req.query.url;
  const response = await axios.get(url);
  res.send(response.data);
});
'''),
    "javascript/xss_innerhtml.js": (["CWE-79"], '''
const express = require("express");
const app = express();

app.get("/hello", function (req, res) {
  const name = req.query.name;
  document.getElementById("out").innerHTML = "Hello " + name;
});
'''),
    "javascript/idor_express.js": (["CWE-639"], '''
const express = require("express");
const app = express();

app.get("/api/invoice/:invoiceId", async function (req, res) {
  const invoice = await Invoice.findById(req.params.invoiceId);
  res.json(invoice);
});
'''),
    "javascript/eval_user_input.js": (["CWE-95"], '''
const express = require("express");
const app = express();

app.post("/calc", function (req, res) {
  const expr = req.body.expr;
  const value = eval(expr);
  res.json({ value: value });
});
'''),
    "javascript/prototype_pollution.js": (["CWE-1321"], '''
const express = require("express");
const app = express();

app.post("/merge", function (req, res) {
  const target = {};
  Object.assign(target, req.body);
  res.json(target);
});
'''),
    "javascript/insecure_tls.js": (["CWE-295"], '''
const https = require("https");

const agent = new https.Agent({ rejectUnauthorized: false });
module.exports = { agent: agent };
'''),
    # ------------------------------------------------------------------ java
    "java/SqlInjection.java": (["CWE-89"], '''
package com.example;

import java.sql.Connection;
import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;

public class SqlInjection {
    public void lookup(Connection conn, HttpServletRequest request) throws Exception {
        String name = request.getParameter("name");
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
    }
}
'''),
    "java/CommandInjection.java": (["CWE-78"], '''
package com.example;

import javax.servlet.http.HttpServletRequest;

public class CommandInjection {
    public void ping(HttpServletRequest request) throws Exception {
        String host = request.getParameter("host");
        Runtime.getRuntime().exec("ping -c 1 " + host);
    }
}
'''),
    "java/PathTraversal.java": (["CWE-22"], '''
package com.example;

import java.io.File;
import java.io.FileInputStream;
import javax.servlet.http.HttpServletRequest;

public class PathTraversal {
    public byte[] read(HttpServletRequest request) throws Exception {
        String name = request.getParameter("file");
        File f = new File("/srv/files/" + name);
        FileInputStream in = new FileInputStream(f);
        return in.readAllBytes();
    }
}
'''),
    "java/UnsafeDeserialization.java": (["CWE-502"], '''
package com.example;

import java.io.ObjectInputStream;
import javax.servlet.http.HttpServletRequest;

public class UnsafeDeserialization {
    public Object load(HttpServletRequest request) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(request.getInputStream());
        return ois.readObject();
    }
}
'''),
    "java/WeakCrypto.java": (["CWE-327"], '''
package com.example;

import java.security.MessageDigest;

public class WeakCrypto {
    public byte[] hash(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(data);
    }
}
'''),
    "java/OpenRedirect.java": (["CWE-601"], '''
package com.example;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class OpenRedirect {
    public void go(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String next = request.getParameter("next");
        response.sendRedirect(next);
    }
}
'''),
    # -------------------------------------------------------------------- go
    "go/sqli_concat.go": (["CWE-89"], '''
package main

import (
	"database/sql"
	"net/http"
)

func user(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	row := db.QueryRow("SELECT * FROM users WHERE name = '" + name + "'")
	_ = row
	_ = sql.ErrNoRows
}
'''),
    "go/cmdi_exec.go": (["CWE-78"], '''
package main

import (
	"net/http"
	"os/exec"
)

func ping(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	cmd := exec.Command("sh", "-c", "ping -c 1 "+host)
	_ = cmd.Run()
}
'''),
    "go/pathtraversal_readfile.go": (["CWE-22"], '''
package main

import (
	"net/http"
	"os"
	"path/filepath"
)

func download(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("file")
	data, _ := os.ReadFile(filepath.Join("/srv/files", name))
	w.Write(data)
}
'''),
    # -------------------------------------------------------------------- c#
    "csharp/SqlInjection.cs": (["CWE-89"], '''
using System.Data.SqlClient;
using Microsoft.AspNetCore.Mvc;

public class UsersController : Controller
{
    public IActionResult Lookup(string name)
    {
        var conn = new SqlConnection(ConnStr);
        var cmd = new SqlCommand("SELECT * FROM users WHERE name = '" + name + "'", conn);
        cmd.ExecuteReader();
        return Ok();
    }
}
'''),
    "csharp/CommandInjection.cs": (["CWE-78"], '''
using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;

public class ToolsController : Controller
{
    public IActionResult Ping(string host)
    {
        Process.Start("cmd.exe", "/c ping -c 1 " + host);
        return Ok();
    }
}
'''),
    "csharp/InsecureDeserialization.cs": (["CWE-502"], '''
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;

public class Loader
{
    public object Load(Stream stream)
    {
        var formatter = new BinaryFormatter();
        return formatter.Deserialize(stream);
    }
}
'''),
}


# --------------------------------------------------------------------------
# NEGATIVES — canonically safe code that a pattern-only matcher may flag
# --------------------------------------------------------------------------
NEGATIVES: dict[str, str] = {
    "python/clean/parameterized_query.py": '''
import sqlite3
from flask import Flask, request

app = Flask(__name__)


@app.route("/user")
def user():
    name = request.args.get("name")
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = ?", (name,))
    return str(cur.fetchall())
''',
    "python/clean/subprocess_list_form.py": '''
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/ping")
def ping():
    host = request.args.get("host")
    subprocess.run(["ping", "-c", "1", host], check=False)
    return "pong"
''',
    "python/clean/safe_yaml.py": '''
import yaml
from flask import Flask, request

app = Flask(__name__)


@app.route("/config", methods=["POST"])
def config():
    doc = yaml.safe_load(request.get_data())
    return str(doc)
''',
    "python/clean/os_path_basename.py": '''
import os
from flask import Flask, request

app = Flask(__name__)


@app.route("/download")
def download():
    name = os.path.basename(request.args.get("file", ""))
    with open(os.path.join("/srv/files", name)) as fh:
        return fh.read()
''',
    "python/clean/constant_url.py": '''
import requests


def health() -> str:
    return requests.get("https://example.com/health", timeout=5).text
''',
    "python/clean/strong_hash.py": '''
import hashlib


def fingerprint(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
''',
    "python/clean/secrets_from_env.py": '''
import os

AWS_ACCESS_KEY_ID = os.environ["AWS_ACCESS_KEY_ID"]
AWS_SECRET_ACCESS_KEY = os.environ["AWS_SECRET_ACCESS_KEY"]
''',
    "python/clean/owner_scoped_django.py": '''
from django.http import JsonResponse
from .models import Invoice


def invoice_detail(request, invoice_id):
    invoice = Invoice.objects.get(pk=invoice_id, owner=request.user)
    return JsonResponse({"total": invoice.total})
''',
    "javascript/clean/parameterized_query.js": '''
const express = require("express");
const app = express();

app.get("/user", async function (req, res) {
  const name = req.query.name;
  const rows = await db.query("SELECT * FROM users WHERE name = $1", [name]);
  res.json(rows);
});
''',
    "javascript/clean/execfile_arguments.js": '''
const express = require("express");
const { execFile } = require("child_process");
const app = express();

app.get("/ping", function (req, res) {
  const host = req.query.host;
  execFile("ping", ["-c", "1", host], function (err, stdout) {
    res.send(stdout);
  });
});
''',
    "javascript/clean/static_fetch.js": '''
const axios = require("axios");

async function health() {
  const response = await axios.get("https://example.com/health");
  return response.data;
}

module.exports = { health: health };
''',
    "javascript/clean/owner_scoped_express.js": '''
const express = require("express");
const app = express();

app.get("/api/invoice/:invoiceId", async function (req, res) {
  const invoice = await Invoice.findOne({
    where: { id: req.params.invoiceId, userId: req.user.id },
  });
  res.json(invoice);
});
''',
    "javascript/clean/textcontent.js": '''
const express = require("express");
const app = express();

app.get("/hello", function (req, res) {
  const name = req.query.name;
  document.getElementById("out").textContent = "Hello " + name;
});
''',
    "javascript/clean/tls_verified.js": '''
const https = require("https");

const agent = new https.Agent({ rejectUnauthorized: true });
module.exports = { agent: agent };
''',
    "java/clean/ParameterizedQuery.java": '''
package com.example;

import java.sql.Connection;
import java.sql.PreparedStatement;
import javax.servlet.http.HttpServletRequest;

public class ParameterizedQuery {
    public void lookup(Connection conn, HttpServletRequest request) throws Exception {
        String name = request.getParameter("name");
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE name = ?");
        ps.setString(1, name);
        ps.executeQuery();
    }
}
''',
    "java/clean/StrongCrypto.java": '''
package com.example;

import java.security.MessageDigest;

public class StrongCrypto {
    public byte[] hash(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(data);
    }
}
''',
    "java/clean/ConstantRedirect.java": '''
package com.example;

import javax.servlet.http.HttpServletResponse;

public class ConstantRedirect {
    public void go(HttpServletResponse response) throws Exception {
        response.sendRedirect("/home");
    }
}
''',
    "go/clean/parameterized_query.go": '''
package main

import "net/http"

func user(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	row := db.QueryRow("SELECT * FROM users WHERE name = $1", name)
	_ = row
}
''',
    "csharp/clean/ParameterizedQuery.cs": '''
using System.Data.SqlClient;
using Microsoft.AspNetCore.Mvc;

public class UsersController : Controller
{
    public IActionResult Lookup(string name)
    {
        var conn = new SqlConnection(ConnStr);
        var cmd = new SqlCommand("SELECT * FROM users WHERE name = @name", conn);
        cmd.Parameters.AddWithValue("@name", name);
        cmd.ExecuteReader();
        return Ok();
    }
}
''',
}


def main() -> int:
    written = 0
    for rel, (_cwes, src) in POSITIVES.items():
        path = CORPUS / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(src.lstrip("\n"), encoding="utf-8")
        written += 1
    for rel, src in NEGATIVES.items():
        path = CORPUS / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(src.lstrip("\n"), encoding="utf-8")
        written += 1

    manifest = {
        "note": (
            "Ground truth for the Guardmarly benchmark corpus. "
            "'positives' map a corpus-relative path to the CWE set a human "
            "auditor would report. 'negatives' are safe code: any security "
            "finding against them is a false positive."
        ),
        "positives": {k: v[0] for k, v in POSITIVES.items()},
        "negatives": sorted(NEGATIVES),
    }
    (HERE / "ground_truth.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    print(f"corpus: {written} files written to {CORPUS}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
