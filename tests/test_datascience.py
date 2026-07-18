"""Tests for the data science / ML security ruleset."""
from __future__ import annotations

import pytest

from guardmarly.rulesets.datascience import analyze_datascience


# ── DS-001: Path traversal via pandas read_csv ───────────────────────────────

def test_ds001_tainted_csv_path():
    code = '''
import pandas as pd
from flask import request

def load_data():
    path = request.args.get("file")
    df = pd.read_csv(path)
    return df
'''
    findings = analyze_datascience(code, "test.py")
    cwes = {f.cwe for f in findings}
    assert "CWE-22" in cwes


def test_ds001_safe_csv_path():
    code = '''
import pandas as pd

def load_data():
    df = pd.read_csv("/data/static_file.csv")
    return df
'''
    findings = analyze_datascience(code, "test.py")
    assert not any(f.cwe == "CWE-22" for f in findings)


# ── DS-002: Pandas query injection ───────────────────────────────────────────

def test_ds002_tainted_query():
    code = '''
import pandas as pd
from flask import request

def filter_data(df):
    user_input = request.args.get("filter")
    return df.query(user_input)
'''
    findings = analyze_datascience(code, "test.py")
    cwes = {f.cwe for f in findings}
    assert "CWE-89" in cwes


def test_ds002_safe_static_query():
    code = '''
import pandas as pd

def filter_data(df):
    return df.query("age > 18")
'''
    findings = analyze_datascience(code, "test.py")
    assert not any(f.cwe == "CWE-89" for f in findings)


# ── DS-003: pickle.loads with tainted data ───────────────────────────────────

def test_ds003_tainted_pickle_loads():
    code = '''
import pickle
from flask import request

def deserialize():
    data = request.get_data()
    obj = pickle.loads(data)
    return obj
'''
    findings = analyze_datascience(code, "test.py")
    cwes = {f.cwe for f in findings}
    assert "CWE-502" in cwes


# ── DS-004: yaml.load without SafeLoader ─────────────────────────────────────

def test_ds004_yaml_load_without_safeloader():
    code = '''
import yaml

def parse_config(data):
    return yaml.load(data)
'''
    findings = analyze_datascience(code, "test.py")
    cwes = {f.cwe for f in findings}
    assert "CWE-502" in cwes


def test_ds004_yaml_safe_load():
    code = '''
import yaml

def parse_config(data):
    return yaml.safe_load(data)
'''
    findings = analyze_datascience(code, "test.py")
    assert not any(f.cwe == "CWE-502" for f in findings)


def test_ds004_yaml_load_with_safe_loader():
    code = '''
import yaml

def parse_config(data):
    return yaml.load(data, Loader=yaml.SafeLoader)
'''
    findings = analyze_datascience(code, "test.py")
    assert not any(f.cwe == "CWE-502" for f in findings)


# ── DS-005: Spark SQL injection ───────────────────────────────────────────────

def test_ds005_tainted_spark_sql():
    code = '''
from flask import request

def run_query(spark):
    user_query = request.args.get("q")
    return spark.sql(user_query)
'''
    findings = analyze_datascience(code, "test.py")
    cwes = {f.cwe for f in findings}
    assert "CWE-89" in cwes


# ── DS-006: SSRF via pd.read_csv with tainted URL ────────────────────────────

def test_ds006_tainted_url_read_csv():
    code = '''
import pandas as pd
from flask import request

def load_remote():
    url = request.args.get("url")
    return pd.read_csv(url)
'''
    findings = analyze_datascience(code, "test.py")
    cwes = {f.cwe for f in findings}
    assert "CWE-918" in cwes or "CWE-22" in cwes


# ── DS-007: numpy.load with allow_pickle=True ────────────────────────────────

def test_ds007_numpy_load_allow_pickle():
    code = '''
import numpy as np
from flask import request

def load_array():
    data = request.get_data()
    return np.load(data, allow_pickle=True)
'''
    findings = analyze_datascience(code, "test.py")
    cwes = {f.cwe for f in findings}
    assert "CWE-502" in cwes


def test_ds007_numpy_load_no_pickle():
    code = '''
import numpy as np

def load_array():
    return np.load("safe_file.npy", allow_pickle=False)
'''
    findings = analyze_datascience(code, "test.py")
    assert not any(f.cwe == "CWE-502" for f in findings)


# ── Empty / parse-error resilience ───────────────────────────────────────────

def test_analyze_empty_code():
    assert analyze_datascience("", "test.py") == []


def test_analyze_syntax_error():
    assert analyze_datascience("def broken(", "test.py") == []


def test_analyze_returns_findings_with_lines():
    code = '''
import pickle
from flask import request

def bad(request):
    return pickle.loads(request.get_data())
'''
    findings = analyze_datascience(code, "test.py")
    for f in findings:
        assert f.line is not None
        assert f.line > 0
