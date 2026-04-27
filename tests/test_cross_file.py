from __future__ import annotations

from ansede_static.ir.global_graph import GlobalGraph
from ansede_static.python_analyzer import analyze_python, index_python_file


def test_cross_file_imported_taint_reaches_sql_sink(tmp_path):
    module_a = tmp_path / 'test_cross_a.py'
    module_b = tmp_path / 'test_cross_b.py'

    module_a.write_text(
        """
import os

untrusted_data = os.getenv('USER_INPUT')
""",
        encoding='utf-8',
    )
    module_b.write_text(
        """
from test_cross_a import untrusted_data
import sqlite3

def do_query():
    cursor = sqlite3.connect('test.db').cursor()
    cursor.execute('SELECT * FROM users WHERE name = ' + untrusted_data)
""",
        encoding='utf-8',
    )

    graph = GlobalGraph()
    index_python_file(module_a.read_text(encoding='utf-8'), str(module_a), graph)
    index_python_file(module_b.read_text(encoding='utf-8'), str(module_b), graph)

    result = analyze_python(module_b.read_text(encoding='utf-8'), filename=str(module_b), global_graph=graph)

    finding = next(f for f in result.findings if f.cwe == 'CWE-89')
    labels = [frame.label for frame in finding.trace]

    assert any('imported `untrusted_data`' == label for label in labels)
    assert labels[-1].endswith('execute()`')


def test_cross_file_safe_import_does_not_produce_false_positive(tmp_path):
    module_a = tmp_path / 'shared_values.py'
    module_b = tmp_path / 'consumer.py'

    module_a.write_text("user_name = 'alice'\n", encoding='utf-8')
    module_b.write_text(
        """
from shared_values import user_name
import sqlite3

def do_query():
    cursor = sqlite3.connect('test.db').cursor()
    cursor.execute('SELECT * FROM users WHERE name = ' + user_name)
""",
        encoding='utf-8',
    )

    graph = GlobalGraph()
    index_python_file(module_a.read_text(encoding='utf-8'), str(module_a), graph)
    index_python_file(module_b.read_text(encoding='utf-8'), str(module_b), graph)

    result = analyze_python(module_b.read_text(encoding='utf-8'), filename=str(module_b), global_graph=graph)

    assert not any(f.cwe == 'CWE-89' for f in result.findings)