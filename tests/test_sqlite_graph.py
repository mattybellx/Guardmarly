"""Test the SQLite relational graph store end-to-end."""
import sys, json, os
from pathlib import Path

import pytest
pytest.importorskip("ansede_rust_core._core", reason="Rust core module not built")

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ansede_static.graph.sqlite_graph import GraphStore
from ansede_static.graph.graph_populator import populate_from_flat_table
from ansede_rust_core._core import parse_flat_table

# Create in-memory store
store = GraphStore(":memory:")
store.migrate()

# Parse a Python file with the Rust core
code = '''
import os
from flask import request

@app.route('/exec')
def execute():
    cmd = request.args.get('cmd')
    os.system(cmd)
    return 'done'
'''

flat = parse_flat_table(code, "python", "test.py")
print(f"Flat table: {flat['node_count']} nodes, {flat['lines_scanned']} lines")

# Populate the store
file_id = populate_from_flat_table(store, flat, "test.py")
print(f"File ID: {file_id}")

stats = store.stats()
print(f"Store stats: {stats}")

# Test recursive CTE taint query
# Add some edges that represent taint flows
nodes = store.conn.execute(
    "SELECT id, name, node_type, kind FROM nodes WHERE node_type IN ('call', 'function')"
).fetchall()
print(f"\nNodes in store:")
for n in nodes:
    print(f"  [{n['node_type']:8s}] {n['name'][:40]:40s} kind={n['kind']}")

# Mark source/sink nodes
source = store.conn.execute(
    "SELECT id FROM nodes WHERE kind='call' AND name LIKE '%request%'"
).fetchone()
sink = store.conn.execute(
    "SELECT id FROM nodes WHERE kind='call' AND name LIKE '%os.system%'"
).fetchone()

if source and sink:
    print(f"\nSource node: {source['id']}, Sink node: {sink['id']}")
    # Add taint edges
    store.add_edge(source['id'], sink['id'], 'taint', 0.9,
                   {"cwe": "CWE-78", "desc": "Command injection"})
    store.record_taint_flow(source['id'], sink['id'], [1], 0.9, "CWE-78")

    # Find paths
    paths = store.find_taint_paths()
    print(f"\nTaint paths found: {len(paths)}")
    for p in paths:
        print(f"  Source L{p['source_line']} -> Sink L{p['sink_line']}: "
              f"{p['source_name'][:30]} -> {p['sink_name'][:30]} ({p['cwe']})")

# Show final stats
print(f"\nFinal store stats: {store.stats()}")
store.close()
print("\nALL OK")
