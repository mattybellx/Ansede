"""Benchmark flat-table vs tree-dict serialization."""
import sys, time
sys.path.insert(0, r'C:\Users\matth\OneDrive\Desktop\ansede-static-focus')

from ansede_rust_core._core import parse_flat_table, parse_code_dict
from ansede_static.dsl.bridge import _flat_table_to_dsl, _rust_dict_to_dsl

code = """
def hello(name):
    print(f'Hello {name}')
    x = 1 + 2
    return x
""" * 200

# Warmup
for _ in range(5):
    flat = parse_flat_table(code, "python", "t.py")
    tree = parse_code_dict(code, "python", "t.py")

# Flat table
t0 = time.perf_counter()
for _ in range(100):
    flat = parse_flat_table(code, "python", "t.py")
    _flat_table_to_dsl(flat["nodes"])
t_flat = time.perf_counter() - t0

# Tree dict (old way)
t0 = time.perf_counter()
for _ in range(100):
    tree = parse_code_dict(code, "python", "t.py")
    _rust_dict_to_dsl(tree["nodes"])
t_tree = time.perf_counter() - t0

n_nodes = len(flat["nodes"])
print(f"Flat table: {t_flat/100*1000:.3f}ms ({n_nodes} nodes)")
print(f"Tree dict:  {t_tree/100*1000:.3f}ms ({len(tree['nodes'])} nodes)")
print(f"Speedup:    {t_tree/t_flat:.2f}x")
print(f"Lines: {flat['lines_scanned']}, Nodes: {flat['node_count']}")
