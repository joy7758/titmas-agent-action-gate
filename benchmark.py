import time
import os
import sys
sys.path.insert(0, os.path.abspath('src'))
from titmas_action_gate.contracts import _validator, SCHEMA_FILES, schema_directory

def bench_original():
    # Warm up schema directory if needed
    schema_directory()

    # We want to measure calling _validator_unwrapped multiple times
    _validator_unwrapped = getattr(_validator, "__wrapped__", _validator)

    start = time.perf_counter()
    for _ in range(10):
        for contract in SCHEMA_FILES.keys():
            _validator_unwrapped(contract)
    end = time.perf_counter()
    print(f"Time for building validators: {end - start:.4f}s")

if __name__ == "__main__":
    bench_original()
