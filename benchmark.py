import time

from src.titmas_action_gate.contracts import _validator

start_time = time.time()
for _ in range(100):
    try:
        _validator("action_request")
        _validator("policy_evaluation")
    except Exception as e:
        print(f"Error: {e}")
        break
end_time = time.time()

print(f"Time taken for 200 calls: {end_time - start_time:.4f} seconds")
