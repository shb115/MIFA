"""
data_check.py — report single-solution trail ratios from the
committed data_{round}r.pkl files in this directory.

The reported number is  data.count(1) / len(data), i.e. the
marginal ratio P(SolCount == 1) over all pkl samples, where the
denominator includes any infeasible (SolCount == 0) and multi-
solution (SolCount > 1) entries.  The committed pkls contain only
SolCount >= 1 entries (the output-diff sample was constructed from
actual encrypted pairs), so in practice the denominator equals the
number of reachable output diffs.
"""
import os
import pickle

ROUNDS = (6, 7, 8)

for round_label in ROUNDS:
    path = f"data_{round_label}r.pkl"
    if not os.path.exists(path):
        print(f"{round_label}r: {path} not found "
              f"(run trail_num_search_on_default.py to regenerate)")
        continue
    try:
        with open(path, "rb") as f:
            data = pickle.load(f)
    except (pickle.UnpicklingError, EOFError) as exc:
        print(f"{round_label}r: {path} looks malformed ({exc}); "
              f"regenerate with trail_num_search_on_default.py")
        continue
    if not isinstance(data, list) or len(data) == 0:
        print(f"{round_label}r: {path} is empty or not a list "
              f"(run trail_num_search to populate)")
        continue
    print(f"{round_label}r:", data.count(1) / len(data))
