# `0x8/` — scripts only, no committed `.pkl`

This subdirectory holds the MILP density-search harness for DEFAULT
under **input difference `0x8`**, but — unlike its `0x1/` and `0x2/`
siblings — it ships **without** the pre-computed
`data_{6,7,8}r.pkl` files.

The paper reports that with input difference `0x8` it is hard to find
trails whose single-solution count is `1` (most sampled output
differences admit multiple simultaneously-valid round-by-round
difference sequences).  Committing a `.pkl` of near-zero ratios would
not contribute a usable number to any paper claim, so we ship the
harness here only for reviewers who want to regenerate the statistic
themselves:

```
cd DEFAULT/Codes/find_diff_trail_with_single_sol/trail_num/0x8/
python3 trail_num_search_on_default.py 6     # writes data_6r.pkl
python3 data_check.py                         # reports the ratio
```

Running the regenerator requires Gurobi (`gurobipy ≥ 12.0`); it is
not driven by `./reproduce.sh`.
