"""
prob.py — average-key-space calculator for the BAKSHEESH key-recovery
attack analysis.

Given
    n_t : number of trails used
    a   : probability that a single trail is "useful" (narrows a nibble
           beyond the default class) — the "active" probability
    b   : probability that a single trail is non-useful (= 1 - a)

this script computes, for each possible remaining per-nibble key-space
size (16, 8, 4, 2), the probability of ending up there and then
reports the expected size and its log2.

Interactive CLI: enter n_t and b each round; enter 'q' to quit.
"""
import math
from fractions import Fraction


def calculate_average_key_space(n_t, a, b):
    """Compute the distribution of the remaining per-nibble key-space
    size and its expectation / log2-expectation.

    Precondition: n_t >= 0, 0 <= a <= 1, 0 <= b <= 1, a + b == 1.
    """
    assert n_t >= 0, f"n_t must be non-negative, got {n_t}"
    assert 0.0 <= a <= 1.0, f"a must lie in [0, 1], got {a}"
    assert 0.0 <= b <= 1.0, f"b must lie in [0, 1], got {b}"
    assert abs((a + b) - 1.0) < 1e-12, \
        f"precondition a + b == 1 violated (a={a}, b={b})"
    # Probabilities of each remaining key-space size
    p4 = math.comb(n_t, 0) * (b ** n_t)                       if n_t >= 0 else 0
    p3 = math.comb(n_t, 1) * a * (b ** (n_t - 1))             if n_t >= 1 else 0
    p2 = math.comb(n_t, 2) * (a ** 2) * (b ** (n_t - 2))      if n_t >= 2 else 0
    # Residual (key-space size 2^1)
    p1 = max(0, 1 - p4 - p3 - p2)

    # Expected key-space size (arithmetic mean over the four possible sizes)
    expected_key_space = (16 * p4) + (8 * p3) + (4 * p2) + (2 * p1)

    # Take log2 of the expectation (0 if expectation is non-positive)
    final_exponent = math.log2(expected_key_space) if expected_key_space > 0 else 0

    return {
        "p4": p4, "p3": p3, "p2": p2, "p1": p1,
        "expected_key_space": expected_key_space,
        "final_exponent":     final_exponent,
    }


def get_user_input(prompt, type_converter, validator=None, validator_msg=None):
    """Read a user input line and convert it via  type_converter.
    Returns None if the user entered 'q' (quit).

    Optional `validator(value) -> bool` additionally rejects out-of-range
    values with the message in `validator_msg`.  Catches every common
    input-parse exception so a fat-fingered '1/0' or 'foo' does not
    crash the interactive loop."""
    while True:
        user_input = input(prompt)
        if user_input.lower() == "q":
            return None
        try:
            value = type_converter(user_input)
        except (ValueError, SyntaxError, NameError, ZeroDivisionError,
                ArithmeticError, TypeError):
            print("Error: invalid format.  Please try again.")
            continue
        if validator is not None and not validator(value):
            print(f"Error: {validator_msg}.  Please try again.")
            continue
        return value


if __name__ == "__main__":
    print("--- Average key-space calculator ---")
    print("Enter n_t and b.  a is computed as 1 - b.")
    print("Enter 'q' at any prompt to quit.")

    while True:
        print("-" * 25)
        n_t = get_user_input("Enter n_t  (e.g. 8): ", int,
                             validator=lambda v: v >= 0,
                             validator_msg="n_t must be >= 0")
        if n_t is None:
            break

        # Accept any format Fraction() can parse: plain decimals
        # (0.663), integer ratios (21/32), or decimal-in-a-ratio
        # (21.21875/32 — handled by splitting on '/').  If the user
        # enters a slash with a decimal on either side, manually
        # parse as num/den to avoid ValueError from Fraction.
        def _parse_b(s: str) -> float:
            s = s.strip()
            if "/" in s:
                num, den = s.split("/", 1)
                return float(num) / float(den)
            return float(Fraction(s))

        b = get_user_input("Enter b    (e.g. 21.21875/32 or 0.663): ",
                           _parse_b,
                           validator=lambda v: 0.0 <= v <= 1.0,
                           validator_msg="b must be a probability in [0, 1]")
        if b is None:
            break

        a = 1.0 - b
        r = calculate_average_key_space(n_t, a, b)

        print("\n--- Result ---")
        print(f"inputs: n_t={n_t}, b={b:.6f} (a = 1 - b = {a:.6f})")
        print(f" P(key space = 16) = {r['p4']:.6f}")
        print(f" P(key space =  8) = {r['p3']:.6f}")
        print(f" P(key space =  4) = {r['p2']:.6f}")
        print(f" P(key space =  2) = {r['p1']:.6f}")
        print("-" * 20)
        print(f"Expected key-space size: {r['expected_key_space']:.6f}")
        print(f"Average key space (log2): 2^{r['final_exponent']:.4f}")
        print("-" * 25)

    print("Bye.")
