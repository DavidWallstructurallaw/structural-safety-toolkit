"""Public fixed names and expansion order, with no runtime decision logic."""
D_CASES = ("D-behavior", "D-declaration", "D-isolation")
E_CASES = ("E0", "E-version", "E-recipient", "E-purpose", "E-interface", "E-expiry",
           "E-issuer", "E-revoked", "E-unknown", "E-task")
F_CASES = ("F-open", "F-locked")
CASES = ("A", "B", "C", *D_CASES, *E_CASES, *F_CASES)
GROUPS = {"D": D_CASES, "E": E_CASES, "F": F_CASES, "all": CASES}
CHOICES = (*CASES, *GROUPS)
