def classify(d):
    if "kind" not in d:
        return "unknown_ratio"
    return d["kind"]
