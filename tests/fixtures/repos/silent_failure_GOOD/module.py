def classify(d):
    if "kind" not in d:
        raise KeyError(f"expected 'kind' key; got: {list(d.keys())}")
    return d["kind"]
