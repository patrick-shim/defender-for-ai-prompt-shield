import json
from collections import Counter
from pathlib import Path


def load(path: str) -> list[dict]:
    p = Path(path)
    if not p.exists():
        return []
    with p.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise RuntimeError(f"{path} must be a JSON list")
    return data


def index_by_prompt_index(rows: list[dict]) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for r in rows:
        k = r.get("prompt_index")
        if k is None:
            continue
        out[str(k)] = r
    return out


def get_decision(row: dict) -> str:
    # Preferred field from single_chat_app.py
    d = row.get("derived")
    if isinstance(d, str):
        return d

    status = row.get("status")
    blocked = row.get("blocked") is True
    refusal = row.get("refusal") is True

    if status == "blocked" or blocked:
        return "hard_block"
    if status == "ok" and refusal:
        return "soft_refuse"
    if status == "ok":
        return "allow"
    return "error"


def short(s: str | None, n: int = 110) -> str:
    if not s:
        return ""
    s = s.replace("\n", " ").strip()
    return s if len(s) <= n else s[: n - 1] + "…"


def print_counts(name: str, rows: list[dict]) -> None:
    c = Counter(get_decision(r) for r in rows)
    total = len(rows)
    print(f"\n== {name} ==")
    print(f"total: {total}")
    for k in ["allow", "soft_refuse", "hard_block", "error"]:
        if k in c:
            print(f"  {k}: {c[k]}")


def print_pair_matrix(a_name: str, a_map: dict[str, dict], b_name: str, b_map: dict[str, dict], keys: list[str]) -> None:
    cnt = Counter()
    for k in keys:
        cnt[(get_decision(a_map[k]), get_decision(b_map[k]))] += 1

    print(f"\n== Pairwise matrix: {a_name} vs {b_name} (n={len(keys)}) ==")
    for (ad, bd), n in sorted(cnt.items()):
        print(f"  ({ad:11s} -> {bd:11s})  {n}")


def print_mismatches(a_name: str, a_map: dict[str, dict], b_name: str, b_map: dict[str, dict], keys: list[str], limit: int = 25) -> None:
    mism = []
    for k in keys:
        ad = get_decision(a_map[k])
        bd = get_decision(b_map[k])
        if ad != bd:
            mism.append((int(k) if k.isdigit() else k, ad, bd, k))

    print(f"\n== Mismatches: {a_name} vs {b_name} ({len(mism)}) ==")
    for _, ad, bd, k in mism[:limit]:
        ar = a_map[k]
        br = b_map[k]

        a_text = ar.get("assistant_text")
        if a_text is None and isinstance(ar.get("native"), dict):
            a_text = ar["native"].get("assistant_text")

        b_text = br.get("assistant_text")
        if b_text is None and isinstance(br.get("native"), dict):
            b_text = br["native"].get("assistant_text")

        a_block_reason = None
        if isinstance(ar.get("native"), dict):
            inner = ar["native"].get("content_filter_result")
            if isinstance(inner, dict) and inner.get("jailbreak", {}).get("filtered") is True:
                a_block_reason = "jailbreak_filtered"

        b_block_reason = None
        if isinstance(br.get("native"), dict):
            inner = br["native"].get("content_filter_result")
            if isinstance(inner, dict) and inner.get("jailbreak", {}).get("filtered") is True:
                b_block_reason = "jailbreak_filtered"

        print(f"  prompt_index={k}: {a_name}={ad} {('('+a_block_reason+')') if a_block_reason else ''} | {b_name}={bd} {('('+b_block_reason+')') if b_block_reason else ''}")
        if a_text:
            print(f"    {a_name}_text: {short(a_text)}")
        if b_text:
            print(f"    {b_name}_text: {short(b_text)}")


def main() -> None:
    paths = {
        "azure_default": "result_azure_default.json",
        "azure_permissive": "result_azure_permissive.json",
        "claude": "result_claude.json",
    }

    rows = {name: load(path) for name, path in paths.items()}
    maps = {name: index_by_prompt_index(r) for name, r in rows.items()}

    # Summary counts
    for name in ["azure_default", "azure_permissive", "claude"]:
        print_counts(name, rows[name])

    # Overlap keys
    all_sets = {name: set(m.keys()) for name, m in maps.items()}
    overlap_all = sorted(set.intersection(*all_sets.values()), key=lambda k: int(k) if k.isdigit() else 10**18)

    print("\n== Overlap ==")
    for name in ["azure_default", "azure_permissive", "claude"]:
        print(f"  {name}: {len(maps[name])}")
    print(f"  overlap_all_3: {len(overlap_all)}")

    # Pairwise matrices + mismatches (using 3-way overlap when possible)
    if overlap_all:
        print_pair_matrix("azure_default", maps["azure_default"], "azure_permissive", maps["azure_permissive"], overlap_all)
        print_pair_matrix("azure_default", maps["azure_default"], "claude", maps["claude"], overlap_all)
        print_pair_matrix("azure_permissive", maps["azure_permissive"], "claude", maps["claude"], overlap_all)

        print_mismatches("azure_default", maps["azure_default"], "azure_permissive", maps["azure_permissive"], overlap_all)
        print_mismatches("azure_default", maps["azure_default"], "claude", maps["claude"], overlap_all)
        print_mismatches("azure_permissive", maps["azure_permissive"], "claude", maps["claude"], overlap_all)

    # If some file has fewer rows, show max pairwise overlap as well
    pairs = [("azure_default", "azure_permissive"), ("azure_default", "claude"), ("azure_permissive", "claude")]
    for a, b in pairs:
        keys = sorted(all_sets[a].intersection(all_sets[b]), key=lambda k: int(k) if k.isdigit() else 10**18)
        if keys == overlap_all:
            continue
        print_pair_matrix(a, maps[a], b, maps[b], keys)
        print_mismatches(a, maps[a], b, maps[b], keys)


if __name__ == "__main__":
    main()
