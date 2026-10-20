
import argparse
import re
import sys
import time
from pathlib import Path

import duckdb

# -------------------------------------------------------------------------------------------
# 1. Column matching: tolerant to small naming differences between dataset versions
# -------------------------------------------------------------------------------------------
WANTED = {
    "ts": ["logintimestamp", "timestamp"],
    "user": ["userid"],
    "rtt": ["roundtriptimems", "roundtriptime", "rtt"],
    "ip": ["ipaddress"],
    "country": ["country"],
    "region": ["region"],
    "city": ["city"],
    "asn": ["asn"],
    "ua": ["useragentstring"],
    "browser": ["browsernameandversion", "browsername"],
    "os": ["osnameandversion", "osname"],
    "device": ["devicetype"],
    "success": ["loginsuccessful"],
    "attack_ip": ["isattackip"],
    "ato": ["isaccounttakeover"],
}


def norm(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


def map_columns(raw_cols):
    lookup = {norm(c): c for c in raw_cols}
    mapping, missing = {}, []
    for key, candidates in WANTED.items():
        hit = next((lookup[c] for c in candidates if c in lookup), None)
        if hit is None:
            missing.append(key)
        else:
            mapping[key] = hit
    return mapping, missing


def q(col: str) -> str:
    return '"' + col.replace('"', '""') + '"'


def bool_expr(col: str) -> str:
    c = f"lower(trim({q(col)}))"
    return f"CASE WHEN {c} IN ('true','t','1') THEN TRUE WHEN {c} IN ('false','f','0') THEN FALSE ELSE NULL END"


# -------------------------------------------------------------------------------------------
# 2. Convert CSV -> typed Parquet
# -------------------------------------------------------------------------------------------
def build_parquet(con, csv_path, parquet_path):
    print(f"[1/3] Reading {csv_path} (everything as text first, then converting types) ...")
    con.execute(f"CREATE OR REPLACE VIEW raw AS SELECT * FROM read_csv('{csv_path}', header=true, all_varchar=true)")
    raw_cols = [r[0] for r in con.execute("DESCRIBE raw").fetchall()]
    mapping, missing = map_columns(raw_cols)
    print("      Column mapping used:")
    for k, v in mapping.items():
        print(f"        {k:10s} <- {v}")
    if missing:
        sys.exit(f"ERROR: could not find these columns in the file: {missing}\nColumns found: {raw_cols}")

    # timestamp: either a date-time text or an integer epoch. Detect which.
    sample = [r[0] for r in con.execute(f"SELECT {q(mapping['ts'])} FROM raw WHERE {q(mapping['ts'])} IS NOT NULL LIMIT 2000").fetchall()]
    all_int = bool(sample) and all(re.fullmatch(r"\d+", v.strip()) for v in sample)
    if all_int:
        mx = max(int(v) for v in sample)
        unit = "ns" if mx > 1e17 else "us" if mx > 1e14 else "ms" if mx > 1e11 else "s"
        print(f"      Timestamps look like integers; treating them as epoch {unit}.")
        ts_expr = {
            "ns": f"make_timestamp(CAST(TRY_CAST({q(mapping['ts'])} AS BIGINT)/1000 AS BIGINT))",
            "us": f"make_timestamp(TRY_CAST({q(mapping['ts'])} AS BIGINT))",
            "ms": f"make_timestamp(TRY_CAST({q(mapping['ts'])} AS BIGINT)*1000)",
            "s": f"make_timestamp(TRY_CAST({q(mapping['ts'])} AS BIGINT)*1000000)",
        }[unit]
    else:
        ts_expr = f"TRY_CAST({q(mapping['ts'])} AS TIMESTAMP)"

    def text(col):  # empty text -> NULL so that missing-value counts are honest
        return f"NULLIF(trim({q(col)}), '')"

    select = f"""
        SELECT
          {ts_expr}                                   AS ts,
          TRY_CAST({q(mapping['user'])} AS BIGINT)    AS user_id,
          TRY_CAST({q(mapping['rtt'])} AS DOUBLE)     AS rtt_ms,
          {text(mapping['ip'])}                       AS ip,
          {text(mapping['country'])}                  AS country,
          {text(mapping['region'])}                   AS region,
          {text(mapping['city'])}                     AS city,
          TRY_CAST({q(mapping['asn'])} AS BIGINT)     AS asn,
          {text(mapping['ua'])}                       AS user_agent,
          {text(mapping['browser'])}                  AS browser,
          {text(mapping['os'])}                       AS os,
          {text(mapping['device'])}                   AS device_type,
          {bool_expr(mapping['success'])}             AS login_success,
          {bool_expr(mapping['attack_ip'])}           AS is_attack_ip,
          {bool_expr(mapping['ato'])}                 AS is_ato
        FROM raw
    """
    t0 = time.time()
    con.execute(f"COPY ({select}) TO '{parquet_path}' (FORMAT PARQUET, COMPRESSION ZSTD)")
    print(f"      Saved {parquet_path}  ({time.time() - t0:.0f} s)")


# -------------------------------------------------------------------------------------------
# 3. Audit checks
# -------------------------------------------------------------------------------------------
def save(con, sql, out_dir, name, show=True, max_rows=15):
    df = con.execute(sql).df()
    df.to_csv(out_dir / f"{name}.csv", index=False)
    if show:
        print(f"\n--- {name} ---")
        print(df.head(max_rows).to_string(index=False))
    return df


def run_audit(con, parquet_path, out_dir, check_duplicates=False):
    con.execute(f"CREATE OR REPLACE VIEW logins AS SELECT * FROM read_parquet('{parquet_path}')")
    flags, facts = [], {}

    # ---- A. basics
    dup_expr = ("(SELECT count(*) FROM (SELECT 1 FROM logins GROUP BY ALL HAVING count(*) > 1))"
                if check_duplicates else "NULL")
    basics = save(con, f"""
        SELECT count(*) AS rows, count(DISTINCT user_id) AS users, count(DISTINCT ip) AS distinct_ips,
               min(ts) AS first_login, max(ts) AS last_login,
               count(*) FILTER (WHERE ts IS NULL) AS null_timestamps,
               {dup_expr} AS duplicated_row_groups
        FROM logins""", out_dir, "01_basics")
    facts.update(basics.iloc[0].to_dict())

    # ---- B. missing values
    cols = [r[0] for r in con.execute("DESCRIBE logins").fetchall()]
    parts = " UNION ALL ".join(
        f"SELECT '{c}' AS column_name, count(*) FILTER (WHERE {c} IS NULL) AS nulls, "
        f"round(100.0*count(*) FILTER (WHERE {c} IS NULL)/count(*),3) AS null_pct FROM logins" for c in cols)
    miss = save(con, parts, out_dir, "02_missing_values", max_rows=20)
    rtt_null = float(miss.loc[miss.column_name == "rtt_ms", "null_pct"].iloc[0])
    facts["rtt_null_pct"] = rtt_null
    if rtt_null > 20:
        flags.append(f"Round-trip time is missing in {rtt_null:.1f}% of logins: treat RTT features with caution.")

    # ---- C. labels
    lab = save(con, """
        SELECT count(*) FILTER (WHERE is_attack_ip) AS attack_ip_logins,
               round(100.0*count(*) FILTER (WHERE is_attack_ip)/count(*),4) AS attack_ip_pct,
               count(*) FILTER (WHERE is_ato) AS account_takeovers,
               round(100.0*count(*) FILTER (WHERE is_ato)/count(*),6) AS ato_pct,
               count(*) FILTER (WHERE is_ato AND is_attack_ip) AS ato_also_attack_ip,
               count(*) FILTER (WHERE is_attack_ip AND login_success) AS attack_ip_successful,
               count(*) FILTER (WHERE is_ato AND NOT login_success) AS ato_marked_failed
        FROM logins""", out_dir, "03_labels")
    facts.update(lab.iloc[0].to_dict())

    # ---- D. positives per month
    pm = save(con, """
        SELECT strftime(ts, '%Y-%m') AS month, count(*) AS logins,
               count(*) FILTER (WHERE is_attack_ip) AS attack_ip,
               count(*) FILTER (WHERE is_ato) AS account_takeover
        FROM logins GROUP BY 1 ORDER BY 1""", out_dir, "04_positives_per_month", max_rows=20)
    zero_months = pm[pm.attack_ip == 0].month.tolist()
    if zero_months:
        flags.append(f"Months with zero attack-IP logins: {zero_months}")

    # ---- E. what a time-based 70/15/15 split would contain
    q70, q85 = [r for r in con.execute("SELECT quantile_cont(epoch(ts), [0.70, 0.85]) FROM logins").fetchone()[0]]
    split = save(con, f"""
        SELECT CASE WHEN epoch(ts) <= {q70} THEN '1_train' WHEN epoch(ts) <= {q85} THEN '2_validation' ELSE '3_test' END AS split,
               count(*) AS logins,
               count(*) FILTER (WHERE is_attack_ip) AS attack_ip,
               count(*) FILTER (WHERE is_ato) AS account_takeover,
               count(DISTINCT ip) FILTER (WHERE is_attack_ip) AS distinct_attack_ips
        FROM logins GROUP BY 1 ORDER BY 1""", out_dir, "05_time_split_check")
    test = split[split.split == "3_test"].iloc[0]
    facts["test_attack_ip"] = int(test.attack_ip)
    facts["test_ato"] = int(test.account_takeover)
    if test.attack_ip < 200:
        flags.append(f"Only {int(test.attack_ip)} attack-IP logins would fall in the test split: thin for firm conclusions.")
    if test.account_takeover < 20:
        flags.append(f"Only {int(test.account_takeover)} account takeovers would fall in the test split: use them as a case study only.")

    # ---- F. timestamps
    ts_check = save(con, """
        WITH x AS (SELECT ts, lag(ts) OVER () AS prev_ts FROM logins)
        SELECT count(*) FILTER (WHERE ts < prev_ts) AS out_of_order_rows_in_file_order,
               (SELECT count(DISTINCT CAST(ts AS DATE)) FROM logins) AS distinct_days,
               (SELECT date_diff('day', min(CAST(ts AS DATE)), max(CAST(ts AS DATE)))+1 FROM logins) AS calendar_days
        FROM x""", out_dir, "06_timestamp_checks")
    facts["out_of_order"] = int(ts_check.iloc[0].out_of_order_rows_in_file_order)

    # ---- G. user history
    save(con, """
        SELECT count(*) AS users, min(n) AS min_logins, median(n) AS median_logins, round(avg(n),2) AS mean_logins,
               quantile_cont(n, 0.9) AS p90, quantile_cont(n, 0.99) AS p99, max(n) AS max_logins,
               round(100.0*count(*) FILTER (WHERE n = 1)/count(*),2) AS pct_users_with_1_login,
               round(100.0*count(*) FILTER (WHERE n < 5)/count(*),2) AS pct_users_under_5_logins
        FROM (SELECT user_id, count(*) AS n FROM logins GROUP BY 1)""", out_dir, "07_logins_per_user")
    hist = save(con, """
        WITH p AS (SELECT row_number() OVER (PARTITION BY user_id ORDER BY ts) - 1 AS prev FROM logins)
        SELECT round(100.0*count(*) FILTER (WHERE prev >= 1)/count(*),2)  AS pct_logins_with_1plus_prior,
               round(100.0*count(*) FILTER (WHERE prev >= 5)/count(*),2)  AS pct_logins_with_5plus_prior,
               round(100.0*count(*) FILTER (WHERE prev >= 10)/count(*),2) AS pct_logins_with_10plus_prior
        FROM p""", out_dir, "08_history_available")
    facts["pct_5plus_prior"] = float(hist.iloc[0].pct_logins_with_5plus_prior)

    # ---- H. attack-IP concentration and persistence (leakage risk)
    conc = save(con, """
        WITH per_ip AS (SELECT ip, count(*) AS n FROM logins WHERE is_attack_ip GROUP BY ip),
             ranked AS (SELECT n, row_number() OVER (ORDER BY n DESC) AS r FROM per_ip)
        SELECT (SELECT count(*) FROM per_ip) AS distinct_attack_ips,
               (SELECT sum(n) FROM per_ip) AS attack_ip_logins,
               round(100.0*(SELECT sum(n) FROM ranked WHERE r <= 10)/(SELECT sum(n) FROM per_ip),2) AS top10_ip_share_pct,
               round(100.0*(SELECT sum(n) FROM ranked WHERE r <= 100)/(SELECT sum(n) FROM per_ip),2) AS top100_ip_share_pct,
               round(100.0*(SELECT count(*) FILTER (WHERE NOT login_success) FROM logins WHERE is_attack_ip)/
                     (SELECT count(*) FROM logins WHERE is_attack_ip),2) AS attack_ip_failed_pct""", out_dir, "09_attack_ip_concentration")
    facts["top10_share"] = float(conc.iloc[0].top10_ip_share_pct)
    seen = save(con, f"""
        WITH train_ips AS (SELECT DISTINCT ip FROM logins WHERE is_attack_ip AND epoch(ts) <= {q70}),
             test_attack AS (SELECT ip FROM logins WHERE is_attack_ip AND epoch(ts) > {q85})
        SELECT count(*) AS test_attack_ip_logins,
               round(100.0*count(*) FILTER (WHERE ip IN (SELECT ip FROM train_ips))/nullif(count(*),0),2) AS pct_from_ips_flagged_in_train
        FROM test_attack""", out_dir, "10_attack_ip_overlap_train_test")
    pct_seen = seen.iloc[0].pct_from_ips_flagged_in_train
    facts["pct_seen"] = None if pct_seen != pct_seen else float(pct_seen)
    if facts["pct_seen"] is not None and facts["pct_seen"] > 50:
        flags.append(f"{facts['pct_seen']:.0f}% of test-period attack-IP logins come from IPs already flagged in the training period: "
                     "a model could just memorize IPs. Plan the IP-grouped split and the IP-feature ablation.")

    # ---- I. artificial values named in the README (ASN >= 500000, IPs in 10.0.0.0/8, empty device type)
    save(con, """
        SELECT 'ASN >= 500000' AS artifact, count(*) FILTER (WHERE asn >= 500000) AS rows,
               count(*) FILTER (WHERE asn >= 500000 AND is_attack_ip) AS attack_ip_rows,
               count(*) FILTER (WHERE asn >= 500000 AND is_ato) AS ato_rows FROM logins
        UNION ALL
        SELECT 'IP in 10.0.0.0/8', count(*) FILTER (WHERE ip LIKE '10.%'),
               count(*) FILTER (WHERE ip LIKE '10.%' AND is_attack_ip), count(*) FILTER (WHERE ip LIKE '10.%' AND is_ato) FROM logins
        UNION ALL
        SELECT 'empty device type', count(*) FILTER (WHERE device_type IS NULL),
               count(*) FILTER (WHERE device_type IS NULL AND is_attack_ip), count(*) FILTER (WHERE device_type IS NULL AND is_ato) FROM logins""",
         out_dir, "11_known_artificial_values")

    # ---- J. geography sanity (are location fields usable?)
    geo = save(con, """
        WITH u AS (SELECT user_id, count(*) n, count(DISTINCT country) countries FROM logins GROUP BY 1 HAVING count(*) >= 10)
        SELECT (SELECT count(DISTINCT country) FROM logins) AS distinct_countries,
               (SELECT count(DISTINCT city) FROM logins) AS distinct_cities,
               (SELECT count(*) FROM (SELECT ip FROM logins GROUP BY ip HAVING count(DISTINCT country) > 1)) AS ips_with_multiple_countries,
               (SELECT count(*) FROM (SELECT ip FROM logins GROUP BY ip HAVING count(DISTINCT asn) > 1)) AS ips_with_multiple_asns,
               round(100.0*(SELECT count(*) FROM u WHERE countries > 1)/nullif((SELECT count(*) FROM u),0),2) AS pct_users10plus_with_more_than_1_country""",
        out_dir, "12_geography_checks")

    # ---- K. round-trip time: does a per-user baseline mean anything?
    rtt = save(con, """
        WITH u AS (SELECT user_id, stddev_pop(rtt_ms) sd FROM logins WHERE rtt_ms IS NOT NULL GROUP BY 1 HAVING count(rtt_ms) >= 10)
        SELECT (SELECT count(*) FROM u) AS users_with_10plus_rtt,
               round((SELECT avg(sd) FROM u),1) AS avg_within_user_sd,
               round((SELECT stddev_pop(rtt_ms) FROM logins),1) AS overall_sd,
               round((SELECT avg(sd) FROM u)/nullif((SELECT stddev_pop(rtt_ms) FROM logins),0),3) AS within_over_overall,
               (SELECT median(rtt_ms) FROM logins) AS median_rtt,
               (SELECT count(*) FROM logins WHERE rtt_ms > 1000000) AS rtt_over_1000s""", out_dir, "13_rtt_baseline_check")
    ratio = rtt.iloc[0].within_over_overall
    if ratio == ratio and ratio > 0.8:
        flags.append(f"Within-user RTT spread is {ratio:.2f} of the overall spread: a per-user RTT baseline carries little information "
                     "(the README says RTTs were reassigned among users).")

    # ---- L. label consistency by device type (quick look)
    save(con, """
        SELECT coalesce(device_type, '(empty)') AS device_type, count(*) AS logins,
               count(*) FILTER (WHERE is_attack_ip) AS attack_ip, count(*) FILTER (WHERE is_ato) AS ato
        FROM logins GROUP BY 1 ORDER BY 2 DESC""", out_dir, "14_device_type_overview")

    # ---- optional chart
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        fig, ax = plt.subplots(figsize=(9, 4))
        ax.bar(pm.month, pm.attack_ip, color="#009497")
        ax.set_title("Attack-IP logins per month")
        ax.set_ylabel("logins")
        plt.xticks(rotation=60, ha="right")
        plt.tight_layout()
        fig.savefig(out_dir / "positives_per_month.png", dpi=150)
        plt.close(fig)
    except Exception as e:  # chart is optional
        print(f"(chart skipped: {e})")

    return facts, flags


def write_summary(facts, flags, out_dir, csv_path):
    lines = [
        "# RBA dataset audit summary",
        "",
        f"File audited: `{csv_path}`",
        "",
        "## Key numbers",
        f"- Rows: {int(facts['rows']):,}   Users: {int(facts['users']):,}   Distinct IPs: {int(facts['distinct_ips']):,}",
        f"- Time range: {facts['first_login']}  to  {facts['last_login']}",
        f"- Attack-IP logins: {int(facts['attack_ip_logins']):,} ({facts['attack_ip_pct']}%)",
        f"- Account takeovers: {int(facts['account_takeovers']):,} ({facts['ato_pct']}%)",
        f"- Test split (time-based 70/15/15): attack-IP {facts['test_attack_ip']:,}, account takeovers {facts['test_ato']:,}",
        f"- Round-trip time missing: {facts['rtt_null_pct']}%",
        f"- Logins with 5+ earlier logins by the same user: {facts['pct_5plus_prior']}%",
        f"- Top-10 attacker IPs' share of attack-IP logins: {facts['top10_share']}%",
        f"- Rows out of time order in the file: {facts['out_of_order']:,}",
        "",
        "## Warning flags (rules of thumb, not verdicts)",
    ]
    lines += [f"- {f}" for f in flags] or ["- none raised"]
    lines += [
        "",
        "## Remember",
        "- The dataset README says feature values are plausible but artificial, and warns against using it for production intrusion detection.",
        "- Country was randomly assigned per unique value; region and city do not reflect the original relations; RTTs were reassigned among users.",
        "- Read every CSV in this folder yourself before deciding the scope.",
    ]
    (out_dir / "audit_summary.md").write_text("\n".join(lines), encoding="utf-8")
    print(f"\nSummary written to {out_dir / 'audit_summary.md'}")


def main():
    ap = argparse.ArgumentParser(description="Audit the RBA login dataset")
    ap.add_argument("--csv", required=True, help="path to the raw CSV")
    ap.add_argument("--out", default="reports/audit", help="folder for the result tables")
    ap.add_argument("--parquet", default=None, help="where to store the converted Parquet file")
    ap.add_argument("--memory-limit", default=None, help="e.g. 6GB")
    ap.add_argument("--threads", type=int, default=None)
    ap.add_argument("--rebuild", action="store_true")
    ap.add_argument("--check-duplicates", action="store_true", help="also count fully duplicated rows (slow and memory-hungry on the full dataset)")
    a = ap.parse_args()

    csv_path = Path(a.csv)
    if not csv_path.exists():
        sys.exit(f"ERROR: file not found: {csv_path}")
    out_dir = Path(a.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    parquet_path = Path(a.parquet) if a.parquet else Path("data/processed") / (csv_path.stem + ".parquet")
    parquet_path.parent.mkdir(parents=True, exist_ok=True)

    con = duckdb.connect()
    if a.memory_limit:
        con.execute(f"SET memory_limit='{a.memory_limit}'")
    if a.threads:
        con.execute(f"SET threads={a.threads}")
    con.execute("SET temp_directory='duckdb_tmp'")

    if parquet_path.exists() and not a.rebuild:
        print(f"[1/3] Using existing {parquet_path} (use --rebuild to convert again)")
    else:
        build_parquet(con, csv_path.as_posix(), parquet_path.as_posix())

    print("[2/3] Running audit checks ...")
    facts, flags = run_audit(con, parquet_path.as_posix(), out_dir, a.check_duplicates)
    print("[3/3] Writing summary ...")
    write_summary(facts, flags, out_dir, csv_path)


if __name__ == "__main__":
    main()
