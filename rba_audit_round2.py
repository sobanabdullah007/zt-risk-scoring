"""
rba_audit_round2.py  -  second-round audit of the RBA login dataset.

Run AFTER rba_audit.py: it reads the Parquet file that the first script created.

Questions this round answers
  A. The catch-all user: what does the user ID with ~14M logins look like?
  B. Is the attack-IP label a fixed property of an IP, or does it change over time?
  C. Does the presence of round-trip time (RTT) depend on the label?
  D. Do the placeholder values (10.x IPs, ASN >= 500000) interact with device type?
  E. Which candidate features separate the labels (single-feature AUC, exploratory)?
  F. What do the account takeovers look like (new country? new device? how much history)?
  G. How big would an IP-disjoint test set be?
  H. Which ASNs, countries and hours of day dominate the attack-IP label?

Usage (project folder, virtual environment active):
    python rba_audit_round2.py --parquet data/processed/rba-dataset.parquet --out reports/audit2

Options:
    --memory-limit 6GB    cap DuckDB memory
    --threads 4           limit CPU threads
    --auc-sample 2000000  rows used for the single-feature AUC on attack-IP
    --user-sample-mod 20  use 1 in N users for the "new for this user" rates

Everything here is exploratory. Per-IP and per-user aggregates are computed over the WHOLE period,
so they leak information across time. Use them to understand the data, not as final features.
"""
import argparse
import sys
import time
from pathlib import Path

import duckdb
import numpy as np
import pandas as pd


# ----------------------------------------------------------------------------------------
def save(con, sql, out_dir, name, show=True, max_rows=12):
    df = con.execute(sql).df()
    df.to_csv(out_dir / f"{name}.csv", index=False)
    if show:
        print(f"\n--- {name} ---")
        print(df.head(max_rows).to_string(index=False))
    return df


def save_df(df, out_dir, name, show=True, max_rows=12):
    df.to_csv(out_dir / f"{name}.csv", index=False)
    if show:
        print(f"\n--- {name} ---")
        print(df.head(max_rows).to_string(index=False))
    return df


def auc_score(y, x):
    """Rank-based AUC (probability that a positive scores higher than a negative)."""
    y = np.asarray(y).astype(int)
    n1 = int(y.sum())
    n0 = len(y) - n1
    if n1 == 0 or n0 == 0:
        return float("nan")
    ranks = pd.Series(np.asarray(x, dtype=float)).rank(method="average").to_numpy()
    return (ranks[y == 1].sum() - n1 * (n1 + 1) / 2) / (n1 * n0)


FEATURE_SQL = """
    (device_type = 'mobile')::INT        AS is_mobile,
    (device_type = 'desktop')::INT       AS is_desktop,
    (device_type = 'bot')::INT           AS is_bot,
    (device_type = 'unknown')::INT       AS is_unknown_device,
    (ip LIKE '10.%')::INT                AS ip_in_10x,
    (asn >= 500000)::INT                 AS asn_ge_500k,
    coalesce(login_success::INT, 0)      AS login_success_i,
    ln(1 + ip_logins)                    AS log_ip_logins,
    ip_users                             AS ip_distinct_users,
    ip_fail_rate                         AS ip_fail_rate,
    ip_months                            AS ip_active_months,
    ip_logins * 1.0 / ip_users           AS ip_logins_per_user,
    ln(1 + user_logins)                  AS log_user_logins,
    (rtt_ms IS NOT NULL)::INT            AS rtt_present
"""
FEATURES = ["is_mobile", "is_desktop", "is_bot", "is_unknown_device", "ip_in_10x", "asn_ge_500k", "login_success_i",
            "log_ip_logins", "ip_distinct_users", "ip_fail_rate", "ip_active_months", "ip_logins_per_user",
            "log_user_logins", "rtt_present"]


def auc_table(df, label_col):
    rows = []
    for f in FEATURES:
        a = auc_score(df[label_col], df[f])
        rows.append({"feature": f, "auc": round(a, 4), "distance_from_0.5": round(abs(a - 0.5), 4)})
    return pd.DataFrame(rows).sort_values("distance_from_0.5", ascending=False)


# ----------------------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="RBA audit, round 2")
    ap.add_argument("--parquet", required=True, help="Parquet file created by rba_audit.py")
    ap.add_argument("--out", default="reports/audit2")
    ap.add_argument("--memory-limit", default=None)
    ap.add_argument("--threads", type=int, default=None)
    ap.add_argument("--auc-sample", type=int, default=2_000_000)
    ap.add_argument("--user-sample-mod", type=int, default=20)
    a = ap.parse_args()

    pq = Path(a.parquet)
    if not pq.exists():
        sys.exit(f"ERROR: Parquet file not found: {pq}\nRun rba_audit.py first.")
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)

    con = duckdb.connect()
    if a.memory_limit:
        con.execute(f"SET memory_limit='{a.memory_limit}'")
    if a.threads:
        con.execute(f"SET threads={a.threads}")
    con.execute("SET temp_directory='duckdb_tmp'")
    con.execute(f"CREATE OR REPLACE VIEW logins AS SELECT * FROM read_parquet('{pq.as_posix()}')")

    facts, flags = {}, []
    t0 = time.time()

    def tick(msg):
        print(f"\n[{time.time() - t0:6.0f}s] {msg}")

    # ---------------- helper tables (computed once)
    tick("Building per-IP and per-user summary tables (this is the slow step) ...")
    con.execute("""
        CREATE TEMP TABLE ip_stats AS
        SELECT ip, count(*) AS n_logins, count(DISTINCT user_id) AS n_users,
               count(*) FILTER (WHERE login_success = FALSE) AS n_fail,
               count(*) FILTER (WHERE is_attack_ip) AS n_attack,
               min(ts) AS first_ts, max(ts) AS last_ts,
               min(ts) FILTER (WHERE is_attack_ip) AS first_attack_ts,
               min(ts) FILTER (WHERE NOT is_attack_ip) AS first_clean_ts,
               count(DISTINCT strftime(ts, '%Y-%m')) AS n_months
        FROM logins GROUP BY ip""")
    con.execute("""
        CREATE TEMP TABLE user_stats AS
        SELECT user_id, count(*) AS n, min(ts) AS first_ts, max(ts) AS last_ts,
               count(*) FILTER (WHERE is_attack_ip) AS n_attack,
               count(*) FILTER (WHERE is_ato) AS n_ato,
               count(*) FILTER (WHERE login_success) AS n_success
        FROM logins GROUP BY user_id""")
    top_user = con.execute("SELECT user_id FROM user_stats ORDER BY n DESC LIMIT 1").fetchone()[0]
    facts["top_user_id"] = top_user
    q70, q85 = con.execute("SELECT quantile_cont(epoch(ts), [0.70, 0.85]) FROM logins").fetchone()[0]

    # ---------------- A. catch-all user
    tick("A. Top users and the catch-all user")
    top20 = save(con, """
        WITH t AS (SELECT user_id FROM user_stats ORDER BY n DESC LIMIT 20)
        SELECT l.user_id, count(*) AS logins,
               round(100.0 * count(*) / (SELECT count(*) FROM logins), 3) AS share_of_all_pct,
               round(100.0 * count(*) FILTER (WHERE l.is_attack_ip) / count(*), 2) AS attack_ip_pct,
               count(*) FILTER (WHERE l.is_ato) AS takeovers,
               round(100.0 * count(*) FILTER (WHERE l.login_success) / count(*), 2) AS success_pct,
               count(DISTINCT l.ip) AS distinct_ips, count(DISTINCT l.country) AS distinct_countries,
               count(DISTINCT l.device_type) AS distinct_device_types,
               min(l.ts) AS first_login, max(l.ts) AS last_login,
               count(DISTINCT CAST(l.ts AS DATE)) AS active_days
        FROM logins l JOIN t USING (user_id) GROUP BY l.user_id ORDER BY logins DESC""", out, "21_top_users")
    facts["top_user_share"] = float(top20.iloc[0].share_of_all_pct)
    facts["top_user_attack_pct"] = float(top20.iloc[0].attack_ip_pct)
    facts["top_user_success_pct"] = float(top20.iloc[0].success_pct)
    facts["top_user_ips"] = int(top20.iloc[0].distinct_ips)
    n_big = int((top20.share_of_all_pct > 1.0).sum())
    facts["users_over_1pct"] = n_big
    if facts["top_user_share"] > 10:
        flags.append(f"User {top_user} holds {facts['top_user_share']}% of all logins ({facts['top_user_ips']:,} distinct IPs, "
                     f"{facts['top_user_success_pct']}% successful). Treat it as a catch-all ID, not a real user.")
    save(con, f"""
        SELECT strftime(ts, '%Y-%m') AS month, count(*) AS logins,
               round(100.0 * count(*) FILTER (WHERE is_attack_ip) / count(*), 2) AS attack_ip_pct,
               round(100.0 * count(*) FILTER (WHERE login_success) / count(*), 2) AS success_pct,
               count(DISTINCT ip) AS distinct_ips
        FROM logins WHERE user_id = {top_user} GROUP BY 1 ORDER BY 1""", out, "22a_top_user_monthly")
    save(con, f"""
        SELECT coalesce(device_type, '(empty)') AS device_type, count(*) AS logins,
               round(100.0 * count(*) / sum(count(*)) OVER (), 2) AS pct
        FROM logins WHERE user_id = {top_user} GROUP BY 1 ORDER BY 2 DESC""", out, "22b_top_user_devices")

    # ---------------- B. label constancy per IP
    tick("B. Is the attack-IP label a property of the IP?")
    cons = save(con, """
        SELECT count(*) AS ips,
               count(*) FILTER (WHERE n_attack = 0) AS never_flagged,
               count(*) FILTER (WHERE n_attack = n_logins) AS always_flagged,
               count(*) FILTER (WHERE n_attack > 0 AND n_attack < n_logins) AS mixed_ips,
               round(100.0 * count(*) FILTER (WHERE n_attack > 0 AND n_attack < n_logins) / count(*), 3) AS mixed_ip_pct,
               coalesce(sum(n_logins) FILTER (WHERE n_attack > 0 AND n_attack < n_logins), 0) AS logins_from_mixed_ips,
               count(*) FILTER (WHERE first_attack_ts > first_clean_ts) AS flag_turns_on_later,
               count(*) FILTER (WHERE first_clean_ts > first_attack_ts) AS flag_only_after_first_attack
        FROM ip_stats""", out, "23_ip_label_constancy")
    facts["mixed_ip_pct"] = float(cons.iloc[0].mixed_ip_pct)
    facts["flag_turns_on_later"] = int(cons.iloc[0].flag_turns_on_later)
    if facts["mixed_ip_pct"] < 1.0:
        flags.append(f"Only {facts['mixed_ip_pct']}% of IPs have mixed labels: the attack-IP label is effectively a fixed attribute of the IP. "
                     "Training on it teaches the model IP identity unless you hold IPs out.")
    save(con, """
        SELECT count(*) AS flagged_ips,
               round(100.0 * count(*) FILTER (WHERE first_attack_ts = first_ts) / count(*), 2) AS pct_flagged_from_first_login,
               round(quantile_cont(epoch(first_attack_ts - first_ts) / 86400.0, 0.5), 2) AS median_days_first_seen_to_first_flag,
               round(quantile_cont(epoch(first_attack_ts - first_ts) / 86400.0, 0.9), 2) AS p90_days,
               round(quantile_cont(n_logins, 0.5), 1) AS median_logins_per_flagged_ip,
               round(quantile_cont(n_months, 0.5), 1) AS median_active_months
        FROM ip_stats WHERE n_attack > 0""", out, "24_flagged_ip_timing")

    # ---------------- C. RTT presence
    tick("C. Does RTT presence depend on the label?")
    rtt = save(con, """
        SELECT 'attack_ip' AS dimension, CAST(is_attack_ip AS VARCHAR) AS value, count(*) AS logins,
               count(rtt_ms) AS rtt_present, round(100.0 * count(rtt_ms) / count(*), 3) AS rtt_present_pct FROM logins GROUP BY 2
        UNION ALL SELECT 'takeover', CAST(is_ato AS VARCHAR), count(*), count(rtt_ms), round(100.0 * count(rtt_ms) / count(*), 3) FROM logins GROUP BY 2
        UNION ALL SELECT 'login_success', CAST(login_success AS VARCHAR), count(*), count(rtt_ms), round(100.0 * count(rtt_ms) / count(*), 3) FROM logins GROUP BY 2
        UNION ALL SELECT 'device_type', coalesce(device_type, '(empty)'), count(*), count(rtt_ms), round(100.0 * count(rtt_ms) / count(*), 3) FROM logins GROUP BY 2
        UNION ALL SELECT 'ip_in_10x', CAST(ip LIKE '10.%' AS VARCHAR), count(*), count(rtt_ms), round(100.0 * count(rtt_ms) / count(*), 3) FROM logins GROUP BY 2
        UNION ALL SELECT 'month', strftime(ts, '%Y-%m'), count(*), count(rtt_ms), round(100.0 * count(rtt_ms) / count(*), 3) FROM logins GROUP BY 2
        ORDER BY 1, 2""", out, "25_rtt_presence_by_group", max_rows=40)
    a_true = rtt[(rtt.dimension == "attack_ip") & (rtt.value.str.lower() == "true")].rtt_present_pct
    a_false = rtt[(rtt.dimension == "attack_ip") & (rtt.value.str.lower() == "false")].rtt_present_pct
    if len(a_true) and len(a_false) and a_false.iloc[0] > 0:
        ratio = float(a_true.iloc[0]) / float(a_false.iloc[0])
        facts["rtt_presence_ratio"] = ratio
        if ratio > 2 or ratio < 0.5:
            flags.append(f"RTT is present {ratio:.2f} times as often for attack-IP logins as for others: "
                         "its presence alone carries label information. Do not use it unless you understand why.")

    # ---------------- D. placeholders by device type
    tick("D. Placeholder values by device type")
    save(con, """
        SELECT coalesce(device_type, '(empty)') AS device_type, (ip LIKE '10.%') AS ip_in_10x, (asn >= 500000) AS asn_ge_500k,
               count(*) AS logins, count(*) FILTER (WHERE is_attack_ip) AS attack_ip,
               round(100.0 * count(*) FILTER (WHERE is_attack_ip) / count(*), 2) AS attack_ip_pct
        FROM logins GROUP BY ALL ORDER BY 1, 2, 3""", out, "26_placeholders_by_device", max_rows=30)

    # ---------------- E. single-feature AUC
    tick(f"E. Single-feature AUC for attack-IP (sample of {a.auc_sample:,} rows, catch-all user excluded)")
    atk = con.execute(f"""
        WITH s AS (SELECT * FROM (SELECT * FROM logins USING SAMPLE reservoir({a.auc_sample} ROWS) REPEATABLE (42))
                   WHERE user_id <> {top_user}),
             j AS (SELECT s.*, i.n_logins AS ip_logins, i.n_users AS ip_users,
                          coalesce(i.n_fail, 0) * 1.0 / i.n_logins AS ip_fail_rate, i.n_months AS ip_months, u.n AS user_logins
                   FROM s JOIN ip_stats i USING (ip) JOIN user_stats u USING (user_id))
        SELECT is_attack_ip::INT AS y, {FEATURE_SQL} FROM j""").df()
    save_df(atk.groupby("y").agg(rows=("y", "size"), ip_logins_median=("log_ip_logins", lambda v: round(float(np.expm1(v.median())), 1)),
                                 ip_users_median=("ip_distinct_users", "median"), ip_fail_rate_median=("ip_fail_rate", "median"),
                                 ip_months_median=("ip_active_months", "median")).reset_index(), out, "27_ip_aggregates_by_label")
    auc_atk = save_df(auc_table(atk, "y"), out, "28_univariate_auc_attack_ip", max_rows=14)
    facts["best_atk_feature"] = auc_atk.iloc[0].feature
    facts["best_atk_auc"] = float(auc_atk.iloc[0].auc)
    if max(auc_atk.auc.max(), 1 - auc_atk.auc.min()) > 0.9:
        flags.append("A single feature separates attack-IP from the rest with AUC above 0.9 (see 28_...). "
                     "Check it is not an artifact or an IP-identity proxy before building on it.")
    del atk

    tick("E2. Single-feature AUC for takeovers (all takeovers vs a sample of other logins)")
    ato = con.execute(f"""
        WITH pos AS (SELECT * FROM logins WHERE is_ato AND user_id <> {top_user}),
             neg AS (SELECT * FROM (SELECT * FROM logins USING SAMPLE reservoir(1000000 ROWS) REPEATABLE (7))
                     WHERE NOT is_ato AND user_id <> {top_user}),
             s AS (SELECT * FROM pos UNION ALL SELECT * FROM neg),
             j AS (SELECT s.*, i.n_logins AS ip_logins, i.n_users AS ip_users,
                          coalesce(i.n_fail, 0) * 1.0 / i.n_logins AS ip_fail_rate, i.n_months AS ip_months, u.n AS user_logins
                   FROM s JOIN ip_stats i USING (ip) JOIN user_stats u USING (user_id))
        SELECT is_ato::INT AS y, {FEATURE_SQL} FROM j""").df()
    facts["ato_rows_in_auc"] = int(ato.y.sum())
    save_df(auc_table(ato, "y"), out, "29_univariate_auc_takeover", max_rows=14)
    del ato

    # ---------------- F. takeovers in detail + "new for this user" baselines
    tick("F. The takeovers in detail")
    flag_sql = """
        row_number() OVER (PARTITION BY user_id ORDER BY ts) - 1                      AS prior_logins,
        row_number() OVER (PARTITION BY user_id, country ORDER BY ts) = 1             AS new_country,
        row_number() OVER (PARTITION BY user_id, asn ORDER BY ts) = 1                 AS new_asn,
        row_number() OVER (PARTITION BY user_id, device_type ORDER BY ts) = 1         AS new_device_type,
        epoch(ts - lag(ts) OVER (PARTITION BY user_id ORDER BY ts)) / 3600.0          AS hours_since_prev_login"""
    detail = save(con, f"""
        WITH u AS (SELECT DISTINCT user_id FROM logins WHERE is_ato),
             f AS (SELECT l.*, {flag_sql} FROM logins l JOIN u USING (user_id))
        SELECT f.user_id, f.ts, coalesce(f.device_type, '(empty)') AS device_type, f.country, f.asn, f.ip,
               f.login_success, f.is_attack_ip, f.prior_logins, f.new_country, f.new_asn, f.new_device_type,
               round(f.hours_since_prev_login, 1) AS hours_since_prev_login, i.n_users AS ip_distinct_users, i.n_logins AS ip_logins
        FROM f JOIN ip_stats i USING (ip) WHERE f.is_ato ORDER BY f.ts""", out, "30_takeover_detail", max_rows=6)
    with_hist = detail[detail.prior_logins >= 1]
    ato_row = {
        "group": "takeovers (all)", "logins": len(detail),
        "with_history_n": len(with_hist),
        "pct_zero_prior_logins": round(100 * (detail.prior_logins == 0).mean(), 1),
        "median_prior_logins": float(detail.prior_logins.median()),
        "pct_new_country": round(100 * with_hist.new_country.mean(), 1) if len(with_hist) else None,
        "pct_new_asn": round(100 * with_hist.new_asn.mean(), 1) if len(with_hist) else None,
        "pct_new_device_type": round(100 * with_hist.new_device_type.mean(), 1) if len(with_hist) else None,
        "pct_desktop": round(100 * (detail.device_type == "desktop").mean(), 1),
        "pct_attack_ip": round(100 * detail.is_attack_ip.mean(), 1),
        "pct_login_success": round(100 * detail.login_success.mean(), 1),
    }
    tick(f"F2. 'New for this user' rates on a 1-in-{a.user_sample_mod} user sample (catch-all user excluded)")
    base = con.execute(f"""
        WITH s AS (SELECT * FROM logins WHERE hash(user_id) % {a.user_sample_mod} = 0 AND user_id <> {top_user}),
             f AS (SELECT s.*, {flag_sql} FROM s)
        SELECT CASE WHEN is_attack_ip THEN 'attack-IP logins (sample)' ELSE 'other logins (sample)' END AS "group",
               count(*) AS logins, count(*) FILTER (WHERE prior_logins >= 1) AS with_history_n,
               round(100.0 * count(*) FILTER (WHERE prior_logins = 0) / count(*), 1) AS pct_zero_prior_logins,
               NULL AS median_prior_logins,
               round(100.0 * avg(new_country::INT) FILTER (WHERE prior_logins >= 1), 1) AS pct_new_country,
               round(100.0 * avg(new_asn::INT) FILTER (WHERE prior_logins >= 1), 1) AS pct_new_asn,
               round(100.0 * avg(new_device_type::INT) FILTER (WHERE prior_logins >= 1), 1) AS pct_new_device_type,
               round(100.0 * avg((device_type = 'desktop')::INT), 1) AS pct_desktop,
               round(100.0 * avg(is_attack_ip::INT), 1) AS pct_attack_ip,
               round(100.0 * avg(login_success::INT), 1) AS pct_login_success
        FROM f GROUP BY 1""").df()
    summary_rows = pd.concat([pd.DataFrame([ato_row]), base], ignore_index=True)
    save_df(summary_rows, out, "31_takeover_vs_others_new_for_user", max_rows=5)
    facts["ato_pct_new_country"] = ato_row["pct_new_country"]
    facts["ato_zero_prior"] = ato_row["pct_zero_prior_logins"]
    oth = base[base["group"].str.startswith("other")]
    if len(oth) and ato_row["pct_new_country"] is not None and oth.iloc[0].pct_new_country is not None:
        facts["other_pct_new_country"] = float(oth.iloc[0].pct_new_country)
    bucket = save(con, f"""
        WITH s AS (SELECT * FROM logins WHERE hash(user_id) % {a.user_sample_mod} = 0 AND user_id <> {top_user}),
             f AS (SELECT s.*, row_number() OVER (PARTITION BY user_id ORDER BY ts) - 1 AS prior_logins FROM s)
        SELECT CASE WHEN prior_logins = 0 THEN '0 (first login)' WHEN prior_logins < 5 THEN '1-4' WHEN prior_logins < 10 THEN '5-9' ELSE '10+' END AS prior_logins,
               count(*) AS logins, round(100.0 * avg(is_attack_ip::INT), 2) AS attack_ip_pct
        FROM f GROUP BY 1 ORDER BY 1""", out, "32_attack_rate_by_user_history")

    # ---------------- G. IP-disjoint viability
    tick("G. How big would an IP-disjoint evaluation be?")
    disj = save(con, f"""
        SELECT CASE WHEN epoch(l.ts) <= {q70} THEN '1_train' WHEN epoch(l.ts) <= {q85} THEN '2_validation' ELSE '3_test' END AS split,
               count(*) AS logins,
               count(*) FILTER (WHERE l.is_attack_ip) AS attack_ip_logins,
               count(*) FILTER (WHERE l.is_attack_ip AND epoch(i.first_ts) > {q70}) AS attack_ip_from_ips_unseen_in_train,
               count(*) FILTER (WHERE NOT l.is_attack_ip AND epoch(i.first_ts) > {q70}) AS other_logins_from_ips_unseen_in_train,
               count(DISTINCT l.ip) FILTER (WHERE l.is_attack_ip AND epoch(i.first_ts) > {q70}) AS unseen_attack_ips
        FROM logins l JOIN ip_stats i USING (ip) GROUP BY 1 ORDER BY 1""", out, "33_ip_disjoint_sizes")
    t = disj[disj.split == "3_test"].iloc[0]
    facts["test_attack_unseen"] = int(t.attack_ip_from_ips_unseen_in_train)
    facts["test_other_unseen"] = int(t.other_logins_from_ips_unseen_in_train)
    if facts["test_attack_unseen"] < 5000:
        flags.append(f"Only {facts['test_attack_unseen']:,} test attack-IP logins come from IPs unseen in training: "
                     "a time-based IP-disjoint test is small. Consider holding out random groups of IPs instead.")

    # ---------------- H. ASN, country, hour
    tick("H. Which ASNs, countries and hours dominate?")
    save(con, """
        SELECT asn, count(*) AS logins, count(*) FILTER (WHERE is_attack_ip) AS attack_ip_logins,
               round(100.0 * count(*) FILTER (WHERE is_attack_ip) / count(*), 2) AS attack_ip_pct,
               round(100.0 * count(*) FILTER (WHERE is_attack_ip) / (SELECT count(*) FROM logins WHERE is_attack_ip), 2) AS share_of_all_attack_pct,
               count(DISTINCT ip) AS distinct_ips
        FROM logins GROUP BY asn ORDER BY attack_ip_logins DESC LIMIT 15""", out, "34a_top_asn_by_attack")
    save(con, """
        SELECT country, count(*) AS logins, count(*) FILTER (WHERE is_attack_ip) AS attack_ip_logins,
               round(100.0 * count(*) FILTER (WHERE is_attack_ip) / count(*), 2) AS attack_ip_pct,
               round(100.0 * count(*) FILTER (WHERE is_attack_ip) / (SELECT count(*) FROM logins WHERE is_attack_ip), 2) AS share_of_all_attack_pct
        FROM logins GROUP BY country ORDER BY attack_ip_logins DESC LIMIT 15""", out, "34b_top_country_by_attack")
    hour = save(con, """
        SELECT hour(ts) AS hour_of_day, count(*) AS logins, count(*) FILTER (WHERE is_attack_ip) AS attack_ip_logins,
               round(100.0 * count(*) FILTER (WHERE is_attack_ip) / count(*), 2) AS attack_ip_pct,
               count(*) FILTER (WHERE is_ato) AS takeovers
        FROM logins GROUP BY 1 ORDER BY 1""", out, "35_hourly_profile", max_rows=24)
    facts["hour_rate_range"] = (float(hour.attack_ip_pct.min()), float(hour.attack_ip_pct.max()))

    write_summary(facts, flags, out, pq)
    print(f"\nDone in {time.time() - t0:.0f} s. Summary: {out / 'audit2_summary.md'}")


def write_summary(f, flags, out, pq):
    def pct(x):
        return "n/a" if x is None else f"{x}%"
    L = [
        "# RBA audit, round 2: summary", "", f"Parquet audited: `{pq}`", "",
        "## Key numbers",
        f"- Catch-all candidate: user {f['top_user_id']} holds {f['top_user_share']}% of all logins; attack-IP rate {f['top_user_attack_pct']}%, "
        f"success rate {f['top_user_success_pct']}%, {f['top_user_ips']:,} distinct IPs. Users above 1% of logins: {f['users_over_1pct']}.",
        f"- IPs with mixed attack labels: {f['mixed_ip_pct']}%. IPs whose flag turns on after clean logins: {f['flag_turns_on_later']:,}.",
        f"- RTT presence ratio (attack-IP vs other): {('%.2f' % f['rtt_presence_ratio']) if 'rtt_presence_ratio' in f else 'n/a'}",
        f"- Strongest single feature for attack-IP (sample): {f['best_atk_feature']} (AUC {f['best_atk_auc']:.3f})",
        f"- Test attack-IP logins from IPs unseen in training: {f['test_attack_unseen']:,} (other logins: {f['test_other_unseen']:,})",
        f"- Takeovers: zero prior logins {pct(f['ato_zero_prior'])}; new country among those with history {pct(f['ato_pct_new_country'])}"
        f" (other logins: {pct(f.get('other_pct_new_country'))})",
        f"- Attack-IP rate by hour of day ranges {f['hour_rate_range'][0]}% to {f['hour_rate_range'][1]}%", "",
        "## Warning flags (rules of thumb, not verdicts)",
    ]
    L += [f"- {x}" for x in flags] or ["- none raised"]
    L += ["", "## Reading guide",
          "- 21 and 22: what the catch-all ID is. Do not name it in the thesis until you have read these.",
          "- 23 and 24: if almost no IP has mixed labels, the label is an IP attribute.",
          "- 25: RTT presence that differs by label is itself a leak.",
          "- 28 and 29: single-feature AUC is exploratory. Per-IP aggregates use the whole period and leak across time.",
          "- 30 to 32: how takeovers differ from other logins in 'new for this user' terms.",
          "- 33: whether an IP-disjoint test is large enough.",
          "- 35: if attack rate is flat across hours, time-of-day features carry little signal."]
    (out / "audit2_summary.md").write_text("\n".join(L), encoding="utf-8")


if __name__ == "__main__":
    main()
