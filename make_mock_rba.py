"""
make_mock_rba.py  -  creates a FAKE login file with the same columns as the RBA dataset.

Purpose: let you rehearse the audit steps on a small file (a few seconds) BEFORE you
download and process the real 30+ million row dataset.

WARNING: every value here is random. Results from this file mean NOTHING about the real data.

Usage:
    python make_mock_rba.py --out data/raw/mock_rba.csv --rows 300000
    python make_mock_rba.py --out data/raw/mock_rba_epoch.csv --rows 300000 --epoch   # integer timestamps
"""
import argparse
import numpy as np
import pandas as pd


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--rows", type=int, default=300_000)
    ap.add_argument("--epoch", action="store_true", help="write timestamps as integer milliseconds")
    ap.add_argument("--seed", type=int, default=42)
    a = ap.parse_args()

    rng = np.random.default_rng(a.seed)
    n = a.rows
    n_users = max(1000, n // 8)

    # timestamps spread over Feb 2020 - Feb 2021, then sorted like a real log
    start = pd.Timestamp("2020-02-01").value // 10**6
    end = pd.Timestamp("2021-02-01").value // 10**6
    ts_ms = np.sort(rng.integers(start, end, n))

    # most users log in rarely (skewed), a few log in a lot
    user_w = rng.pareto(1.5, n_users) + 0.05
    user_w /= user_w.sum()
    user = rng.choice(n_users, n, p=user_w)

    countries = np.array(["NO", "US", "DE", "SE", "CN", "RU", "BR", "IN", "FR", "GB"])
    country = rng.choice(countries, n, p=[0.8, 0.04, 0.03, 0.03, 0.02, 0.02, 0.02, 0.02, 0.01, 0.01])
    asn = rng.integers(100, 60000, n)
    fake_asn = rng.random(n) < 0.01          # mimics the README's placeholder ASNs (>= 500000)
    asn = np.where(fake_asn, rng.integers(500000, 600000, n), asn)

    ip = np.array([f"{rng.integers(11, 223)}.{rng.integers(0, 255)}.{rng.integers(0, 255)}.{rng.integers(1, 255)}" for _ in range(n)])
    fake_ip = rng.random(n) < 0.01           # mimics the README's 10.0.0.0/8 placeholder IPs
    ip = np.where(fake_ip, [f"10.{rng.integers(0, 255)}.{rng.integers(0, 255)}.{rng.integers(1, 255)}" for _ in range(n)], ip)

    # a small pool of attacker IPs that repeat many times (concentration)
    attack_pool = np.array([f"203.0.{i // 250}.{i % 250 + 1}" for i in range(400)])
    is_attack = rng.random(n) < 0.004
    ip = np.where(is_attack, rng.choice(attack_pool, n), ip)
    # attack logins mostly fail
    success = np.where(is_attack, rng.random(n) < 0.05, rng.random(n) < 0.9)

    # a handful of account takeovers (successful logins)
    ato = np.zeros(n, dtype=bool)
    ato[rng.choice(np.where(success)[0], 60, replace=False)] = True

    device = rng.choice(np.array(["desktop", "mobile", "tablet", "bot", ""]), n, p=[0.55, 0.38, 0.05, 0.015, 0.005])
    os_ = rng.choice(np.array(["Windows 10", "Android 10", "iOS 13", "Mac OS X", "Linux"]), n)
    browser = rng.choice(np.array(["Chrome 80", "Firefox 74", "Safari 13", "Edge 80"]), n)
    ua = np.array([f"Mozilla/5.0 ({o}) {b}" for o, b in zip(os_, browser)])
    rtt = rng.lognormal(5.5, 1.0, n).astype(int)
    null_rtt = rng.random(n) < 0.3           # pretend RTT is partly missing
    region = np.where(rng.random(n) < 0.02, "", "Region" + (asn % 50).astype(str))
    city = np.where(region == "", "", "City" + (asn % 400).astype(str))

    df = pd.DataFrame({
        "index": np.arange(n),
        "Login Timestamp": ts_ms if a.epoch else pd.to_datetime(ts_ms, unit="ms").strftime("%Y-%m-%d %H:%M:%S.%f").str[:-3],
        "User ID": user.astype(np.int64) * 7919,
        "Round-Trip Time [ms]": np.where(null_rtt, "", rtt.astype(str)),
        "IP Address": ip,
        "Country": country,
        "Region": region,
        "City": city,
        "ASN": asn,
        "User Agent String": ua,
        "Browser Name and Version": browser,
        "OS Name and Version": os_,
        "Device Type": device,
        "Login Successful": np.where(success, "True", "False"),
        "Is Attack IP": np.where(is_attack, "True", "False"),
        "Is Account Takeover": np.where(ato, "True", "False"),
    })
    df.to_csv(a.out, index=False)
    print(f"wrote {len(df):,} FAKE rows to {a.out}")


if __name__ == "__main__":
    main()
