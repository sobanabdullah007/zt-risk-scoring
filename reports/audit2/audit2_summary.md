# RBA audit, round 2: summary

Parquet audited: `data\processed\rba-dataset.parquet`

## Key numbers
- Catch-all candidate: user -4324475583306591935 holds 44.855% of all logins; attack-IP rate 11.77%, success rate 0.0%, 2,047,733 distinct IPs. Users above 1% of logins: 1.
- IPs with mixed attack labels: 0.0%. IPs whose flag turns on after clean logins: 0.
- RTT presence ratio (attack-IP vs other): 0.15
- Strongest single feature for attack-IP (sample): ip_fail_rate (AUC 0.799)
- Test attack-IP logins from IPs unseen in training: 40,357 (other logins: 873,722)
- Takeovers: zero prior logins 34.0%; new country among those with history 73.1% (other logins: 0.6%)
- Attack-IP rate by hour of day ranges 4.55% to 17.27%

## Warning flags (rules of thumb, not verdicts)
- User -4324475583306591935 holds 44.855% of all logins (2,047,733 distinct IPs, 0.0% successful). Treat it as a catch-all ID, not a real user.
- Only 0.0% of IPs have mixed labels: the attack-IP label is effectively a fixed attribute of the IP. Training on it teaches the model IP identity unless you hold IPs out.
- RTT is present 0.15 times as often for attack-IP logins as for others: its presence alone carries label information. Do not use it unless you understand why.

## Reading guide
- 21 and 22: what the catch-all ID is. Do not name it in the thesis until you have read these.
- 23 and 24: if almost no IP has mixed labels, the label is an IP attribute.
- 25: RTT presence that differs by label is itself a leak.
- 28 and 29: single-feature AUC is exploratory. Per-IP aggregates use the whole period and leak across time.
- 30 to 32: how takeovers differ from other logins in 'new for this user' terms.
- 33: whether an IP-disjoint test is large enough.
- 35: if attack rate is flat across hours, time-of-day features carry little signal.