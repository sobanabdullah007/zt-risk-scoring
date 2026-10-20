# RBA dataset audit summary

File audited: `data\raw\rba-dataset.csv`

## Key numbers
- Rows: 31,269,264   Users: 4,304,857   Distinct IPs: 3,512,330
- Time range: 2020-02-03 12:43:30.772000  to  2021-02-28 23:59:58.756000
- Attack-IP logins: 3,096,977 (9.9042%)
- Account takeovers: 141 (0.000451%)
- Test split (time-based 70/15/15): attack-IP 552,561, account takeovers 0
- Round-trip time missing: 95.92%
- Logins with 5+ earlier logins by the same user: 64.86%
- Top-10 attacker IPs' share of attack-IP logins: 2.64%
- Rows out of time order in the file: 0

## Warning flags (rules of thumb, not verdicts)
- Round-trip time is missing in 95.9% of logins: treat RTT features with caution.
- Only 0 account takeovers would fall in the test split: use them as a case study only.
- 93% of test-period attack-IP logins come from IPs already flagged in the training period: a model could just memorize IPs. Plan the IP-grouped split and the IP-feature ablation.

## Remember
- The dataset README says feature values are plausible but artificial, and warns against using it for production intrusion detection.
- Country was randomly assigned per unique value; region and city do not reflect the original relations; RTTs were reassigned among users.
- Read every CSV in this folder yourself before deciding the scope.