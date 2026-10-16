# Risk Scoring

The score is a **transparent triage aid**. It is not a probability of compromise.

**Detection score.** Each rule has a default risk score, overridable per rule ID. The severity bands are:
0-29 LOW, 30-59 MEDIUM, 60-79 HIGH, 80-100 CRITICAL. A detection at or above `alert_threshold` (default 30) becomes an alert.

**Per-IP risk profile.** For each source IP, every *distinct* rule that fired contributes its points once, and a rule
firing at least `repeat_threshold` (3) times adds `repeat_bonus` (+10). The total is capped at 100. The reasons are always listed:

```
203.0.113.5  score=100 (CRITICAL)
    +90 SSH Brute Force
    +85 Successful Login After Multiple Failures
    +10 Failed SSH Login
    +10 Repeated: Failed SSH Login x12
```

**Configuration** (`--scoring file.json`):

```json
{"points": {"RULE-010": 20}, "alert_threshold": 40, "repeat_bonus": 5}
```

Unknown keys are rejected. Points are clamped to 0-100.

**Known limitation.** Summing scores saturates quickly: two serious findings on one IP already reach 100. Read the reasons, not just the number.
