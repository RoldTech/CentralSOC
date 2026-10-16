# Detection Engine

Three mechanisms, all driven by `Rule` objects:

1. **Event rules** (`target` = `raw`, `request` or `user_agent`) run each pattern against one event; any match fires the rule.
   The reason string records the matched text.
2. **Correlation rules** (`target=correlation`) use their patterns to choose candidate events, group them by source IP,
   and apply one of three window kinds:
   - `threshold`: at least N events within T seconds (brute force, 404/403 floods)
   - `distinct`: at least N distinct values of a field within T seconds (spraying = usernames, scan = destination ports).
     `max_per_value` separates spraying (few tries per account) from brute force (many tries per account).
   - `success_after_failures`: a success preceded by at least N failures from the same IP within T seconds
3. **IOC extraction** (`target=ioc`) records indicators with type, value, source event, timestamp and context. Values are
   validated with `ipaddress`/`urlsplit` (so `13:04:00` is not an IPv6 address) and hashes use lookarounds so a SHA-256 does not
   also yield an MD5.

**Tuning.** Thresholds live in each rule's `params`. Disable noisy rules with `python -m regexsoc rules disable RULE-010`.

**Known blind spots.** POST bodies and TLS-encrypted payloads are not in access logs. Attackers can spoof User-Agents.
Timestamp-less logs cannot be correlated. Slow attacks outside the configured window are missed.
