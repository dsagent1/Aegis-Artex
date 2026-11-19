# Red-Team Mode — Doctrine (defensive, fail-closed)

Red-Team is the scope-enforcing, first-class pentest mode. It is **authorization-gated** and
**fail-closed**: it refuses to run without a valid, in-date `redteam/authorization.json` that names the
hosts you are authorized to test. Non-destructiveness alone is **not** authorization.

## Non-negotiable rules
1. **Authorized, owned targets only.** Every host must appear in the scope of a signed
   `authorization.json` (self-owned asset, or explicit written client authorization). Out of scope = not
   touched. Copy `authorization.json.example` and fill it in; the file is gitignored.
2. **Contained by default.** Prefer a local mirror/twin. Production and third-party systems require
   explicit written authorization and a defined rules-of-engagement (RoE).
3. **Non-destructive.** Prove a finding by planting/reading a benign marker — never erase, delete, drop,
   truncate, corrupt or exfiltrate real data, and never degrade availability. Stop at proof.
4. **Probe classification (`authorization.py::classify_probe`).** Every probe is classified
   recon / active / destructive. Read-only recon is allowed in-scope; destructive or out-of-scope probes
   are blocked, fail-closed.
5. **Foothold = proof only (`foothold_policy.json`).** A foothold MAY prove and explore; it MUST NEVER
   persist, impact, exfiltrate, or evade. The beacon is loopback-only, ephemeral, TTL-bound, self-cleaning.
   No service/scheduled-task/registry/cron/implant that survives reboot or session exit.
6. **Lateral movement stays in scope.** Pivots follow the RoE `pivot_map`; a pivot to any host not in
   scope is refused.
7. **Evidence-gated truth.** Only oracle-verified findings count. Report for remediation; never use access
   beyond the authorized assessment.
8. **Law & disclosure.** Respect applicable law, contracts and terms of service; handle findings under
   responsible disclosure.

This mirrors the platform doctrine in `operator/aegis_operator.py::_DOCTRINE`. Circumvention of
licensing/DRM, credential theft, persistence, anti-forensics/evasion, and C2 against non-owned systems are
**out of scope** for this project.
