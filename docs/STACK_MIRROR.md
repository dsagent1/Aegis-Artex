# Stack mirroring & probing — the code-less twin ("build the vault, crack the copy")

Most real-world compromise is **unpatched components + misconfiguration**, not bespoke application-logic
zero-days — and that entire class lives in the **stack**: the server, runtime, framework, CMS and plugins
at their deployed versions, plus the stack-level config. You do **not** need the owner's source code to
reconstruct that and attack it locally.

This is the **scaffold** tier of stage 4 (see `PIPELINE.md`): fingerprint the real target, stand up a
**local twin of its stack + components + observed config** in Kali Docker, then run intrusive — even
destructive — probing against the **copy**, never production. It is the Ocean's-Eleven model: build a
faithful replica of the vault's **make, model and lock** and practise cracking *that*; the real vault is
never touched, and what you learn transfers to the extent the real one is the same build, unpatched and
unshielded. You are **not** replicating the vault's *contents* (their custom logic and data) — that is the
boundary, stated honestly below.

## How it's built (from the fingerprint, no source)
- **`operator/aegis_operator.py :: t_provision_twin(manifest)`** (the `provision_twin` tool) takes the
  fingerprint manifest (`tech`, `cms`, `versions`, `plugins`) and stands up a local twin at the **detected
  versions**, on a loopback port, isolated.
- **Exact (even EOL) stack via a pinned image.** For a legacy PHP/Symfony stack the host OS can't run
  natively, it pulls the matching image — `_DOCKER_LEGACY_TPL` → `php:<ver>-apache` — so a target on, say,
  PHP 5.6 is mirrored on `php:5.6-apache`. Old registry tags are generally still published, so historic
  stacks are reproducible.
- **Components at their versions.** For WordPress it reinstalls the detected **plugins at their detected
  versions** (`wp plugin install <slug> --version=<v>`), and reproduces the **observed stack config/misconfig**
  (exposed `phpinfo()`, a Symfony `app_dev.php` profiler, `display_errors`, cookie flags).
- **Snapshot/restore.** `operator/mirror_snapshot.py` baselines the twin so destructive probes reset cleanly.
- **Fidelity gate.** `operator/mirror_fidelity.py` runs known-good behaviours the real target exhibits and
  **records measured divergence**, so a non-firing result is later judged against drift, not assumption.

## What the code-less twin legitimately finds (the value)
Everything here is a property of the **stack/components/config**, not the bespoke app, so the twin reproduces
it faithfully and the finding is confirmed by **reproduction on the copy** (oracle-gated), prod untouched:
- **Known-CVE / unpatched-component / dependency & plugin vulnerabilities** — the known-vuln pass
  (`rag_search` over NVD/KEV/EPSS/Exploit-DB/MSF/PoC/nuclei, plus the `supply_chain` vector matching
  dependencies/plugins to advisories) fires at the twin and is oracle-verified.
- **Version-specific framework exploits** — EOL-framework RCE/deserialization/etc. that only run on the exact
  old version the twin pins.
- **Stack-level misconfiguration** — exposed debug/profiler endpoints, default credentials, missing security
  headers, directory listing, verbose errors, dangerous `php.ini`/server settings.
- **Component interaction weaknesses** — plugin↔core and plugin↔plugin issues at those versions.

Because this is the class most breaches actually use, a code-less twin is **high-signal**, not a consolation
prize for "we didn't get the source."

## Operational value — intrusive testing with no production blast radius
The deeper value is not only *what* it finds, but *where* it runs. Because every aggressive action lands on
the isolated local twin, an authorized researcher can:
- **Run noisy, intrusive, even destructive checks** — exploit attempts, fuzzing, brute force, DoS-adjacent
  probes — with **zero load, log noise, alerts, WAF triggers, rate-limit lockouts or downtime risk on
  production**. The real target sees only the earlier passive fingerprint.
- **Attack autonomously and repeatably** — snapshot → hammer → restore → retry. No human babysitting a live
  system, no state left behind to clean up, no chance of causing an incident mid-test.
- **Confirm before prod is ever touched** — a weakness is **reproduced on the copy and oracle-verified**
  (and, for components, range-matched to the exact deployed version), so what reaches a report is an
  **evidenced result**, not a scanner's guess. Promoting it to a production claim is then a single low-touch,
  authorized check (version + exposure match) rather than a noisy live campaign.

In short: the copy absorbs the noise and the risk, so the owner's production stays quiet, stable and
un-marked while the stack is exercised thoroughly. This is the legitimate, **in-doctrine** form of "test it
hard without disturbing the real thing" — on **your own authorized target**, you avoid alarming or
destabilising *your own* production; it is not a means to evade a third party's defences.

## The honest boundary (what it does NOT establish)
- **Application-logic bugs** specific to the owner's code — IDOR, broken-authz, business-logic — will **not**
  appear; the scaffold is the stack, not their app. Those need the **real-code mirror** (the high-fidelity
  tier) or live, authorized black-box probing.
- **Live data, real secrets, and WAF/edge controls** are not reproduced. So a twin result is a **production
  CANDIDATE**: it holds on prod only to the extent prod runs the same version, unpatched and unshielded. It
  should be transferred to prod only under authorization, with a low-touch confirmation (version + exposure
  match) — never assumed.
- **Fidelity is bounded and measured, not perfect** — the fidelity gate records where the twin diverges so
  judgments stay honest.

## The two tiers, and the bridge
```
scaffold (stack + components + config)  ⇄  real-code mirror (stack + app)
  code-less, from the fingerprint            needs owner source / build
  finds: component CVEs, version exploits,    adds: application-logic bugs,
         stack misconfig                             data-flow, business logic
```
A **scaffold finding** (a plugin/DB-tier weakness or a fuzzing crash) is real on its own; where a seam is
found, the engine can **bridge scaffold → code** to deepen it when source becomes available.

## Current coverage & roadmap
- **Today:** the pinned-image + component-reinstall path covers **PHP/Symfony and WordPress** faithfully
  (legacy image pinning + plugin versions + observed misconfig).
- **Roadmap:** generalize the versioned-image provisioner to **Node / Python / Ruby / Java / .NET + database
  tiers** (map fingerprint → image tag → `docker compose` the multi-tier stack), and broaden the component
  advisory matching (OSV / GHSA ecosystems, WPScan for CMS plugins) behind the same oracle gate.

## Doctrine
Owned / authorized targets only; everything aggressive hits the **twin, never production**; contained,
non-destructive to prod; the one network reach — pulling a stack image — is gated and runs the untrusted
image inside the isolated Kali Docker sandbox. A twin finding is **proof-on-the-copy**; promoting it to a
production claim requires authorized transfer validation.
