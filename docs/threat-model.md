# Threat Model - GDID-Class Tracking

Last updated: 2026-07-13

## Purpose of this model

Define what we are defending against when we research and counter Microsoft Global Device Identifier (GDID) tracking - and what we are **not** claiming to solve.

**GDID-only completion boundary:** on a supported unmanaged, single-user Windows
system, the tool is complete when it can continuously block DeviceAdd and remove
known active real Device PUID state. General telemetry suppression and discovery of
the exact Stokes URL-association sensor are open research, not release gates.

---

## Assets

| Asset | Why it matters |
|-------|----------------|
| Install anonymity vs Microsoft | Ability for MS (or recipients of MS records) to recognize *this Windows install* over time |
| Continuity break | Ability to remove known active real PUID state locally while preventing a replacement DeviceAdd |
| Never-mint / starve registration | Continuously prevent DeviceAdd so Microsoft does not receive a new live install id from this image |
| Activity unlinkability | Reduce join of install id ↔ browsing/IP/activity timelines |
| Update survivability | Keep Windows Update working while identity registration is blocked |
| User awareness | Know that the id exists, where it lives, what talks |

Non-goals as primary assets: defeating court orders; hiding crime; full OS anonymity.

**Preferred countermeasure direction:** prevent mint at install; on contaminated
images, use the **canonical expanded wipe + continuous DeviceAdd blocks**
(`degdid.ps1 -Protect`) - not online server re-mint, which hands Microsoft a fresh
real GDID. Decoy mode is experimental.

---

## Adversaries / observers

| Actor | Access | Motivation |
|-------|--------|------------|
| **Microsoft (platform)** | Full mint, DDS, telemetry, lawful retention | Product analytics, fraud, security, compliance, LE response |
| **Law enforcement via MS** | GDID records under legal process (Stokes) | Attribution |
| **Enterprise admin** | WUfB/DO reports with GlobalDeviceId; Intune/Autopilot | Inventory, compliance |
| **Local malware / snoop** | Can read `HKCU\...\LID` easily | Fingerprint device |
| **Network eavesdropper** | Sees IPs to MS hosts, not GDID plaintext (TLS) | Weak alone |
| **Third-party site** | Does **not** automatically receive GDID | Unless MS-side correlation |

---

## Capabilities demonstrated (Stokes)

`[COURT]`-backed:

1. MS can retain records keyed by GDID including **time-aligned access** to specific URLs and VPN infrastructure IPs.
2. GDID IP history can be joined to other account IP logs.
3. VPN does not prevent MS-side install attribution.
4. GDID persists across updates; reinstall yields a new one.

Unknown exact sensor for "URL accessed by GDID" - treat as **high-impact, channel-unverified**.

---

## Trust boundaries

```
[ User apps / browser ] --TLS--> [ Third-party sites ]
         |
         | OS / WinHTTP / services
         v
[ Windows identity + CDP + DO + DiagTrack ]
         | TLS to Microsoft
         v
[ login.live.com | DDS | activity | telemetry backends ]
         |
         v
[ Microsoft retention / LE disclosure ]
```

VPN typically sits under apps or system tunnel; **Microsoft-bound service traffic may still identify the install** if it originates from OS identity stack.

---

## Threat scenarios

### T1 - Persistent install fingerprint by Microsoft
**Precondition:** Normal Windows online use.  
**Impact:** Same `g:...` ties months of activity.  
**Status:** By design.

### T2 - Cross-service correlation (MSA + GDID + IP)
**Precondition:** MSA and/or overlapping IPs.  
**Impact:** Install linked to person.  
**Status:** Expected; court footnote multi-GDID per user.

### T3 - Third-party event attribution via MS records
**Precondition:** MS retains GDID↔time↔destination; LE asks.
**Impact:** VPN'd actions still attributed to install.  
**Status:** Demonstrated in Stokes; channel opaque.

### T4 - Local GDID theft
**Precondition:** Any user-mode read of registry.  
**Impact:** Attacker learns fingerprint (less sensitive than tickets, still identifying).  
**Status:** Trivial.

### T5 - False sense of safety after "GDID change"
**Precondition:** User rotates PUID but keeps MSA / hardware / IP.  
**Impact:** Server-side join re-links.  
**Status:** `[ASSESSED]` major residual risk.

### T6 - Enterprise inventory
**Precondition:** WUfB / DO reports.  
**Impact:** Admin tracks devices by GlobalDeviceId.  
**Status:** Documented schema.

---

## What countermeasures can / cannot do

| Can (implemented or lab-backed where noted) | Cannot (honest) |
|---------------------------------------------|-----------------|
| Detect and display current GDID (`degdid.ps1 -Status`) | Erase Microsoft's historical records |
| Apply dual-stack hosts, report FQDN firewall hydration, and enforce a `wlidsvc` service-firewall block (`-Protect`) | Guarantee no other MS id plane tracks you |
| Canonically wipe known active real PUID state, including the conservative Immersive Property/Token bundle | Prove which single C3 store was uniquely causal without ablation |
| Offer an experimental local decoy mode | Claim the decoy is server-issued or recognized |
| Isolate research in VMs | Make Windows "anonymous OS" |
| Preserve a WU scan and Defender update under the historical block (partial EXP-D evidence) | Hide all OS->MS metadata |

The earlier hosts-based lab runs support the core DeviceAdd-starvation model
(`[LAB]` EXP-A4/C3), while the integrated dual-stack FQDN + service-firewall
implementation still needs longitudinal validation.

### Release hardening still required

- 24-hour protection soak across multiple reboots with the current integrated rules.
- The real target-user/machine GDID contamination shape is covered by interim
  EXP-G; actual MSA UI/sign-in behavior is optional compatibility research.
- Windows 10 22H2/build 19045 and Windows 11 builds outside the lab-validated
  25H2/build-26200 line require their own closure matrices.

C3 single-store ablation would strengthen the causal account of rehydration, but the
canonical wipe already removes the entire observed bundle; unique-cause attribution
is research, not a GDID-only release gate.

---

## Assumptions

1. Consumer Windows 10/11 with network access will attempt device registration.
2. Local account ≠ no GDID (anonymous path) - **confirmed** `[LAB]` EXP-B (SYSTEM/`.DEFAULT` mint without MSA).
3. Hardware sent at DeviceAdd enables *possible* cross-reinstall matching - unproven strength.
4. Official opt-out for GDID does not exist.

---

## Privacy vs legality

This project targets **unwarranted, opaque consumer tracking** and user agency (inspect, reduce, rotate, verify).

It does **not** aim to help evade lawful investigations. Studying Stokes shows *why* the mechanism is powerful - that is research input, not a playbook for crime.

---

## Related docs

- `architecture.md` - how generation and I/O work  
- `surfaces.md` - concrete stores and endpoints  
- `plan.md` - phased countermeasure work  
- `open-questions.md` - gaps that change this model  
