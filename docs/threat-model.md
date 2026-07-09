# Threat Model — GDID-Class Tracking

Last updated: 2026-07-09

## Purpose of this model

Define what we are defending against when we research and counter Microsoft Global Device Identifier (GDID) tracking — and what we are **not** claiming to solve.

---

## Assets

| Asset | Why it matters |
|-------|----------------|
| Install anonymity vs Microsoft | Ability for MS (or recipients of MS records) to recognize *this Windows install* over time |
| Continuity break | Ability to end an old GDID’s usefulness for *future* local correlation (local-only decoy and/or never-mint) |
| Never-mint / starve registration | Prevent DeviceAdd and DDS registration so Microsoft never (or no longer) gets a live install id from this image |
| Activity unlinkability | Reduce join of install id ↔ browsing/IP/activity timelines |
| Update survivability | Keep Windows Update working while identity registration is blocked |
| User awareness | Know that the id exists, where it lives, what talks |

Non-goals as primary assets: defeating court orders; hiding crime; full OS anonymity.

**Preferred countermeasure direction (to validate in lab):** prevent mint at install; on contaminated images, **local-only offline rotate + permanent registration-server blocks** — not online server re-mint (that hands MS a fresh real GDID).

---

## Adversaries / observers

| Actor | Access | Motivation |
|-------|--------|------------|
| **Microsoft (platform)** | Full mint, DDS, telemetry, lawful retention | Product analytics, fraud, security, compliance, LE response |
| **Law enforcement via MS** | GDID records under legal process (Stokes) | Attribution |
| **Enterprise admin** | WUfB/DO reports with GlobalDeviceId; Intune/Autopilot | Inventory, compliance |
| **Local malware / snoop** | Can read `HKCU\…\LID` easily | Fingerprint device |
| **Network eavesdropper** | Sees IPs to MS hosts, not GDID plaintext (TLS) | Weak alone |
| **Third-party site** | Does **not** automatically receive GDID | Unless MS-side correlation |

---

## Capabilities demonstrated (Stokes)

`[COURT]`-backed:

1. MS can retain records keyed by GDID including **time-aligned access** to specific URLs and VPN infrastructure IPs.
2. GDID IP history can be joined to other account IP logs.
3. VPN does not prevent MS-side install attribution.
4. GDID persists across updates; reinstall yields a new one.

Unknown exact sensor for “URL accessed by GDID” — treat as **high-impact, channel-unverified**.

---

## Trust boundaries

```
[ User apps / browser ] --TLS--> [ Third-party sites ]
         │
         │ OS / WinHTTP / services
         ▼
[ Windows identity + CDP + DO + DiagTrack ]
         │ TLS to Microsoft
         ▼
[ login.live.com | DDS | activity | telemetry backends ]
         │
         ▼
[ Microsoft retention / LE disclosure ]
```

VPN typically sits under apps or system tunnel; **Microsoft-bound service traffic may still identify the install** if it originates from OS identity stack.

---

## Threat scenarios

### T1 — Persistent install fingerprint by Microsoft
**Precondition:** Normal Windows online use.  
**Impact:** Same `g:…` ties months of activity.  
**Status:** By design.

### T2 — Cross-service correlation (MSA + GDID + IP)
**Precondition:** MSA and/or overlapping IPs.  
**Impact:** Install linked to person.  
**Status:** Expected; court footnote multi-GDID per user.

### T3 — Third-party event attribution via MS records
**Precondition:** MS retains GDID↔time↔destination; LE asks.  
**Impact:** VPN’d actions still attributed to install.  
**Status:** Demonstrated in Stokes; channel opaque.

### T4 — Local GDID theft
**Precondition:** Any user-mode read of registry.  
**Impact:** Attacker learns fingerprint (less sensitive than tickets, still identifying).  
**Status:** Trivial.

### T5 — False sense of safety after “GDID change”
**Precondition:** User rotates PUID but keeps MSA / hardware / IP.  
**Impact:** Server-side join re-links.  
**Status:** `[ASSESSED]` major residual risk.

### T6 — Enterprise inventory
**Precondition:** WUfB / DO reports.  
**Impact:** Admin tracks devices by GlobalDeviceId.  
**Status:** Documented schema.

---

## What countermeasures can / cannot do

| Can (aspirational, to validate) | Cannot (honest) |
|--------------------------------|-----------------|
| Detect and display current GDID | Erase Microsoft’s historical records |
| Reduce DDS/activity emission | Guarantee no other MS id plane tracks you |
| Force new local PUID | Prevent LE with lawful MS process on *new* id |
| Isolate research in VMs | Make Windows “anonymous OS” |
| Block some endpoints (with breakage) | Hide all OS→MS metadata |

---

## Assumptions

1. Consumer Windows 10/11 with network access will attempt device registration.
2. Local account ≠ no GDID (anonymous CDP path exists) — pending clean-VM proof.
3. Hardware sent at DeviceAdd enables *possible* cross-reinstall matching — unproven strength.
4. Official opt-out for GDID does not exist.

---

## Privacy vs legality

This project targets **unwarranted, opaque consumer tracking** and user agency (inspect, reduce, rotate, verify).

It does **not** aim to help evade lawful investigations. Studying Stokes shows *why* the mechanism is powerful — that is research input, not a playbook for crime.

---

## Related docs

- `architecture.md` — how generation and I/O work  
- `surfaces.md` — concrete stores and endpoints  
- `plan.md` — phased countermeasure work  
- `open-questions.md` — gaps that change this model  
