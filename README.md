# Firmware Configuration Drift Monitor (FCDM)

### Automated Semantic Regression Testing for Embedded Systems Using Formal Verification

**Author & Researcher:** Daniel Tsang

**Research (Placeholder):** [The White Paper](https://docs.google.com/document/d/1dvo2aGpmg9PZXCSbwvTNaZjAVUBT6GMpx7uueXkYGJw/edit?tab=t.0)

<img width="924" height="824" alt="image" src="https://github.com/user-attachments/assets/98f72bc0-367d-4a07-aeb5-f2b0adbf9fbc" />

---

## Overview

Firmware updates often introduce unintended security regressions—small configuration mistakes that weaken the system without being noticed. This phenomenon is known as **Silent Security Drift**.

The **Firmware Configuration Drift Monitor (FCDM)** is a formal-verification–driven framework that analyzes firmware versions and mathematically proves whether a developer introduced a dangerous misconfiguration.

> **FCDM automatically scans firmware updates and checks if any security-related settings changed in ways that make the device less secure.**

---

## Project Summary

A Python-based pipeline that:

1. Extracts configuration data from firmware.
2. Normalizes it into a structured semantic state.
3. Uses the **Z3 SMT solver** to prove security invariants.
4. Reports any regression ("drift") between firmware versions.

---

## MVP Scope (Vertical Slice)

Target system: **Linux/OpenWrt-based embedded firmware (SquashFS)**

**Input:** Two extracted firmware filesystem directories:

* `firmware_v1/`
* `firmware_v2/`

**Policies Checked (3 Core Rules):**

1. **Auth Integrity** – Root password removed? Remote root login enabled?
2. **Network Surface** – Were critical ports (22, 23, 80) opened/closed unexpectedly?
3. **Service Hardening** – Did debug services (e.g., Telnet) get unintentionally re-enabled?

---

## Technical Architecture

The FCDM pipeline consists of four modules:

### Module A — Extractor (Python + Binwalk API)

* Unpacks firmware images.
* Locates config files such as `/etc/shadow`, `/etc/config/firewall`, `/etc/services`.

### Module B — Normalizer (Python)

* Converts text config into structured Python dictionaries.
* Example normalization:
  `PermitRootLogin yes → state['ssh_root'] = True`

### Module C — Formal Verifier (Z3 SMT Solver)

* Encodes the firmware state as logical variables.
* Applies the FCDM security policy as safety invariants.
* Output: `UNSAT` → Secure, `SAT` → Insecure (provides counterexample)

### Module D — Reporter (CLI)

Outputs a clear, human-readable Pass/Fail report showing which policy rule drifted.

---

## White Paper Summary

**Silent Drift: Mitigating Firmware Security Regressions via Automated Formal Verification of Configuration State**

### Executive Summary

* Firmware security often focuses on malware and CVEs—but ignores developer mistakes.
* Tools like UEFI Secure Boot ensure *authenticity*, not *security correctness*.
* FCDM introduces automated, mathematical checking for misconfiguration regressions.

### Problem Space

* **Silent Drift:** A Wi-Fi fix might unintentionally re-enable Telnet.
* **Human diffing fails:** Thousands of files, no semantic context.
* **Industry gap:** Traditional scanners miss configuration-level risks.

References:

* Eclypsium: *Ensuring Device Security in Federal Environments*

### Background & Related Work

* **UEFI Secure Boot** = provenance
* **FCDM** = intent verification
* **NIST 800-193** → Detection & Resiliency
* Formal methods used by large cloud systems; embedded systems lag behind.

References:

* Microsoft Research: *SecGuru*
* NIST SP 800-193

### Methodology

* **Symbolic Execution** vs text scanning
* **SMT Solving** with Z3
* **Policy sources:** Yocto Hardening Guide, CIS Linux Benchmarks

References:

* MIT 6.858 Labs (symbolic execution)
* Andrew Helwer: Firewall verification with Z3

### Implementation (PoC)

* Full walkthrough of the Extract → Normalize → Verify → Report pipeline.
* Case study comparing Firmware v1.0 vs v1.1.

### Future Work

* Scaling to hundreds/thousands of rules.
* Integrating into CI/CD for auto-blocking insecure builds.

Reference:

* Adam Chlipala (MIT CSAIL): Verified systems & Bedrock

### Conclusion

Silent Drift is preventable—and formal verification provides a scalable, automated solution that catches regressions before firmware is shipped.

---

## Q&A

**1. What is Silent Security Drift?**

* When firmware evolves, a developer may unintentionally weaken security—such as enabling root login or forgetting a firewall rule. The new image is signed and official but less secure.

**2. How does FCDM detect drift?**

1. Extracts firmware configs.
2. Models them as logical variables.
3. Verifies them using the Z3 solver.
4. Produces proofs identifying the exact misconfiguration.

**3. Why is this better than traditional security scanners?**

* Automated, mathematical, repeatable.
* Catches *semantic* misconfigurations.
* Provides a "Shift-Left" control: issues surface **before** release.

---

## Installation & Usage

1. Ensure Python 3.10+ is installed.
2. Install dependencies:

```bash
pip install z3-solver
```

3. Install Binwalk:

```bash
sudo apt install binwalk
```

4. Run the FCDM analysis:

```bash
python main.py
```

* Update `HOME_DIR`, `FIRMWARE_V1_BIN`, and `FIRMWARE_V2_BIN` in `main.py` to match your firmware paths.

---

## Project Structure

```
FCDM/
├─ main.py
├─ fcdm_classes.py
├─ README.md
├─ firmware_v1_hardened.img
├─ firmware_v2_drift.img
└─ extracted_configs/
```

---

## Current Implementation

* **FirmwareExtractor** – Extracts firmware configs using Binwalk.
* **ConfigParser** – Parses Dropbear configuration and normalizes policy settings.
* **PolicyVerifier** – Encodes Z3 SMT constraints to detect security drift.
* **FCDMController** – Orchestrates extraction, parsing, and verification.

---

## Roadmap

* [ ] Add support for more file formats
* [ ] Expand policy rulesets
* [ ] Add CI/CD GitHub Action integration
* [ ] Develop GUI-based dashboard

---

## Technologies Used

* **Python**
* **Z3 SMT Solver**
* **Binwalk API**
* **Linux/OpenWrt Firmware Structures**

---

## Contributions

PRs, issues, and feature requests are welcome.

---

## References

* Eclypsium – *Ensuring Device Security in Federal Environments*
* NIST SP 800-193 – *Platform Firmware Resiliency Guidelines*
* Yocto Project – Security Hardening
* CIS Benchmarks – Linux Systems
* MIT 6.858 – Computer Systems Security
* Microsoft SecGuru – Formal Policy Checking
* Andrew Helwer – Firewall Verification with Z3
* Adam Chlipala – Bedrock Project

---

## License

MIT License (or project-specific license TBD).
