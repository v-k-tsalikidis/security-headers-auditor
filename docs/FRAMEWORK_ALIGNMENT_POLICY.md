# Framework Alignment And Claims Policy

**Status:** Accepted and primary-source reviewed for v0.5; release validation pending
**Reviewed:** 2026-07-19

## Purpose

Security Headers Auditor remains an HTTP response-header assessment tool. It
does not become a general compliance platform, ATT&CK navigator, D3FEND browser,
vulnerability scanner, or risk-management suite.

Framework references are included only when they improve the interpretation of
observed header evidence. They never add score merely because a framework
identifier exists.

## Evidence Taxonomy

Every external relationship is assigned one evidence family:

| Family | Meaning | Permitted claim |
| --- | --- | --- |
| Verification requirement | The observed response can support part of a published verification requirement | "Provides evidence relevant to..." |
| Test procedure | The auditor implements a bounded part of a published test objective | "Test coverage aligned with..." |
| Security control | The header is related to one element of a broader control | "Control-informed relationship to..." |
| Threat mitigation | The header contributes to a mitigation that addresses named adversary behavior | "Threat context linked to..." |
| Defensive technique | The configuration is an instance or close relation of a defensive technique | "Related defensive-technique context..." |
| Technical format | A generated artifact validates against a published machine-readable schema | "Conforms to [format/version]" |

The relationship strength and limitation are mandatory fields. A relationship
identifier without rationale and limitations is invalid.

## Framework Decisions

### OWASP Secure Headers Project

**Role:** Primary header-specific implementation guidance.

The project can state that its rules are informed by the OWASP Secure Headers
Project when each rule cites the exact guidance reviewed. This is alignment with
guidance, not OWASP certification or endorsement.

### OWASP ASVS 5.0.0

**Role:** Versioned verification-requirement evidence.

An observed header can support selected ASVS requirements, especially in V3.4
and V3.5. It cannot prove route coverage, application behavior, policy
compatibility, or overall ASVS verification.

Permitted wording:

> Includes versioned evidence mappings to selected OWASP ASVS 5.0.0
> requirements.

Prohibited wording:

> OWASP compliant, ASVS certified, or passes ASVS.

### OWASP WSTG

**Role:** Test-procedure alignment.

WSTG-CONF-14 defines objectives for identifying and assessing HTTP security
header misconfigurations. The auditor can claim bounded test coverage aligned
with those objectives only for the headers and response evidence it actually
evaluates. It does not inspect conflicting HTML `meta` policies, every route,
browser runtime behavior, or complete application configuration.

### NIST SP 800-53 Rev. 5

**Role:** Control-informed evidence relationship.

HSTS and CSP observations can be related to parts of broader controls such as
SC-8 and SC-18. A single response cannot establish implementation of the full
organizational control, assessment objective, inherited control, or operating
effectiveness.

Permitted wording:

> Includes control-informed evidence relationships to selected NIST SP 800-53
> Rev. 5 controls.

Prohibited wording:

> NIST compliant, NIST certified, or SP 800-53 compliant.

### MITRE ATT&CK

**Role:** Non-scoring threat and mitigation context.

ATT&CK Enterprise mitigation M1021 explicitly includes enforcing Content
Security Policy to restrict script execution, iframe embedding, and cross-origin
requests. ATT&CK also identifies CSP as one mitigation consideration for HTML
Smuggling under T1027.006.

These links explain adversary behavior that a strong CSP can help constrain.
They do not prove that CSP prevents the technique, that the application is free
from XSS, or that the organization has implemented the broader ATT&CK
mitigation.

ATT&CK identifiers never affect the response-profile score or continuous
assurance result.

### MITRE D3FEND

**Role:** Low-confidence, non-scoring defensive-technique context.

D3FEND D3-ACH describes Application Configuration Hardening as modifying
application configuration to reduce attack surface. Security response headers
can reasonably be discussed as application configuration hardening, but D3FEND
does not provide a header-specific technique or a normative compliance
requirement.

The relationship must therefore be labelled `related` and `inferred`, with the
limitation visible in reports. D3FEND itself describes several ATT&CK
relationships as inferred and experimental.

### SARIF 2.1.0

**Role:** Technical artifact conformance.

The project may state that its SARIF output conforms to SARIF 2.1.0 only while
release tests validate generated artifacts against the official OASIS schema.
This statement applies to the output format, not to security or compliance.

## Report Presentation

Reports separate framework material into:

1. **Verification evidence** - OWASP ASVS and WSTG.
2. **Control relationships** - NIST SP 800-53.
3. **Threat context** - MITRE ATT&CK.
4. **Defensive-technique context** - MITRE D3FEND.
5. **Specifications and research** - W3C, WHATWG, IETF, MDN, and peer-reviewed
   literature.

The report must not place these identifiers in a compliance badge, combined
percentage, or pass/fail matrix.

## Version And Review Rules

- Every mapping set has a version and review date.
- Framework versions and source URLs are pinned in the citation manifest.
- A mapping change makes an existing approved assurance baseline incompatible.
- Framework updates require a reviewed diff, regression fixtures, and release
  notes.
- Deprecated, renumbered, or withdrawn requirements remain in historical
  mapping sets but are not silently reinterpreted.

## Primary-Source Review Record

On 2026-07-19, mapping set `2026.07.2` was reviewed against the official
OWASP ASVS 5.0.0 requirements, the current OWASP WSTG-CONF-12 and
WSTG-CONF-14 procedures, NIST SP 800-53 Rev. 5 Update 1, MITRE ATT&CK M1021
and T1027.006, and MITRE D3FEND D3-ACH. The review confirmed that:

- ASVS entries stay limited to observed response evidence and retain their
  route, browser, and application-behavior limitations.
- WSTG-CONF-14 is represented as bounded test-procedure alignment, rather than
  full configuration or browser-behavior validation.
- NIST entries remain control-informed relationships only.
- ATT&CK stays non-scoring threat context; M1021 is a direct CSP mitigation
  relationship, while the T1027.006 relationship is explicitly related.
- D3-ACH remains an auditor-maintained inferred relationship, not a
  header-specific D3FEND assertion.

## References

- OWASP Secure Headers Project:
  https://owasp.org/www-project-secure-headers/
- OWASP WSTG, WSTG-CONF-14:
  https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/14-Test_Other_HTTP_Security_Header_Misconfigurations
- OWASP ASVS 5.0.0:
  https://github.com/OWASP/ASVS/tree/v5.0.0
- NIST SP 800-53 Rev. 5:
  https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final
- MITRE ATT&CK M1021:
  https://attack.mitre.org/mitigations/M1021/
- MITRE ATT&CK T1027.006:
  https://attack.mitre.org/techniques/T1027/006/
- MITRE D3FEND D3-ACH:
  https://next.d3fend.mitre.org/technique/d3f%3AApplicationConfigurationHardening/
- OASIS SARIF 2.1.0:
  https://docs.oasis-open.org/sarif/sarif/v2.1.0/
