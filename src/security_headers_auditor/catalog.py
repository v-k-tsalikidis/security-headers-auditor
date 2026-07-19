"""Research-grounded rule and citation catalogue for HTTP header assessment."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Citation:
    key: str
    title: str
    publisher: str
    source_type: str
    url: str
    accessed: str = "2026-07-19"


@dataclass(frozen=True)
class HeaderRule:
    key: str
    name: str
    purpose: str
    recommendation: str
    citation_keys: tuple[str, ...]
    standards: tuple[str, ...] = ()


CITATIONS: dict[str, Citation] = {
    "asvs-5": Citation(
        key="asvs-5",
        title="OWASP Application Security Verification Standard 5.0.0",
        publisher="OWASP Foundation",
        source_type="verification standard",
        url=(
            "https://github.com/OWASP/ASVS/raw/v5.0.0/5.0/docs_en/"
            "OWASP_Application_Security_Verification_Standard_5.0.0_en.csv"
        ),
    ),
    "owasp-secure-headers": Citation(
        key="owasp-secure-headers",
        title="OWASP Secure Headers Project",
        publisher="OWASP Foundation",
        source_type="official project guidance",
        url="https://owasp.org/www-project-secure-headers/",
    ),
    "owasp-rest": Citation(
        key="owasp-rest",
        title="REST Security Cheat Sheet",
        publisher="OWASP Foundation",
        source_type="official security guidance",
        url="https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html",
    ),
    "owasp-csp-testing": Citation(
        key="owasp-csp-testing",
        title="Testing for Content Security Policy",
        publisher="OWASP Web Security Testing Guide",
        source_type="official testing guidance",
        url=(
            "https://owasp.org/www-project-web-security-testing-guide/latest/"
            "4-Web_Application_Security_Testing/"
            "02-Configuration_and_Deployment_Management_Testing/"
            "12-Test_for_Content_Security_Policy"
        ),
    ),
    "rfc-6797": Citation(
        key="rfc-6797",
        title="RFC 6797: HTTP Strict Transport Security",
        publisher="IETF / RFC Editor",
        source_type="internet standard",
        url="https://www.rfc-editor.org/rfc/rfc6797",
    ),
    "w3c-csp3": Citation(
        key="w3c-csp3",
        title="Content Security Policy Level 3",
        publisher="W3C",
        source_type="web standard",
        url="https://www.w3.org/TR/CSP3/",
    ),
    "w3c-referrer": Citation(
        key="w3c-referrer",
        title="Referrer Policy",
        publisher="W3C",
        source_type="web standard",
        url="https://www.w3.org/TR/referrer-policy/",
    ),
    "w3c-permissions": Citation(
        key="w3c-permissions",
        title="Permissions Policy",
        publisher="W3C",
        source_type="web standard",
        url="https://www.w3.org/TR/permissions-policy-1/",
    ),
    "w3c-reporting": Citation(
        key="w3c-reporting",
        title="Reporting API",
        publisher="W3C",
        source_type="web standard",
        url="https://www.w3.org/TR/reporting-1/",
    ),
    "w3c-reporting-legacy": Citation(
        key="w3c-reporting-legacy",
        title="Reporting API Working Draft, September 2018",
        publisher="W3C",
        source_type="historical web specification",
        url="https://www.w3.org/TR/2018/WD-reporting-1-20180925/",
    ),
    "whatwg-fetch": Citation(
        key="whatwg-fetch",
        title="Fetch Standard",
        publisher="WHATWG",
        source_type="living web standard",
        url="https://fetch.spec.whatwg.org/",
    ),
    "whatwg-html": Citation(
        key="whatwg-html",
        title="HTML Standard: Cross-origin opener policies",
        publisher="WHATWG",
        source_type="living web standard",
        url="https://html.spec.whatwg.org/multipage/browsers.html#cross-origin-opener-policies",
    ),
    "w3c-post-spectre": Citation(
        key="w3c-post-spectre",
        title="Post-Spectre Web Development",
        publisher="W3C",
        source_type="security architecture guidance",
        url="https://www.w3.org/TR/post-spectre-webdev/",
    ),
    "nist-800-53r5": Citation(
        key="nist-800-53r5",
        title="NIST SP 800-53 Rev. 5",
        publisher="National Institute of Standards and Technology",
        source_type="security control catalogue",
        url="https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final",
    ),
    "csp-is-dead": Citation(
        key="csp-is-dead",
        title="CSP Is Dead, Long Live CSP! On the Insecurity of Whitelists and the Future of CSP",
        publisher="ACM CCS 2016",
        source_type="peer-reviewed research",
        url="https://dl.acm.org/doi/10.1145/2976749.2978363",
    ),
    "mdn-x-content-type": Citation(
        key="mdn-x-content-type",
        title="X-Content-Type-Options",
        publisher="MDN Web Docs",
        source_type="platform reference",
        url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Content-Type-Options",
    ),
    "mdn-x-frame-options": Citation(
        key="mdn-x-frame-options",
        title="X-Frame-Options",
        publisher="MDN Web Docs",
        source_type="platform reference",
        url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Frame-Options",
    ),
    "mdn-clear-site-data": Citation(
        key="mdn-clear-site-data",
        title="Clear-Site-Data",
        publisher="MDN Web Docs",
        source_type="platform reference",
        url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Clear-Site-Data",
    ),
    "mdn-cache-control": Citation(
        key="mdn-cache-control",
        title="Cache-Control",
        publisher="MDN Web Docs",
        source_type="platform reference",
        url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cache-Control",
    ),
}


RULES: tuple[HeaderRule, ...] = (
    HeaderRule(
        key="strict-transport-security",
        name="Strict-Transport-Security",
        purpose="Reduces protocol downgrade and stripping exposure after first HTTPS use.",
        recommendation=(
            "Serve the origin over HTTPS and define max-age of at least 31536000 seconds. "
            "Add includeSubDomains only after confirming that every subdomain is HTTPS-ready."
        ),
        citation_keys=("rfc-6797", "asvs-5", "owasp-secure-headers", "nist-800-53r5"),
        standards=(
            "OWASP ASVS v5.0.0-3.4.1",
            "NIST SP 800-53 Rev. 5 SC-8 (control-informed)",
        ),
    ),
    HeaderRule(
        key="content-security-policy",
        name="Content-Security-Policy",
        purpose="Constrains executable and embeddable content to reduce XSS blast radius.",
        recommendation=(
            "Use an application-specific policy. Prefer nonce/hash-based script controls, "
            "object-src 'none', base-uri 'none', and an explicit frame-ancestors policy."
        ),
        citation_keys=(
            "w3c-csp3",
            "asvs-5",
            "owasp-csp-testing",
            "csp-is-dead",
            "nist-800-53r5",
        ),
        standards=(
            "OWASP ASVS v5.0.0-3.4.3",
            "OWASP ASVS v5.0.0-3.4.6",
            "NIST SP 800-53 Rev. 5 SC-18 (control-informed)",
        ),
    ),
    HeaderRule(
        key="x-content-type-options",
        name="X-Content-Type-Options",
        purpose="Prevents MIME sniffing when the declared content type should be authoritative.",
        recommendation="Use X-Content-Type-Options: nosniff on all responses.",
        citation_keys=("asvs-5", "mdn-x-content-type", "owasp-rest"),
        standards=("OWASP ASVS v5.0.0-3.4.4",),
    ),
    HeaderRule(
        key="x-frame-options",
        name="X-Frame-Options",
        purpose="Provides legacy clickjacking protection where CSP frame-ancestors is unavailable.",
        recommendation=(
            "Prefer CSP frame-ancestors. Retain X-Frame-Options: DENY or SAMEORIGIN only "
            "for legacy compatibility where appropriate."
        ),
        citation_keys=("asvs-5", "mdn-x-frame-options"),
        standards=("OWASP ASVS v5.0.0-3.4.6",),
    ),
    HeaderRule(
        key="referrer-policy",
        name="Referrer-Policy",
        purpose="Limits leakage of URL paths and query data through the Referer header.",
        recommendation=(
            "Choose a policy such as no-referrer, same-origin, strict-origin, or "
            "strict-origin-when-cross-origin based on application requirements."
        ),
        citation_keys=("w3c-referrer", "asvs-5"),
        standards=("OWASP ASVS v5.0.0-3.4.5",),
    ),
    HeaderRule(
        key="permissions-policy",
        name="Permissions-Policy",
        purpose="Restricts powerful browser features for the document and embedded content.",
        recommendation="Declare an allowlist and disable browser features that the application does not use.",
        citation_keys=("w3c-permissions", "owasp-secure-headers"),
    ),
    HeaderRule(
        key="cross-origin-opener-policy",
        name="Cross-Origin-Opener-Policy",
        purpose="Limits cross-origin Window relationships and supports process isolation.",
        recommendation=(
            "Use same-origin, or same-origin-allow-popups when documented federated "
            "sign-in or payment workflows require opener compatibility."
        ),
        citation_keys=("whatwg-html", "w3c-post-spectre", "asvs-5"),
        standards=("OWASP ASVS v5.0.0-3.4.8",),
    ),
    HeaderRule(
        key="cross-origin-resource-policy",
        name="Cross-Origin-Resource-Policy",
        purpose="Restricts which origins may load a response in no-cors contexts.",
        recommendation="Use same-origin or same-site for sensitive resources where compatible.",
        citation_keys=("whatwg-fetch", "w3c-post-spectre", "asvs-5"),
        standards=("OWASP ASVS v5.0.0-3.5.8",),
    ),
    HeaderRule(
        key="cross-origin-embedder-policy",
        name="Cross-Origin-Embedder-Policy",
        purpose="Enables cross-origin isolation for applications that need protected advanced capabilities.",
        recommendation=(
            "Evaluate require-corp only when cross-origin isolation is required and all "
            "dependent resources have compatible policies."
        ),
        citation_keys=("whatwg-fetch", "w3c-post-spectre"),
    ),
    HeaderRule(
        key="clear-site-data",
        name="Clear-Site-Data",
        purpose="Can clear browser-side state during sensitive transitions such as logout.",
        recommendation="Consider it on logout or account-reset responses, not as a global header.",
        citation_keys=("mdn-clear-site-data", "owasp-secure-headers"),
    ),
    HeaderRule(
        key="cache-control",
        name="Cache-Control",
        purpose="Controls whether sensitive responses may be stored by browser or intermediary caches.",
        recommendation=(
            "Use no-store for authenticated or sensitive responses. Preserve deliberate "
            "caching for public resources rather than applying no-store globally."
        ),
        citation_keys=("mdn-cache-control", "owasp-rest"),
    ),
    HeaderRule(
        key="x-permitted-cross-domain-policies",
        name="X-Permitted-Cross-Domain-Policies",
        purpose="Restricts legacy Adobe cross-domain policy files.",
        recommendation="Use none unless a documented legacy client requirement exists.",
        citation_keys=("owasp-secure-headers",),
    ),
    HeaderRule(
        key="x-dns-prefetch-control",
        name="X-DNS-Prefetch-Control",
        purpose="Controls DNS prefetching for privacy-sensitive documents.",
        recommendation="Consider off for sensitive pages after a performance and privacy review.",
        citation_keys=("owasp-secure-headers",),
    ),
)


RULES_BY_KEY: dict[str, HeaderRule] = {rule.key: rule for rule in RULES}


DISCLOSURE_HEADERS: dict[str, tuple[str, str]] = {
    "server": ("Server", "May disclose web server or platform details."),
    "x-powered-by": ("X-Powered-By", "May disclose framework, language, or hosting details."),
    "x-aspnet-version": ("X-AspNet-Version", "May disclose ASP.NET runtime details."),
    "x-aspnetmvc-version": ("X-AspNetMvc-Version", "May disclose ASP.NET MVC details."),
    "x-generator": ("X-Generator", "May disclose CMS or generator details."),
    "x-cms": ("X-CMS", "May disclose CMS details."),
    "x-php-version": ("X-Php-Version", "May disclose PHP version details."),
}
