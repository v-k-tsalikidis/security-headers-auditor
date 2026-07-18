# Methodology

## Research Basis

This project uses public guidance as an initial methodology base:

- [OWASP Secure Headers Project](https://www.owasp.community/projects/secure-headers-project)
- [OWASP Secure Headers Project best practices](https://github.com/OWASP/www-project-secure-headers/blob/master/mainsite/03_best_practices.md)
- [MDN HTTP headers reference](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers)
- [MDN HTTP Observatory scoring methodology](https://developer.mozilla.org/en-US/observatory/docs/tests_and_scoring)
- [web.dev security headers quick reference](https://web.dev/articles/security-headers)
- [MDN Referrer-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referrer-Policy)

The tool does not copy Mozilla HTTP Observatory scoring. It uses a simpler local scoring model designed for transparent portfolio, maintenance, and learning use.

## Assessment Model

Findings are divided into three categories.

### Baseline

Baseline findings affect the score. These controls are broadly useful for common public websites and web applications:

| Header | Weight |
| --- | ---: |
| `Strict-Transport-Security` | 20 |
| `Content-Security-Policy` | 20 |
| `X-Content-Type-Options` | 10 |
| `X-Frame-Options` | 10 |
| `Referrer-Policy` | 10 |
| `Permissions-Policy` | 10 |
| `Cross-Origin-Opener-Policy` | 10 |
| `Cross-Origin-Resource-Policy` | 10 |

### Contextual

Contextual findings are reported but not scored. These headers may be valuable, but their correct use depends on endpoint type, compatibility, and application behavior:

- `Cross-Origin-Embedder-Policy`
- `Clear-Site-Data`
- `Cache-Control`
- `X-Permitted-Cross-Domain-Policies`
- `X-DNS-Prefetch-Control`

### Information Disclosure

Information-disclosure observations are reported separately. They do not prove a vulnerability, but they may reveal unnecessary platform or framework details:

- `Server`
- `X-Powered-By`
- `X-AspNet-Version`
- `X-AspNetMvc-Version`
- `X-Generator`
- `X-CMS`
- `X-Php-Version`

## Scoring

Each baseline header can receive:

- full points for strong expected values;
- partial points for present but weak or incomplete values;
- zero points when missing.

The score is calculated as:

```text
score = round(100 * earned_baseline_points / available_baseline_points)
```

Score summaries:

| Score | Summary |
| ---: | --- |
| 85-100 | Strong |
| 60-84 | Moderate |
| 35-59 | Needs Review |
| 0-34 | Weak |

## Interpretation Guardrails

- A high score does not prove that an application is secure.
- A low score does not prove active compromise.
- Header values must be reviewed in application context.
- CSP and cross-origin policies can break applications if applied blindly.
- Security headers are one layer of web security hygiene, not a substitute for secure design, patching, authentication, logging, dependency management, and vulnerability management.
