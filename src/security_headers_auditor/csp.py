"""Bounded parsing primitives for selected CSP Level 3 header semantics.

This module intentionally parses only serialized response-header policies. It
does not model browser execution, HTML meta policies, or composite-policy
enforcement.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


MAX_CSP_HEADER_LENGTH = 16 * 1024
_ASCII_WHITESPACE = "\t\n\f\r "
_ASCII_SPLIT = re.compile(r"[\t\n\f\r ]+")
_DIRECTIVE_NAME = re.compile(r"[A-Za-z0-9-]+\Z")
_NONCE_OR_HASH_SOURCE = re.compile(
    r"'(?:nonce-|sha(?:256|384|512)-)[A-Za-z0-9+/_-]+={0,2}'\Z",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class CSPParseIssue:
    code: str
    directive_name: str | None = None


@dataclass(frozen=True)
class CSPDirective:
    name: str
    values: tuple[str, ...]


@dataclass(frozen=True)
class CSPPolicy:
    directives: tuple[CSPDirective, ...]
    issues: tuple[CSPParseIssue, ...]

    def directive(self, name: str) -> CSPDirective | None:
        normalized = name.lower()
        return next(
            (directive for directive in self.directives if directive.name == normalized),
            None,
        )

    def directive_values(self, name: str) -> tuple[str, ...]:
        directive = self.directive(name)
        return directive.values if directive else ()

    def has_directive(self, name: str) -> bool:
        return self.directive(name) is not None


@dataclass(frozen=True)
class CSPPolicyList:
    policies: tuple[CSPPolicy, ...]
    issues: tuple[CSPParseIssue, ...]

    def directive_values(self, name: str) -> tuple[str, ...]:
        return tuple(
            value
            for policy in self.policies
            for value in policy.directive_values(name)
        )

    def has_directive(self, name: str) -> bool:
        return any(policy.has_directive(name) for policy in self.policies)

    @property
    def all_issues(self) -> tuple[CSPParseIssue, ...]:
        return (*self.issues, *(issue for policy in self.policies for issue in policy.issues))


def parse_csp(value: str) -> CSPPolicyList:
    """Parse a bounded comma-delimited CSP list using selected Level 3 rules.

    The first duplicate directive is retained, matching browser parsing. Source
    values deliberately retain case because nonce and hash material is
    case-sensitive. The result exposes parser uncertainty instead of guessing.
    """
    if len(value) > MAX_CSP_HEADER_LENGTH:
        return CSPPolicyList(
            policies=(),
            issues=(CSPParseIssue("header_too_long"),),
        )

    policies: list[CSPPolicy] = []
    for serialized_policy in value.split(","):
        policy = _parse_serialized_policy(serialized_policy)
        if policy.directives:
            policies.append(policy)
    return CSPPolicyList(policies=tuple(policies), issues=())


def is_valid_nonce_or_hash_source(value: str) -> bool:
    """Return whether a token matches the CSP nonce/hash source grammar subset."""
    return bool(_NONCE_OR_HASH_SOURCE.fullmatch(value))


def _parse_serialized_policy(value: str) -> CSPPolicy:
    directives: list[CSPDirective] = []
    seen_directives: set[str] = set()
    issues: list[CSPParseIssue] = []
    for raw_directive in value.split(";"):
        token = raw_directive.strip(_ASCII_WHITESPACE)
        if not token:
            continue
        if not _is_valid_ascii_directive(token):
            issues.append(CSPParseIssue("non_ascii_or_control_directive_ignored"))
            continue
        parts = tuple(part for part in _ASCII_SPLIT.split(token) if part)
        directive_name = parts[0].lower()
        if not _DIRECTIVE_NAME.fullmatch(directive_name):
            issues.append(CSPParseIssue("invalid_directive_name_ignored"))
            continue
        if directive_name in seen_directives:
            issues.append(CSPParseIssue("duplicate_directive_ignored", directive_name))
            continue
        seen_directives.add(directive_name)
        directives.append(CSPDirective(directive_name, parts[1:]))
    return CSPPolicy(directives=tuple(directives), issues=tuple(issues))


def _is_valid_ascii_directive(value: str) -> bool:
    return all(
        0x20 <= ord(character) <= 0x7E or character in _ASCII_WHITESPACE
        for character in value
    )
