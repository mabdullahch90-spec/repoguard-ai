"""RepoGuard AI — deterministic static analysis rule engine ("The Scout").

Design notes
------------
* Rules are **data, not code**: adding a new detector = appending a `Rule`.
* Detection is regex/heuristic based (no execution of user code — we only
  ever *read* text, satisfying the "zero unsafe evaluation" requirement).
* Every rule carries an OWASP mapping + remediation hint so the app still
  gives useful output when no AI engine is reachable (graceful degradation).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .models import Finding, Language, ScanResult, Severity

# Guardrail: never let a single paste blow up memory / token budgets.
MAX_INPUT_CHARS = 12_000


@dataclass(frozen=True)
class Rule:
    """A single static-analysis detection rule."""

    rule_id: str
    title: str
    severity: Severity
    owasp: str
    pattern: re.Pattern
    description: str
    remediation: str
    languages: tuple[Language, ...] = (Language.PYTHON, Language.JAVASCRIPT)
    # Optional: a second pattern that SUPPRESSES the hit (e.g. safe usage).
    allow_pattern: re.Pattern | None = field(default=None, compare=False)


# ---------------------------------------------------------------------------
# Rule pack — mapped to OWASP Top 10 (2021)
# ---------------------------------------------------------------------------
RULES: tuple[Rule, ...] = (
    # ---------------- Hardcoded secrets (A07) ----------------
    Rule(
        rule_id="SEC-001",
        title="Hardcoded API key / secret",
        severity=Severity.CRITICAL,
        owasp="A07:2021 – Identification and Authentication Failures",
        pattern=re.compile(
            r"""(?ix)
            (?:api[_-]?key|apikey|secret|secret[_-]?key|token|access[_-]?token|
               password|passwd|private[_-]?key)
            \s*=\s*["'][A-Za-z0-9/+=_\-]{12,}["']
            """
        ),
        description=(
            "Secrets embedded in source end up in git history, CI logs and every "
            "clone of the repo. Anyone with read access owns the credential."
        ),
        remediation=(
            "Load the value from the environment (os.environ[...]) or a secrets "
            "manager, and rotate the exposed credential immediately."
        ),
    ),
    Rule(
        rule_id="SEC-002",
        title="Well-known credential pattern (AWS/OpenAI/GitHub)",
        severity=Severity.CRITICAL,
        owasp="A07:2021 – Identification and Authentication Failures",
        pattern=re.compile(
            r"(?x)\b(AKIA[0-9A-Z]{16})\b|\b(sk-[A-Za-z0-9]{20,})\b|\b(ghp_[A-Za-z0-9]{36})\b"
        ),
        description="A real-looking provider token is present in plaintext.",
        remediation="Revoke & rotate the key, then use an env var / secret store.",
    ),

    # ---------------- Injection (A03) ----------------
    Rule(
        rule_id="SEC-003",
        title="SQL injection risk (string built into query)",
        severity=Severity.HIGH,
        owasp="A03:2021 – Injection",
        pattern=re.compile(
            r"""(?ix)
            (?:execute|executemany|raw|extra)\s*\(\s*
               (?:f["']|["'][^"']*(?:%s|\{\})[^"']*["']\s*%|["'][^"']*["']\s*\+|\+\s*)
            """
        ),
        description=(
            "Interpolating untrusted input into SQL lets an attacker alter the "
            "query structure (UNION SELECT, tautologies, stacked queries)."
        ),
        remediation="Use parameterised queries: cursor.execute('... WHERE id=%s', (user_id,)).",
    ),
    Rule(
        rule_id="SEC-004",
        title="Command injection risk (shell=True / os.system)",
        severity=Severity.HIGH,
        owasp="A03:2021 – Injection",
        pattern=re.compile(
            r"""(?ix)
            (?:os\.system|os\.popen|subprocess\.(?:run|call|Popen|check_output))
            \s*\([^)]*(?:shell\s*=\s*True|\+\s*|f["'])
            """
        ),
        description=(
            "Building shell commands from variables allows OS command injection "
            "(; rm -rf, `curl evil | sh`, $(...))."
        ),
        remediation=(
            "Avoid the shell: pass an argument list with shell=False, e.g. "
            "subprocess.run(['ping','-c','1',host], check=True)."
        ),
    ),
    Rule(
        rule_id="SEC-005",
        title="Code execution via eval()/exec()",
        severity=Severity.HIGH,
        owasp="A03:2021 – Injection",
        pattern=re.compile(r"(?<![A-Za-z0-9_])(?:eval|exec)\s*\((?!\s*['\"]?\s*\))"),
        description="eval/exec on dynamic input executes arbitrary attacker code.",
        remediation=(
            "Use literal_eval for data, json.loads for JSON, or explicit dispatch "
            "tables instead of executing strings."
        ),
        languages=(Language.PYTHON,),
    ),
    Rule(
        rule_id="SEC-006",
        title="Unsafe deserialization (pickle/yaml.load/marshal)",
        severity=Severity.CRITICAL,
        owasp="A08:2021 – Software and Data Integrity Failures",
        pattern=re.compile(r"pickle\.loads?\s*\(|yaml\.load\s*\((?!.*SafeLoader)|marshal\.loads?\s*\("),
        description=(
            "Deserialising untrusted bytes can trigger remote code execution "
            "(pickle __reduce__ gadgets, yaml python/object tags)."
        ),
        remediation=(
            "Use yaml.safe_load / json.loads, or sign serialised payloads and "
            "verify signatures before parsing."
        ),
        languages=(Language.PYTHON,),
    ),

    # ---------------- Crypto failures (A02) ----------------
    Rule(
        rule_id="SEC-007",
        title="Weak password hashing (MD5/SHA1)",
        severity=Severity.HIGH,
        owasp="A02:2021 – Cryptographic Failures",
        pattern=re.compile(r"hashlib\.(?:md5|sha1)\s*\("),
        description=(
            "MD5/SHA1 are fast, collision-broken hashes — trivially brute-forced "
            "against password dumps."
        ),
        remediation=(
            "Use bcrypt / argon2-cffi / scrypt via passlib, e.g. "
            "bcrypt.hashpw(password, bcrypt.gensalt())."
        ),
        allow_pattern=re.compile(r"(?i)#.*(checksum|integrity|non[- ]?security)"),
        languages=(Language.PYTHON,),
    ),
    Rule(
        rule_id="SEC-008",
        title="Predictable randomness for security tokens",
        severity=Severity.MEDIUM,
        owasp="A02:2021 – Cryptographic Failures",
        pattern=re.compile(r"(?i)random\.(?:random|randint|choice|choices)\s*\("),
        description=(
            "The Mersenne Twister PRNG is deterministic; session tokens/CSRF/OTP "
            "generated with it can be predicted."
        ),
        remediation=(
            "Use the secrets module: secrets.token_urlsafe(32) / "
            "secrets.choice()."
        ),
        allow_pattern=re.compile(r"#\s*(?:test|demo|dummy)"),
        languages=(Language.PYTHON,),
    ),
    Rule(
        rule_id="SEC-009",
        title="TLS verification disabled (verify=False)",
        severity=Severity.MEDIUM,
        owasp="A07:2021 – Identification and Authentication Failures",
        pattern=re.compile(r"verify\s*=\s*False"),
        description=(
            "Disabling certificate verification enables silent MITM interception "
            "of credentials/tokens in transit."
        ),
        remediation="Remove verify=False; supply the correct CA bundle instead.",
    ),

    # ---------------- Misc web / config ----------------
    Rule(
        rule_id="SEC-010",
        title="Flask/Django debug mode in production path",
        severity=Severity.MEDIUM,
        owasp="A05:2021 – Security Misconfiguration",
        pattern=re.compile(r"debug\s*=\s*True"),
        description=(
            "Debug mode exposes the interactive debugger (PIN-authenticated RCE) "
            "and full stack traces with secrets."
        ),
        remediation="Drive debug from an env var that is False in production.",
    ),
    Rule(
        rule_id="SEC-011",
        title="HTML rendered from f-string / concatenation (XSS risk)",
        severity=Severity.MEDIUM,
        owasp="A03:2021 – Injection",
        pattern=re.compile(r"""innerHTML\s*=\s*(?:`[^`]*\$\{|["'][^"']*["']\s*\+)"""),
        description=(
            "Interpolating untrusted data into innerHTML allows script execution "
            "in the victim's browser (stored/reflected XSS)."
        ),
        remediation=(
            "Use textContent for plain text, or sanitise with DOMPurify before "
            "assigning to innerHTML."
        ),
        languages=(Language.JAVASCRIPT,),
    ),
    Rule(
        rule_id="SEC-012",
        title="SQL query built with template literals",
        severity=Severity.HIGH,
        owasp="A03:2021 – Injection",
        pattern=re.compile(
            r"""(?i)(?:query|sql)\s*[:=]\s*`[^`]*\$\{"""
        ),
        description="JS template literal inside SQL = classic Node SQLi.",
        remediation="Use placeholder parameters (? / $1) supplied as an array.",
        languages=(Language.JAVASCRIPT,),
    ),
    Rule(
        rule_id="SEC-013",
        title="SQL query assembled in a variable (cross-line SQLi)",
        severity=Severity.HIGH,
        owasp="A03:2021 – Injection",
        pattern=re.compile(
            r"""(?ix)
            (?:query|sql|stmt|statement)\s*[:=]\s*
               (?:f["']                      # f-string
               |["'][^"']*["']\s*(?:%|\+)    # "%s" % ...  or  "..." + var
               |\+\s*)                        # var + "..."
            """
        ),
        description=(
            "Interpolating input into a query *variable* before execute() is "
            "still SQL injection — sanitising the execute call alone is not enough."
        ),
        remediation=(
            "Keep the query string parameterised and pass values separately: "
            "cursor.execute('SELECT ... WHERE id=%s', (user_id,))."
        ),
        languages=(Language.PYTHON,),
    ),
)


# ---------------------------------------------------------------------------
# Language sniffing (cheap first-char heuristic)
# ---------------------------------------------------------------------------
def detect_language(code: str) -> Language:
    if re.search(r"^\s*(?:def |import |from |class )", code, re.M):
        return Language.PYTHON
    if re.search(r"(?:=>|function\s|const\s|let\s|require\()", code):
        return Language.JAVASCRIPT
    return Language.UNKNOWN


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------
def scan(code: str, language: Language | None = None) -> ScanResult:
    """Scan a code snippet and return every rule hit.

    The scanner never executes the snippet — it is treated purely as text.
    """
    truncated = len(code) > MAX_INPUT_CHARS
    if truncated:
        code = code[:MAX_INPUT_CHARS]

    language = language or detect_language(code)
    lines = code.splitlines()
    findings: list[Finding] = []

    for lineno, line in enumerate(lines, start=1):
        # Skip obvious comment-only lines to cut false positives.
        stripped = line.strip()
        if stripped.startswith(("#", "//", "*", "/*")):
            continue

        for rule in RULES:
            if language != Language.UNKNOWN and language not in rule.languages:
                continue
            if not rule.pattern.search(line):
                continue
            # Suppression check (e.g. "# checksum only — not security relevant")
            if rule.allow_pattern and rule.allow_pattern.search(line):
                continue
            findings.append(
                Finding(
                    rule_id=rule.rule_id,
                    title=rule.title,
                    severity=rule.severity,
                    owasp=rule.owasp,
                    line_no=lineno,
                    code=stripped,
                    description=rule.description,
                    remediation=rule.remediation,
                )
            )

    return ScanResult(
        language=language,
        total_lines=len(lines),
        findings=findings,
        truncated=truncated,
    )
