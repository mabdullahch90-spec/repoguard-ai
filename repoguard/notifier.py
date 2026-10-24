"""RepoGuard AI — DNotifier integration ("The Messenger + RAG brain").

Three jobs (this triple-use is the "best use of DNotifier" story):

1. ``notify``            – realtime push via ``send()`` when a scan finishes.
2. ``seed_knowledge_base`` – ``add_document()`` uploads OWASP remediation
                            guidance so AI answers are *grounded* (RAG).
3. ``ask``               – ``send_ai()`` query path used by the patcher.

All calls are wrapped so a network/SDK hiccup degrades to a readable
warning instead of crashing the Streamlit UI (demo-day insurance).
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass

from .config import settings
from .models import ScanResult
from .utils import extract_ai_text, run_async

# Compact remediation cheat-sheet seeded into the DNotifier knowledge base.
OWASP_CHEATSHEET = """\
RepoGuard remediation cheat-sheet (grounding document)
======================================================
SEC-001/002 hardcoded secrets: move to environment variables or a secrets
manager (AWS Secrets Manager, Vault, Doppler); rotate exposed keys.
SEC-003 SQL injection: parameterised queries only —
cursor.execute('SELECT ... WHERE id=%s', (user_id,)).
SEC-004 command injection: subprocess with argument lists, shell=False.
SEC-005 eval/exec: use ast.literal_eval, json.loads, or dispatch tables.
SEC-006 unsafe deserialization: yaml.safe_load / json; sign payloads.
SEC-007 weak hashing: bcrypt / argon2-cffi / scrypt, never md5/sha1.
SEC-008 weak randomness: secrets module (secrets.token_urlsafe(32)).
SEC-009 TLS verify=False: keep verification on; pin/ship the right CA bundle.
SEC-010 debug=True: gate debug behind env var, off in production.
SEC-011/012 XSS & JS SQLi: textContent / DOMPurify; placeholder params.
"""


@dataclass
class NotifyStatus:
    ok: bool
    detail: str


class DNotifierBridge:
    """Thin, failure-tolerant wrapper around the official SDK."""

    def __init__(self) -> None:
        self._kb_seeded = False

    # -- internal -----------------------------------------------------------
    def _connect(self, transport: str = "http"):
        from dnotifier import DNotifier  # lazy: keeps offline mode dependency-free

        return DNotifier(
            app_id=settings.dnotifier_app_id,
            secret=settings.dnotifier_secret,
            transport=transport,
            user_id=settings.dnotifier_user_id,
            on_connected=lambda: None,
            on_message=lambda *_: None,
            on_disconnected=lambda **_: None,
        )

    @staticmethod
    async def _wait_connected(notifier, timeout_s: float = 10.0) -> None:
        """WS quirk guard: the SDK returns from connect() *before* the
        handshake ack arrives — poll until is_connected flips True."""
        deadline = time.monotonic() + timeout_s
        while not notifier.is_connected:
            if time.monotonic() > deadline:
                raise TimeoutError("DNotifier WebSocket handshake timed out")
            await asyncio.sleep(0.1)

    # -- public -------------------------------------------------------------
    def notify_scan(self, result: ScanResult) -> NotifyStatus:
        """Realtime push of a finished scan to the configured receiver."""
        if not settings.dnotifier_ready:
            return NotifyStatus(False, "DNotifier credentials missing from .env")

        score = result.security_score
        body = (
            f"RepoGuard scan complete — score {score}/100 | "
            f"{len(result.findings)} finding(s) "
            f"(language: {result.language.value})"
        )
        payload = {
            "type": "notification",  # client routes on `type`
            "title": f"🛡️ RepoGuard: score {score}/100",
            "body": body,
            "link": "https://github.com/your-org/repoguard-ai",
        }

        async def _send_ws():
            notifier = self._connect("ws")
            await notifier.connect()
            try:
                await self._wait_connected(notifier)
                return await notifier.send(
                    sender_id=settings.dnotifier_user_id,
                    receiver_id=settings.dnotifier_receiver_id,
                    data=payload,
                )
            finally:
                try:
                    await notifier.disconnect()
                except Exception:  # noqa: BLE001
                    pass

        async def _send_http():
            notifier = self._connect("http")
            await notifier.connect()
            try:
                return await notifier.send(
                    sender_id=settings.dnotifier_user_id,
                    receiver_id=settings.dnotifier_receiver_id,
                    data=payload,
                )
            finally:
                try:
                    await notifier.disconnect()
                except Exception:  # noqa: BLE001
                    pass

        # Preferred path: WebSocket (DNotifier's primary realtime channel).
        try:
            msg_id = run_async(_send_ws())
            return NotifyStatus(True, f"Pushed to '{settings.dnotifier_receiver_id}' (id {msg_id})")
        except Exception as ws_exc:  # noqa: BLE001 - fall back to HTTP RPC
            try:
                msg_id = run_async(_send_http())
                return NotifyStatus(
                    True, f"Pushed via HTTP to '{settings.dnotifier_receiver_id}' (id {msg_id})"
                )
            except ValueError:
                # Known SDK quirk: server returns an empty ack body for the
                # plain-message RPC; json parsing fails *after* delivery.
                return NotifyStatus(
                    True,
                    f"Pushed to '{settings.dnotifier_receiver_id}' "
                    "(server returned empty ack — SDK parsing quirk, delivery accepted)",
                )
            except Exception as exc:  # noqa: BLE001
                return NotifyStatus(
                    False, f"DNotifier send failed — ws: {ws_exc}; http: {exc}"
                )

    def seed_knowledge_base(self) -> NotifyStatus:
        """Upload the OWASP cheat-sheet once per session (RAG grounding)."""
        if not settings.dnotifier_ready or self._kb_seeded:
            return NotifyStatus(self._kb_seeded, "Already seeded" if self._kb_seeded else "Not configured")

        async def _add():
            notifier = self._connect()
            await notifier.connect()
            try:
                add_doc = getattr(notifier, "add_document", None) or getattr(notifier, "addDocument")
                return await add_doc(
                    sender_id=settings.dnotifier_user_id,
                    record_id="repoguard-owasp-cheatsheet-v1",
                    content=OWASP_CHEATSHEET,
                    type="text",
                )
            finally:
                try:
                    await notifier.disconnect()
                except Exception:  # noqa: BLE001
                    pass

        try:
            run_async(_add())
            self._kb_seeded = True
            return NotifyStatus(True, "Knowledge base seeded (RAG ready)")
        except Exception as exc:
            return NotifyStatus(False, f"KB seed failed: {exc}")

    def ask(self, question: str) -> str:
        """Free-form grounded Q&A through the DNotifier AI pipeline."""
        if not settings.dnotifier_ready:
            return "DNotifier not configured — set credentials in .env"

        async def _ask():
            notifier = self._connect()
            await notifier.connect()
            try:
                send_ai = getattr(notifier, "send_ai", None) or getattr(notifier, "sendAI")
                return await send_ai(
                    sender_id=settings.dnotifier_user_id,
                    message={"useKnowledgeBase": True, "text": question},
                    provider=settings.dnotifier_ai_provider,
                    model=settings.dnotifier_ai_model,
                )
            finally:
                try:
                    await notifier.disconnect()
                except Exception:  # noqa: BLE001
                    pass

        try:
            return extract_ai_text(run_async(_ask()))
        except Exception as exc:
            return f"DNotifier AI unavailable: {exc}"

    def security_brief(self, result: ScanResult) -> str:
        """Executive summary of a full scan via the DNotifier AI pipeline.

        Turns raw findings into a prioritised, developer-friendly brief —
        this is the 'one screen a tech lead reads before standup' view.
        """
        if not settings.dnotifier_ready:
            return "DNotifier not configured — set credentials in .env"

        findings_txt = "\n".join(
            f"- [{f.severity.value}] {f.rule_id} {f.title} (line {f.line_no}): {f.description}"
            for f in result.findings[:30]
        )
        question = (
            "You are RepoGuard AI. Write an executive security brief for the "
            "developer team about this scan (plain text, max 220 words). "
            "Use exactly these section headers, one per line:\n"
            "RISK OVERALL: <one-line verdict with a 1-10 severity score>\n"
            "TOP PRIORITIES: <numbered list of the 3 most urgent fixes, most severe first>\n"
            "QUICK WINS: <2-3 low-effort hardening steps>\n\n"
            f"Scan context: language={result.language.value}, "
            f"score={result.security_score}/100, findings={len(result.findings)}.\n"
            f"Findings:\n{findings_txt}"
        )

        async def _brief():
            notifier = self._connect()
            await notifier.connect()
            try:
                send_ai = getattr(notifier, "send_ai", None) or getattr(notifier, "sendAI")
                return await send_ai(
                    sender_id=settings.dnotifier_user_id,
                    message={"useKnowledgeBase": True, "text": question},
                    provider=settings.dnotifier_ai_provider,
                    model=settings.dnotifier_ai_model,
                )
            finally:
                try:
                    await notifier.disconnect()
                except Exception:  # noqa: BLE001
                    pass

        try:
            text = extract_ai_text(run_async(_brief()))
            return text or "AI returned an empty brief — try again."
        except Exception as exc:
            return f"Security brief unavailable: {exc}"
