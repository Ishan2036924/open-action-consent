# OAC Approver

**A small, self-hostable approval page. The person's key never leaves their browser.**

Install: `pip install "open-action-consent[approver]"`, then `from oac.approver import Approver`.

The hard part of adding consent to an agent is the approval screen and the signer. The Approver is both:

| Step | What happens |
|---|---|
| Enrol | the server prints a one-time code; the person opens `/enroll`, types it, and the browser creates a **non-extractable** P-256 key (WebCrypto, kept in IndexedDB). Only the public key reaches the server. |
| Ask | an executor (for example the [Gated Browser](gated-browser.md) or any server using [`oac.mcp`](mcp-python.md)) sends the person to `/consent?r=<preview id>` |
| Show | the page shows the summary, every field and detail, whether it can be undone ("NO: this cannot be undone"), the cancellation policy and who asks, all as plain text |
| Approve | the **browser** signs the Consent JWS (ES256, low-S, `signer.kind: "device"`); the Approver checks it and hands it to the executor through `deliver` |
| Decline | nothing is signed; the executor runs nothing |
| Discover | `/.well-known/oac-issuer[/path]` publishes the person's public keys (spec 3.5) |

The browser key is a device key, not a passkey. `signer.kind: "device"` is the Approver's own statement (spec 3.4).
When an executor needs proof it can check for itself, it also asks for a passkey assertion over the Consent (spec 3.6).

```python
from oac.approver import Approver

approver = Approver(issuer="https://approve.example", person="person:1",
                    previews=lambda preview_id: executor.preview(preview_id),
                    deliver=lambda token: executor.accept_consent(token))
print("Enrolment code:", approver.enrollment_code)
app = approver.app()   # Starlette; serve with uvicorn behind HTTPS
```

Hardening: strict Content-Security-Policy (no inline or eval'd script, no framing, no form posts), same-origin checks
on every POST, single-use enrolment code compared in constant time, everything rendered with `textContent`.

Tests (`sdk/python/tests/integrations/approver`) drive a real headless Chromium through enrolment, approval, decline, hostile preview
text and cross-origin posts, and verify the browser-made Consent with the Python SDK.

0.1 limits: one person per Approver, in-memory state, no payment references yet (a pay action needs the rail's
reference, which this page does not collect), no key recovery: losing the browser profile means enrolling again.
