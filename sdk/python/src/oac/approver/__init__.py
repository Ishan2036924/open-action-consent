"""OAC Approver: a small self-hostable approval page where a person approves (or declines) an agent's action.

The person's key never leaves their browser: it is a non-extractable WebCrypto P-256 key (OAC `signer.kind`
"device"), created at enrolment with a one-time code. The page shows the Preview (summary, every field and detail,
whether it can be undone, the cancellation policy), and on Approve the browser itself signs the Consent JWS and posts
it here; the Approver checks it and hands it to the executor through `deliver`. It also publishes the person's
public keys as issuer metadata (spec 3.5) so executors can find them.

    from oac.approver import Approver

    approver = Approver(issuer="https://approve.example", person="person:1",
                        previews=lambda preview_id: executor.preview(preview_id),
                        deliver=lambda token: executor.accept_consent(token))
    app = approver.app()   # a Starlette app; serve it with uvicorn behind HTTPS

0.1 limits: one person per Approver; in-memory state; no payment references in Consents (a pay action needs the
rail's reference, which this page does not collect yet).
"""

from __future__ import annotations

import hmac
import secrets
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

try:
    from starlette.applications import Starlette
    from starlette.requests import Request
    from starlette.responses import HTMLResponse, JSONResponse, Response
    from starlette.routing import Route
except ImportError as e:  # the optional dependency is not installed
    raise ImportError('oac.approver needs Starlette: pip install "open-action-consent[approver]"') from e

from oac import KeySet, OACError, digest, shapes, verify
from oac.discovery import metadata_url

PAGE_JS = (Path(__file__).parent / "page.js").read_text()
CSP = "default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
STYLE = ("body{font:16px -apple-system,Segoe UI,sans-serif;max-width:560px;margin:40px auto;padding:0 16px;color:#111}"
         "td{padding:6px 10px;border-bottom:1px solid #eee;vertical-align:top}button{font-size:16px;padding:10px 18px;margin-right:8px}"
         "#status{margin-top:16px;color:#374151}")


def _page(title: str, body: str, start: str) -> HTMLResponse:
    html = (f"<!doctype html><html><head><meta charset=utf-8><meta name=viewport content='width=device-width'>"
            f"<title>{title}</title><style>{STYLE}</style></head><body>{body}<p id=status></p>"
            f"<script src='page.js'></script><script src='start-{start}.js'></script></body></html>")
    return HTMLResponse(html, headers={"Content-Security-Policy": CSP, "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer",
                                        "Cache-Control": "no-store"})


class Approver:
    def __init__(self, *, issuer: str, person: str, previews: Callable[[str], Mapping[str, Any] | None],
                 deliver: Callable[[str], bool], enrollment_code: str | None = None) -> None:
        self.issuer, self.person, self._previews, self._deliver = issuer, person, previews, deliver
        self.enrollment_code = enrollment_code or secrets.token_urlsafe(9)
        self._code_used = False
        self.keys: list[dict[str, Any]] = []
        self.declined: list[str] = []
        self.well_known_path = urlsplit(metadata_url(issuer)).path

    def metadata(self) -> dict[str, Any]:
        return {"oac": "0.1", "type": "issuer-metadata", "issuer": self.issuer, "keys": list(self.keys)}

    def keyset(self) -> KeySet:
        return KeySet({self.issuer: self.keys})

    def _same_origin(self, request: Request) -> bool:
        origin = request.headers.get("origin")
        return origin is not None and origin == f"{request.url.scheme}://{request.url.netloc}"

    def app(self) -> Starlette:
        async def js(request: Request) -> Response:
            return Response(PAGE_JS, media_type="text/javascript", headers={"Cache-Control": "no-store"})

        async def start_enroll(request: Request) -> Response:
            return Response("document.getElementById('go').onclick = enroll;", media_type="text/javascript")

        async def start_consent(request: Request) -> Response:
            return Response("showPreview();", media_type="text/javascript")

        async def enroll_page(request: Request) -> HTMLResponse:
            return _page("Enrol this browser", "<h1>Enrol this browser</h1><p>Enter the one-time code from the server.</p>"
                         "<input id=code autocomplete=off> <button id=go>Enrol</button>", "enroll")

        async def consent_page(request: Request) -> HTMLResponse:
            return _page("Approve an action", "<h1>An agent asks to act for you</h1><p id=summary></p><table id=fields></table>"
                         "<p id=buttons hidden><button id=approve>Approve</button><button id=decline>Decline</button></p>",
                         "consent")

        async def api_enroll(request: Request) -> JSONResponse:
            if not self._same_origin(request):
                return JSONResponse({"error": "wrong origin"}, status_code=403)
            body = await request.json()
            if self._code_used or not hmac.compare_digest(str(body.get("code", "")), self.enrollment_code):
                return JSONResponse({"error": "That code is not valid."}, status_code=403)
            jwk = body.get("jwk", {})
            try:
                if not isinstance(jwk, dict) or set(jwk) != {"kty", "crv", "x", "y"} or jwk["kty"] != "EC" or jwk["crv"] != "P-256":
                    raise OACError("malformed", "a P-256 public key")
                shapes.check(jwk, shapes.JWK_FIELDS, "jwk")
                KeySet({self.issuer: [jwk]})  # computes the thumbprint, refuses a key already bound elsewhere
            except OACError:
                return JSONResponse({"error": "That is not a valid public key."}, status_code=400)
            self._code_used = True
            self.keys.append(dict(jwk))
            return JSONResponse({"ok": True})

        async def api_preview(request: Request) -> JSONResponse:
            p = self._previews(request.query_params.get("r", ""))
            if p is None or p.get("sub") != self.person:
                return JSONResponse({"error": "unknown"}, status_code=404)
            return JSONResponse({"preview": p, "issuer": self.issuer, "person": self.person}, headers={"Cache-Control": "no-store"})

        async def api_consent(request: Request) -> JSONResponse:
            if not self._same_origin(request):
                return JSONResponse({"error": "wrong origin"}, status_code=403)
            token = (await request.json()).get("token", "")
            try:
                p = verify(token, self.keyset(), "oac-consent+jws")
                shapes.consent(p)
                if p["sub"] != self.person or p["signer"]["kind"] != "device":
                    raise OACError("malformed", "not this person's device consent")
            except OACError as e:
                return JSONResponse({"error": f"Not accepted ({e.code})."}, status_code=400)
            return JSONResponse({"ok": True}) if self._deliver(token) else JSONResponse({"error": "The agent did not accept it."}, status_code=409)

        async def api_decline(request: Request) -> JSONResponse:
            if not self._same_origin(request):
                return JSONResponse({"error": "wrong origin"}, status_code=403)
            self.declined.append(str((await request.json()).get("r", "")))
            return JSONResponse({"ok": True})

        async def well_known(request: Request) -> JSONResponse:
            return JSONResponse(self.metadata())

        return Starlette(routes=[
            Route("/page.js", js), Route("/start-enroll.js", start_enroll), Route("/start-consent.js", start_consent),
            Route("/enroll", enroll_page), Route("/consent", consent_page),
            Route("/api/enroll", api_enroll, methods=["POST"]), Route("/api/preview", api_preview),
            Route("/api/consent", api_consent, methods=["POST"]), Route("/api/decline", api_decline, methods=["POST"]),
            Route(self.well_known_path, well_known),
        ])
