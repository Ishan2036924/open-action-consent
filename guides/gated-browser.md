# Gated Browser

**An MCP browser for AI agents that stops before every final click.**

Agents can open pages, read them, fill fields and follow links on their own. Anything final (Book, Pay, Send,
Submit, Delete, Sign up...) goes through one tool, `submit`, which needs the person's signed yes for *that exact
page*, using Open Action Consent ([spec](../spec/oac-v0.1.md)).

Install: `pip install "open-action-consent[browser]"`, then `playwright install chromium`.

| Tool | Level | What happens |
|---|---|---|
| `open(url)` | A | opens an https page (network guard below) |
| `read()` | A | page text (fenced as untrusted data) + elements with refs; final buttons are marked |
| `fill(ref, text)` | A | types into a field; never passwords, card numbers or similar |
| `click(ref)` | A | links and non-final controls; a final button is refused ("use submit") |
| `submit(ref, site, button)` | **C** | the person sees the site, the button and digests of a screenshot and the page; after their signed yes the click happens only if the page is unchanged |

**Code decides what is final**, never the model: submit buttons in forms, `input[type=submit]`, and buttons or links
whose text says book, pay, buy, order, send, confirm, delete, subscribe, donate, transfer and the like.

**Never, by design:**
- solving a CAPTCHA or "verify you are human" check: the agent stops and the person takes over;
- typing passwords, card numbers (Luhn-checked) or one-time codes;
- reaching private, loopback, link-local or cloud-metadata addresses, checked for every request the page makes
  (redirects and images included); plain http only for hosts you allow; a block list for sites you never want
  automated.

**If the page changes between the preview and the click** (a price, the button, the terms), the click is refused with
`page_changed`, and the agent has to ask again.

## Run it

```
oac-gated-browser --person person:me --signer-metadata signer.json \
    --consent-url "https://signer.example/consent?r={id}"
```

Or embed it: `from oac.browser import build_server`; `server, oac, browser = build_server(executor=..., key=..., signers=..., consent_url=..., person=...)`.

## Tests

`sdk/python/tests/integrations/browser` runs the whole stack: the official MCP SDK client, the OAC extension, a real
headless Chromium and a local test site (a booking form, a page with hidden injected "pay now" text, a CAPTCHA page,
a sign-in form). `test_load_bearing.py` switches the final-button detector, the page-change check and the
CAPTCHA detector off one at a time and proves a test then fails.

Status: 0.1, one person per process, state in memory. Not yet for unattended production use.
