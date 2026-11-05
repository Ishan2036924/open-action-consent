# Security

OAC is a security protocol, so reports are very welcome.

**Please do not open a public issue for a vulnerability.** Email **support@atlasiw.com** with "OAC security" in the
subject, or use GitHub's private "Report a vulnerability" button on this repository if it is shown. Include:

- what breaks (which promise of the spec: a check that can be bypassed, two SDKs that disagree, a crash);
- a minimal input or script that shows it;
- which SDK and commit.

You will get an answer within 3 working days. Fixes land with a new conformance vector that fails before the fix,
in both SDKs, and the report is credited in the changelog unless you ask otherwise.

Scope: the specification (`spec/`), the SDKs (`sdk/`), the vectors and the tools. The example server is a teaching
aid, not production code; reports about it are still welcome.
