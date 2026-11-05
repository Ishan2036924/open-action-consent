# @oac/vercel-ai: OAC for the Vercel AI SDK

AI SDK 7 can pause a tool call (`toolApproval` -> `tool-approval-request`) and resume on a `tool-approval-response`
with `approved: true`. `withOAC` asks for approval exactly for tier C (with the Preview's summary as the reason) and
lets the tool execute only with the person's **signed** Consent; a client that just sends `approved: true` gets
nothing run.

```ts
import { generateText } from "ai";
import { Gate } from "@oac/sdk";
import { withOAC, previewFor, approvalMessage } from "@oac/vercel-ai";

const { tools, toolApproval } = withOAC(gate, { send_email: sendEmail },
  { send_email: { effect: "send", binds: { to: "to", title: "subject" }, otherArgs: ["body"] } },
  { person: "person:1", tainted: () => hostSaysOutsideTextEntered() });

const r1 = await generateText({ model, tools, toolApproval, messages });
const req = r1.content.find((p) => p.type === "tool-approval-request");
const preview = previewFor(gate, req, "person:1");              // show it; the person's signer signs a Consent
await generateText({ model, tools, toolApproval,
  messages: [...messages, ...r1.response.messages, approvalMessage(gate, req.approvalId, consentToken)] });
```

The SDK's `experimental_toolApprovalSecret` (an HMAC the server holds) and OAC fit together: the HMAC stops a client
forging an approval request; OAC proves the person approved exactly what they saw, with a receipt afterwards.
Tests use the SDK's `MockLanguageModelV4`: no API key.
