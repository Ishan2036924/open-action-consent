# oac-openai-agents: OAC for the OpenAI Agents SDK

The Agents SDK can pause a tool for approval (`needs_approval`) and resume after `state.approve(item)`, but that is an
unsigned flag. `oac_tool` makes the pause happen exactly for tier C (computed by OAC) and runs the tool only if the
person's **signed** Consent verifies for these exact arguments. An approval alone runs nothing.

```python
from agents import Agent, Runner
from oac.gate import Gate
from oac_openai_agents import oac_tool, preview_for, approve

gate = Gate(executor="https://app.example/oac", key=executor_key, signers=signer_keys)
send = oac_tool(gate, send_email, person=lambda ctx: ctx.context.user_id, tainted=lambda ctx: ctx.context.tainted,
                effect="send", binds={"to": "to", "title": "subject"}, other_args=["body"])
agent = Agent(name="assistant", tools=[send])

result = await Runner.run(agent, "Email Sam about lunch")
for item in result.interruptions:
    preview = preview_for(gate, item, send, person="person:1")   # show it; the person's signer signs a Consent
    state = result.to_state()
    approve(gate, state, item, consent_token)                   # False (and no approval) if the Consent is not valid
    result = await Runner.run(agent, state)
```

Tests (`python -m pytest -q -p anyio`) run the real `Runner` with a scripted model: no API key, no network.
