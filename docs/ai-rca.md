# Root cause analysis

## The rules engine (`cs_rca_rules`)

Findings are nodes of a causal graph. Edges say which kind of finding can cause
which other kind, for example:

```
net.connect_failure ──► app.error, cross.error_propagation, net.retry_storm, fn.slow_call
net.dns_failure     ──► app.error, net.connect_failure
net.slow_io         ──► fn.slow_call, cross.slow_because_network, fn.hang
net.conn_leak       ──► net.connect_failure (EMFILE), app.error
fn.recursion        ──► fn.crash
cross.error_propagation (crash) ──► fn.crash, net.reset
```

An edge only applies when the two findings are related: same peer, same function,
the cause's function appears in the effect's call path, or the effect is
process-wide (exit status). For every finding:

```
score = rootability(kind) × (severity + 2.5 × findings_it_explains + 0.3 × log2(count + 1))
```

`rootability` encodes that an `app.error` is almost always a symptom (0.25) while
a refused connection (1.0), a socket leak (1.2) or runaway recursion (1.1) are
causes. The winner becomes the root; everything it explains, in time order, is the
causal chain. Confidence grows with the number of explained findings and the
margin over the runner-up.

The knowledge base (`core/rca/knowledge.c`) maps `(detector, errno)` to a
category, an explanation template and fixes / next checks, with `{peer}`, `{fn}`,
`{err}`, `{count}` placeholders filled from the root finding.

## The AI agent (`cs_rca_ai`)

1. Builds an **evidence pack**: trace summary, top functions (with network-wait
   share), peers, DNS, the 15 highest findings with their call paths, and the
   rules engine's hypothesis.
2. Starts a chat with a system prompt that defines the job (root cause, not
   symptom; evidence only) and the required JSON verdict.
3. Offers read-only tools backed by the analysis:

| Tool | Returns |
|---|---|
| `get_finding(id)` | detail + evidence events with the call path of each |
| `get_events(start, count, tid)` | raw events in time order |
| `search_events(kind, peer, error, function)` | matching events |
| `get_call_stack(event_index)` | the stack that was active for an event |
| `get_function_stats(name)` | timing stats, network wait, slowest call path |
| `get_peer_stats(peer)` | error histogram and individual connections |

4. Loops (default 6 rounds of tool calls) until the model answers.
5. **Validates** the verdict: `root_finding` must be an existing finding (or
   `none`), chain ids that do not exist are dropped, confidence is clamped. An
   invalid answer gets one correction round; after that, or on any HTTP / parse
   error, the rules result is returned with a note explaining why.

Any OpenAI-compatible endpoint works (`/chat/completions` with tool calling):
Groq, OpenAI, Together, OpenRouter, vLLM, LM Studio, Ollama. The API key is
sent in a header (libcurl) or through a private temporary header file (curl
CLI fallback), never on a command line.

## Testing without a network

`cs_ai_config.transport` lets tests inject a fake LLM. `tests/test_ai.c` scripts
tool calls, a valid verdict, a hallucinated verdict and HTTP errors.
