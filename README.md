# On-chain TEE status checker

A small script that fetches the enterprise-validator set and its TEE
attestation state over a node's CometBFT RPC websocket, to be shown in web
dashboards (since there is not much use for it beyond that).

See index.html for usage example. Just take the `attestation.js` file to use.

One call, `fetchTEEStatus(socket, expected)`, returns the block it read at and
one entry per enterprise validator, each carrying four lamps already decided —
`{ ok, text }`, where `ok` is true for green, false for red, and null for
grey. Every lamp is named for its good state, so green always means the thing
the name says:

- **live** — not soft-jailed, and keeping up with its proposer slots
- **binding** — the key the chain hands out is the one made inside that TD
- **sealed** — the TD's memory is closed to the host it runs on
- **pins** — the measurements match yours

Grey is for what could not be checked, never for what is fine: no pins
configured, an unreadable quote, a node that did not answer, or a chain with
`ev_hijack_enabled` off, where the liveness counters stand still and a clean
streak would mean nothing.

To enable measurements check, populate `expected-measurements.json` file to be
deposited alongside with the script; remember to update it when the chain
updates, naturally. Both it and the block height are optional arguments.

Websocket only. `x/tee` stores the announced quote but exposes no query that
reads it back, so the quote is fetched with a raw ABCI store query — a
`/store/tee/key` read at `0x02` followed by the validator's address bytes —
and the REST gateway has no route for that. The key layout is internal to the
module rather than part of its proto API, so a chain that reorganises its
store needs `QUOTE_KEY_PREFIX` in `attestation.js` changed to match.

The DCAP signature chain is not verified — no static page can do that.

tested with commit injectived-core `451dbd4`
