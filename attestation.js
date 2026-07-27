// attestation.js — read an Injective chain's enterprise-validator TEE
// attestation from a browser, and check what a browser is able to check.
//
// A plain script: no build step, no dependencies, no DOM. Drop it next to
// your page and load it before your own script.
//
//   <script src="attestation.js"></script>
//
//
// ── WHAT TO CALL ────────────────────────────────────────────────────────────
//
//   fetchAttestation(lcdURL)
//     The easy one. Reads the attestation from a node's REST (LCD) endpoint,
//     e.g. "http://a.node:1317". Requires that node to allow cross-origin
//     reads (enabled-unsafe-cors in its app.toml); many public endpoints do,
//     and there is nothing else to set up.
//
//   fetchAttestationOverRPC(socketOrURL, height)
//     The same answer over CometBFT's RPC websocket, e.g.
//     "ws://a.node:26657/websocket". Prefer it when you can: websockets are
//     exempt from CORS, so no node has to opt in to being read by a browser,
//     and it can query a past block by height, which the REST route cannot.
//     Pass a socket you already have open — a NewBlock subscription, say —
//     and it shares it without disturbing your own message handler.
//
//   checkQuote(attestation, expected)
//     Takes what either of those returned and reports four checks, ready to
//     render. `expected` is optional.
//
//   loadExpectedMeasurements(url)
//     Convenience for checkQuote's second argument: fetches
//     ./expected-measurements.json from your own server.
//
//
// ── WHAT YOU GET BACK ───────────────────────────────────────────────────────
//
// Both fetch functions resolve to the same object. Every field is either a
// value or null — an explicit "none", never a missing key — so you can render
// it field by field without testing for shape:
//
//   validator             string | null   EV candidate valoper address
//   isActive              bool   | null   S_EV currently active
//   softJailed            bool   | null   EV soft-jailed right now
//   softJailUntilHeight   number | null   height the jail lifts at, while jailed
//   missStreak            number | null   consecutive missed EV slots
//   jailEscalationCount   number | null   consecutive soft-jail episodes
//   isDcap                bool   | null   a full DCAP quote, not a bare TDREPORT
//   quote                 string | null   the quote itself, base64 as stored on-chain
//   quoteHash             string | null   sha256(quote), hex
//   teePubkey             string | null   ed25519 key generated inside the TD, hex
//   attestationHeight     number | null   height the attestation was last submitted at
//
// They throw only when the query itself failed — node unreachable, or an
// answer that was not a query result. That is worth showing as an error; an
// absent value is not, and comes back as null instead.
//
// checkQuote resolves to four results, each { ok, text }, where ok is true,
// false, or null for "could not tell" — never null for "fine". Put text next
// to a green / red / grey light and you are done:
//
//   binding   the registered key was generated inside this TD
//   debug     the TD is not host-debuggable
//   hash      the quote matches the quote_hash that vouches are counted against
//   pins      the measurements match the ones you pinned
//
//
// ── WHAT THIS DOES NOT TELL YOU ─────────────────────────────────────────────
//
// None of it verifies the quote's DCAP signature chain against Intel's roots,
// which no static page can do. Everything compared here arrived from the same
// node and could have been fabricated together: these checks catch a
// misconfigured or mismatched deployment, which is the usual failure, not a
// hostile one. A green card is not an attestation verdict.
//
//
// ── EXAMPLE ─────────────────────────────────────────────────────────────────
//
//   const a = await fetchAttestation("http://localhost:1317");
//   const checks = await checkQuote(a, await loadExpectedMeasurements());
//
//   console.log(a.validator, a.isActive);              // who, and is it live
//   console.log(checks.binding.ok, checks.binding.text);
//
// ════════════════════════════════════════════════════════════════════════════
// THE FOUR ENTRY POINTS
// ════════════════════════════════════════════════════════════════════════════

async function fetchAttestation(base) {
  const ev = await getJSON(base + "/injective/tee/v1/ev_status");
  const validator = ev.candidate || null;

  return build(ev, validator ? await getAttestation(base, validator) : {});
}

// Sharing a socket is safe: this listens with addEventListener and matches on
// the JSON-RPC id, leaving the page's own socket.onmessage to fire alongside
// it untouched. Give it a ws:// string instead and it opens and closes a
// socket of its own around the two queries.
async function fetchAttestationOverRPC(socketOrURL, height) {
  const rpc = await openRPC(socketOrURL);
  try {
    const ev = decodeEVStatus(await rpc.query(EV_STATUS_PATH, "", height));
    const validator = ev.candidate || null;

    // A candidate with no attestation answers with a non-zero code, the
    // equivalent of the REST gateway's 404: absent, not broken.
    const raw = validator
      ? await rpc.query(ATTESTATION_PATH, encodeStringField(1, validator), height, true)
      : null;
    return build(ev, raw ? decodeAttestation(raw) : {});
  } finally {
    rpc.close();
  }
}

async function checkQuote(attestation, expected) {
  const quote = attestation.quote ? base64ToBytes(attestation.quote) : null;
  const body = quote ? quoteBody(quote) : null;

  return {
    binding: bindingCheck(attestation, body),
    debug: debugCheck(body),
    hash: await hashCheck(attestation, quote),
    pins: pinsCheck(body, expected),
  };
}

// Same origin, so no CORS and no node involved. A missing file is a normal
// state, not an error: it returns null and the pin check reports itself as
// unpinned rather than passing quietly.
//
// The file is a flat object — { source, mrtd, rtmr0, rtmr1 }, hex, `source`
// being free text naming where the values came from. Get it from whoever
// builds the image, never from the node being checked: a node's own account
// of what it is running proves nothing.
async function loadExpectedMeasurements(url) {
  try {
    const resp = await fetch(url || "./expected-measurements.json");
    return resp.ok ? await resp.json() : null;
  } catch {
    return null;
  }
}

// ════════════════════════════════════════════════════════════════════════════
// INTERNALS — nothing below here is meant to be called from a page
// ════════════════════════════════════════════════════════════════════════════

// ── the returned shape ──────────────────────────────────────────────────────

// build turns the two raw chain messages into the returned object. Both
// transports feed it the same snake_case shape — the REST gateway produces it
// directly, and the protobuf decoder is written to match — so the field list,
// and the rules about what counts as none, live here once.
function build(ev, attestation) {
  const validator = ev.candidate || null;

  // With no candidate there is no EV to be active, jailed or attested. Leaving
  // the rest as none beats reporting the zeroes the chain happens to store.
  const status = validator ? ev : {};
  const att = validator ? attestation : {};

  const softJailed = boolOrNull(status.soft_jailed);
  return {
    validator,
    isActive: boolOrNull(status.is_active),
    softJailed,
    // The stored height outlives the jail it belongs to, so it is only an
    // answer to "until when?" while the jail is actually on.
    softJailUntilHeight: softJailed ? numberOrNull(status.soft_jail_until_height) : null,
    missStreak: numberOrNull(status.miss_streak),
    jailEscalationCount: numberOrNull(status.jail_escalation_count),
    isDcap: boolOrNull(att.is_dcap),
    quote: valueOrNull(att.quote),
    quoteHash: hexOrNull(att.quote_hash),
    teePubkey: hexOrNull(att.tee_pubkey),
    attestationHeight: numberOrNull(att.height),
  };
}

// null, not undefined and not "": undefined reads as "nobody filled this in",
// null as "asked the chain, it has nothing" — and null is what JSON carries.
function valueOrNull(v) {
  return v === undefined || v === null || v === "" ? null : v;
}

function boolOrNull(v) {
  return typeof v === "boolean" ? v : null;
}

// The chain reports its 64-bit integers as JSON strings, to protect a
// precision that block heights and small counters never come near — they stay
// many orders of magnitude below Number.MAX_SAFE_INTEGER — so they are handed
// over as numbers, ready to compare and format. Anything unparseable becomes
// none rather than NaN, which no widget should ever have to render.
function numberOrNull(v) {
  const n = Number(valueOrNull(v));
  return Number.isFinite(n) ? n : null;
}

// Proto bytes fields cross the REST gateway base64-encoded, and arrive as
// JSON null when empty.
function hexOrNull(b64) {
  if (!b64) return null;
  return Array.from(atob(b64), (c) => c.charCodeAt(0).toString(16).padStart(2, "0")).join("");
}

// ── transport: REST ─────────────────────────────────────────────────────────

// A candidate that has never registered an attestation is a 404 from the
// gateway: an absent value, not a failure. Only this second query tolerates
// one, so a base URL that isn't an LCD at all still fails loudly on the first.
async function getAttestation(base, validator) {
  const resp = await getJSON(base + "/injective/tee/v1/attestations/" + validator, true);
  return (resp && resp.attestation) || {};
}

async function getJSON(url, nullOn404) {
  let resp;
  try {
    resp = await fetch(url);
  } catch (err) {
    // fetch() reports a CORS refusal and an unreachable host identically, as
    // a bare TypeError, so both have to be named here.
    throw new Error(
      url + ": " + err.message +
      " — node unreachable, or its API server has enabled-unsafe-cors = false in app.toml"
    );
  }
  if (resp.status === 404 && nullOn404) return null;
  if (!resp.ok) {
    // grpc-gateway returns errors as {code, message, details}.
    const body = await resp.json().catch(() => null);
    throw new Error(body && body.message ? body.message : "HTTP " + resp.status + " " + resp.statusText);
  }
  return resp.json();
}

// ── transport: CometBFT RPC websocket ───────────────────────────────────────

const EV_STATUS_PATH = "/injective.tee.v1.Query/EVStatus";
const ATTESTATION_PATH = "/injective.tee.v1.Query/Attestation";
const RPC_TIMEOUT_MS = 10000;

let nextRPCID = 1000; // clear of the ids a page uses for its own subscriptions

function openRPC(socketOrURL) {
  if (typeof socketOrURL !== "string") return whenOpen(socketOrURL, false);

  const socket = new WebSocket(socketOrURL);
  return whenOpen(socket, true).catch(() => {
    throw new Error(socketOrURL + ": websocket connection failed");
  });
}

function whenOpen(socket, owned) {
  const client = {
    query: (path, data, height, allowError) => rpcQuery(socket, path, data, height, allowError),
    // Only a socket opened here gets closed here; a borrowed one outlives the
    // query and stays whatever the page made of it.
    close: () => { if (owned) socket.close(); },
  };
  if (socket.readyState === WebSocket.OPEN) return Promise.resolve(client);

  return new Promise((resolve, reject) => {
    socket.addEventListener("open", () => resolve(client), { once: true });
    socket.addEventListener("error", () => reject(new Error("websocket connection failed")), { once: true });
  });
}

function rpcQuery(socket, path, data, height, allowError) {
  const id = nextRPCID++;
  const params = { path: path, data: data, prove: false };
  if (height) params.height = String(height);

  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      socket.removeEventListener("message", onMessage);
      reject(new Error(path + ": no answer in " + RPC_TIMEOUT_MS + "ms"));
    }, RPC_TIMEOUT_MS);

    function onMessage(e) {
      const msg = JSON.parse(e.data);
      if (msg.id !== id) return; // somebody else's reply on a shared socket
      socket.removeEventListener("message", onMessage);
      clearTimeout(timer);

      if (msg.error) return reject(new Error(path + ": " + (msg.error.data || msg.error.message)));

      const resp = msg.result.response;
      if (resp.code !== 0) {
        if (allowError) return resolve(null);
        return reject(new Error(path + ": " + (resp.log || "query failed with code " + resp.code)));
      }
      resolve(base64ToBytes(resp.value));
    }

    socket.addEventListener("message", onMessage);
    socket.send(JSON.stringify({ jsonrpc: "2.0", id: id, method: "abci_query", params: params }));
  });
}

// ── protobuf ────────────────────────────────────────────────────────────────
//
// Only enough of the wire format to read two messages: varints, length-
// delimited fields, and enough of the fixed-width ones to step over anything
// unrecognized. The decoders name fields by number, so they stay correct as
// long as injective/tee/v1 only ever appends — the compatibility promise
// protobuf makes anyway.

function decodeEVStatus(bytes) {
  const f = readFields(bytes);
  return {
    candidate: utf8(f[1]),
    is_active: bool(f[2]),
    bonded_vp_fraction: utf8(f[3]),
    soft_jailed: bool(f[4]),
    soft_jail_until_height: int(f[5]),
    miss_streak: int(f[6]),
    jail_escalation_count: int(f[7]),
  };
}

function decodeAttestation(bytes) {
  // QueryAttestationResponse wraps the Attestation in field 1.
  const inner = readFields(bytes)[1];
  if (inner === undefined) return {};

  const f = readFields(inner);
  return {
    tee_pubkey: bytesToBase64(f[1]),
    quote: bytesToBase64(f[2]),
    is_dcap: bool(f[3]),
    event_log: bytesToBase64(f[4]),
    quote_hash: bytesToBase64(f[5]),
    peer_id: utf8(f[6]),
    height: int(f[7]),
  };
}

// readFields returns the last value seen per field number: varints as numbers,
// length-delimited fields as byte slices. A field the message never set is
// simply missing — protobuf does not put default values on the wire — so the
// accessors below supply the proto defaults, which is what an absent field
// means. Absent is never "unknown" here, unlike over REST.
function readFields(bytes) {
  const fields = {};
  let i = 0;

  while (i < bytes.length) {
    const tag = readVarint(bytes, i);
    const number = Math.floor(tag.value / 8);
    const wire = tag.value % 8;
    i = tag.next;

    if (wire === 0) {
      const v = readVarint(bytes, i);
      fields[number] = v.value;
      i = v.next;
    } else if (wire === 2) {
      const len = readVarint(bytes, i);
      fields[number] = bytes.subarray(len.next, len.next + len.value);
      i = len.next + len.value;
    } else if (wire === 5 || wire === 1) {
      i += wire === 5 ? 4 : 8; // fixed32 / fixed64: unused here, stepped over
    } else {
      throw new Error("unsupported protobuf wire type " + wire);
    }
  }
  return fields;
}

function readVarint(bytes, i) {
  let value = 0;
  let shift = 1;

  for (;;) {
    if (i >= bytes.length) throw new Error("truncated protobuf varint");
    const byte = bytes[i++];
    // Multiply rather than shift: << is a 32-bit operator, and heights are
    // read as int64.
    value += (byte & 0x7f) * shift;
    if ((byte & 0x80) === 0) return { value: value, next: i };
    shift *= 128;
  }
}

const utf8 = (b) => (b === undefined ? "" : new TextDecoder().decode(b));
const bool = (v) => v !== undefined && v !== 0;
const int = (v) => (v === undefined ? 0 : v);

// The one thing this has to write — a request carrying a single string,
// hex-encoded the way CometBFT's RPC expects its byte params.
function encodeStringField(number, value) {
  const body = new TextEncoder().encode(value);
  const header = [number * 8 + 2].concat(varintBytes(body.length));
  return toHex(header) + toHex(body);
}

function varintBytes(n) {
  const out = [];
  while (n > 127) {
    out.push((n % 128) + 128);
    n = Math.floor(n / 128);
  }
  out.push(n);
  return out;
}

// ── the quote, and the four checks ──────────────────────────────────────────

// Byte offsets into a TD Quote v4: a 48-byte header, then the 584-byte body.
// Fixed by the structure, so a plain slice is all it takes to read them.
const QUOTE_MIN_LENGTH = 632;
const OFF_TD_ATTRIBUTES = 168;
const OFF_MRTD = 184;
const OFF_RTMR = 376; // four 48-byte registers, back to back
const OFF_REPORT_DATA = 568;

function quoteBody(quote) {
  if (quote.length < QUOTE_MIN_LENGTH) return null;

  const version = quote[0] + quote[1] * 256;
  const teeType = quote[4] + quote[5] * 256 + quote[6] * 65536 + quote[7] * 16777216;
  if (version !== 4 || teeType !== 0x81) return null; // not a TDX v4 quote

  return {
    // TDATTRIBUTES is little-endian, so TUD.DEBUG — bit 0 of the u64 — is bit
    // 0 of the first byte.
    debug: (quote[OFF_TD_ATTRIBUTES] & 1) !== 0,
    mrtd: toHex(quote.subarray(OFF_MRTD, OFF_MRTD + 48)),
    rtmr: [0, 1, 2, 3].map((i) => toHex(quote.subarray(OFF_RTMR + i * 48, OFF_RTMR + (i + 1) * 48))),
    // REPORT_DATA is 64 bytes; the TD puts its public key in the first 32.
    reportDataKey: toHex(quote.subarray(OFF_REPORT_DATA, OFF_REPORT_DATA + 32)),
  };
}

// The check that makes fetching both halves from chain state worth something:
// the key the chain hands out is the key this TD generated, not merely one
// stored next to a quote.
function bindingCheck(attestation, body) {
  if (!body) return unreadable(attestation);
  if (!attestation.teePubkey) return { ok: null, text: "no registered key to compare against" };

  return body.reportDataKey === attestation.teePubkey.toLowerCase()
    ? { ok: true, text: "TEE key is the one generated inside this TD" }
    : { ok: false, text: "REPORT_DATA does not match the registered key" };
}

function debugCheck(body) {
  if (!body) return { ok: null, text: "debug flag unreadable" };

  // Nothing else gives this away: a debug TD booted from the pinned image has
  // identical measurements, and the host can read its memory.
  return body.debug
    ? { ok: false, text: "TD is host-debuggable — its key must not be trusted" }
    : { ok: true, text: "TD is not host-debuggable" };
}

async function hashCheck(attestation, quote) {
  if (!quote || !attestation.quoteHash) return { ok: null, text: "nothing to hash" };
  // Vouches name a quote by this hash, so it is what the tally is really about.
  if (!globalThis.crypto || !crypto.subtle) {
    return { ok: null, text: "hashing needs a secure context (https, or localhost)" };
  }

  const digest = toHex(new Uint8Array(await crypto.subtle.digest("SHA-256", quote)));
  return digest === attestation.quoteHash.toLowerCase()
    ? { ok: true, text: "quote matches the hash vouches are counted against" }
    : { ok: false, text: "quote does not hash to the stored quote_hash" };
}

function pinsCheck(body, expected) {
  if (!body) return { ok: null, text: "measurements unreadable" };
  if (!expected) return { ok: null, text: "not pinned — add expected-measurements.json" };

  const measured = { mrtd: body.mrtd, rtmr0: body.rtmr[0], rtmr1: body.rtmr[1] };
  const compared = Object.keys(measured).filter((k) => expected[k]);
  if (compared.length === 0) return { ok: null, text: "pin file names no measurements" };

  const wrong = compared.filter((k) => measured[k] !== String(expected[k]).toLowerCase());
  const source = expected.source ? " from " + expected.source : "";
  return wrong.length === 0
    ? { ok: true, text: `matches ${compared.join(", ")} pinned${source}` }
    : { ok: false, text: `${wrong.join(", ")} does not match the pins${source}` };
}

function unreadable(attestation) {
  return attestation.quote
    ? { ok: null, text: "not a TD Quote v4" }
    : { ok: null, text: "no quote registered" };
}

// ── bytes ───────────────────────────────────────────────────────────────────

function toHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function base64ToBytes(b64) {
  const bin = atob(b64 || "");
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// Chunked, because a quote is ~8 kB and String.fromCharCode takes its bytes as
// arguments — the whole thing at once risks blowing the argument limit.
function bytesToBase64(bytes) {
  if (bytes === undefined) return "";
  let bin = "";
  for (let i = 0; i < bytes.length; i += 4096) {
    bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 4096));
  }
  return btoa(bin);
}
