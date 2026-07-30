// attestation.js — read an Injective chain's enterprise validators and the
// TEE quotes they announced, from a browser, and check what a browser is
// able to check.
//
// A plain script: no build step, no dependencies, no DOM. Drop it next to
// your page and load it before your own script.
//
//   <script src="attestation.js"></script>
//
//
// ── WHAT TO CALL ────────────────────────────────────────────────────────────
//
//   fetchTEEStatus(socketOrURL, expected, height)
//     The whole thing in one call: reads the enterprise-validator set over
//     CometBFT's RPC websocket, e.g. "ws://a.node:26657/websocket", fetches
//     each one's quote and the module's params, and hands back the lamps
//     already decided. Websockets are exempt from CORS, so no node has to opt
//     in to being read by a browser. Pass a socket you already have open — a
//     NewBlock subscription, say — and it shares it without disturbing your
//     own message handler.
//
//     Both `expected` and `height` are optional. Without pins, the pins lamp
//     goes grey rather than passing; without a height, the query is answered
//     at the last committed block. Nothing here fails for want of either —
//     what cannot be checked is reported as grey, never as fine.
//
//     There is no REST route. The quote is not exposed by any query RPC, and
//     the raw store read that reaches it is an ABCI query, which the LCD does
//     not proxy — see WHERE THE QUOTE COMES FROM below.
//
//   loadExpectedMeasurements(url)
//     Convenience for the `expected` argument: fetches
//     ./expected-measurements.json from your own server.
//
//
// ── WHAT YOU GET BACK ───────────────────────────────────────────────────────
//
//   height       number   the block the answers were read at
//   validators   array    one entry per enterprise validator the chain
//                         recognises, in its order; empty if it knows none
//
// Every field of an entry is either a value or null — an explicit "none",
// never a missing key:
//
//   valoper     string | null   operator address; null when the chain could
//                               not resolve one from the consensus address
//   consAddr    string | null   consensus address, hex — the form CometBFT
//                               reports a block proposer in
//   teePubkey   string | null   ed25519 key generated inside the TD, hex
//   quote       string | null   the quote itself, base64 as stored on-chain
//   checks      object          the four lamps, below
//
// It throws only when the query itself failed — node unreachable, or an
// answer that was not a query result. That is worth showing as an error; an
// absent value is not, and comes back as null instead.
//
// `checks` holds four results, each { ok, text }, where ok is true, false, or
// null for "could not tell" — never null for "fine". Each is named for the
// good state, so a green lamp always means the thing the name says. Put text
// next to a green / red / grey light and you are done:
//
//   live      the EV is not soft-jailed and is keeping up
//   binding   the registered key was generated inside this TD
//   sealed    the TD's memory is closed to the host it runs on
//   pins      the measurements match the ones you pinned
//
// The chain keeps one set of liveness counters, not one per validator, and
// they belong to the first entry; any entry after it gets a grey `live`. The
// counters also only move while the module's ev_hijack_enabled is on, so with
// governance holding that switch off, `live` is grey rather than green: an EV
// that is never given a slot cannot be said to be keeping up.
//
//
// ── WHERE THE QUOTE COMES FROM ──────────────────────────────────────────────
//
// x/tee stores the announced quote but exposes no query that reads it back
// out, so this reads the module's store directly: an ABCI query against
// /store/tee/key at the key the module writes under, 0x02 followed by the
// validator's 20 address bytes.
//
// That key layout is internal to the module. It is not part of the proto API
// and nothing promises to keep it, so a chain that reorganises its store will
// need QUOTE_KEY_PREFIX below changed to match. It is, today, the only route
// from a browser to a quote.
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
//   const expected = await loadExpectedMeasurements();
//   const status = await fetchTEEStatus("ws://localhost:26657/websocket", expected);
//
//   console.log("as of block", status.height);
//   for (const v of status.validators) {
//     console.log(v.valoper);
//     for (const [lamp, { ok, text }] of Object.entries(v.checks)) {
//       console.log(" ", lamp, ok, text);
//     }
//   }
//
// ════════════════════════════════════════════════════════════════════════════
// THE TWO ENTRY POINTS
// ════════════════════════════════════════════════════════════════════════════

// Sharing a socket is safe: this listens with addEventListener and matches on
// the JSON-RPC id, leaving the page's own socket.onmessage to fire alongside
// it untouched. Give it a ws:// string instead and it opens and closes a
// socket of its own around the queries.
async function fetchTEEStatus(socketOrURL, expected, height) {
  const rpc = await openRPC(socketOrURL);
  try {
    const answer = await rpc.query(EV_STATUS_PATH, "", height);
    const status = decodeEVStatus(answer.bytes);
    // The params say what the liveness counters are measured against, and
    // whether they are being kept at all — without them a miss streak is a
    // number with nothing to compare it to.
    const params = decodeParams((await rpc.query(PARAMS_PATH, "", height)).bytes);

    // One quote query per validator, in turn. They share the one socket, and
    // an EV set numbers a handful at most, so there is nothing here worth the
    // machinery of issuing them together.
    const validators = [];
    for (const ev of status.enterprise_validators) {
      const quote = ev.valoper ? await fetchQuote(rpc, ev.valoper, height) : null;
      validators.push(build(ev, quote, status, params, expected, validators.length === 0));
    }

    return { height: answer.height, validators: validators };
  } finally {
    rpc.close();
  }
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

// build turns one decoded validator and its quote into an entry of the
// returned array, lamps and all, so the rules about what counts as none live
// here once.
function build(ev, quote, status, params, expected, first) {
  const body = quoteBody(decodeQuote(quote));
  const validator = {
    valoper: ev.valoper || null,
    consAddr: ev.cons_addr ? toHex(ev.cons_addr) : null,
    teePubkey: ev.tee_pubkey ? toHex(ev.tee_pubkey) : null,
    quote: quote,
  };

  validator.checks = {
    live: liveCheck(status, params, first),
    binding: bindingCheck(validator, body),
    sealed: sealedCheck(body),
    pins: pinsCheck(body, expected),
  };
  return validator;
}

// ── transport: CometBFT RPC websocket ───────────────────────────────────────

const EV_STATUS_PATH = "/injective.tee.v1.Query/EVStatus";
const PARAMS_PATH = "/injective.tee.v1.Query/Params";
const STORE_PATH = "/store/tee/key";

// x/tee's EnterpriseValidatorQuoteKey — see WHERE THE QUOTE COMES FROM.
const QUOTE_KEY_PREFIX = "02";

const RPC_TIMEOUT_MS = 10000;

let nextRPCID = 1000; // clear of the ids a page uses for its own subscriptions

// A validator that is whitelisted but has not announced a quote yet is a key
// the store simply does not hold: an empty value under a successful query,
// which is an absent quote and not a failure.
async function fetchQuote(rpc, valoper, height) {
  const key = QUOTE_KEY_PREFIX + toHex(bech32Data(valoper));
  const answer = await rpc.query(STORE_PATH, key, height);

  // The module stores the base64 text the announcing message carried, not the
  // bytes it decodes to, so what comes back out of the store is already the
  // form the rest of this file expects.
  return answer.bytes.length ? utf8(answer.bytes) : null;
}

function openRPC(socketOrURL) {
  if (typeof socketOrURL !== "string") return whenOpen(socketOrURL, false);

  const socket = new WebSocket(socketOrURL);
  return whenOpen(socket, true).catch(() => {
    throw new Error(socketOrURL + ": websocket connection failed");
  });
}

function whenOpen(socket, owned) {
  const client = {
    query: (path, data, height) => rpcQuery(socket, path, data, height),
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

// Resolves { bytes, height }: the height is the block the node actually
// answered at, which is the honest label for what is on screen — it is the
// last committed block, not necessarily the one whose arrival triggered this.
function rpcQuery(socket, path, data, height) {
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
        return reject(new Error(path + ": " + (resp.log || "query failed with code " + resp.code)));
      }
      resolve({ bytes: base64ToBytes(resp.value), height: Number(resp.height) });
    }

    socket.addEventListener("message", onMessage);
    socket.send(JSON.stringify({ jsonrpc: "2.0", id: id, method: "abci_query", params: params }));
  });
}

// ── bech32 ──────────────────────────────────────────────────────────────────
//
// The store is keyed by a validator's raw address bytes, so the bech32 string
// the chain hands out has to be taken apart. Only the payload is wanted: the
// checksum is there to catch a human mistyping an address, and this one
// arrived from the chain in the same answer as everything else.

const BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32_CHECKSUM_LENGTH = 6;

function bech32Data(address) {
  // The human-readable part is allowed to contain a "1" of its own, so the
  // separator is the last one, not the first.
  const separator = address.lastIndexOf("1");
  if (separator < 0) throw new Error(address + ": not a bech32 address");

  const out = [];
  let acc = 0;
  let bits = 0;

  for (const c of address.slice(separator + 1, -BECH32_CHECKSUM_LENGTH)) {
    const value = BECH32_CHARSET.indexOf(c);
    if (value < 0) throw new Error(address + ": not a bech32 address");

    // Five bits in per character, eight out per byte, oldest bits first.
    acc = (acc << 5) | value;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((acc >> bits) & 0xff);
      acc &= (1 << bits) - 1;
    }
  }

  if (out.length === 0) throw new Error(address + ": not a bech32 address");
  return new Uint8Array(out);
}

// ── protobuf ────────────────────────────────────────────────────────────────
//
// Only enough of the wire format to read one message and the one nested in
// it: varints, length-delimited fields, and enough of the fixed-width ones to
// step over anything unrecognized. The decoders name fields by number, so
// they stay correct as long as injective/tee/v1 only ever appends — the
// compatibility promise protobuf makes anyway.

function decodeEVStatus(bytes) {
  const f = readFields(bytes);
  return {
    // 1 to 3 are reserved: the EV candidate, the derived S_EV flag and the
    // vouching fraction, from the stake-based model the whitelist replaced.
    soft_jailed: bool(f[4]),
    soft_jail_until_height: int(f[5]),
    miss_streak: int(f[6]),
    jail_escalation_count: int(f[7]),
    enterprise_validators: readRepeated(bytes, 8).map(decodeEnterpriseValidator),
  };
}

function decodeParams(bytes) {
  // QueryParamsResponse wraps Params in field 1.
  const inner = readFields(bytes)[1];
  const f = inner === undefined ? {} : readFields(inner);
  return {
    // 1 to 3 are reserved: the EV candidate and the vouch thresholds.
    ev_grace_rounds: int(f[4]),
    ev_miss_threshold: int(f[5]),
    ev_soft_jail_base_blocks: int(f[6]),
    ev_backpressure_growth_blocks: int(f[7]),
    ev_hijack_enabled: bool(f[8]),
  };
}

function decodeEnterpriseValidator(bytes) {
  const f = readFields(bytes);
  return {
    valoper: utf8(f[1]),
    cons_addr: f[2],
    tee_pubkey: f[3],
  };
}

// readFields returns the last value seen per field number: varints as
// numbers, length-delimited fields as byte slices. A field the message never
// set is simply missing — protobuf does not put default values on the wire —
// so the accessors below supply the proto defaults, which is what an absent
// field means. Absent is never "unknown" here.
function readFields(bytes) {
  const fields = {};
  for (const field of walk(bytes)) fields[field.number] = field.value;
  return fields;
}

// Last-seen is what proto3 means by a scalar appearing twice, but a repeated
// field is the one case where every occurrence counts, so it gets a pass of
// its own rather than a shape that would complicate every other read.
function readRepeated(bytes, number) {
  const out = [];
  for (const field of walk(bytes)) {
    if (field.number === number && field.value !== undefined) out.push(field.value);
  }
  return out;
}

// walk yields the message's fields in the order they appear on the wire, so
// the wire format itself is written out once and read two ways.
function* walk(bytes) {
  let i = 0;

  while (i < bytes.length) {
    const tag = readVarint(bytes, i);
    const number = Math.floor(tag.value / 8);
    const wire = tag.value % 8;
    i = tag.next;

    if (wire === 0) {
      const v = readVarint(bytes, i);
      i = v.next;
      yield { number: number, value: v.value };
    } else if (wire === 2) {
      const len = readVarint(bytes, i);
      i = len.next + len.value;
      yield { number: number, value: bytes.subarray(len.next, i) };
    } else if (wire === 5 || wire === 1) {
      i += wire === 5 ? 4 : 8; // fixed32 / fixed64: unused here, stepped over
    } else {
      throw new Error("unsupported protobuf wire type " + wire);
    }
  }
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

// ── the quote, and the four lamps ───────────────────────────────────────────

// Byte offsets into a TD Quote v4: a 48-byte header, then the 584-byte body.
// Fixed by the structure, so a plain slice is all it takes to read them.
const QUOTE_MIN_LENGTH = 632;
const OFF_TD_ATTRIBUTES = 168;
const OFF_MRTD = 184;
const OFF_RTMR = 376; // four 48-byte registers, back to back
const OFF_REPORT_DATA = 568;

// The store holds text, so the quote is base64 only by convention: the chain
// checks that on the way in, nothing checks it on the way out. Unparseable
// reads as no readable quote, the same as a truncated one, rather than
// throwing out of the middle of a render.
function decodeQuote(b64) {
  if (!b64) return null;
  try {
    return base64ToBytes(b64);
  } catch {
    return null;
  }
}

function quoteBody(quote) {
  if (!quote || quote.length < QUOTE_MIN_LENGTH) return null;

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

// The chain keeps one set of these counters, not one per validator, and they
// only move while the proposer hijack is on: with it off the EV is never
// handed a slot to miss, so a clean streak would mean nothing at all.
function liveCheck(status, params, first) {
  if (!first) return { ok: null, text: "liveness counted for the first EV only" };
  if (!params.ev_hijack_enabled) return { ok: null, text: "liveness not enforced by this chain" };

  const escalation = status.jail_escalation_count ? ` · escalation ${status.jail_escalation_count}` : "";
  if (status.soft_jailed) {
    return { ok: false, text: `soft-jailed until block ${status.soft_jail_until_height}${escalation}` };
  }

  // A miss streak below the threshold is not yet a fault, so it stays green —
  // but it is the number worth watching, and it is meaningless without the
  // threshold it is racing.
  const missed = status.miss_streak
    ? ` · missed ${status.miss_streak} of ${params.ev_miss_threshold}`
    : "";
  return { ok: true, text: `not jailed${missed}${escalation}` };
}

// The check that makes reading both halves of the chain's state worth
// something: the key the chain hands out is the key this TD generated, not
// merely one stored next to a quote.
function bindingCheck(validator, body) {
  if (!body) return unreadable(validator);
  if (!validator.teePubkey) return { ok: null, text: "no registered key to compare" };

  return body.reportDataKey === validator.teePubkey.toLowerCase()
    ? { ok: true, text: "key was made inside this TD" }
    : { ok: false, text: "key is not the one in the quote" };
}

function sealedCheck(body) {
  if (!body) return { ok: null, text: "debug flag unreadable" };

  // Nothing else gives this away: a debug TD booted from the pinned image has
  // identical measurements, and the host can read its memory.
  return body.debug
    ? { ok: false, text: "host can read this TD — key unsafe" }
    : { ok: true, text: "memory sealed from the host" };
}

function pinsCheck(body, expected) {
  if (!body) return { ok: null, text: "measurements unreadable" };
  if (!expected) return { ok: null, text: "not pinned" };

  const measured = { mrtd: body.mrtd, rtmr0: body.rtmr[0], rtmr1: body.rtmr[1] };
  const compared = Object.keys(measured).filter((k) => expected[k]);
  if (compared.length === 0) return { ok: null, text: "pin file names no measurements" };

  const wrong = compared.filter((k) => measured[k] !== String(expected[k]).toLowerCase());
  const source = expected.source ? ` · ${expected.source}` : "";
  return wrong.length === 0
    ? { ok: true, text: `matches ${compared.join(", ")}${source}` }
    : { ok: false, text: `${wrong.join(", ")} differs from pins${source}` };
}

function unreadable(validator) {
  return validator.quote
    ? { ok: null, text: "not a TD Quote v4" }
    : { ok: null, text: "no quote announced" };
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
