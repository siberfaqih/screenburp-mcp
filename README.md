# ScreenBurp MCP

**Turn Burp traffic into screenshots your report can actually use — without leaving your AI chat.**

If you do web security testing, you know the drill. You find something
interesting in Burp, then you stop, switch windows, take a screenshot, crop it,
highlight the important bit, black out the tokens, save it somewhere… and by
then you've lost your train of thought.

ScreenBurp takes that busywork off your plate. It's a Burp Suite extension that
lets AI assistants like OpenCode, Claude, and ChatGPT look at your Proxy
history and hand you back a clean, ready-to-paste evidence screenshot — real
request, real response, important parts highlighted, secrets hidden.

It's a fork of PortSwigger's
[Burp MCP Server](https://github.com/PortSwigger/mcp-server), so everything
that extension could already do is still here. ScreenBurp just adds the
screenshot tools on top.

---

## What you get

- **Screenshots straight from Proxy history** — pick an entry, get a PNG back
  in the chat. No tab-switching, no cropping by hand.
- **Highlights and callouts** — point at the status line, a header, or a JSON
  field and say *"this bit matters."* The image shows exactly that.
- **Secrets hidden by default** — Authorization headers, cookies, tokens,
  passwords, and JWTs are blacked out before anything leaves Burp. You have to
  explicitly ask if you ever want them visible.
- **Honest images, always** — ScreenBurp never invents, rebuilds, or "tidies
  up" an HTTP message to make a nicer picture. If it can't capture something
  for real, it tells you why instead of faking it.
- **All the upstream Burp MCP tools** — send requests, browse history, use
  Repeater/Intruder/Collaborator, tweak config, and the rest, just like before.

## Which screenshot tool should I use?

There are five. In plain terms:

| Tool | Reach for it when… |
| --- | --- |
| `screenshot_proxy_http_history` | You already know which history entry you want (by its position in the list). Quick, headless render. |
| `screenshot_proxy_http_history_regex` | You'd rather describe the entry — *"the login POST that got a 401"* — than count rows. |
| `burp_capture_evidence` | You want it to look like Burp itself, because it *is* Burp: the real message editors, your theme, your fonts. |
| `burp_smart_evidence` | The response is huge and only a few lines matter. It finds them, scrolls to them, and shoots each spot. |
| `burp_diff_evidence` | You're proving an exploit: *"here's the normal request, here's my payload, and here's what changed."* It diffs the pair, labels the payload and the evidence, and gives you a verdict. |

You don't have to memorise any of this. Just tell your assistant what you
want in normal words — see the example at the bottom — and let it pick.

### A quick look at each one

**`screenshot_proxy_http_history`** — renders one entry by its zero-based
offset in Proxy history (run `get_proxy_http_history` first to find it):

```json
{
  "offset": 0,
  "redactSecrets": true,
  "maxBodyCharacters": 4000,
  "title": "Authorization bypass evidence",
  "highlights": [{ "match": "HTTP/1.1 200 OK", "color": "green" }],
  "annotations": [
    {
      "match": "Access-Control-Allow-Origin: *",
      "label": "Wildcard CORS policy",
      "color": "red"
    }
  ]
}
```

**`screenshot_proxy_http_history_regex`** — same idea, but it searches
history for you. `matchOffset` counts only the entries that match:

```json
{
  "regex": "POST /api/login|HTTP/1.1 401",
  "matchOffset": 0,
  "title": "Authentication test"
}
```

Both return a short text summary plus the PNG itself. Highlights take a
literal string or a regex, a colour (`yellow`, `red`, `green`, `purple`, … or
any `#rrggbb`), and optional `regex` / `caseSensitive` flags. Annotations are
the same plus a `label` — they get numbered callouts and a small legend under
the response. Up to 25 highlights and 20 annotations per shot. Matching runs
*after* redaction and truncation, so a callout can never accidentally reveal
something that was supposed to stay hidden.

**`burp_capture_evidence`** — the "make it look native" one. In its default
`native_editor` mode it opens Burp's real request/response editors with the
exact captured messages, in your current theme, and photographs the actual
pixels. No HTML mock-up, no look-alike renderer.

```json
{
  "request_id": "123",
  "mode": "native_editor",
  "layout": "side_by_side",
  "capture_width": 1920,
  "capture_height": 1080,
  "highlight": {
    "request": ["mechanic_api"],
    "response": ["HTTP/1.1 200"]
  },
  "redact_sensitive": true,
  "output": "evidence/step-01.png"
}
```

There's also a `repeater` mode that photographs what's really on screen in
Repeater — bring the tab you want to the front first. Good to know:

- `layout` is `side_by_side` or `stacked`; `theme` just follows Burp.
- Highlights also draw neat red boxes around every match we can actually
  locate on screen. Anything we can't pin down exactly is listed in the
  summary and left unboxed — we'd rather miss a box than draw one in the
  wrong place. Turn this off with `"bounding_boxes": false`.
- You only ever see the visible part of the message in the picture. The full
  message is still there underneath, untouched, and the summary reminds you
  of that every time.
- Redaction here is a black bar painted over the pixels after the shot. The
  original bytes are never edited. (In `repeater` mode there's no automatic
  redaction, so give the frame a glance before you share it.)
- Bad IDs, silly dimensions (outside 400–3840 × 300–2160), a hidden Burp
  window, or a headless box all get you a clear error — never a pretend image.
- One honest limitation: Burp's API can't list or select Repeater tabs, so
  `repeater` mode can't switch tabs for you.

**`burp_smart_evidence`** — for the 3,000-line response where three lines
prove your point. Tell it what to look for with a keyword, a regex, a
JSONPath, or just describe the goal and let it work out where to look:

```json
{
  "request_id": "id:456",
  "select": [
    { "type": "regex", "expression": "fetched \\S+ content" },
    { "type": "jsonpath", "expression": "$..url" }
  ],
  "goal": "The request supplies an external URL. Find the response field containing content retrieved from that URL.",
  "context_lines": 8,
  "max_regions": 5,
  "output_prefix": "evidence/smart"
}
```

Matches that sit close together become one screenshot; far-apart matches get
one each (capped by `max_regions`, and anything left out is listed, not
quietly dropped). Every match is checked character-for-character against
the original message — if it can't be verified, it's reported as unmatched
rather than smoothed over. `request_id` takes either a history offset
(`"123"`) or Burp's stable item ID (`"id:456"`). JSONPath supports `$`,
`.name`, `['name']`, `[N]`, `[*]`/`.*`, and `..name`; anything fancier gets
a clear error. You get back the summary, the complete original request and
response, one picture per region, and a metadata block that says exactly
what was matched, scrolled to, boxed, and redacted.

**`burp_diff_evidence`** — built for *"did my payload actually work?"*
Give it a normal (baseline) request and your test request. It works out what
you changed, checks the response for proof, and tells you plainly whether it
looks like `success`, `observed`, `inconclusive`, or `failed` — with its
confidence, and never with more certainty than the evidence earns.

```json
{
  "baseline_id": "429",
  "request_id": "432",
  "objective": "server fetches the supplied external URL",
  "payload_hint": "http://<payload>.oastify.com/final",
  "output_prefix": "evidence/ssrf"
}
```

You get the full baseline and test messages, a structured diff (method,
path, params, headers, cookies, JSON/form bodies), the payload-and-evidence
breakdown, a clean native screenshot, and an annotated copy with numbered
red boxes and a legend that ties each number back to the payload and the
proof. A `success` verdict requires real reflection or genuinely new
evidence in the response; a request that got newly rejected counts as
`failed`. Everything in between is reported as-is.

---

## Get it running

You'll need JDK 21 or newer (and the `jar` command on your PATH).

**1. Build it**

```bash
./gradlew test embedProxyJar
```

That leaves you with `build/libs/screenburp-mcp-all.jar`.

**2. Load it in Burp**

1. If the official **MCP Server** extension is installed, disable or remove
   it first — the two can't share the same port.
2. Go to **Extensions → Installed → Add**, choose **Java**, and load the JAR
   above.
3. Open the **MCP** tab, switch the server on, and leave it on
   `http://127.0.0.1:9876` unless that port is taken.
4. If Burp asks whether the agent may read your Proxy history, approve it.

**3. Point your AI client at it**

The usual stdio proxy setup still works:

```json
{
  "mcp": {
    "servers": {
      "burp": {
        "type": "local",
        "command": [
          "java",
          "-jar",
          "/Users/you/tools/mcp-proxy.jar",
          "--sse-url",
          "http://127.0.0.1:9876"
        ]
      }
    }
  }
}
```

After swapping the extension, restart or reconnect your MCP client so it
picks up the new tool list.

## Just ask, in plain words

You rarely need to touch the JSON yourself. Something like this is enough:

> Search Burp Proxy history for `POST /identity/api/auth/verify`, take a
> redacted screenshot of the full request and response, highlight the status
> line, and title it "JWT verification evidence".

## Checking it against real Burp (worth doing once)

The automated tests run headless with stand-in editors, so before you trust
this in a report, spend two minutes confirming it against the real thing:

1. Build and load the extension, then open a request/response in Repeater.
2. Ask for a `burp_capture_evidence` shot (`native_editor`,
   `redact_sensitive: false`) of a history entry you can see.
3. Put the PNG next to Burp and compare: tabs, colours, fonts, line numbers,
   and the exact bytes should match.
4. Try `repeater` mode and check the picture is the frame you were looking at.
5. Turn redaction back on and confirm secrets are covered and labelled as a
   redacted copy.
6. For `burp_smart_evidence`, try a long response with a regex plus a plain
   `goal`, and check each picture shows the right lines and the metadata
   offsets really do match the original text.

## The fine print

- History access goes through Burp's normal approval flow — nothing is read
  behind your back.
- Bodies are shown up to 4,000 characters by default (20,000 max), and
  renders are capped at 700 lines so chats don't drown in output.
- The server listens on your own machine only, with the upstream DNS
  rebinding protections kept intact.
- Only test systems you're authorised to test. (You knew that, but it has to
  be said.)

## For developers

```bash
./gradlew test
```

The suite covers the headless renderer, redaction, truncation, the native
capture wiring and its error paths, ID lookup, the diff/smart-evidence
engines, and the full upstream test suite.

## Credits and licence

ScreenBurp is a fork of PortSwigger's
[Burp MCP Server](https://github.com/PortSwigger/mcp-server) and is released
under the same GPL licence — see [`LICENSE`](LICENSE). All credit for the
original MCP server goes to PortSwigger; the screenshot and evidence tools
are the part added here.
