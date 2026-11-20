# cspdryrun

[![CI](https://github.com/jatingargiitk/cspdryrun/actions/workflows/ci.yml/badge.svg)](https://github.com/jatingargiitk/cspdryrun/actions/workflows/ci.yml)

Check what a Content-Security-Policy would block on your built static site, before you deploy it.

A CSP that is too tight doesn't fail your build. It fails in your users' browsers: the theme script stops running, the web font falls back, the YouTube embed goes blank. Usually you find out from the console after the deploy. `cspdryrun` reads your build output (`dist/`, `build/`, `out/`, `public/`) and the policy the host will send, and lists each thing a browser would block. For each one you get the file and line, the directive that blocked it (after fallback, e.g. `frame-src -> default-src`), and a change that would allow it, including the exact `'sha256-…'` for inline code.

It reads policies from:

- a Netlify / Cloudflare Pages `_headers` file (picked up from `DIR/_headers` automatically, or `--headers FILE`), including Cloudflare's `! Header` detach
- the `headers` array in `vercel.json` (`--vercel FILE`)
- `<meta http-equiv="Content-Security-Policy">` tags in each page
- `--policy "..."` on the command line, e.g. the policy you're about to propose (`--only` checks just that one)

Each page is checked against every policy that applies to it, the way a browser enforces all of them. `Content-Security-Policy-Report-Only` policies are reported separately and don't fail the run. Pass `--enforce-report-only` to see what breaks when you switch report-only to enforcing.

Python 3.9+, no dependencies, runs offline.

## Install

```console
pip install git+https://github.com/jatingargiitk/cspdryrun
```

## Example

`examples/site` is a small build: three pages, a stylesheet with a self-hosted font, Google Analytics, a YouTube embed, an inline theme script and the kind of `onclick` and `style=` attributes that end up in real builds. Its `_headers`:

```
# Netlify / Cloudflare Pages headers for this build
/*
  Content-Security-Policy: default-src 'self'; script-src 'self' https://www.googletagmanager.com; style-src 'self' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self'
  X-Content-Type-Options: nosniff

/blog/*
  Content-Security-Policy-Report-Only: default-src 'self'; script-src 'self' 'strict-dynamic' 'nonce-r4nd0m'; object-src 'none'; base-uri 'none'
```

```console
$ cspdryrun examples/site --origin https://example.com
about/index.html
  policy 1: header _headers:2 (/*)
  BLOCK  line 6: url(/assets/acme-sans.woff2) (in /assets/app.css)
         font-src; fix: add 'self' to font-src
  BLOCK  line 6: url(https://images.example-cdn.net/hero.jpg) (in /assets/app.css)
         img-src; fix: add https://images.example-cdn.net to img-src
  BLOCK  line 10: <iframe src="https://www.youtube-nocookie.com/embed/abc123">
         frame-src -> default-src; fix: set frame-src 'self' https://www.youtube-nocookie.com  (it inherits default-src now)

blog/post.html
  policy 1: header _headers:2 (/*)
  policy 2: Report-Only header _headers:6 (/blog/*)
  BLOCK  line 6: url(/assets/acme-sans.woff2) (in /assets/app.css)
         font-src [policy 1]; fix: add 'self' to font-src
  BLOCK  line 6: url(https://images.example-cdn.net/hero.jpg) (in /assets/app.css)
         img-src [policy 1]; fix: add https://images.example-cdn.net to img-src
  BLOCK  line 11: <img src="https://images.example-cdn.net/cover.webp">
         img-src [policy 1]; fix: add https://images.example-cdn.net to img-src
  REPORT line 6: url(https://images.example-cdn.net/hero.jpg) (in /assets/app.css)
         img-src -> default-src [policy 2]; fix: set img-src 'self' https://images.example-cdn.net  (it inherits default-src now)
  REPORT line 8: <script src="https://www.googletagmanager.com/gtag/js?id=G-XXXX">
         script-src-elem -> script-src [policy 2]; fix: give it a nonce, or an integrity hash listed in the policy ('strict-dynamic' ignores URLs)
  REPORT line 11: <img src="https://images.example-cdn.net/cover.webp">
         img-src -> default-src [policy 2]; fix: set img-src 'self' https://images.example-cdn.net  (it inherits default-src now)

index.html
  policy 1: header _headers:2 (/*)
  BLOCK  line 6: inline <script> 'document.documentElement.data…'
         script-src-elem -> script-src; fix: add 'sha256-hUizg0THL3POThjSDVwpjWQRCwbqMmpUTVQH8Hce5tI=' to script-src
  BLOCK  line 8: url(/assets/acme-sans.woff2) (in /assets/app.css)
         font-src; fix: add 'self' to font-src
  BLOCK  line 8: url(https://images.example-cdn.net/hero.jpg) (in /assets/app.css)
         img-src; fix: add https://images.example-cdn.net to img-src
  BLOCK  line 9: <link href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg…">
         img-src; fix: add data: to img-src
  BLOCK  line 15: <button onclick="window.print()">
         script-src-attr -> script-src; fix: move it to a script file, or add 'unsafe-hashes' 'sha256-MguIPR6qNR8D3B+eAlK+bIRTZe8t3wkOY4B/56Me9FU=' to script-src
  BLOCK  line 16: <p style="color: rebeccapurple">
         style-src-attr -> style-src; fix: move it to a stylesheet, or add 'unsafe-hashes' 'sha256-AbQMTXlkez1/aRYDtOSgHhtZ29+NRfwaHapcKx/QcAI=' to style-src

3 page(s) checked: 12 blocked on 3 page(s), 3 more only reported (Report-Only)
$ echo $?
1
```

`--origin` is the origin the site is served from. It decides what `'self'` matches and what relative URLs resolve to. Without it, relative URLs still count as same-origin, but a policy that names your own domain instead of `'self'` won't match them.

Taking those fixes into a new policy and checking only that one:

```console
$ cspdryrun examples/site --origin https://example.com --only --policy "default-src 'self'; script-src 'self' https://www.googletagmanager.com 'sha256-hUizg0THL3POThjSDVwpjWQRCwbqMmpUTVQH8Hce5tI='; style-src 'self' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: https://images.example-cdn.net; frame-src https://www.youtube-nocookie.com"
about/index.html
  policy 1: --policy
  ok: nothing blocked

blog/post.html
  policy 1: --policy
  ok: nothing blocked

index.html
  policy 1: --policy
  BLOCK  line 15: <button onclick="window.print()">
         script-src-attr -> script-src; fix: move it to a script file, or add 'unsafe-hashes' 'sha256-MguIPR6qNR8D3B+eAlK+bIRTZe8t3wkOY4B/56Me9FU=' to script-src
  BLOCK  line 16: <p style="color: rebeccapurple">
         style-src-attr -> style-src; fix: move it to a stylesheet, or add 'unsafe-hashes' 'sha256-AbQMTXlkez1/aRYDtOSgHhtZ29+NRfwaHapcKx/QcAI=' to style-src

3 page(s) checked: 2 blocked on 1 page(s)
$ echo $?
1
```

The two attributes are left. Moving them into `app.js` and `app.css` is the better fix; `'unsafe-hashes'` is the escape hatch.

<details>
<summary>What breaks if the /blog/* Report-Only policy is switched to enforcing</summary>

```console
$ cspdryrun examples/site --origin https://example.com --enforce-report-only
about/index.html
  policy 1: header _headers:2 (/*)
  BLOCK  line 6: url(/assets/acme-sans.woff2) (in /assets/app.css)
         font-src; fix: add 'self' to font-src
  BLOCK  line 6: url(https://images.example-cdn.net/hero.jpg) (in /assets/app.css)
         img-src; fix: add https://images.example-cdn.net to img-src
  BLOCK  line 10: <iframe src="https://www.youtube-nocookie.com/embed/abc123">
         frame-src -> default-src; fix: set frame-src 'self' https://www.youtube-nocookie.com  (it inherits default-src now)

blog/post.html
  policy 1: header _headers:2 (/*)
  policy 2: Report-Only header _headers:6 (/blog/*)
  BLOCK  line 6: url(/assets/acme-sans.woff2) (in /assets/app.css)
         font-src [policy 1]; fix: add 'self' to font-src
  BLOCK  line 6: url(https://images.example-cdn.net/hero.jpg) (in /assets/app.css)
         img-src [policy 1]; fix: add https://images.example-cdn.net to img-src
  BLOCK  line 11: <img src="https://images.example-cdn.net/cover.webp">
         img-src [policy 1]; fix: add https://images.example-cdn.net to img-src
  BLOCK  line 6: url(https://images.example-cdn.net/hero.jpg) (in /assets/app.css)
         img-src -> default-src [policy 2]; fix: set img-src 'self' https://images.example-cdn.net  (it inherits default-src now)
  BLOCK  line 8: <script src="https://www.googletagmanager.com/gtag/js?id=G-XXXX">
         script-src-elem -> script-src [policy 2]; fix: give it a nonce, or an integrity hash listed in the policy ('strict-dynamic' ignores URLs)
  BLOCK  line 11: <img src="https://images.example-cdn.net/cover.webp">
         img-src -> default-src [policy 2]; fix: set img-src 'self' https://images.example-cdn.net  (it inherits default-src now)

index.html
  policy 1: header _headers:2 (/*)
  BLOCK  line 6: inline <script> 'document.documentElement.data…'
         script-src-elem -> script-src; fix: add 'sha256-hUizg0THL3POThjSDVwpjWQRCwbqMmpUTVQH8Hce5tI=' to script-src
  BLOCK  line 8: url(/assets/acme-sans.woff2) (in /assets/app.css)
         font-src; fix: add 'self' to font-src
  BLOCK  line 8: url(https://images.example-cdn.net/hero.jpg) (in /assets/app.css)
         img-src; fix: add https://images.example-cdn.net to img-src
  BLOCK  line 9: <link href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg…">
         img-src; fix: add data: to img-src
  BLOCK  line 15: <button onclick="window.print()">
         script-src-attr -> script-src; fix: move it to a script file, or add 'unsafe-hashes' 'sha256-MguIPR6qNR8D3B+eAlK+bIRTZe8t3wkOY4B/56Me9FU=' to script-src
  BLOCK  line 16: <p style="color: rebeccapurple">
         style-src-attr -> style-src; fix: move it to a stylesheet, or add 'unsafe-hashes' 'sha256-AbQMTXlkez1/aRYDtOSgHhtZ29+NRfwaHapcKx/QcAI=' to style-src

3 page(s) checked: 15 blocked on 3 page(s)
$ echo $?
1
```

</details>

## In CI

The exit code is 0 when nothing is blocked, 1 when something would be, and 2 on a usage or input error. Run it after the build step:

```yaml
- run: npm run build
- run: pip install git+https://github.com/jatingargiitk/cspdryrun
- run: cspdryrun dist --origin https://example.com
```

`--format json` prints every finding with file, line, URL, effective directive, the directive that decided, the policy's source, and the suggested fix.

## What it checks

| In your build | Directive (CSP3 fallback order) |
|:--|:--|
| inline `<script>` (classic, `module`, `importmap`) and `javascript:` URLs | `script-src-elem` → `script-src` → `default-src` |
| `<script src>`, `<link rel=modulepreload>` | `script-src-elem` → `script-src` → `default-src` |
| `on*=` event handler attributes | `script-src-attr` → `script-src` → `default-src` |
| inline `<style>`, `<link rel=stylesheet>`, CSS `@import` | `style-src-elem` → `style-src` → `default-src` |
| `style=` attributes | `style-src-attr` → `style-src` → `default-src` |
| `<img src/srcset>`, `<picture><source>`, `poster`, icons, CSS `url()` | `img-src` → `default-src` |
| `url()` inside `@font-face`, `<link rel=preload as=font>` | `font-src` → `default-src` |
| `<video>`, `<audio>`, `<source>`, `<track>` | `media-src` → `default-src` |
| `<iframe>`, `<frame>` | `frame-src` → `child-src` → `default-src` |
| `<object>`, `<embed>` | `object-src` → `default-src` |
| `<form action>`, `formaction` | `form-action` (no fallback) |
| `<base href>` | `base-uri` (no fallback) |

Matching follows CSP Level 3: `'self'`, `*`, scheme sources, host sources with `*.` wildcards, ports and paths, nonces, `sha256`/`sha384`/`sha512` hashes, `'unsafe-inline'` being ignored once a nonce or hash is present, `'unsafe-hashes'` for attributes and `javascript:` URLs, `'strict-dynamic'` ignoring URL sources, and integrity hashes on external scripts. `<script>` blocks with a non-JavaScript `type` (`application/ld+json`, templates) are data, never run, and are skipped. Stylesheets the pages link are read from the build directory, so their `url()`s and `@import`s are checked too.

The test suite loads `examples/site` and a fixture of edge cases in headless Chromium, with the same headers, and checks that every `securitypolicyviolation` the browser fires was predicted by `cspdryrun`. It also checks that the hashes in the proposed policy above are accepted by the browser.

## What it can't see

- **Anything added at runtime.** Scripts injected by your JavaScript, `fetch`/XHR targets (`connect-src`), `eval` (`'unsafe-eval'`), workers and anything a third-party script loads after it runs. A static build doesn't contain them. Use a Report-Only policy in production for those.
- **CSS rules nothing uses.** A `url()` in a stylesheet is reported whether or not any element matches its rule. The browser only fetches it when one does.
- **Server-rendered pages and per-request nonces.** It reads files, not responses. A nonce baked into static HTML is matched as written.
- **Host config beyond `_headers` and `vercel.json` headers.** No nginx/Apache configs, no `has`/`missing` conditions (they're treated as always matching, with a warning), and no mixed-content upgrades.
- Each `.html` file is matched against header rules at every URL it can be served at (`about/index.html` as `/about/`, `/about/index.html` and `/about`), so a rule matching any of them applies.

## License

MIT
