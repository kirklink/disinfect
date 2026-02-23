# Disinfect

Whitelist-based HTML sanitizer for Dart.

## What

Sanitize untrusted HTML to prevent XSS attacks. Ported from [js-xss](https://github.com/leizongmin/js-xss) v1.0.15 with inlined CSS property filtering.

## Why

- **Whitelist, not blacklist.** 74 HTML tags and ~250 CSS properties allowed by default. Everything else is escaped or stripped. You add to the allowlist — you don't chase new attack vectors.
- **Callback hooks.** Six hooks (`onTag`, `onIgnoreTag`, `onTagAttr`, `onIgnoreTagAttr`, `safeAttrValue`, `escapeHtml`) let you customize every filtering decision without forking.
- **Zero dependencies.** CSS filtering is inlined. No runtime deps, no transitive supply chain.
- **Battle-tested rules.** Filters protocol injection (`javascript:`, `vbscript:`, `livescript:`), CSS expression attacks, entity encoding tricks, and invisible character smuggling. All OWASP XSS Filter Evasion Cheat Sheet vectors pass.

## Features

- Whitelist-based HTML tag and attribute filtering (74 tags default)
- Inline CSS property filtering (~250 properties default)
- Protocol whitelist for `href`/`src` (http, https, mailto, tel, data:image, ftp, relative)
- Strip or escape non-whitelisted tags
- Strip tag bodies (e.g., remove `<script>...</script>` entirely)
- HTML comment removal (or preservation)
- Invisible/control character stripping
- Single or double quote attribute wrapping
- Reusable `Disinfectant` class or one-shot `disinfect()` function

## Quick Start

```dart
import 'package:disinfect/disinfect.dart';

void main() {
  // One-shot
  final clean = disinfect('<script>alert("xss")</script><p>Hello</p>');
  // '&lt;script&gt;alert("xss")&lt;/script&gt;<p>Hello</p>'

  // Reusable (same options, multiple inputs)
  final sanitizer = Disinfectant(
    stripIgnoreTagBody: ['script', 'style'],
  );
  print(sanitizer.process('<script>bad</script><b>bold</b>'));
  // '<b>bold</b>'
}
```

## Docs

- [CLAUDE.md](CLAUDE.md) — for AI modifying this package
- [docs/guide.md](docs/guide.md) — for AI using this package

## Status

v1.0.0 — 5 source files, 33 tests. Zero runtime dependencies.
