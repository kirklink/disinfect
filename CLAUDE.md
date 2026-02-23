# Disinfect — Contributor Guide

## Commands

```bash
dart test --reporter github 2>/dev/null          # all tests
dart test --reporter github 2>/dev/null | tail -1 # summary only
dart analyze                                      # static analysis
```

## Package Structure

```
lib/
  disinfect.dart          # barrel export (re-exports all public API)
  src/
    disinfect.dart        # Disinfectant class, disinfect() convenience, TagInfo, 6 callback typedefs
    whitelist.dart        # getDefaultWhiteList() — 74 HTML tags with allowed attributes
    defaults.dart         # escape/unescape functions, safeAttrValue(), StripTagBody, strip helpers
    parser.dart           # parseTag() — char-by-char HTML parser, parseAttr() — attribute parser
    css_filter.dart       # CssFilter class, CssAttrInfo, getDefaultCssWhiteList() (~250 CSS props),
                          # CssOnAttrHandler/CssSafeAttrValueHandler typedefs, _parseStyle() CSS parser
test/
  xss_test.dart           # 7 groups — OWASP XSS Filter Evasion vectors (script, event, javascript:, entity, style, img, iframe)
  custom_method_test.dart # 22 cases — callback hooks, stripIgnoreTag, stripIgnoreTagBody, custom whitelist, CSS options
  parser_test.dart        # 3 groups — parseTag position tracking, parseAttr quoted/unquoted/malformed
  default_test.dart       # 1 case — stripCommentTag
```

## Architecture

### Processing Pipeline

```
disinfect(html) or Disinfectant.process(html)
  → stripBlankChar(html)?            // optional: remove invisible/control chars
  → stripCommentTag(html)?           // default: remove <!-- ... -->
  → set up StripTagBody?             // optional: track tag body regions for removal
  → parseTag(html, onTag, escapeHtml)
      ↓ for each tag:
      → TagInfo(sourcePosition, position, isClosing, isWhite)
      → onTag(tag, html, info)       // user hook — return string to replace, null for default
      → if whitelisted:
          → _getAttrs(tagHtml)       // extract attribute portion
          → parseAttr(attrs, onAttr)
              ↓ for each attribute:
              → onTagAttr(tag, name, value, isWhiteAttr)?
              → if whitelisted attr:
                  → safeAttrValue(tag, name, value, cssFilter)
                    → friendlyAttrValue(): unescape + decode entities + clear non-printable
                    → href/src: protocol whitelist check
                    → background: javascript: pattern check
                    → style: expression() + url(javascript:) check, then CssFilter.process()
                    → escapeAttrValue(): escape quotes + angle brackets
              → else: onIgnoreTagAttr()?
          → rebuild tag with filtered attributes
      → if not whitelisted:
          → onIgnoreTag(tag, html, info)?
          → default: escapeHtml(tagHtml)
  → StripTagBody.remove(html)?       // strip marked regions
  → return sanitized HTML
```

### Key Patterns

- **Callback-oriented design**: 6 user hooks that return `String?` — `null` means "use default behavior" (maps JS `undefined` pattern). This lets consumers override any filtering decision without subclassing.
- **Whitelist defaults**: Security by default. `getDefaultWhiteList()` and `getDefaultCssWhiteList()` return new mutable maps each call so consumers can modify without affecting other instances.
- **CSS filter inlined**: The `cssfilter` npm package (649 LOC) was too small for a standalone Dart package. `css_filter.dart` contains the full CSS parser + whitelist + `CssFilter` class.
- **Char-by-char parsers**: Both `parseTag()` and `_parseStyle()` are state machines that scan character by character. No regex for structural parsing — regex only for pattern matching within values.
- **StripTagBody state machine**: `StripTagBody` tracks open/close positions of non-whitelisted tags during parsing, marks them with `[removed]`/`[/removed]` sentinels, then strips those regions in a post-processing pass via `remove()`.

### Design Decisions

- **`Disinfectant` not `FilterXss`**: Renamed from the JS original to match Dart naming and avoid the security-tool-sounding name. The convenience function is `disinfect()`.
- **`TagInfo` class not ad-hoc object**: The JS code passes `{sourcePosition, position, isClosing, isWhite}` as a plain object. Dart uses a typed class with const constructor.
- **`whiteList` / `allowList` dual param**: Both names accepted for the same option. `allowList` is the modern term; `whiteList` kept for js-xss familiarity.
- **`Object? css` parameter**: Accepts `false` (disable), `Map` (custom CSS whitelist), or omit (default). Matches js-xss options shape. Not ideal Dart typing, but preserves API compatibility.
- **`Object? stripIgnoreTagBody`**: Accepts `true` (strip all), `List<String>` (strip specific tags), or omit. Same js-xss compatibility trade-off.
- **Closure capture fix**: The JS code reassigns `onIgnoreTag` after `StripTagBody` captures it by closure. Fixed in Dart by capturing the original value in a `final` before reassignment to prevent infinite recursion.
- **CSS output format**: Uses `'$name:$value; '` concatenation + `trim()` to match js-xss output exactly. `join('; ')` was incorrect (omits trailing format).

### Security Model

Default `safeAttrValue` checks:
- **href/src**: Protocol whitelist — `http://`, `https://`, `mailto:`, `tel:`, `data:image/`, `ftp://`, `./`, `../`, `#`, `/`. Anything else → empty string.
- **background**: Rejects `javascript:`, `vbscript:`, `livescript:`, `mocha:` (with space evasion via `j\s*a\s*v\s*a...` regex).
- **style**: Rejects `expression(` (IE-specific), `url(javascript:)`. Passes through `CssFilter.process()` if CSS enabled.
- **All values**: Decoded entities (`&#123;`), danger entities (`&colon;`, `&NewLine;`), non-printable chars, then escaped for output.

## Consumer API Reference

See [docs/guide.md](docs/guide.md) for complete API with signatures and examples.

## Status

v1.0.0 — 5 source files, 33 tests. Ported from js-xss v1.0.15. Zero runtime dependencies.
