# js-xss → Dart Port Report

## Source

- **Repo**: [leizongmin/js-xss](https://github.com/leizongmin/js-xss) v1.0.15
- **Stars**: ~5.3K
- **JS LOC**: ~1040 (xss core) + ~649 (cssfilter dep) = ~1689 total
- **JS deps**: `cssfilter` (0.0.10, inline CSS sanitizer), `commander` (CLI only — skipped)

## Architecture

### JS Design

- **Entry** (`index.js`, 52 LOC) — exports `filterXSS()` function + `FilterXSS` class
- **Core** (`xss.js`, 233 LOC) — `FilterXSS` class, whitelist-based tag/attr processing
- **Parser** (`parser.js`, 258 LOC) — char-by-char HTML tag parser + attribute parser
- **Defaults** (`default.js`, 462 LOC) — whitelist (74 tags), escape functions, safe-attr-value checker, `StripTagBody` closure, `stripCommentTag`, `stripBlankChar`
- **Util** (`util.js`, 35 LOC) — polyfills for `indexOf`, `forEach`, `trim`, `spaceIndex`
- **cssfilter** (separate npm package, 649 LOC) — CSS property whitelist (~250 props), CSS parser, `FilterCSS` class

Heavily callback-oriented: 6 user hooks (`onTag`, `onIgnoreTag`, `onTagAttr`, `onIgnoreTagAttr`, `safeAttrValue`, `escapeHtml`) control all filtering behavior. Default callbacks return `undefined` to signal "use default behavior".

### Dart Translation

- **css_filter.dart** (543 LOC) — cssfilter inlined: CSS whitelist + parser + `CssFilter` class
- **whitelist.dart** (96 LOC) — HTML tag whitelist (74 tags)
- **parser.dart** (250 LOC) — HTML `parseTag` + `parseAttr`
- **defaults.dart** (247 LOC) — escape functions, `safeAttrValue`, `StripTagBody`, strip helpers
- **xss.dart** (336 LOC) — `FilterXss` class, `filterXss()` convenience, typedefs, `TagInfo`
- **xss.dart barrel** (23 LOC) — public API exports

**Total**: 1472 LOC source, 1010 LOC tests (33 tests)

## Key Decisions

### 1. Inline cssfilter (not a separate package)

The cssfilter npm package is 649 LOC, mostly a CSS property whitelist (~250 entries). Too small for a standalone Dart package, and only used by xss. Inlined as a single file.

### 2. Null return replaces undefined for "no opinion" callbacks

JS callbacks return `undefined` to signal "use default behavior". Dart uses nullable return types (`String?`). Six typed callback typedefs:

```dart
typedef OnTagHandler = String? Function(String tag, String html, TagInfo info);
typedef OnTagAttrHandler = String? Function(String tag, String name, String value, bool isWhiteAttr);
// etc.
```

### 3. Named parameters for all options

The JS options object becomes named parameters on both `FilterXss()` constructor and `filterXss()` convenience function. Dart type system prevents invalid option values at compile time.

### 4. TagInfo record class replaces ad-hoc options object

JS passes `{sourcePosition, position, isClosing, isWhite}` as a plain object. Dart uses a typed `TagInfo` class with const constructor.

### 5. Dual-type variables → nullable types

JS uses `false`/number patterns (e.g., `tagStart = false` or `tagStart = currentPos`). Dart uses `int? tagStart` with `null` for "not started".

## Dependency Map

| JS Dep | Purpose | Dart Disposition | Notes |
|--------|---------|-----------------|-------|
| `cssfilter` 0.0.10 | CSS property whitelist + sanitizer | **inlined** | 649 LOC, too small for standalone package |
| `commander` ^2.20.3 | CLI binary | **skipped** | CLI not part of the port |

## Porting Notes

### What went smoothly

- The char-by-char parsers (HTML tags, attributes, CSS properties) translated directly with no structural changes
- Callback-heavy architecture maps well to Dart typedefs
- Security tests (OWASP XSS Filter Evasion Cheat Sheet) all pass with no modifications
- Zero runtime dependencies — cssfilter inlined, nothing else needed

### Bugs caught

1. **Closure variable capture in stripIgnoreTagBody** — The JS code reassigns `onIgnoreTag` after passing it (by closure) to `StripTagBody`. Both JS and Dart capture variables by reference, but the Dart implementation created infinite recursion because the closure read the variable after reassignment. Fixed by capturing the original value in a separate `final` before reassignment.

2. **CSS filter output format** — The agent-generated CSS filter used `join('; ')` which omitted trailing semicolons. The JS concatenates `ret + '; '` and trims. Fixed by matching the JS accumulation pattern exactly.

### Dropped tests

- `xss()` / `xss(null)` / `xss(123)` / `xss({a:1111})` — JS coercion tests impossible in typed Dart
- `singleQuotedAttributeValue: 'invalid'` — can't pass string for bool parameter
- Options mutation deep-equal test — simplified to "doesn't crash" since Dart named params aren't mutable objects

## LOC Comparison

| Component | JS | Dart | Delta |
|-----------|-----|------|-------|
| Source | 1689 | 1472 | -13% |
| Tests | 1051 | 1010 | -4% |
| Total | 2740 | 2482 | -9% |

## Verdict

Clean port. The callback architecture maps naturally to Dart typedefs with nullable returns. Inlining cssfilter was the right call — it avoided a micro-dependency and kept the package self-contained. The OWASP XSS cheat sheet tests provide real security validation. This is a viable Swoop middleware candidate for HTML sanitization.
