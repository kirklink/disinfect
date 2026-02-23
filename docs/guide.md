# Disinfect — Consumer Guide

Whitelist-based HTML sanitizer to prevent XSS attacks. Zero runtime dependencies.

## Import

```dart
import 'package:disinfect/disinfect.dart';
```

## Quick Start

```dart
import 'package:disinfect/disinfect.dart';

void main() {
  // One-shot sanitization
  final clean = disinfect('<script>alert("xss")</script><p>Hello</p>');
  print(clean); // '&lt;script&gt;alert("xss")&lt;/script&gt;<p>Hello</p>'

  // Reusable sanitizer (same options, multiple inputs)
  final sanitizer = Disinfectant(
    stripIgnoreTagBody: ['script', 'style'],
  );
  print(sanitizer.process('<script>bad</script><b>bold</b>'));
  // '<b>bold</b>'
}
```

---

## disinfect() — Convenience Function

```dart
String disinfect(
  String html, {
  Map<String, List<String>>? whiteList,
  Map<String, List<String>>? allowList,
  OnTagHandler? onTag,
  OnIgnoreTagHandler? onIgnoreTag,
  OnTagAttrHandler? onTagAttr,
  OnIgnoreTagAttrHandler? onIgnoreTagAttr,
  SafeAttrValueHandler? safeAttrValue,
  EscapeHtmlHandler? escapeHtml,
  bool stripIgnoreTag = false,
  Object? stripIgnoreTagBody,
  bool allowCommentTag = false,
  bool stripBlankChar = false,
  Object? css,
  bool singleQuotedAttributeValue = false,
})
```

Creates a `Disinfectant` with the given options, calls `process(html)`, and returns the result. For repeated use with the same options, create a `Disinfectant` directly.

```dart
final clean = disinfect('<img src=x onerror=alert(1)>');
// '<img src>'
```

---

## Disinfectant

Reusable, stateless sanitizer. Create once, call `process()` many times.

### Constructor

```dart
Disinfectant({
  Map<String, List<String>>? whiteList,
  Map<String, List<String>>? allowList,
  OnTagHandler? onTag,
  OnIgnoreTagHandler? onIgnoreTag,
  OnTagAttrHandler? onTagAttr,
  OnIgnoreTagAttrHandler? onIgnoreTagAttr,
  SafeAttrValueHandler? safeAttrValue,
  EscapeHtmlHandler? escapeHtml,
  bool stripIgnoreTag = false,
  Object? stripIgnoreTagBody,
  bool allowCommentTag = false,
  bool stripBlankChar = false,
  Object? css,
  bool singleQuotedAttributeValue = false,
})
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `whiteList` / `allowList` | `Map<String, List<String>>?` | 74 HTML tags | Tag name → allowed attribute names. Both parameter names accepted. |
| `onTag` | `OnTagHandler?` | no-op | Called for every tag. Return string to replace, `null` for default. |
| `onIgnoreTag` | `OnIgnoreTagHandler?` | no-op | Called for non-whitelisted tags. Return string to replace, `null` to escape. |
| `onTagAttr` | `OnTagAttrHandler?` | no-op | Called for every attribute on whitelisted tags. |
| `onIgnoreTagAttr` | `OnIgnoreTagAttrHandler?` | no-op | Called for non-whitelisted attributes. |
| `safeAttrValue` | `SafeAttrValueHandler?` | built-in | Custom attribute value sanitizer. |
| `escapeHtml` | `EscapeHtmlHandler?` | built-in | Custom HTML escape function. |
| `stripIgnoreTag` | `bool` | `false` | Strip (remove) all non-whitelisted tags instead of escaping. |
| `stripIgnoreTagBody` | `Object?` | `null` | `true` to strip all non-whitelisted tag bodies, or `List<String>` of specific tag names. |
| `allowCommentTag` | `bool` | `false` | Preserve HTML comments. Default: strip them. |
| `stripBlankChar` | `bool` | `false` | Remove invisible/control characters. |
| `css` | `Object?` | enabled | `false` to disable CSS filtering, or `Map` with `'whiteList'` key for custom CSS settings. |
| `singleQuotedAttributeValue` | `bool` | `false` | Use `'` instead of `"` to wrap attribute values in output. |

### process

```dart
String process(String html)
```

Sanitize the input HTML string and return the result.

```dart
final sanitizer = Disinfectant();
final clean = sanitizer.process('<div onclick="alert(1)">Hello</div>');
// '<div>Hello</div>'
```

---

## Callback Types

All callbacks return `String?`. Return a string to use as the replacement; return `null` to use default processing.

### OnTagHandler

```dart
typedef OnTagHandler = String? Function(String tag, String html, TagInfo info)
```

Called for every tag (whitelisted and non-whitelisted):

```dart
final clean = disinfect(html, onTag: (tag, html, info) {
  if (tag == 'marquee') return ''; // strip entirely
  return null; // default processing
});
```

### OnIgnoreTagHandler

```dart
typedef OnIgnoreTagHandler = String? Function(String tag, String html, TagInfo info)
```

Called for non-whitelisted tags only:

```dart
final clean = disinfect(html, onIgnoreTag: (tag, html, info) {
  if (tag == 'iframe') return ''; // strip iframes
  return null; // escape other non-whitelisted tags
});
```

### OnTagAttrHandler

```dart
typedef OnTagAttrHandler = String? Function(
    String tag, String name, String value, bool isWhiteAttr)
```

Called for every attribute on whitelisted tags:

```dart
final clean = disinfect(html, onTagAttr: (tag, name, value, isWhiteAttr) {
  if (tag == 'div' && name == 'class') {
    return 'class="safe-class"'; // override value
  }
  return null; // default processing
});
```

### OnIgnoreTagAttrHandler

```dart
typedef OnIgnoreTagAttrHandler = String? Function(
    String tag, String name, String value, bool isWhiteAttr)
```

Called for non-whitelisted attributes. Return a string to keep the attribute:

```dart
final clean = disinfect(html, onIgnoreTagAttr: (tag, name, value, isWhiteAttr) {
  if (name == 'class') return 'class="$value"'; // allow class everywhere
  return null; // omit
});
```

### SafeAttrValueHandler

```dart
typedef SafeAttrValueHandler = String Function(
    String tag, String name, String value, CssFilter? cssFilter)
```

Custom attribute value sanitizer. Unlike other callbacks, this returns `String` (not nullable) — it must always produce a value:

```dart
final clean = disinfect(html, safeAttrValue: (tag, name, value, cssFilter) {
  if (name == 'href' && value.startsWith('custom://')) {
    return value; // allow custom protocol
  }
  return safeAttrValue(tag, name, value, cssFilter); // fall through to default
});
```

### EscapeHtmlHandler

```dart
typedef EscapeHtmlHandler = String Function(String html)
```

Custom HTML escape function:

```dart
final clean = disinfect(html, escapeHtml: (html) {
  return html.replaceAll('<', '[').replaceAll('>', ']');
});
```

---

## TagInfo

Information passed to tag callbacks.

```dart
class TagInfo {
  const TagInfo({
    required int sourcePosition,
    required int position,
    required bool isClosing,
    required bool isWhite,
  })
}
```

| Field | Type | Description |
|-------|------|-------------|
| `sourcePosition` | `int` | Character offset of this tag in the original HTML string |
| `position` | `int` | Zero-based index of this tag among all tags parsed so far |
| `isClosing` | `bool` | Whether this is a closing tag (`</tag>`) |
| `isWhite` | `bool` | Whether this tag is in the whitelist |

---

## Default Whitelist

`getDefaultWhiteList()` returns a new mutable `Map<String, List<String>>` with 74 HTML tags.

### Tags and Allowed Attributes

| Tag | Allowed Attributes |
|-----|--------------------|
| `a` | `target`, `href`, `title` |
| `abbr` | `title` |
| `address`, `article`, `aside` | *(none)* |
| `audio` | `autoplay`, `controls`, `crossorigin`, `loop`, `muted`, `preload`, `src` |
| `b`, `big`, `i`, `small`, `tt`, `u`, `s`, `strike` | *(none)* |
| `bdi` | `dir` |
| `bdo` | `dir` |
| `blockquote` | `cite` |
| `br`, `hr` | *(none)* |
| `caption`, `center`, `cite`, `code` | *(none)* |
| `col`, `colgroup` | `align`, `valign`, `span`, `width` |
| `dd`, `dl`, `dt` | *(none)* |
| `del`, `ins` | `datetime` |
| `details` | `open` |
| `div`, `span` | *(none)* |
| `em`, `strong`, `mark`, `kbd` | *(none)* |
| `figure`, `figcaption` | *(none)* |
| `font` | `color`, `size`, `face` |
| `footer`, `header`, `nav`, `section` | *(none)* |
| `h1`–`h6` | *(none)* |
| `img` | `src`, `alt`, `title`, `width`, `height`, `loading` |
| `li`, `ol`, `ul` | *(none)* |
| `p`, `pre` | *(none)* |
| `sub`, `sup` | *(none)* |
| `summary` | *(none)* |
| `table` | `width`, `border`, `align`, `valign` |
| `tbody`, `thead`, `tfoot` | `align`, `valign` |
| `td`, `th` | `width`, `rowspan`, `colspan`, `align`, `valign` |
| `tr` | `rowspan`, `align`, `valign` |
| `video` | `autoplay`, `controls`, `crossorigin`, `loop`, `muted`, `playsinline`, `poster`, `preload`, `src`, `height`, `width` |

### Custom Whitelist

```dart
final clean = disinfect(html, whiteList: {
  'p': [],
  'a': ['href', 'title'],
  'img': ['src', 'alt'],
});
```

Only the tags you specify are allowed. Start from the default and modify:

```dart
final wl = getDefaultWhiteList();
wl['iframe'] = ['src', 'width', 'height']; // add iframe support
wl.remove('font'); // disallow font tag
final sanitizer = Disinfectant(whiteList: wl);
```

---

## Tag Stripping

### stripIgnoreTag — Remove Non-Whitelisted Tags

```dart
final clean = disinfect('<em>ok</em><script>bad</script>', stripIgnoreTag: true);
// '<em>ok</em>bad'
```

The tag markup is removed but the text content remains. Cannot be used with `onIgnoreTag`.

### stripIgnoreTagBody — Remove Tags and Their Content

Strip all non-whitelisted tag bodies:

```dart
final clean = disinfect('<em>ok</em><script>bad</script>', stripIgnoreTagBody: true);
// '<em>ok</em>'
```

Strip specific tag bodies only:

```dart
final clean = disinfect(
  '<script>bad</script><style>.x{}</style><noframes>old</noframes>',
  stripIgnoreTagBody: ['script', 'style'],
);
// '&lt;noframes&gt;old&lt;/noframes&gt;'
```

---

## Comment Handling

Comments are stripped by default:

```dart
disinfect('<!-- secret --><p>visible</p>');
// '<p>visible</p>'
```

Preserve comments:

```dart
disinfect('<!-- kept --><p>text</p>', allowCommentTag: true);
// '<!-- kept --><p>text</p>'
```

---

## CSS Filtering

Inline `style` attribute values are filtered by default using `CssFilter`.

### Default Behavior

```dart
disinfect('<div style="color: red; position: fixed">text</div>');
// '<div style="color:red;">text</div>'
// 'position' is not in the default CSS whitelist
```

### Disable CSS Filtering

```dart
disinfect(html, css: false);
```

### Custom CSS Whitelist

```dart
disinfect(html, css: {
  'whiteList': {
    'color': true,
    'font-size': true,
    'position': true, // allow position (disallowed by default)
  },
});
```

---

## CssFilter

Standalone CSS property filter. Used internally for `style` attributes, but available for direct use.

### Constructor

```dart
CssFilter({
  Map<String, Object>? whiteList,
  CssOnAttrHandler? onAttr,
  CssOnAttrHandler? onIgnoreAttr,
  CssSafeAttrValueHandler? safeAttrValue,
})
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `whiteList` | `Map<String, Object>?` | ~250 CSS properties | Property name → `true`/`false`/`Function`/`RegExp` |
| `onAttr` | `CssOnAttrHandler?` | no-op | Called for whitelisted properties |
| `onIgnoreAttr` | `CssOnAttrHandler?` | no-op | Called for non-whitelisted properties |
| `safeAttrValue` | `CssSafeAttrValueHandler?` | rejects `javascript:` | Custom value sanitizer |

### process

```dart
String process(String css)
```

Filter an inline CSS string:

```dart
final filter = CssFilter();
final clean = filter.process('color: red; position: fixed; font-size: 16px');
// 'color:red; font-size:16px'
```

### CSS Whitelist Values

The default CSS whitelist (`getDefaultCssWhiteList()`) maps property names to:

| Value | Meaning |
|-------|---------|
| `true` | Unconditionally allowed |
| `false` | Listed but not allowed by default (override via callback) |
| `bool Function(String)` | Custom predicate on the property value |
| `RegExp` | Regex match on the property value |

Allowed by default (`true`): `background*`, `border*`, `box-*`, `break-*`, `clear`, `color`, `display*`, `font*`, `height`, `letter-spacing`, `lighting-color`, `line-height`, `list-style*`, `margin*`, `max-height`, `max-width`, `min-height`, `min-width`, `padding*`, `text-*`, `width`, `word-*`.

Not allowed by default (`false`): `animation*`, `flex*`, `grid*`, `position`, `overflow*`, `transform*`, `transition*`, `opacity`, `z-index`, `float`, `cursor`, `outline*`, and others.

### CssAttrInfo

```dart
class CssAttrInfo {
  const CssAttrInfo({
    required int position,
    required int sourcePosition,
    required String source,
    required bool isWhite,
  })
}
```

| Field | Type | Description |
|-------|------|-------------|
| `position` | `int` | Zero-based property index |
| `sourcePosition` | `int` | Character offset in original CSS |
| `source` | `String` | Raw `name:value` text |
| `isWhite` | `bool` | Whether property is whitelisted |

### CSS Callback Types

```dart
typedef CssOnAttrHandler = String? Function(String name, String value, CssAttrInfo info)
typedef CssSafeAttrValueHandler = String Function(String name, String value)
```

---

## Escape and Utility Functions

### escapeHtml

```dart
String escapeHtml(String html)
```

Replace `<` with `&lt;` and `>` with `&gt;`:

```dart
escapeHtml('<script>'); // '&lt;script&gt;'
```

### escapeQuote / unescapeQuote

```dart
String escapeQuote(String str)   // " → &quot;
String unescapeQuote(String str) // &quot; → "
```

### escapeHtmlEntities

```dart
String escapeHtmlEntities(String str)
```

Decode HTML numeric character references (`&#123;` → `{`, `&#x1a;` → char):

```dart
escapeHtmlEntities('&#60;script&#62;'); // '<script>'
```

### escapeDangerHtml5Entities

```dart
String escapeDangerHtml5Entities(String str)
```

Replace `&colon;` → `:` and `&NewLine;` → space.

### clearNonPrintableCharacter

```dart
String clearNonPrintableCharacter(String str)
```

Replace characters with code < 32 with spaces, then trim.

### friendlyAttrValue

```dart
String friendlyAttrValue(String str)
```

Chain: `unescapeQuote` → `escapeHtmlEntities` → `escapeDangerHtml5Entities` → `clearNonPrintableCharacter`.

### escapeAttrValue

```dart
String escapeAttrValue(String str)
```

Chain: `escapeQuote` → `escapeHtml`.

### safeAttrValue

```dart
String safeAttrValue(String tag, String name, String value, CssFilter? cssFilter)
```

Default attribute value sanitizer. Applies `friendlyAttrValue`, checks protocol whitelist for `href`/`src`, rejects `javascript:` in `background`, filters `style` through CSS filter, then escapes for output.

### stripCommentTag

```dart
String stripCommentTag(String html)
```

Remove `<!-- ... -->` comment tags.

### stripBlankChar

```dart
String stripBlankChar(String html)
```

Remove invisible/control characters (code ≤ 31 except `\n`/`\r`, and code 127).

---

## Parser Functions

### parseTag

```dart
String parseTag(
  String html,
  String Function(int sourcePosition, int position, String tag, String html, bool isClosing) onTag,
  String Function(String html) escapeHtml,
)
```

Parse HTML and invoke `onTag` for each tag found. Text between tags is escaped via `escapeHtml`. Returns the reconstructed HTML.

### parseAttr

```dart
String parseAttr(
  String html,
  String? Function(String name, String value) onAttr,
)
```

Parse HTML attribute string and invoke `onAttr` for each attribute. Returns the reconstructed attributes string. Return `null` from `onAttr` to omit the attribute.

---

## Protocol Whitelist

The default `safeAttrValue` allows these protocols for `href` and `src` attributes:

| Protocol | Example |
|----------|---------|
| `http://` | `http://example.com` |
| `https://` | `https://example.com` |
| `mailto:` | `mailto:user@example.com` |
| `tel:` | `tel:+1234567890` |
| `data:image/` | `data:image/png;base64,...` |
| `ftp://` | `ftp://files.example.com` |
| `./` or `../` | Relative paths |
| `#` | Fragment identifiers |
| `/` | Absolute paths |

Anything else (including `javascript:`, `vbscript:`, `data:text/html`) returns an empty string.

---

## Complete Example

```dart
import 'package:disinfect/disinfect.dart';

void main() {
  // -- Basic XSS prevention --
  print(disinfect('<script>alert("xss")</script>'));
  // '&lt;script&gt;alert("xss")&lt;/script&gt;'

  print(disinfect('<img src=x onerror=alert(1)>'));
  // '<img src>'

  print(disinfect('<a href="javascript:alert(1)">click</a>'));
  // '<a href>click</a>'

  // -- Strip dangerous tags entirely --
  final sanitizer = Disinfectant(
    stripIgnoreTagBody: ['script', 'style', 'iframe'],
  );
  print(sanitizer.process(
    '<p>Hello</p><script>evil()</script><style>.x{}</style><p>World</p>',
  ));
  // '<p>Hello</p><p>World</p>'

  // -- Custom whitelist --
  final minimal = Disinfectant(whiteList: {
    'p': [],
    'b': [],
    'i': [],
    'a': ['href'],
  });
  print(minimal.process(
    '<p><b>Bold</b> and <div>blocked</div></p>',
  ));
  // '<p><b>Bold</b> and &lt;div&gt;blocked&lt;/div&gt;</p>'

  // -- Allow a non-default attribute via callback --
  final withClass = disinfect(
    '<div class="container" onclick="evil()">text</div>',
    onIgnoreTagAttr: (tag, name, value, isWhiteAttr) {
      if (name == 'class') return 'class="${escapeAttrValue(value)}"';
      return null;
    },
  );
  print(withClass);
  // '<div class="container">text</div>'

  // -- CSS filtering --
  print(disinfect(
    '<p style="color: red; position: fixed; font-size: 14px">styled</p>',
  ));
  // '<p style="color:red; font-size:14px;">styled</p>'

  // -- Standalone CSS filter --
  final cssFilter = CssFilter();
  print(cssFilter.process('color: red; opacity: 0.5; margin: 10px'));
  // 'color:red; margin:10px'
}
```

---

## Framework Integration

Disinfect is part of an interconnected framework. For how it works with Swoop (as HTML sanitization middleware) and the rest of the stack, see `docs/integration-guide.md` in the workspace root.
