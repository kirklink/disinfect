/// Default settings for XSS filtering.
///
/// Ported from js-xss/lib/default.js.
library;

import 'css_filter.dart';

// ---------------------------------------------------------------------------
// Regex patterns
// ---------------------------------------------------------------------------

final _regexpLt = RegExp(r'<');
final _regexpGt = RegExp(r'>');
final _regexpQuote = RegExp(r'"');
final _regexpQuote2 = RegExp(r'&quot;');
final _regexpAttrValue1 = RegExp(r'&#([a-zA-Z0-9]*);?', caseSensitive: false);
final _regexpAttrValueColon = RegExp(r'&colon;?', caseSensitive: false);
final _regexpAttrValueNewline = RegExp(r'&newline;?', caseSensitive: false);
final _regexpJavascriptLike = RegExp(
  r'((j\s*a\s*v\s*a|v\s*b|l\s*i\s*v\s*e)\s*s\s*c\s*r\s*i\s*p\s*t\s*|m\s*o\s*c\s*h\s*a):',
  caseSensitive: false,
);
final _regexpExpression = RegExp(
  r'e\s*x\s*p\s*r\s*e\s*s\s*s\s*i\s*o\s*n\s*\(.*',
  caseSensitive: false,
);
final _regexpUrl = RegExp(
  r'u\s*r\s*l\s*\(.*',
  caseSensitive: false,
);

// ---------------------------------------------------------------------------
// Escape / unescape helpers
// ---------------------------------------------------------------------------

/// Default HTML escape: replaces `<` and `>` with entities.
String escapeHtml(String html) {
  return html.replaceAll(_regexpLt, '&lt;').replaceAll(_regexpGt, '&gt;');
}

/// Escape double quotes to `&quot;`.
String escapeQuote(String str) {
  return str.replaceAll(_regexpQuote, '&quot;');
}

/// Unescape `&quot;` back to `"`.
String unescapeQuote(String str) {
  return str.replaceAll(_regexpQuote2, '"');
}

/// Decode HTML numeric character references (`&#123;`, `&#x1a;`).
String escapeHtmlEntities(String str) {
  return str.replaceAllMapped(_regexpAttrValue1, (m) {
    final code = m.group(1)!;
    if (code.startsWith('x') || code.startsWith('X')) {
      final n = int.tryParse(code.substring(1), radix: 16);
      return n != null ? String.fromCharCode(n) : m.group(0)!;
    }
    final n = int.tryParse(code, radix: 10);
    return n != null ? String.fromCharCode(n) : m.group(0)!;
  });
}

/// Replace HTML5 danger entities `&colon;` → `:` and `&NewLine;` → ` `.
String escapeDangerHtml5Entities(String str) {
  return str
      .replaceAll(_regexpAttrValueColon, ':')
      .replaceAll(_regexpAttrValueNewline, ' ');
}

/// Replace non-printable characters (code < 32) with spaces, then trim.
String clearNonPrintableCharacter(String str) {
  final buf = StringBuffer();
  for (var i = 0; i < str.length; i++) {
    buf.write(str.codeUnitAt(i) < 32 ? ' ' : str[i]);
  }
  return buf.toString().trim();
}

/// Unescape quotes, decode entities, replace danger entities, clear
/// non-printable characters.
String friendlyAttrValue(String str) {
  str = unescapeQuote(str);
  str = escapeHtmlEntities(str);
  str = escapeDangerHtml5Entities(str);
  str = clearNonPrintableCharacter(str);
  return str;
}

/// Escape an attribute value for safe output (quotes + angle brackets).
String escapeAttrValue(String str) {
  str = escapeQuote(str);
  str = escapeHtml(str);
  return str;
}

// ---------------------------------------------------------------------------
// Safe attribute value
// ---------------------------------------------------------------------------

/// Default safe-attribute-value checker.
///
/// Sanitizes `href`/`src` (protocol whitelist), `background` (javascript:),
/// and `style` (expression(), url(javascript:)). Applies [cssFilter] to
/// style values when not null.
String safeAttrValue(
    String tag, String name, String value, CssFilter? cssFilter) {
  // Unescape attribute value first.
  value = friendlyAttrValue(value);

  if (name == 'href' || name == 'src') {
    value = value.trim();
    if (value == '#') return '#';
    if (!(value.startsWith('http://') ||
        value.startsWith('https://') ||
        value.startsWith('mailto:') ||
        value.startsWith('tel:') ||
        value.startsWith('data:image/') ||
        value.startsWith('ftp://') ||
        value.startsWith('./') ||
        value.startsWith('../') ||
        (value.isNotEmpty && value[0] == '#') ||
        (value.isNotEmpty && value[0] == '/'))) {
      return '';
    }
  } else if (name == 'background') {
    if (_regexpJavascriptLike.hasMatch(value)) {
      return '';
    }
  } else if (name == 'style') {
    if (_regexpExpression.hasMatch(value)) {
      return '';
    }
    if (_regexpUrl.hasMatch(value)) {
      if (_regexpJavascriptLike.hasMatch(value)) {
        return '';
      }
    }
    if (cssFilter != null) {
      value = cssFilter.process(value);
    }
  }

  // Escape `<>"` before returning.
  value = escapeAttrValue(value);
  return value;
}

// ---------------------------------------------------------------------------
// Strip helpers
// ---------------------------------------------------------------------------

/// `onIgnoreTag` handler that strips all ignored tags (returns empty string).
String onIgnoreTagStripAll(String tag, String html, dynamic info) {
  return '';
}

/// Holds state for stripping tag bodies from the output.
///
/// When [tags] is `true`, all non-whitelisted tag bodies are removed.
/// When [tags] is a `List<String>`, only those tag bodies are removed.
/// Tags not in the list are forwarded to [next].
class StripTagBody {
  final bool _isRemoveAll;
  final List<String> _tags;
  final String? Function(String tag, String html, dynamic info) _next;
  final List<List<int>> _removeList = [];
  int? _posStart;

  /// Creates a strip-tag-body handler for the given [tags] list and fallback [next] callback.
  StripTagBody(Object tags,
      String? Function(String tag, String html, dynamic info) next)
      : _isRemoveAll = tags is! List,
        _tags = tags is List<String> ? tags : const [],
        _next = next;

  bool _isRemoveTag(String tag) {
    if (_isRemoveAll) return true;
    return _tags.contains(tag);
  }

  /// The `onIgnoreTag` callback to use during parsing.
  String? onIgnoreTag(String tag, String html, dynamic info) {
    if (_isRemoveTag(tag)) {
      if (info.isClosing) {
        final ret = '[/removed]';
        final end = info.position + ret.length;
        _removeList.add([_posStart ?? info.position, end]);
        _posStart = null;
        return ret;
      } else {
        _posStart ??= info.position;
        return '[removed]';
      }
    } else {
      return _next(tag, html, info);
    }
  }

  /// Remove marked regions from the final HTML.
  String remove(String html) {
    final buf = StringBuffer();
    var lastPos = 0;
    for (final pos in _removeList) {
      buf.write(html.substring(lastPos, pos[0]));
      lastPos = pos[1];
    }
    buf.write(html.substring(lastPos));
    return buf.toString();
  }
}

/// Remove HTML comment tags `<!-- ... -->`.
String stripCommentTag(String html) {
  final buf = StringBuffer();
  var lastPos = 0;
  while (lastPos < html.length) {
    final i = html.indexOf('<!--', lastPos);
    if (i == -1) {
      buf.write(html.substring(lastPos));
      break;
    }
    buf.write(html.substring(lastPos, i));
    final j = html.indexOf('-->', i);
    if (j == -1) {
      break;
    }
    lastPos = j + 3;
  }
  return buf.toString();
}

/// Remove invisible/control characters (code ≤ 31 except `\n` and `\r`,
/// and code 127).
String stripBlankChar(String html) {
  final buf = StringBuffer();
  for (var i = 0; i < html.length; i++) {
    final c = html.codeUnitAt(i);
    if (c == 127) continue;
    if (c <= 31) {
      if (c == 10 || c == 13) {
        buf.write(html[i]);
      }
      continue;
    }
    buf.write(html[i]);
  }
  return buf.toString();
}
