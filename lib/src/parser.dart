/// Simple HTML parser.
///
/// Ported from js-xss/lib/parser.js.
library;

/// Find the index of the first whitespace character in [str].
/// Returns -1 if no whitespace is found.
int _spaceIndex(String str) {
  final reg = RegExp(r'\s');
  final match = reg.firstMatch(str);
  return match?.start ?? -1;
}

/// Extract the tag name from an HTML tag string like `<a href="#">`.
String _getTagName(String html) {
  var i = _spaceIndex(html);
  String tagName;
  if (i == -1) {
    tagName = html.substring(1, html.length - 1);
  } else {
    tagName = html.substring(1, i + 1);
  }
  tagName = tagName.trim().toLowerCase();
  if (tagName.startsWith('/')) tagName = tagName.substring(1);
  if (tagName.endsWith('/')) tagName = tagName.substring(0, tagName.length - 1);
  return tagName;
}

/// Check whether the HTML tag string is a closing tag.
bool _isClosing(String html) {
  return html.length >= 2 && html.substring(0, 2) == '</';
}

/// Parse HTML and invoke [onTag] for each tag found.
///
/// [onTag] receives `(sourcePosition, position, tag, html, isClosing)` and
/// returns the replacement string for that tag.
///
/// Text between tags is escaped via [escapeHtml].
String parseTag(
  String html,
  String Function(
          int sourcePosition, int position, String tag, String html, bool isClosing)
      onTag,
  String Function(String html) escapeHtml,
) {
  var rethtml = '';
  var lastPos = 0;
  int? tagStart;
  String? quoteStart;
  var currentPos = 0;
  final len = html.length;

  for (currentPos = 0; currentPos < len; currentPos++) {
    final c = html[currentPos];
    if (tagStart == null) {
      if (c == '<') {
        tagStart = currentPos;
        continue;
      }
    } else {
      if (quoteStart == null) {
        if (c == '<') {
          rethtml += escapeHtml(html.substring(lastPos, currentPos));
          tagStart = currentPos;
          lastPos = currentPos;
          continue;
        }
        if (c == '>' || currentPos == len - 1) {
          rethtml += escapeHtml(html.substring(lastPos, tagStart));
          final currentHtml = html.substring(tagStart, currentPos + 1);
          final currentTagName = _getTagName(currentHtml);
          rethtml += onTag(
            tagStart,
            rethtml.length,
            currentTagName,
            currentHtml,
            _isClosing(currentHtml),
          );
          lastPos = currentPos + 1;
          tagStart = null;
          continue;
        }
        if (c == '"' || c == "'") {
          var i = 1;
          var ic = currentPos - i >= 0 ? html[currentPos - i] : '';

          while (ic.trim().isEmpty || ic == '=') {
            if (ic == '=') {
              quoteStart = c;
              break;
            }
            i++;
            ic = currentPos - i >= 0 ? html[currentPos - i] : '';
          }
        }
      } else {
        if (c == quoteStart) {
          quoteStart = null;
          continue;
        }
      }
    }
  }
  if (lastPos < len) {
    rethtml += escapeHtml(html.substring(lastPos));
  }

  return rethtml;
}

final _regexpIllegalAttrName = RegExp(r'[^a-zA-Z0-9\\_:.\-]', caseSensitive: false);

/// Find the next `=` after position [i], skipping spaces.
/// Returns -1 if a non-space, non-`=` character is found first.
int _findNextEqual(String str, int i) {
  for (; i < str.length; i++) {
    final c = str[i];
    if (c == ' ') continue;
    if (c == '=') return i;
    return -1;
  }
  return -1;
}

/// Find the next quotation mark (`'` or `"`) after position [i], skipping spaces.
/// Returns -1 if a non-space, non-quote character is found first.
int _findNextQuotationMark(String str, int i) {
  for (; i < str.length; i++) {
    final c = str[i];
    if (c == ' ') continue;
    if (c == "'" || c == '"') return i;
    return -1;
  }
  return -1;
}

/// Scan backwards from position [i] looking for `=`, skipping spaces.
/// Returns -1 if a non-space, non-`=` character is found first.
int _findBeforeEqual(String str, int i) {
  for (; i > 0; i--) {
    final c = str[i];
    if (c == ' ') continue;
    if (c == '=') return i;
    return -1;
  }
  return -1;
}

/// Check if [text] is wrapped in matching quotes.
bool _isQuoteWrapString(String text) {
  if (text.isEmpty) return false;
  return (text[0] == '"' && text[text.length - 1] == '"') ||
      (text[0] == "'" && text[text.length - 1] == "'");
}

/// Remove wrapping quotes from [text] if present.
String _stripQuoteWrap(String text) {
  if (_isQuoteWrapString(text)) {
    return text.substring(1, text.length - 1);
  }
  return text;
}

/// Parse HTML attributes string and invoke [onAttr] for each attribute found.
///
/// [onAttr] receives `(name, value)` and returns the replacement string for
/// that attribute, or `null` to omit it.
String parseAttr(String html, String? Function(String name, String value) onAttr) {
  var lastPos = 0;
  var lastMarkPos = 0;
  final retAttrs = <String>[];
  String? tmpName;
  var len = html.length;

  void addAttr(String name, [String? value]) {
    name = name.trim();
    name = name.replaceAll(_regexpIllegalAttrName, '').toLowerCase();
    if (name.isEmpty) return;
    final ret = onAttr(name, value ?? '');
    if (ret != null) retAttrs.add(ret);
  }

  for (var i = 0; i < len; i++) {
    var c = html[i];
    if (tmpName == null && c == '=') {
      tmpName = html.substring(lastPos, i);
      lastPos = i + 1;
      if (lastPos < html.length &&
          (html[lastPos] == '"' || html[lastPos] == "'")) {
        lastMarkPos = lastPos;
      } else {
        lastMarkPos = _findNextQuotationMark(html, i + 1);
      }
      continue;
    }
    if (tmpName != null) {
      if (i == lastMarkPos && lastMarkPos != -1) {
        final j = html.indexOf(c, i + 1);
        if (j == -1) {
          break;
        } else {
          final v = html.substring(lastMarkPos + 1, j).trim();
          addAttr(tmpName, v);
          tmpName = null;
          i = j;
          lastPos = i + 1;
          continue;
        }
      }
    }
    if (RegExp(r'\s|\n|\t').hasMatch(c)) {
      html = html.replaceAll(RegExp(r'\s|\n|\t'), ' ');
      if (tmpName == null) {
        final j = _findNextEqual(html, i);
        if (j == -1) {
          final v = html.substring(lastPos, i).trim();
          addAttr(v);
          tmpName = null;
          lastPos = i + 1;
          continue;
        } else {
          i = j - 1;
          continue;
        }
      } else {
        final j = _findBeforeEqual(html, i - 1);
        if (j == -1) {
          var v = html.substring(lastPos, i).trim();
          v = _stripQuoteWrap(v);
          addAttr(tmpName, v);
          tmpName = null;
          lastPos = i + 1;
          continue;
        } else {
          continue;
        }
      }
    }
  }

  if (lastPos < html.length) {
    if (tmpName == null) {
      addAttr(html.substring(lastPos));
    } else {
      addAttr(tmpName, _stripQuoteWrap(html.substring(lastPos).trim()));
    }
  }

  return retAttrs.join(' ').trim();
}
