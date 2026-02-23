/// HTML sanitizer.
///
/// Ported from js-xss/lib/xss.js and js-xss/lib/index.js.

import 'css_filter.dart';
import 'defaults.dart' as defaults;
import 'parser.dart' as parser;
import 'whitelist.dart' as wl;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Information passed to tag callback handlers.
class TagInfo {
  final int sourcePosition;
  final int position;
  final bool isClosing;
  final bool isWhite;

  const TagInfo({
    required this.sourcePosition,
    required this.position,
    required this.isClosing,
    required this.isWhite,
  });
}

/// Called for every tag. Return a string to replace the tag HTML,
/// or `null` to use default processing.
typedef OnTagHandler = String? Function(String tag, String html, TagInfo info);

/// Called for non-whitelisted tags. Return a string to replace the tag HTML,
/// or `null` to use default processing (escape).
typedef OnIgnoreTagHandler = String? Function(
    String tag, String html, TagInfo info);

/// Called for every attribute on a whitelisted tag. Return a string to use
/// as the attribute output, or `null` for default processing.
typedef OnTagAttrHandler = String? Function(
    String tag, String name, String value, bool isWhiteAttr);

/// Called for non-whitelisted attributes. Return a string to use as the
/// attribute output, or `null` to omit.
typedef OnIgnoreTagAttrHandler = String? Function(
    String tag, String name, String value, bool isWhiteAttr);

/// Returns a sanitized attribute value.
typedef SafeAttrValueHandler = String Function(
    String tag, String name, String value, CssFilter? cssFilter);

/// Escapes HTML for output.
typedef EscapeHtmlHandler = String Function(String html);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

int _spaceIndex(String str) {
  final match = RegExp(r'\s').firstMatch(str);
  return match?.start ?? -1;
}

/// Extract the attribute portion of a tag for parsing.
({String html, bool closing}) _getAttrs(String html) {
  final i = _spaceIndex(html);
  if (i == -1) {
    return (html: '', closing: html.length >= 2 && html[html.length - 2] == '/');
  }
  html = html.substring(i + 1, html.length - 1).trim();
  final isClosing = html.isNotEmpty && html[html.length - 1] == '/';
  if (isClosing) html = html.substring(0, html.length - 1).trim();
  return (html: html, closing: isClosing);
}

Map<String, List<String>> _keysToLowerCase(Map<String, List<String>> obj) {
  final ret = <String, List<String>>{};
  for (final entry in obj.entries) {
    ret[entry.key.toLowerCase()] =
        entry.value.map((item) => item.toLowerCase()).toList();
  }
  return ret;
}

// ---------------------------------------------------------------------------
// FilterXss
// ---------------------------------------------------------------------------

/// Whitelist-based HTML sanitizer.
class Disinfectant {
  late final Map<String, List<String>> _whiteList;
  late final OnTagHandler _onTag;
  late final OnIgnoreTagHandler _onIgnoreTag;
  late final OnTagAttrHandler _onTagAttr;
  late final OnIgnoreTagAttrHandler _onIgnoreTagAttr;
  late final SafeAttrValueHandler _safeAttrValue;
  late final EscapeHtmlHandler _escapeHtml;
  late final String _attributeWrapSign;
  late final CssFilter? _cssFilter;
  late final bool _stripBlankChar;
  late final bool _allowCommentTag;
  late final Object? _stripIgnoreTagBody;

  /// Create a new sanitizer with the given options.
  ///
  /// - [whiteList] / [allowList]: tag → allowed-attribute-names map.
  /// - [onTag]: called for every tag (return string to replace, null for default).
  /// - [onIgnoreTag]: called for non-whitelisted tags.
  /// - [onTagAttr]: called for every attribute on whitelisted tags.
  /// - [onIgnoreTagAttr]: called for non-whitelisted attributes.
  /// - [safeAttrValue]: sanitize attribute values.
  /// - [escapeHtml]: custom HTML escape function.
  /// - [stripIgnoreTag]: strip all non-whitelisted tags (conflicts with [onIgnoreTag]).
  /// - [stripIgnoreTagBody]: `true` to strip all non-whitelisted tag bodies,
  ///   or a `List<String>` of specific tag names to strip.
  /// - [allowCommentTag]: preserve HTML comments (default: strip them).
  /// - [stripBlankChar]: remove invisible control characters.
  /// - [css]: `false` to disable CSS filtering, or a `Map` with a `'whiteList'`
  ///   key for custom CSS filter settings. Default: use built-in CSS filter.
  /// - [singleQuotedAttributeValue]: use `'` instead of `"` to wrap attribute values.
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
  }) {
    if (stripIgnoreTag && onIgnoreTag != null) {
      // ignore: avoid_print
      print(
          'Notes: cannot use these two options "stripIgnoreTag" and "onIgnoreTag" at the same time');
    }

    final effectiveOnIgnoreTag =
        stripIgnoreTag ? _stripAllIgnoreTag : onIgnoreTag;

    if (whiteList != null || allowList != null) {
      _whiteList = _keysToLowerCase(whiteList ?? allowList!);
    } else {
      _whiteList = wl.getDefaultWhiteList();
    }

    _attributeWrapSign = singleQuotedAttributeValue ? "'" : '"';
    _onTag = onTag ?? _defaultOnTag;
    _onTagAttr = onTagAttr ?? _defaultOnTagAttr;
    _onIgnoreTag = effectiveOnIgnoreTag ?? _defaultOnIgnoreTag;
    _onIgnoreTagAttr = onIgnoreTagAttr ?? _defaultOnIgnoreTagAttr;
    _safeAttrValue = safeAttrValue ?? defaults.safeAttrValue;
    _escapeHtml = escapeHtml ?? defaults.escapeHtml;
    _stripBlankChar = stripBlankChar;
    _allowCommentTag = allowCommentTag;
    _stripIgnoreTagBody = stripIgnoreTagBody;

    if (css == false) {
      _cssFilter = null;
    } else if (css is Map) {
      final cssWhiteList = css['whiteList'];
      _cssFilter = CssFilter(
        whiteList: cssWhiteList is Map<String, Object>
            ? cssWhiteList
            : null,
      );
    } else {
      _cssFilter = CssFilter();
    }
  }

  /// Process [html] and return the sanitized result.
  String process(String html) {
    if (html.isEmpty) return '';

    // Remove invisible characters.
    if (_stripBlankChar) {
      html = defaults.stripBlankChar(html);
    }

    // Remove HTML comments.
    if (!_allowCommentTag) {
      html = defaults.stripCommentTag(html);
    }

    // Set up stripIgnoreTagBody if enabled.
    defaults.StripTagBody? stripBody;
    OnIgnoreTagHandler onIgnoreTag = _onIgnoreTag;
    final stripIgnoreTagBody = _stripIgnoreTagBody;
    if (stripIgnoreTagBody != null && stripIgnoreTagBody != false) {
      // Capture the original before replacing to avoid recursive closure.
      final originalOnIgnoreTag = onIgnoreTag;
      stripBody = defaults.StripTagBody(
        stripIgnoreTagBody,
        (tag, html, info) => originalOnIgnoreTag(tag, html, info as TagInfo),
      );
      onIgnoreTag = (tag, html, info) => stripBody!.onIgnoreTag(tag, html, info);
    }

    final whiteList = _whiteList;
    final onTag = _onTag;
    final onTagAttr = _onTagAttr;
    final onIgnoreTagAttr = _onIgnoreTagAttr;
    final safeAttrValue = _safeAttrValue;
    final escapeHtml = _escapeHtml;
    final attributeWrapSign = _attributeWrapSign;
    final cssFilter = _cssFilter;

    var retHtml = parser.parseTag(
      html,
      (sourcePosition, position, tag, tagHtml, isClosing) {
        final info = TagInfo(
          sourcePosition: sourcePosition,
          position: position,
          isClosing: isClosing,
          isWhite: whiteList.containsKey(tag),
        );

        // Call onTag().
        var ret = onTag(tag, tagHtml, info);
        if (ret != null) return ret;

        if (info.isWhite) {
          if (info.isClosing) {
            return '</$tag>';
          }

          final attrs = _getAttrs(tagHtml);
          final whiteAttrList = whiteList[tag]!;
          final attrsHtml =
              parser.parseAttr(attrs.html, (name, value) {
            final isWhiteAttr = whiteAttrList.contains(name);
            final attrRet = onTagAttr(tag, name, value, isWhiteAttr);
            if (attrRet != null) return attrRet;

            if (isWhiteAttr) {
              final safeVal = safeAttrValue(tag, name, value, cssFilter);
              if (safeVal.isNotEmpty) {
                return '$name=$attributeWrapSign$safeVal$attributeWrapSign';
              } else {
                return name;
              }
            } else {
              final ignoreRet =
                  onIgnoreTagAttr(tag, name, value, isWhiteAttr);
              if (ignoreRet != null) return ignoreRet;
              return null;
            }
          });

          // Build new tag HTML.
          var newHtml = '<$tag';
          if (attrsHtml.isNotEmpty) newHtml += ' $attrsHtml';
          if (attrs.closing) newHtml += ' /';
          newHtml += '>';
          return newHtml;
        } else {
          // Call onIgnoreTag().
          ret = onIgnoreTag(tag, tagHtml, info);
          if (ret != null) return ret;
          return escapeHtml(tagHtml);
        }
      },
      escapeHtml,
    );

    // Apply stripIgnoreTagBody removal.
    if (stripBody != null) {
      retHtml = stripBody.remove(retHtml);
    }

    return retHtml;
  }
}

// Default no-op callbacks (return null = use default behavior).
String? _defaultOnTag(String tag, String html, TagInfo info) => null;
String? _defaultOnIgnoreTag(String tag, String html, TagInfo info) => null;
String? _defaultOnTagAttr(
        String tag, String name, String value, bool isWhiteAttr) =>
    null;
String? _defaultOnIgnoreTagAttr(
        String tag, String name, String value, bool isWhiteAttr) =>
    null;

String? _stripAllIgnoreTag(String tag, String html, TagInfo info) => '';

// ---------------------------------------------------------------------------
// Convenience function
// ---------------------------------------------------------------------------

/// Sanitize [html] using a whitelist-based filter.
///
/// Creates a new [Disinfectant] instance with the given options and processes
/// the input. For repeated use with the same options, create a [Disinfectant]
/// instance directly.
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
}) {
  final xss = Disinfectant(
    whiteList: whiteList,
    allowList: allowList,
    onTag: onTag,
    onIgnoreTag: onIgnoreTag,
    onTagAttr: onTagAttr,
    onIgnoreTagAttr: onIgnoreTagAttr,
    safeAttrValue: safeAttrValue,
    escapeHtml: escapeHtml,
    stripIgnoreTag: stripIgnoreTag,
    stripIgnoreTagBody: stripIgnoreTagBody,
    allowCommentTag: allowCommentTag,
    stripBlankChar: stripBlankChar,
    css: css,
    singleQuotedAttributeValue: singleQuotedAttributeValue,
  );
  return xss.process(html);
}
