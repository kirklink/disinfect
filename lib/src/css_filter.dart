/// Dart port of the JS `cssfilter` package (v0.0.10).
///
/// Provides CSS property whitelisting and sanitization for use in XSS
/// filtering. Ported from https://github.com/nicedoc/cssfilter.
library;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Information about a CSS attribute encountered during filtering.
class CssAttrInfo {
  /// Zero-based index of this property among all properties parsed so far.
  final int position;

  /// Character offset of this property in the original CSS string.
  final int sourcePosition;

  /// The raw `name:value` source text of this property.
  final String source;

  /// Whether this property is in the whitelist.
  final bool isWhite;

  /// Creates a CSS attribute info record.
  const CssAttrInfo({
    required this.position,
    required this.sourcePosition,
    required this.source,
    required this.isWhite,
  });
}

/// Callback invoked for each CSS property during filtering.
///
/// Return a replacement `name:value` string to include in output, or `null`
/// to use the default behaviour (include whitelisted attrs, drop others).
typedef CssOnAttrHandler = String? Function(
  String name,
  String value,
  CssAttrInfo info,
);

/// Callback that sanitises a CSS property value.
typedef CssSafeAttrValueHandler = String Function(String name, String value);

// ---------------------------------------------------------------------------
// Default callbacks
// ---------------------------------------------------------------------------

String? _defaultOnAttr(String name, String value, CssAttrInfo info) => null;

String? _defaultOnIgnoreAttr(String name, String value, CssAttrInfo info) =>
    null;

final RegExp _jsUrlPattern = RegExp(r'javascript\s*:', caseSensitive: false);

String _defaultSafeAttrValue(String name, String value) {
  if (_jsUrlPattern.hasMatch(value)) return '';
  return value;
}

// ---------------------------------------------------------------------------
// CSS whitelist (~250 properties)
// ---------------------------------------------------------------------------

/// Returns a **new** mutable map of default CSS property whitelist entries.
///
/// Each key is a CSS property name. A value of `true` means the property is
/// unconditionally allowed; `false` means it is listed but not allowed by
/// default (consumers can override via callbacks).
Map<String, Object> getDefaultCssWhiteList() {
  return {
    'align-content': false,
    'align-items': false,
    'align-self': false,
    'alignment-adjust': false,
    'alignment-baseline': false,
    'all': false,
    'anchor-point': false,
    'animation': false,
    'animation-delay': false,
    'animation-direction': false,
    'animation-duration': false,
    'animation-fill-mode': false,
    'animation-iteration-count': false,
    'animation-name': false,
    'animation-play-state': false,
    'animation-timing-function': false,
    'azimuth': false,
    'backface-visibility': false,
    'background': true,
    'background-attachment': true,
    'background-clip': true,
    'background-color': true,
    'background-image': true,
    'background-origin': true,
    'background-position': true,
    'background-repeat': true,
    'background-size': true,
    'baseline-shift': false,
    'binding': false,
    'bleed': false,
    'bookmark-label': false,
    'bookmark-level': false,
    'bookmark-state': false,
    'border': true,
    'border-bottom': true,
    'border-bottom-color': true,
    'border-bottom-left-radius': true,
    'border-bottom-right-radius': true,
    'border-bottom-style': true,
    'border-bottom-width': true,
    'border-collapse': true,
    'border-color': true,
    'border-image': true,
    'border-image-outset': true,
    'border-image-repeat': true,
    'border-image-slice': true,
    'border-image-source': true,
    'border-image-width': true,
    'border-left': true,
    'border-left-color': true,
    'border-left-style': true,
    'border-left-width': true,
    'border-radius': true,
    'border-right': true,
    'border-right-color': true,
    'border-right-style': true,
    'border-right-width': true,
    'border-spacing': true,
    'border-style': true,
    'border-top': true,
    'border-top-color': true,
    'border-top-left-radius': true,
    'border-top-right-radius': true,
    'border-top-style': true,
    'border-top-width': true,
    'border-width': true,
    'bottom': false,
    'box-decoration-break': true,
    'box-shadow': true,
    'box-sizing': true,
    'box-snap': true,
    'box-suppress': true,
    'break-after': true,
    'break-before': true,
    'break-inside': true,
    'caption-side': false,
    'chains': false,
    'clear': true,
    'clip': false,
    'clip-path': false,
    'clip-rule': false,
    'color': true,
    'color-interpolation-filters': true,
    'column-count': false,
    'column-fill': false,
    'column-gap': false,
    'column-rule': false,
    'column-rule-color': false,
    'column-rule-style': false,
    'column-rule-width': false,
    'column-span': false,
    'column-width': false,
    'columns': false,
    'contain': false,
    'content': false,
    'counter-increment': false,
    'counter-reset': false,
    'counter-set': false,
    'crop': false,
    'cue': false,
    'cue-after': false,
    'cue-before': false,
    'cursor': false,
    'direction': false,
    'display': true,
    'display-inside': true,
    'display-list': true,
    'display-outside': true,
    'dominant-baseline': false,
    'elevation': false,
    'empty-cells': false,
    'filter': false,
    'flex': false,
    'flex-basis': false,
    'flex-direction': false,
    'flex-flow': false,
    'flex-grow': false,
    'flex-shrink': false,
    'flex-wrap': false,
    'float': false,
    'float-offset': false,
    'flood-color': false,
    'flood-opacity': false,
    'flow-from': false,
    'flow-into': false,
    'font': true,
    'font-family': true,
    'font-feature-settings': true,
    'font-kerning': true,
    'font-language-override': true,
    'font-size': true,
    'font-size-adjust': true,
    'font-stretch': true,
    'font-style': true,
    'font-synthesis': true,
    'font-variant': true,
    'font-variant-alternates': true,
    'font-variant-caps': true,
    'font-variant-east-asian': true,
    'font-variant-ligatures': true,
    'font-variant-numeric': true,
    'font-variant-position': true,
    'font-weight': true,
    'grid': false,
    'grid-area': false,
    'grid-auto-columns': false,
    'grid-auto-flow': false,
    'grid-auto-rows': false,
    'grid-column': false,
    'grid-column-end': false,
    'grid-column-gap': false,
    'grid-column-start': false,
    'grid-gap': false,
    'grid-row': false,
    'grid-row-end': false,
    'grid-row-gap': false,
    'grid-row-start': false,
    'grid-template': false,
    'grid-template-areas': false,
    'grid-template-columns': false,
    'grid-template-rows': false,
    'hanging-punctuation': false,
    'height': true,
    'hyphens': false,
    'icon': false,
    'image-orientation': false,
    'image-resolution': false,
    'ime-mode': false,
    'initial-letters': false,
    'inline-size': false,
    'isolation': false,
    'justify-content': false,
    'justify-items': false,
    'justify-self': false,
    'left': false,
    'letter-spacing': true,
    'lighting-color': true,
    'line-break': false,
    'line-grid': false,
    'line-height': true,
    'line-snap': false,
    'line-stacking': false,
    'line-stacking-ruby': false,
    'line-stacking-shift': false,
    'line-stacking-strategy': false,
    'list-style': true,
    'list-style-image': true,
    'list-style-position': true,
    'list-style-type': true,
    'margin': true,
    'margin-bottom': true,
    'margin-left': true,
    'margin-right': true,
    'margin-top': true,
    'marker-offset': false,
    'marker-side': false,
    'marks': false,
    'mask': false,
    'mask-box': false,
    'mask-box-outset': false,
    'mask-box-repeat': false,
    'mask-box-slice': false,
    'mask-box-source': false,
    'mask-box-width': false,
    'mask-clip': false,
    'mask-image': false,
    'mask-origin': false,
    'mask-position': false,
    'mask-repeat': false,
    'mask-size': false,
    'mask-source-type': false,
    'mask-type': false,
    'max-block-size': false,
    'max-height': true,
    'max-inline-size': false,
    'max-lines': false,
    'max-width': true,
    'min-block-size': false,
    'min-height': true,
    'min-inline-size': false,
    'min-width': true,
    'mix-blend-mode': false,
    'nav-down': false,
    'nav-index': false,
    'nav-left': false,
    'nav-right': false,
    'nav-up': false,
    'object-fit': false,
    'object-position': false,
    'offset-block-end': false,
    'offset-block-start': false,
    'offset-inline-end': false,
    'offset-inline-start': false,
    'opacity': false,
    'order': false,
    'orphans': false,
    'outline': false,
    'outline-color': false,
    'outline-offset': false,
    'outline-style': false,
    'outline-width': false,
    'overflow': false,
    'overflow-wrap': false,
    'overflow-x': false,
    'overflow-y': false,
    'padding': true,
    'padding-bottom': true,
    'padding-left': true,
    'padding-right': true,
    'padding-top': true,
    'page-break-after': false,
    'page-break-before': false,
    'page-break-inside': false,
    'pause': false,
    'pause-after': false,
    'pause-before': false,
    'perspective': false,
    'perspective-origin': false,
    'pitch': false,
    'pitch-range': false,
    'play-during': false,
    'position': false,
    'presentation-level': false,
    'quotes': false,
    'region-fragment': false,
    'resize': false,
    'rest': false,
    'rest-after': false,
    'rest-before': false,
    'richness': false,
    'right': false,
    'rotation': false,
    'rotation-point': false,
    'ruby-align': false,
    'ruby-merge': false,
    'ruby-position': false,
    'shape-image-threshold': false,
    'shape-margin': false,
    'shape-outside': false,
    'size': false,
    'speak': false,
    'speak-as': false,
    'speak-header': false,
    'speak-numeral': false,
    'speak-punctuation': false,
    'speech-rate': false,
    'stress': false,
    'string-set': false,
    'tab-size': false,
    'table-layout': false,
    'text-align': true,
    'text-align-last': true,
    'text-combine-upright': true,
    'text-decoration': true,
    'text-decoration-color': true,
    'text-decoration-line': true,
    'text-decoration-skip': true,
    'text-decoration-style': true,
    'text-emphasis': true,
    'text-emphasis-color': true,
    'text-emphasis-position': true,
    'text-emphasis-style': true,
    'text-height': true,
    'text-indent': true,
    'text-justify': true,
    'text-orientation': true,
    'text-overflow': true,
    'text-rendering': true,
    'text-shadow': true,
    'text-space-collapse': true,
    'text-transform': true,
    'text-underline-position': true,
    'text-wrap': true,
    'top': false,
    'touch-action': false,
    'transform': false,
    'transform-origin': false,
    'transform-style': false,
    'transition': false,
    'transition-delay': false,
    'transition-duration': false,
    'transition-property': false,
    'transition-timing-function': false,
    'unicode-bidi': false,
    'vertical-align': false,
    'visibility': false,
    'voice-balance': false,
    'voice-duration': false,
    'voice-family': false,
    'voice-pitch': false,
    'voice-range': false,
    'voice-rate': false,
    'voice-stress': false,
    'voice-volume': false,
    'volume': false,
    'white-space': false,
    'widows': false,
    'width': true,
    'will-change': false,
    'word-break': true,
    'word-spacing': true,
    'word-wrap': true,
    'wrap-flow': false,
    'wrap-through': false,
    'writing-mode': false,
    'z-index': false,
  };
}

// ---------------------------------------------------------------------------
// CSS style parser
// ---------------------------------------------------------------------------

typedef _OnAttrCallback = void Function(
  int sourcePosition,
  int position,
  String name,
  String value,
  String source,
);

void _parseStyle(String css, _OnAttrCallback onAttr) {
  css = css.trimRight();
  if (css.isEmpty) return;
  // Ensure trailing semicolon so the last property is emitted.
  if (css[css.length - 1] != ';') css = '$css;';

  var cssLength = css.length;
  var isParenthesisOpen = false;
  var lastPos = 0;
  var position = 0;
  var i = 0;

  while (i < cssLength) {
    var c = css[i];

    // Skip comment blocks /* ... */
    if (c == '/' && css.length > i + 1 && css[i + 1] == '*') {
      var j = css.indexOf('*/', i + 2);
      if (j == -1) break; // unclosed comment — stop parsing
      i = j + 2;
      continue;
    }

    // Track parentheses depth (semicolons inside parens are not delimiters).
    if (c == '(') {
      isParenthesisOpen = true;
    } else if (c == ')') {
      isParenthesisOpen = false;
    }

    // Property delimiter: semicolon (outside parens) or newline.
    if (c == ';' || (c == '\n' && !isParenthesisOpen)) {
      // Ignore empty segments.
      if (i > lastPos) {
        var source = css.substring(lastPos, i).trim();
        if (source.isNotEmpty) {
          var colonIdx = source.indexOf(':');
          if (colonIdx != -1) {
            var name = source.substring(0, colonIdx).trim().toLowerCase();
            var value = source.substring(colonIdx + 1).trim();
            onAttr(lastPos, position, name, value, source);
            position++;
          }
        }
      }
      lastPos = i + 1;
    }

    i++;
  }
}

// ---------------------------------------------------------------------------
// CssFilter
// ---------------------------------------------------------------------------

/// CSS property filter. Parses inline CSS and removes non-whitelisted
/// properties, with hooks for custom allow/deny logic.
class CssFilter {
  final Map<String, Object> _whiteList;
  final CssOnAttrHandler _onAttr;
  final CssOnAttrHandler _onIgnoreAttr;
  final CssSafeAttrValueHandler _safeAttrValue;

  /// Creates a CSS filter with optional custom whitelist and callbacks.
  CssFilter({
    Map<String, Object>? whiteList,
    CssOnAttrHandler? onAttr,
    CssOnAttrHandler? onIgnoreAttr,
    CssSafeAttrValueHandler? safeAttrValue,
  })  : _whiteList = whiteList ?? getDefaultCssWhiteList(),
        _onAttr = onAttr ?? _defaultOnAttr,
        _onIgnoreAttr = onIgnoreAttr ?? _defaultOnIgnoreAttr,
        _safeAttrValue = safeAttrValue ?? _defaultSafeAttrValue;

  /// Filters an inline CSS string, keeping only whitelisted properties.
  String process(String css) {
    var retCss = '';

    _parseStyle(css, (sourcePosition, position, name, value, source) {
      var check = _whiteList[name];
      var isWhite = false;
      if (check == true) {
        isWhite = true;
      } else if (check is bool Function(String)) {
        isWhite = check(value);
      } else if (check is RegExp) {
        isWhite = check.hasMatch(value);
      }

      // Filter value through safeAttrValue (for all properties).
      value = _safeAttrValue(name, value);
      if (value.isEmpty) return;

      final info = CssAttrInfo(
        position: position,
        sourcePosition: sourcePosition,
        source: source,
        isWhite: isWhite,
      );

      if (isWhite) {
        var result = _onAttr(name, value, info);
        if (result == null) {
          retCss += '$name:$value; ';
        } else {
          retCss += '$result; ';
        }
      } else {
        var result = _onIgnoreAttr(name, value, info);
        if (result != null) {
          retCss += '$result; ';
        }
      }
    });

    return retCss.trim();
  }
}
