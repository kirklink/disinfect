/// Whitelist-based HTML sanitizer to prevent XSS attacks.
///
/// Ported from [js-xss](https://github.com/leizongmin/js-xss) v1.0.15.
/// Includes CSS property filtering (inlined from cssfilter v0.0.10).
library;

export 'src/css_filter.dart' show CssFilter, CssAttrInfo, getDefaultCssWhiteList;
export 'src/defaults.dart'
    show
        escapeHtml,
        escapeQuote,
        unescapeQuote,
        escapeHtmlEntities,
        escapeDangerHtml5Entities,
        clearNonPrintableCharacter,
        friendlyAttrValue,
        escapeAttrValue,
        stripCommentTag,
        stripBlankChar,
        safeAttrValue;
export 'src/parser.dart' show parseTag, parseAttr;
export 'src/whitelist.dart' show getDefaultWhiteList;
export 'src/disinfect.dart';
