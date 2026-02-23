import 'package:test/test.dart';
import 'package:disinfect/disinfect.dart';

void main() {
  group('test custom XSS method', () {
    test('#onTag - match tag', () {
      final source = 'dd<a href="#"><b><c>haha</c></b></a><br>ff';
      var i = 0;
      final html = disinfect(source, onTag: (tag, html, info) {
        i++;
        if (i == 1) {
          expect(tag, equals('a'));
          expect(html, equals('<a href="#">'));
          expect(info.isClosing, equals(false));
          expect(info.position, equals(2));
          expect(info.sourcePosition, equals(2));
          expect(info.isWhite, equals(true));
        } else if (i == 2) {
          expect(tag, equals('b'));
          expect(html, equals('<b>'));
          expect(info.isClosing, equals(false));
          expect(info.position, equals(14));
          expect(info.sourcePosition, equals(14));
          expect(info.isWhite, equals(true));
        } else if (i == 3) {
          expect(tag, equals('c'));
          expect(html, equals('<c>'));
          expect(info.isClosing, equals(false));
          expect(info.position, equals(17));
          expect(info.sourcePosition, equals(17));
          expect(info.isWhite, equals(false));
        } else if (i == 4) {
          expect(tag, equals('c'));
          expect(html, equals('</c>'));
          expect(info.isClosing, equals(true));
          expect(info.position, equals(30));
          expect(info.sourcePosition, equals(24));
          expect(info.isWhite, equals(false));
        } else if (i == 5) {
          expect(tag, equals('b'));
          expect(html, equals('</b>'));
          expect(info.isClosing, equals(true));
          expect(info.position, equals(40));
          expect(info.sourcePosition, equals(28));
          expect(info.isWhite, equals(true));
        } else if (i == 6) {
          expect(tag, equals('a'));
          expect(html, equals('</a>'));
          expect(info.isClosing, equals(true));
          expect(info.position, equals(44));
          expect(info.sourcePosition, equals(32));
          expect(info.isWhite, equals(true));
        } else if (i == 7) {
          expect(tag, equals('br'));
          expect(html, equals('<br>'));
          expect(info.isClosing, equals(false));
          expect(info.position, equals(48));
          expect(info.sourcePosition, equals(36));
          expect(info.isWhite, equals(true));
        } else {
          fail('unexpected tag #$i');
        }
        return null;
      });
      expect(
        html,
        equals('dd<a href="#"><b>&lt;c&gt;haha&lt;/c&gt;</b></a><br>ff'),
      );
    });

    test('#onTag - return new html', () {
      final source = 'dd<a href="#"><b><c>haha</c></b></a><br>ff';
      final html = disinfect(source, onTag: (tag, html, info) {
        return html;
      });
      expect(html, equals(source));
    });

    test('#onIgnoreTag - match tag', () {
      final source = 'dd<a href="#"><b><c>haha</c></b></a><br>ff';
      var i = 0;
      final html = disinfect(source, onIgnoreTag: (tag, html, info) {
        i++;
        if (i == 1) {
          expect(tag, equals('c'));
          expect(html, equals('<c>'));
          expect(info.isClosing, equals(false));
          expect(info.position, equals(17));
          expect(info.sourcePosition, equals(17));
          expect(info.isWhite, equals(false));
        } else if (i == 2) {
          expect(tag, equals('c'));
          expect(html, equals('</c>'));
          expect(info.isClosing, equals(true));
          expect(info.position, equals(30));
          expect(info.sourcePosition, equals(24));
          expect(info.isWhite, equals(false));
        } else {
          fail('unexpected tag #$i');
        }
        return null;
      });
      expect(
        html,
        equals('dd<a href="#"><b>&lt;c&gt;haha&lt;/c&gt;</b></a><br>ff'),
      );
    });

    test('#onIgnoreTag - return new html', () {
      final source = 'dd<a href="#"><b><c>haha</c></b></a><br>ff';
      final html = disinfect(source, onIgnoreTag: (tag, html, info) {
        return '[${info.isClosing ? '/' : ''}removed]';
      });
      expect(
        html,
        equals('dd<a href="#"><b>[removed]haha[/removed]</b></a><br>ff'),
      );
    });

    test('#onTagAttr - match attr', () {
      final source =
          '<a href="#" target="_blank" checked data-a="b">hi</a href="d">';
      var i = 0;
      final html = disinfect(source, onTagAttr: (tag, name, value, isWhiteAttr) {
        expect(tag, equals('a'));
        i++;
        if (i == 1) {
          expect(name, equals('href'));
          expect(value, equals('#'));
          expect(isWhiteAttr, equals(true));
        } else if (i == 2) {
          expect(name, equals('target'));
          expect(value, equals('_blank'));
          expect(isWhiteAttr, equals(true));
        } else if (i == 3) {
          expect(name, equals('checked'));
          expect(value, equals(''));
          expect(isWhiteAttr, equals(false));
        } else if (i == 4) {
          expect(name, equals('data-a'));
          expect(value, equals('b'));
          expect(isWhiteAttr, equals(false));
        } else {
          fail('unexpected attr #$i');
        }
        return null;
      });
      expect(html, equals('<a href="#" target="_blank">hi</a>'));
    });

    test('#onTagAttr - return new html', () {
      final source =
          '<a href="#" target="_blank" checked data-a="b">hi</a href="d">';
      final html = disinfect(source, onTagAttr: (tag, name, value, isWhiteAttr) {
        return '\$$name\$';
      });
      expect(
        html,
        equals('<a \$href\$ \$target\$ \$checked\$ \$data-a\$>hi</a>'),
      );
    });

    test('#onIgnoreTagAttr - match attr', () {
      final source =
          '<a href="#" target="_blank" checked data-a="b">hi</a href="d">';
      var i = 0;
      final html =
          disinfect(source, onIgnoreTagAttr: (tag, name, value, isWhiteAttr) {
        expect(tag, equals('a'));
        i++;
        if (i == 1) {
          expect(name, equals('checked'));
          expect(value, equals(''));
          expect(isWhiteAttr, equals(false));
        } else if (i == 2) {
          expect(name, equals('data-a'));
          expect(value, equals('b'));
          expect(isWhiteAttr, equals(false));
        } else {
          fail('unexpected attr #$i');
        }
        return null;
      });
      expect(html, equals('<a href="#" target="_blank">hi</a>'));
    });

    test('#onIgnoreTagAttr - return new html', () {
      final source =
          '<a href="#" target="_blank" checked data-a="b">hi</a href="d">';
      final html =
          disinfect(source, onIgnoreTagAttr: (tag, name, value, isWhiteAttr) {
        return '\$$name\$';
      });
      expect(
        html,
        equals('<a href="#" target="_blank" \$checked\$ \$data-a\$>hi</a>'),
      );
    });

    test('#escapeHtml - default', () {
      final source = '<x>yy</x><a>bb</a>';
      final html = disinfect(source);
      expect(html, equals('&lt;x&gt;yy&lt;/x&gt;<a>bb</a>'));
    });

    test('#escapeHtml - return new value', () {
      final source = '<x>yy</x><a>bb</a>';
      final html = disinfect(source, escapeHtml: (str) {
        return str.isNotEmpty ? '[$str]' : str;
      });
      expect(html, equals('[<x>][yy][</x>]<a>[bb]</a>'));
    });

    test('#safeAttrValue - default', () {
      final source = '<a href="javascript:alert(/xss/)" title="hi">link</a>';
      final html = disinfect(source);
      expect(html, equals('<a href title="hi">link</a>'));
    });

    test('#safeAttrValue - return new value', () {
      final source = '<a href="javascript:alert(/xss/)" title="hi">link</a>';
      final html = disinfect(source, safeAttrValue: (tag, name, value, cssFilter) {
        expect(tag, equals('a'));
        return '\$$name\$';
      });
      expect(html, equals('<a href="\$href\$" title="\$title\$">link</a>'));
    });

    test('#stripIgnoreTag', () {
      final source = '<x>yy</x><a>bb</a>';
      final html = disinfect(source, stripIgnoreTag: true);
      expect(html, equals('yy<a>bb</a>'));
    });

    test('#stripTagBody - true', () {
      final source = '<a>link</a><x>haha</x><y>a<y></y>b</y>k';
      final html = disinfect(source, stripIgnoreTagBody: true);
      expect(html, equals('<a>link</a>bk'));
    });

    test('#stripIgnoreTagBody - *', () {
      final source = '<a>link</a><x>haha</x><y>a<y></y>b</y>k';
      final html = disinfect(source, stripIgnoreTagBody: '*');
      expect(html, equals('<a>link</a>bk'));
    });

    test("#stripIgnoreTagBody - ['x']", () {
      final source = '<a>link</a><x>haha</x><y>a<y></y>b</y>k';
      final html = disinfect(source, stripIgnoreTagBody: ['x']);
      expect(
        html,
        equals('<a>link</a>&lt;y&gt;a&lt;y&gt;&lt;/y&gt;b&lt;/y&gt;k'),
      );
    });

    test("#stripIgnoreTagBody - ['x'] & onIgnoreTag", () {
      final source = '<a>link</a><x>haha</x><y>a<y></y>b</y>k';
      final html = disinfect(source,
          stripIgnoreTagBody: ['x'],
          onIgnoreTag: (tag, html, info) {
            return '\$$tag\$';
          });
      expect(html, equals('<a>link</a>\$y\$a\$y\$\$y\$b\$y\$k'));
    });

    test('#stripIgnoreTag & stripIgnoreTagBody', () {
      final source = '<script>alert(/xss/);</script>';
      final html = disinfect(source,
          stripIgnoreTag: true, stripIgnoreTagBody: ['script']);
      expect(html, equals(''));
    });

    test('#stripIgnoreTag & stripIgnoreTagBody - 2', () {
      final source = 'ooxx<script>alert(/xss/);</script>';
      final html = disinfect(source,
          stripIgnoreTag: true, stripIgnoreTagBody: ['script']);
      expect(html, equals('ooxx'));
    });

    test('cssFilter', () {
      final whiteList = getDefaultWhiteList();
      whiteList['div']!.add('style');
      expect(
        disinfect('<div style="width: 50%; vertical-align: top;">hello</div>',
            whiteList: whiteList),
        equals('<div style="width:50%;">hello</div>'),
      );
      expect(
        disinfect('<div style="width: 50%; vertical-align: top;">hello</div>',
            whiteList: whiteList, css: false),
        equals(
            '<div style="width: 50%; vertical-align: top;">hello</div>'),
      );
      final cssWl = getDefaultCssWhiteList();
      cssWl['vertical-align'] = true;
      expect(
        disinfect('<div style="width: 50%; vertical-align: top;">hello</div>',
            whiteList: whiteList, css: {'whiteList': cssWl}),
        equals('<div style="width:50%; vertical-align:top;">hello</div>'),
      );
    });

    test('#onTag - sanitize html parameter space', () {
      final source = '<a target= " href="><script>alert(2)</script>"><span>';
      final html = disinfect(source, onTag: (tag, html, info) {
        if (info.isWhite && tag == 'a') {
          if (info.isClosing) return '</span></a>';
          return '$html<span>';
        }
        return null;
      });
      expect(
        html,
        equals(
            '<a target= " href="><span>&lt;script&gt;alert(2)&lt;/script&gt;"&gt;<span>'),
      );
    });

    test('#onTag - sanitize html parameter tab', () {
      final source = '<a target=\t" href="><script>alert(2)</script>"><span>';
      final html = disinfect(source, onTag: (tag, html, info) {
        if (info.isWhite && tag == 'a') {
          if (info.isClosing) return '</span></a>';
          return '$html<span>';
        }
        return null;
      });
      expect(
        html,
        equals(
            '<a target=\t" href="><span>&lt;script&gt;alert(2)&lt;/script&gt;"&gt;<span>'),
      );
    });
  });
}
