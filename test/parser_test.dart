import 'package:test/test.dart';
import 'package:disinfect/disinfect.dart';

void main() {
  String escapeHtmlHelper(String html) {
    return html.replaceAll('<', '&lt;').replaceAll('>', '&gt;');
  }

  String attr(String n, [String? v]) {
    if (v != null) {
      return '$n="${v.replaceAll('"', '&quote;')}"';
    } else {
      return n;
    }
  }

  group('test HTML parser', () {
    test('#parseTag', () {
      var i = 0;
      final html = parseTag(
        'hello<A href="#">www</A>ccc<b><br/>',
        (sourcePosition, position, tag, html, isClosing) {
          i++;
          if (i == 1) {
            expect(sourcePosition, equals(5));
            expect(position, equals(5));
            expect(tag, equals('a'));
            expect(html, equals('<A href="#">'));
            expect(isClosing, equals(false));
            return '[link]';
          } else if (i == 2) {
            expect(sourcePosition, equals(20));
            expect(position, equals(14));
            expect(tag, equals('a'));
            expect(html, equals('</A>'));
            expect(isClosing, equals(true));
            return '[/link]';
          } else if (i == 3) {
            expect(sourcePosition, equals(27));
            expect(position, equals(24));
            expect(tag, equals('b'));
            expect(html, equals('<b>'));
            expect(isClosing, equals(false));
            return '[B]';
          } else if (i == 4) {
            expect(sourcePosition, equals(30));
            expect(position, equals(27));
            expect(tag, equals('br'));
            expect(html, equals('<br/>'));
            expect(isClosing, equals(false));
            return '[BR]';
          } else {
            throw StateError('unexpected tag #$i');
          }
        },
        escapeHtmlHelper,
      );
      expect(html, equals('hello[link]www[/link]ccc[B][BR]'));
    });

    test('#parseAttr', () {
      var i = 0;
      final html = parseAttr(
        'href="#"attr1=b attr2=c attr3 attr4=\'value4"\'attr5/ attr6\\ attr7= "123 456"',
        (name, value) {
          i++;
          if (i == 1) {
            expect(name, equals('href'));
            expect(value, equals('#'));
            return attr(name, value);
          } else if (i == 2) {
            expect(name, equals('attr1'));
            expect(value, equals('b'));
            return attr(name, value);
          } else if (i == 3) {
            expect(name, equals('attr2'));
            expect(value, equals('c'));
            return attr(name, value);
          } else if (i == 4) {
            expect(name, equals('attr3'));
            expect(value, equals(''));
            return attr(name);
          } else if (i == 5) {
            expect(name, equals('attr4'));
            expect(value, equals('value4"'));
            return attr(name, value);
          } else if (i == 6) {
            expect(name, equals('attr5'));
            expect(value, equals(''));
            return attr(name);
          } else if (i == 7) {
            expect(name, equals('attr6\\'));
            expect(value, equals(''));
            return attr(name);
          } else if (i == 8) {
            expect(name, equals('attr7'));
            expect(value, equals('123 456'));
            return attr(name, value);
          } else {
            throw StateError('unexpected attr #$i');
          }
        },
      );
      expect(
        html,
        equals(
            'href="#" attr1="b" attr2="c" attr3 attr4="value4&quote;" attr5 attr6\\ attr7="123 456"'),
      );
    });

    test('#parseTag & #parseAttr', () {
      final html = parseTag(
        'hi:<a href="#"target=_blank title="this is a link" alt  = hello   class   = "hello2">link</a>',
        (sourcePosition, position, tag, tagHtml, isClosing) {
          if (tag == 'a') {
            if (isClosing) return '</a>';
            final attrhtml = parseAttr(tagHtml.substring(2, tagHtml.length - 1), (name, value) {
              if (name == 'href' || name == 'target' || name == 'alt' || name == 'class') {
                return attr(name, value.isEmpty ? null : value);
              }
              return null;
            });
            return '<a $attrhtml>';
          } else {
            return escapeHtmlHelper(tagHtml);
          }
        },
        escapeHtmlHelper,
      );
      expect(
        html,
        equals('hi:<a href="#" target="_blank" alt="hello" class="hello2">link</a>'),
      );
    });
  });
}
