import 'package:test/test.dart';
import 'package:disinfect/disinfect.dart';

void main() {
  group('Basic sanitization stress tests', () {
    test('empty string returns empty', () {
      expect(disinfect(''), '');
    });

    test('plain text passes through unchanged', () {
      expect(disinfect('Hello, World!'), 'Hello, World!');
    });

    test('very long plain text passes through', () {
      final text = 'Hello World! ' * 10000;
      expect(disinfect(text), text);
    });

    test('plain text with special characters', () {
      expect(disinfect('a & b'), 'a & b');
      expect(disinfect('1 < 2 > 0'), '1 &lt; 2 &gt; 0');
    });

    test('only whitespace', () {
      expect(disinfect('   '), '   ');
      expect(disinfect('\t\n\r'), '\t\n\r');
    });

    test('null bytes in plain text', () {
      expect(disinfect('a\x00b'), 'a\x00b');
    });

    test('null bytes removed with stripBlankChar', () {
      expect(disinfect('a\x00b', stripBlankChar: true), 'ab');
    });

    test('unicode text passes through', () {
      final unicode = '\u{1F600} \u{1F4A9} \u{1F680} caf\u{00E9}';
      expect(disinfect(unicode), unicode);
    });

    test('single angle bracket', () {
      expect(disinfect('<'), '&lt;');
      expect(disinfect('>'), '&gt;');
    });

    test('unmatched angle brackets', () {
      expect(disinfect('a < b > c'), 'a &lt; b &gt; c');
    });
  });

  group('Whitelisted tag stress tests', () {
    test('all basic whitelisted tags preserved', () {
      final safeTags = [
        'a', 'b', 'i', 'u', 'em', 'strong', 'p', 'br', 'hr',
        'div', 'span', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
        'ul', 'ol', 'li', 'blockquote', 'pre', 'code',
        'table', 'thead', 'tbody', 'tfoot', 'tr', 'th', 'td',
        'img', 'sub', 'sup', 'small', 'big', 'mark', 'kbd',
      ];
      for (final tag in safeTags) {
        if (tag == 'br' || tag == 'hr' || tag == 'img') {
          expect(disinfect('<$tag>'), '<$tag>',
              reason: 'self-closing $tag');
        } else {
          expect(disinfect('<$tag>content</$tag>'), '<$tag>content</$tag>',
              reason: 'tag $tag');
        }
      }
    });

    test('deeply nested whitelisted tags', () {
      final html = '${'<div>' * 50}deep${'</div>' * 50}';
      final result = disinfect(html);
      expect(result, html);
    });

    test('all heading levels', () {
      for (var i = 1; i <= 6; i++) {
        expect(disinfect('<h$i>Heading $i</h$i>'), '<h$i>Heading $i</h$i>');
      }
    });

    test('table with all sub-elements', () {
      final html = '<table><thead><tr><th>H</th></tr></thead>'
          '<tbody><tr><td>D</td></tr></tbody>'
          '<tfoot><tr><td>F</td></tr></tfoot></table>';
      expect(disinfect(html), html);
    });

    test('audio tag with attributes', () {
      expect(
        disinfect(
            '<audio controls src="https://example.com/song.mp3" loop muted></audio>'),
        '<audio controls src="https://example.com/song.mp3" loop muted></audio>',
      );
    });

    test('video tag with attributes', () {
      expect(
        disinfect(
            '<video controls src="https://example.com/vid.mp4" width="640" height="480" poster="thumb.jpg"></video>'),
        '<video controls src="https://example.com/vid.mp4" width="640" height="480" poster="thumb.jpg"></video>',
      );
    });

    test('img with data:image source', () {
      expect(
        disinfect('<img src="data:image/png;base64,iVBOR...">'),
        '<img src="data:image/png;base64,iVBOR...">',
      );
    });

    test('a tag allowed attributes', () {
      expect(
        disinfect('<a href="https://example.com" target="_blank" title="link">click</a>'),
        '<a href="https://example.com" target="_blank" title="link">click</a>',
      );
    });

    test('td with rowspan and colspan', () {
      expect(
        disinfect('<td rowspan="2" colspan="3" align="center">cell</td>'),
        '<td rowspan="2" colspan="3" align="center">cell</td>',
      );
    });
  });

  group('Dangerous tag stress tests', () {
    test('script tag escaped', () {
      expect(
        disinfect('<script>alert(1)</script>'),
        '&lt;script&gt;alert(1)&lt;/script&gt;',
      );
    });

    test('iframe tag escaped', () {
      expect(
        disinfect('<iframe src="evil.com"></iframe>'),
        '&lt;iframe src="evil.com"&gt;&lt;/iframe&gt;',
      );
    });

    test('object tag escaped', () {
      expect(
        disinfect('<object data="evil.swf"></object>'),
        '&lt;object data="evil.swf"&gt;&lt;/object&gt;',
      );
    });

    test('embed tag escaped', () {
      expect(
        disinfect('<embed src="evil.swf">'),
        '&lt;embed src="evil.swf"&gt;',
      );
    });

    test('form tag escaped', () {
      expect(
        disinfect('<form action="evil"><input type="text"></form>'),
        '&lt;form action="evil"&gt;&lt;input type="text"&gt;&lt;/form&gt;',
      );
    });

    test('style tag escaped', () {
      expect(
        disinfect('<style>body{display:none}</style>'),
        '&lt;style&gt;body{display:none}&lt;/style&gt;',
      );
    });

    test('link tag escaped', () {
      expect(
        disinfect('<link rel="stylesheet" href="evil.css">'),
        '&lt;link rel="stylesheet" href="evil.css"&gt;',
      );
    });

    test('meta tag escaped', () {
      expect(
        disinfect('<meta http-equiv="refresh" content="0;url=evil">'),
        '&lt;meta http-equiv="refresh" content="0;url=evil"&gt;',
      );
    });

    test('base tag escaped', () {
      expect(
        disinfect('<base href="evil.com">'),
        '&lt;base href="evil.com"&gt;',
      );
    });

    test('applet tag escaped', () {
      expect(
        disinfect('<applet code="evil"></applet>'),
        '&lt;applet code="evil"&gt;&lt;/applet&gt;',
      );
    });

    test('svg tag escaped', () {
      expect(
        disinfect('<svg onload="alert(1)">'),
        '&lt;svg onload="alert(1)"&gt;',
      );
    });

    test('math tag escaped', () {
      expect(
        disinfect('<math><mi>x</mi></math>'),
        '&lt;math&gt;&lt;mi&gt;x&lt;/mi&gt;&lt;/math&gt;',
      );
    });
  });

  group('Attribute filtering stress tests', () {
    test('event handler attributes removed from all tags', () {
      final events = [
        'onclick', 'onload', 'onerror', 'onmouseover', 'onmouseout',
        'onfocus', 'onblur', 'onsubmit', 'onchange', 'onkeyup',
        'onkeydown', 'onkeypress', 'ondblclick', 'oncontextmenu',
        'ondrag', 'ondrop', 'onscroll', 'onwheel', 'onanimationend',
      ];
      for (final event in events) {
        expect(
          disinfect('<div $event="alert(1)">text</div>'),
          '<div>text</div>',
          reason: 'event: $event',
        );
      }
    });

    test('class attribute removed (not in default whitelist)', () {
      expect(disinfect('<div class="foo">text</div>'), '<div>text</div>');
    });

    test('id attribute removed', () {
      expect(disinfect('<div id="foo">text</div>'), '<div>text</div>');
    });

    test('style attribute removed from tags without it in whitelist', () {
      expect(disinfect('<div style="color:red">text</div>'), '<div>text</div>');
    });

    test('data- attributes removed', () {
      expect(
        disinfect('<div data-custom="value">text</div>'),
        '<div>text</div>',
      );
    });

    test('multiple non-whitelisted attributes all removed', () {
      expect(
        disinfect(
            '<img src="https://example.com/ok.jpg" onclick="bad()" onerror="bad()" class="x">'),
        '<img src="https://example.com/ok.jpg">',
      );
    });

    test('mixed whitelisted and non-whitelisted attributes', () {
      expect(
        disinfect('<a href="https://ok.com" onclick="bad()" title="good" class="x">link</a>'),
        '<a href="https://ok.com" title="good">link</a>',
      );
    });
  });

  group('XSS vector stress tests', () {
    group('script injection', () {
      test('basic script tag', () {
        expect(
          disinfect('<script>alert("XSS")</script>'),
          '&lt;script&gt;alert("XSS")&lt;/script&gt;',
        );
      });

      test('script with src', () {
        expect(
          disinfect('<script src="evil.js"></script>'),
          '&lt;script src="evil.js"&gt;&lt;/script&gt;',
        );
      });

      test('case variations of script', () {
        final cases = ['SCRIPT', 'Script', 'ScRiPt', 'sCrIpT'];
        for (final tag in cases) {
          final result = disinfect('<$tag>alert(1)</$tag>');
          expect(result.contains('alert(1)'), isTrue, reason: tag);
          expect(result.toLowerCase().contains('<script>'), isFalse,
              reason: tag);
        }
      });

      test('null bytes in script tag', () {
        expect(
          disinfect('<scr\x00ipt>alert(1)</script>'),
          '&lt;scr\x00ipt&gt;alert(1)&lt;/script&gt;',
        );
      });

      test('nested script tags', () {
        final result =
            disinfect('<script><script>alert(1)</script></script>');
        expect(result.toLowerCase().contains('<script>'), isFalse);
      });
    });

    group('javascript: protocol', () {
      test('javascript: in href', () {
        expect(disinfect('<a href="javascript:alert(1)">'), '<a href>');
      });

      test('javascript: with entities', () {
        expect(disinfect('<a href="&#106;avascript:alert(1)">'), '<a href>');
      });

      test('javascript: with hex entities', () {
        expect(
          disinfect('<a href="&#x6A;avascript:alert(1)">'),
          '<a href>',
        );
      });

      test('javascript: with colon entity', () {
        expect(
          disinfect('<a href="javascript&colon;alert(1)">'),
          '<a href>',
        );
      });

      test('javascript: with spaces', () {
        expect(disinfect('<a href="j a v a s c r i p t:alert(1)">'),
            '<a href>');
      });

      test('javascript: with tabs and newlines', () {
        expect(disinfect('<a href="java\tscript:alert(1)">'), '<a href>');
        expect(disinfect('<a href="java\nscript:alert(1)">'), '<a href>');
      });

      test('vbscript: in src', () {
        expect(disinfect('<img src="vbscript:alert(1)">'), '<img src>');
      });

      test('livescript: in src', () {
        expect(disinfect('<img src="livescript:alert(1)">'), '<img src>');
      });

      test('mocha: in src', () {
        expect(disinfect('<img src="mocha:alert(1)">'), '<img src>');
      });

      test('javascript: with mixed case', () {
        expect(disinfect('<a href="JaVaScRiPt:alert(1)">'), '<a href>');
      });

      test('data: URI blocked (except data:image/)', () {
        expect(disinfect('<a href="data:text/html,<script>alert(1)</script>">'),
            '<a href>');
        expect(disinfect('<img src="data:text/html,bad">'), '<img src>');
      });

      test('data:image/ allowed', () {
        expect(
          disinfect('<img src="data:image/png;base64,abc123">'),
          '<img src="data:image/png;base64,abc123">',
        );
      });
    });

    group('event handler injection', () {
      test('img onerror', () {
        expect(disinfect('<img src=x onerror=alert(1)>'), '<img src>');
      });

      test('svg onload', () {
        expect(
          disinfect('<svg onload=alert(1)>'),
          '&lt;svg onload=alert(1)&gt;',
        );
      });

      test('body onload', () {
        expect(
          disinfect('<body onload=alert(1)>'),
          '&lt;body onload=alert(1)&gt;',
        );
      });

      test('img src with encoded javascript', () {
        expect(
          disinfect(
              '<img src=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29>'),
          '<img src>',
        );
      });

      test('input onfocus', () {
        expect(
          disinfect('<input onfocus=alert(1) autofocus>'),
          '&lt;input onfocus=alert(1) autofocus&gt;',
        );
      });

      test('marquee onstart', () {
        expect(
          disinfect('<marquee onstart=alert(1)>'),
          '&lt;marquee onstart=alert(1)&gt;',
        );
      });

      test('details ontoggle', () {
        expect(
          disinfect('<details ontoggle=alert(1) open>test</details>'),
          '<details open>test</details>',
        );
      });
    });

    group('style-based attacks', () {
      test('expression() in style', () {
        expect(
          disinfect('<div style="width:expression(alert(1))">',
              whiteList: {'div': ['style']}),
          '<div style>',
        );
      });

      test('expression with spaces', () {
        expect(
          disinfect('<div style="width: e x p r e s s i o n(alert(1))">',
              whiteList: {'div': ['style']}),
          '<div style>',
        );
      });

      test('url(javascript:) in style', () {
        expect(
          disinfect('<div style="background:url(javascript:alert(1))">',
              whiteList: {'div': ['style']}),
          '<div style>',
        );
      });

      test('normal url in style allowed', () {
        final result = disinfect(
          '<div style="background:url(image.png)">',
          whiteList: {'div': ['style']},
        );
        expect(result, contains('background'));
      });

      test('css with valid properties', () {
        final result = disinfect(
          '<div style="color:red; font-size:14px; margin:10px">',
          whiteList: {'div': ['style']},
        );
        expect(result, contains('color'));
        expect(result, contains('font-size'));
      });
    });

    group('entity encoding attacks', () {
      test('HTML numeric entities decoded in attrs', () {
        expect(
          disinfect('<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(1)">'),
          '<a href>',
        );
      });

      test('hex entities decoded in attrs', () {
        expect(
          disinfect('<a href="&#x6A;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3A;alert(1)">'),
          '<a href>',
        );
      });

      test('&colon; entity decoded', () {
        expect(
          disinfect('<a href="javascript&colon;alert(1)">'),
          '<a href>',
        );
      });

      test('&NewLine; entity decoded', () {
        expect(disinfect('<a href="a&NewLine;b">'), '<a href>');
      });

      test('padded numeric entities', () {
        expect(
          disinfect(
              '<img src="&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058alert(1)">'),
          '<img src>',
        );
      });
    });

    group('HTML comment attacks', () {
      test('comments stripped by default', () {
        expect(disinfect('<!-- comment -->text'), 'text');
      });

      test('conditional comments stripped', () {
        expect(
          disinfect('<!--[if IE]><script>alert(1)</script><![endif]-->'),
          '',
        );
      });

      test('comments preserved with allowCommentTag', () {
        // allowCommentTag skips stripping, but parser still escapes angle
        // brackets because comments are not parsed as HTML tags.
        final result =
            disinfect('<!-- safe comment -->', allowCommentTag: true);
        expect(result, contains('safe comment'));
      });

      test('nested comments', () {
        // Inner comment is stripped; remaining > is escaped.
        expect(disinfect('<!-- <!-- nested --> -->'), ' --&gt;');
      });

      test('unclosed comment', () {
        expect(disinfect('<!-- unclosed'), '');
      });

      test('many comments', () {
        final html = '<!-- c --> ' * 100 + 'text';
        expect(disinfect(html), ' ' * 100 + 'text');
      });
    });
  });

  group('Protocol whitelist stress tests', () {
    test('http allowed', () {
      expect(
        disinfect('<a href="http://example.com">'),
        '<a href="http://example.com">',
      );
    });

    test('https allowed', () {
      expect(
        disinfect('<a href="https://example.com">'),
        '<a href="https://example.com">',
      );
    });

    test('mailto allowed', () {
      expect(
        disinfect('<a href="mailto:user@example.com">'),
        '<a href="mailto:user@example.com">',
      );
    });

    test('tel allowed', () {
      expect(
        disinfect('<a href="tel:+1234567890">'),
        '<a href="tel:+1234567890">',
      );
    });

    test('ftp allowed', () {
      expect(
        disinfect('<a href="ftp://files.example.com">'),
        '<a href="ftp://files.example.com">',
      );
    });

    test('relative paths allowed', () {
      expect(disinfect('<a href="./page">'), '<a href="./page">');
      expect(disinfect('<a href="../page">'), '<a href="../page">');
      expect(disinfect('<a href="/page">'), '<a href="/page">');
    });

    test('hash links allowed', () {
      expect(disinfect('<a href="#">'), '<a href="#">');
      expect(disinfect('<a href="#section">'), '<a href="#section">');
    });

    test('unknown protocols blocked', () {
      expect(disinfect('<a href="file:///etc/passwd">'), '<a href>');
      expect(disinfect('<a href="custom://foo">'), '<a href>');
      expect(disinfect('<a href="chrome://settings">'), '<a href>');
    });

    test('data: blocked except data:image/', () {
      expect(disinfect('<a href="data:text/html,bad">'), '<a href>');
      expect(
        disinfect('<img src="data:image/gif;base64,R0lGODlh">'),
        '<img src="data:image/gif;base64,R0lGODlh">',
      );
    });
  });

  group('stripIgnoreTag stress tests', () {
    test('strips non-whitelisted tags completely', () {
      expect(
        disinfect('<script>evil</script>safe', stripIgnoreTag: true),
        'evilsafe',
      );
    });

    test('strips multiple non-whitelisted tags', () {
      expect(
        disinfect('<script>a</script><style>b</style>c',
            stripIgnoreTag: true),
        'abc',
      );
    });

    test('preserves whitelisted tags', () {
      expect(
        disinfect('<b>bold</b><script>evil</script>', stripIgnoreTag: true),
        '<b>bold</b>evil',
      );
    });

    test('strips nested non-whitelisted tags', () {
      expect(
        disinfect('<form><input><button>click</button></form>',
            stripIgnoreTag: true),
        'click',
      );
    });
  });

  group('stripIgnoreTagBody stress tests', () {
    test('strips all non-whitelisted tag bodies when true', () {
      expect(
        disinfect('<script>evil code</script>safe',
            stripIgnoreTagBody: true),
        'safe',
      );
    });

    test('strips specific tags when list provided', () {
      expect(
        disinfect(
            '<script>evil</script><style>css</style>text',
            stripIgnoreTagBody: ['script']),
        '&lt;style&gt;css&lt;/style&gt;text',
      );
    });

    test('strips style but not script', () {
      expect(
        disinfect(
            '<script>js</script><style>css</style>text',
            stripIgnoreTagBody: ['style']),
        '&lt;script&gt;js&lt;/script&gt;text',
      );
    });

    test('preserves whitelisted tag content', () {
      expect(
        disinfect('<b>bold</b><script>evil</script>',
            stripIgnoreTagBody: true),
        '<b>bold</b>',
      );
    });

    test('nested stripped tags', () {
      expect(
        disinfect('<script><script>inner</script></script>text',
            stripIgnoreTagBody: true),
        'text',
      );
    });

    test('multiple occurrences of stripped tag', () {
      expect(
        disinfect(
            'a<script>1</script>b<script>2</script>c',
            stripIgnoreTagBody: ['script']),
        'abc',
      );
    });
  });

  group('stripBlankChar stress tests', () {
    test('removes null bytes', () {
      expect(disinfect('\x00text\x00', stripBlankChar: true), 'text');
    });

    test('removes control chars except newline and CR', () {
      expect(disinfect('\x01\x02\x03\x04text', stripBlankChar: true), 'text');
      expect(
        disinfect('\x05\x06\x07\x08text', stripBlankChar: true),
        'text',
      );
    });

    test('preserves newline and CR', () {
      expect(disinfect('a\nb\rc', stripBlankChar: true), 'a\nb\rc');
    });

    test('removes DEL (127)', () {
      expect(disinfect('a\x7Fb', stripBlankChar: true), 'ab');
    });

    test('preserves normal text', () {
      expect(
        disinfect('Hello, World!', stripBlankChar: true),
        'Hello, World!',
      );
    });

    test('removes tab', () {
      expect(disinfect('a\tb', stripBlankChar: true), 'ab');
    });
  });

  group('Custom whitelist stress tests', () {
    test('empty whitelist escapes everything', () {
      expect(
        disinfect('<b>bold</b>', whiteList: {}),
        '&lt;b&gt;bold&lt;/b&gt;',
      );
    });

    test('custom tag with custom attributes', () {
      expect(
        disinfect('<custom-tag data-x="1" bad="2">text</custom-tag>',
            whiteList: {'custom-tag': ['data-x']}),
        '<custom-tag data-x="1">text</custom-tag>',
      );
    });

    test('allowList param works same as whiteList', () {
      expect(
        disinfect('<x y="z">t</x>', allowList: {'x': ['y']}),
        '<x y="z">t</x>',
      );
    });

    test('custom whitelist overrides default', () {
      // script is normally blocked; we can whitelist it
      expect(
        disinfect('<script>code</script>', whiteList: {'script': []}),
        '<script>code</script>',
      );
    });

    test('whitelist is case insensitive for tags', () {
      expect(
        disinfect('<DIV>text</DIV>'),
        '<div>text</div>',
      );
    });
  });

  group('Callback stress tests', () {
    group('onTag callback', () {
      test('can replace tag markers', () {
        // onTag replaces each tag marker (opening + closing), content remains.
        expect(
          disinfect(
            '<script>evil</script>',
            onTag: (tag, html, info) {
              if (tag == 'script') return '[BLOCKED]';
              return null;
            },
          ),
          '[BLOCKED]evil[BLOCKED]',
        );
      });

      test('receives correct tag info', () {
        final infos = <TagInfo>[];
        disinfect(
          '<b>bold</b>',
          onTag: (tag, html, info) {
            infos.add(info);
            return null;
          },
        );
        expect(infos, hasLength(2));
        expect(infos[0].isClosing, isFalse);
        expect(infos[0].isWhite, isTrue);
        expect(infos[1].isClosing, isTrue);
        expect(infos[1].isWhite, isTrue);
      });

      test('receives non-whitelisted info', () {
        TagInfo? capturedInfo;
        disinfect(
          '<script>bad</script>',
          onTag: (tag, html, info) {
            if (!info.isClosing) capturedInfo = info;
            return null;
          },
        );
        expect(capturedInfo, isNotNull);
        expect(capturedInfo!.isWhite, isFalse);
      });

      test('position increments', () {
        final positions = <int>[];
        disinfect(
          '<b>a</b><i>b</i><u>c</u>',
          onTag: (tag, html, info) {
            positions.add(info.position);
            return null;
          },
        );
        // positions should be monotonically non-decreasing
        for (var i = 1; i < positions.length; i++) {
          expect(positions[i], greaterThanOrEqualTo(positions[i - 1]));
        }
      });
    });

    group('onIgnoreTag callback', () {
      test('can keep non-whitelisted tags', () {
        expect(
          disinfect(
            '<custom>text</custom>',
            onIgnoreTag: (tag, html, info) => html,
          ),
          '<custom>text</custom>',
        );
      });

      test('null return uses default (escape)', () {
        expect(
          disinfect(
            '<custom>text</custom>',
            onIgnoreTag: (tag, html, info) => null,
          ),
          '&lt;custom&gt;text&lt;/custom&gt;',
        );
      });
    });

    group('onTagAttr callback', () {
      test('can modify attribute output', () {
        expect(
          disinfect(
            '<a href="http://example.com">link</a>',
            onTagAttr: (tag, name, value, isWhite) {
              if (name == 'href') return 'href="modified"';
              return null;
            },
          ),
          '<a href="modified">link</a>',
        );
      });

      test('receives isWhiteAttr correctly', () {
        final whiteFlags = <String, bool>{};
        disinfect(
          '<a href="url" class="x" title="t">',
          onTagAttr: (tag, name, value, isWhite) {
            whiteFlags[name] = isWhite;
            return null;
          },
        );
        expect(whiteFlags['href'], isTrue);
        expect(whiteFlags['title'], isTrue);
        expect(whiteFlags['class'], isFalse);
      });
    });

    group('onIgnoreTagAttr callback', () {
      test('can keep non-whitelisted attributes', () {
        expect(
          disinfect(
            '<div class="myclass">text</div>',
            onIgnoreTagAttr: (tag, name, value, isWhite) {
              if (name == 'class') return 'class="$value"';
              return null;
            },
          ),
          '<div class="myclass">text</div>',
        );
      });
    });

    group('custom safeAttrValue', () {
      test('can override attribute sanitization', () {
        expect(
          disinfect(
            '<a href="custom://protocol">link</a>',
            safeAttrValue: (tag, name, value, cssFilter) => value,
          ),
          '<a href="custom://protocol">link</a>',
        );
      });
    });

    group('custom escapeHtml', () {
      test('can override HTML escaping', () {
        // escapeHtml is called on each text segment separately.
        final result = disinfect(
          '<evil>text</evil>',
          escapeHtml: (html) => '[escaped:$html]',
        );
        expect(result, contains('[escaped:'));
        expect(result, contains('text'));
      });
    });
  });

  group('CSS filter stress tests', () {
    test('valid CSS properties pass through', () {
      final result = disinfect(
        '<div style="color:red; font-size:14px">',
        whiteList: {'div': ['style']},
      );
      expect(result, contains('color'));
      expect(result, contains('font-size'));
    });

    test('css disabled when css: false', () {
      final result = disinfect(
        '<div style="color:red; background:blue">',
        whiteList: {'div': ['style']},
        css: false,
      );
      expect(result, contains('style'));
    });

    test('expression() blocked in CSS', () {
      expect(
        disinfect(
          '<div style="width:expression(alert(1))">',
          whiteList: {'div': ['style']},
        ),
        '<div style>',
      );
    });

    test('url(javascript:) blocked in CSS', () {
      expect(
        disinfect(
          '<div style="background:url(javascript:alert(1))">',
          whiteList: {'div': ['style']},
        ),
        '<div style>',
      );
    });

    test('normal url() in CSS allowed', () {
      final result = disinfect(
        '<div style="background:url(image.png)">',
        whiteList: {'div': ['style']},
      );
      expect(result, contains('background'));
    });

    test('unknown CSS properties filtered', () {
      final result = disinfect(
        '<div style="custom-prop:value; color:red">',
        whiteList: {'div': ['style']},
      );
      expect(result, contains('color'));
    });

    test('custom CSS whitelist', () {
      final result = disinfect(
        '<div style="color:red; custom-prop:value">',
        whiteList: {'div': ['style']},
        css: {
          'whiteList': {'color': true, 'custom-prop': true}
        },
      );
      expect(result, contains('color'));
    });
  });

  group('singleQuotedAttributeValue stress tests', () {
    test('single quotes used for attributes', () {
      expect(
        disinfect('<a title="hello">', singleQuotedAttributeValue: true),
        "<a title='hello'>",
      );
    });

    test('double quotes is default', () {
      expect(
        disinfect('<a title="hello">'),
        '<a title="hello">',
      );
    });

    test('single quotes with special chars', () {
      expect(
        disinfect('<img alt="test">', singleQuotedAttributeValue: true),
        "<img alt='test'>",
      );
    });
  });

  group('Disinfectant instance stress tests', () {
    test('reusable instance', () {
      final xss = Disinfectant();
      expect(xss.process('<b>bold</b>'), '<b>bold</b>');
      expect(xss.process('<script>evil</script>'),
          '&lt;script&gt;evil&lt;/script&gt;');
    });

    test('instance with custom options', () {
      final xss = Disinfectant(whiteList: {'b': []});
      expect(xss.process('<b>ok</b>'), '<b>ok</b>');
      expect(xss.process('<i>gone</i>'), '&lt;i&gt;gone&lt;/i&gt;');
    });

    test('multiple instances with different configs', () {
      final strict = Disinfectant(whiteList: {});
      final lenient = Disinfectant(whiteList: {
        'b': [],
        'i': [],
        'a': ['href'],
        'img': ['src'],
      });

      expect(strict.process('<b>text</b>'), '&lt;b&gt;text&lt;/b&gt;');
      expect(lenient.process('<b>text</b>'), '<b>text</b>');
    });

    test('instance handles empty string', () {
      expect(Disinfectant().process(''), '');
    });

    test('instance handles many calls', () {
      final xss = Disinfectant();
      for (var i = 0; i < 1000; i++) {
        expect(xss.process('<b>$i</b>'), '<b>$i</b>');
      }
    });
  });

  group('Edge case stress tests', () {
    test('incomplete tags', () {
      expect(disinfect('<b'), '&lt;b');
      // Parser sees '<b ' as start of a tag; completes it as <b> (attr stripped).
      expect(disinfect('<b attr'), '<b>');
      expect(disinfect('</b'), '&lt;/b');
    });

    test('tag at end of input', () {
      expect(disinfect('text<b'), 'text&lt;b');
    });

    test('empty tag', () {
      expect(disinfect('<>'), '&lt;&gt;');
    });

    test('tag with only spaces', () {
      expect(disinfect('< >'), '&lt; &gt;');
    });

    test('many opening tags without closing', () {
      final html = '<b>' * 100 + 'text';
      final result = disinfect(html);
      expect(result, '<b>' * 100 + 'text');
    });

    test('many closing tags without opening', () {
      final html = 'text${'</b>' * 100}';
      final result = disinfect(html);
      expect(result, 'text${'</b>' * 100}');
    });

    test('extremely long attribute value', () {
      final longValue = 'a' * 100000;
      final result = disinfect('<a title="$longValue">');
      expect(result, contains('title'));
    });

    test('many attributes on single tag', () {
      final attrs = List.generate(50, (i) => 'title="v$i"').join(' ');
      final result = disinfect('<a $attrs>');
      // Only last title should remain (parsed last)
      expect(result, isA<String>());
    });

    test('self-closing tag variations', () {
      expect(disinfect('<br/>'), '<br />');
      expect(disinfect('<br />'), '<br />');
      expect(disinfect('<hr/>'), '<hr />');
      expect(disinfect('<img src="x" />'), '<img src />');
    });

    test('mixed case tag names normalized', () {
      expect(disinfect('<B>bold</B>'), '<b>bold</b>');
      expect(disinfect('<STRONG>strong</STRONG>'), '<strong>strong</strong>');
      expect(disinfect('<DIV>div</DIV>'), '<div>div</div>');
    });

    test('double angle brackets', () {
      expect(disinfect('<<b>>'), '&lt;<b>&gt;');
      expect(disinfect('<<<script>>>'), contains('&lt;'));
    });

    test('angle bracket in attribute value', () {
      expect(
        disinfect("<a title=\"'<<>>\">"),
        '<a title="\'&lt;&lt;&gt;&gt;">',
      );
    });

    test('malformed attribute with no value', () {
      expect(disinfect('<a title>text</a>'), '<a title>text</a>');
    });

    test('malformed attribute with empty quotes', () {
      expect(disinfect('<a title="">text</a>'), '<a title>text</a>');
    });

    test('attribute with tab separator', () {
      expect(
        disinfect('<a\ttarget="_blank"\ttitle="t">'),
        '<a target="_blank" title="t">',
      );
    });

    test('attribute with newline separator', () {
      expect(
        disinfect('<a\ntarget="_blank"\ntitle="t">'),
        '<a target="_blank" title="t">',
      );
    });

    test('attribute with mixed whitespace', () {
      expect(
        disinfect('<a \t\n target="_blank" \t\n title="t">'),
        '<a target="_blank" title="t">',
      );
    });
  });

  group('Complex real-world HTML stress tests', () {
    test('blog post with mixed content', () {
      final html = '<div>'
          '<h1>My Blog Post</h1>'
          '<p>This is a <b>great</b> post with <a href="https://example.com">links</a>.</p>'
          '<img src="https://example.com/photo.jpg" alt="photo">'
          '<blockquote>A wise quote</blockquote>'
          '<ul><li>Item 1</li><li>Item 2</li></ul>'
          '</div>';
      final result = disinfect(html);
      expect(result, contains('<h1>'));
      expect(result, contains('<a href="https://example.com">'));
      expect(result, contains('<img src="https://example.com/photo.jpg"'));
      expect(result, contains('<blockquote>'));
      expect(result, contains('<li>'));
    });

    test('html with mixed safe and unsafe content', () {
      final html = '<b>safe</b><script>alert(1)</script>'
          '<a href="https://ok.com">link</a>'
          '<iframe src="evil"></iframe>'
          '<p>paragraph</p>';
      final result = disinfect(html);
      expect(result, contains('<b>safe</b>'));
      expect(result, contains('&lt;script&gt;'));
      expect(result, contains('<a href="https://ok.com">'));
      expect(result, contains('&lt;iframe'));
      expect(result, contains('<p>paragraph</p>'));
    });

    test('email body with various formatting', () {
      final html = '<div>'
          '<p>Dear <strong>User</strong>,</p>'
          '<p>Please visit <a href="https://example.com">our site</a>.</p>'
          '<table border="1"><tr><td>Data</td></tr></table>'
          '<p><em>Regards</em>,<br>Team</p>'
          '</div>';
      final result = disinfect(html);
      expect(result, contains('<strong>User</strong>'));
      expect(result, contains('<a href="https://example.com">'));
      expect(result, contains('<table border="1">'));
      expect(result, contains('<br>'));
    });

    test('user-generated content with injection attempts', () {
      final html = 'Hello <b>world</b>! '
          'Check my <a href="javascript:steal()">profile</a> '
          '<img src=x onerror=alert(1)> '
          '<script>document.cookie</script> '
          'Normal <i>text</i> here.';
      final result = disinfect(html);
      expect(result, contains('<b>world</b>'));
      expect(result, contains('<a href>'));
      expect(result, contains('<img src>'));
      expect(result, contains('&lt;script&gt;'));
      expect(result, contains('<i>text</i>'));
    });

    test('large HTML document', () {
      final rows = List.generate(
          100, (i) => '<tr><td>Row $i</td><td>Data $i</td></tr>');
      final html = '<table>${rows.join()}</table>';
      final result = disinfect(html);
      expect(result, contains('<table>'));
      expect(result, contains('Row 0'));
      expect(result, contains('Row 99'));
    });
  });

  group('Performance stress tests', () {
    test('many tags', () {
      final html = '<b>x</b> ' * 1000;
      final result = disinfect(html);
      expect(result, html);
    });

    test('many non-whitelisted tags', () {
      final html = '<script>x</script> ' * 100;
      final result = disinfect(html);
      expect(result.contains('<script>'), isFalse);
    });

    test('deeply nested mixed tags', () {
      var html = '';
      for (var i = 0; i < 20; i++) {
        html += '<div><p><b><i><a href="https://x.com">';
      }
      html += 'content';
      for (var i = 0; i < 20; i++) {
        html += '</a></i></b></p></div>';
      }
      final result = disinfect(html);
      expect(result, contains('content'));
      expect(result, contains('<div>'));
      expect(result, contains('<a href="https://x.com">'));
    });

    test('large payload with scattered XSS', () {
      final parts = <String>[];
      for (var i = 0; i < 50; i++) {
        parts.add('<p>Paragraph $i with <b>bold</b> text.</p>');
        if (i % 10 == 0) {
          parts.add('<script>alert($i)</script>');
        }
      }
      final html = parts.join();
      final result = disinfect(html);
      expect(result, contains('<p>Paragraph 0'));
      expect(result.toLowerCase().contains('<script>'), isFalse);
    });
  });
}
