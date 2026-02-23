import 'package:test/test.dart';
import 'package:disinfect/disinfect.dart';

void main() {
  group('test XSS', () {
    test('#normal', () {
      // Empty / blank input
      expect(disinfect(''), equals(''));

      // Strip blank chars
      expect(
        disinfect('a\u0000\u0001\u0002\u0003\r\n b'),
        equals('a\u0000\u0001\u0002\u0003\r\n b'),
      );
      expect(
        disinfect('a\u0000\u0001\u0002\u0003\r\n b', stripBlankChar: true),
        equals('a\r\n b'),
      );

      // Filter tags not in whitelist
      expect(disinfect('<b>abcd</b>'), equals('<b>abcd</b>'));
      expect(disinfect('<o>abcd</o>'), equals('&lt;o&gt;abcd&lt;/o&gt;'));
      expect(disinfect('<b>abcd</o>'), equals('<b>abcd&lt;/o&gt;'));
      expect(
        disinfect('<b><o>abcd</b></o>'),
        equals('<b>&lt;o&gt;abcd</b>&lt;/o&gt;'),
      );
      expect(disinfect('<hr>'), equals('<hr>'));
      expect(disinfect('<xss>'), equals('&lt;xss&gt;'));
      expect(disinfect('<xss o="x">'), equals('&lt;xss o="x"&gt;'));
      expect(disinfect('<a><b>c</b></a>'), equals('<a><b>c</b></a>'));
      expect(
        disinfect('<a><c>b</c></a>'),
        equals('<a>&lt;c&gt;b&lt;/c&gt;</a>'),
      );

      // Filter non-tag < >
      expect(disinfect('<>>'), equals('&lt;&gt;&gt;'));
      expect(disinfect('<script>'), equals('&lt;script&gt;'));
      expect(disinfect('<<a>b>'), equals('&lt;<a>b&gt;'));
      expect(
        disinfect('<<<a>>b</a><x>'),
        equals('&lt;&lt;<a>&gt;b</a>&lt;x&gt;'),
      );

      // Filter non-whitelisted attributes
      expect(
        disinfect('<a oo="1" xx="2" title="3">yy</a>'),
        equals('<a title="3">yy</a>'),
      );
      expect(disinfect('<a title xx oo>pp</a>'), equals('<a title>pp</a>'));
      expect(disinfect('<a title "">pp</a>'), equals('<a title>pp</a>'));
      expect(disinfect('<a t="">'), equals('<a>'));

      // Special chars in attributes
      expect(
        disinfect('<a title="\'<<>>">'),
        equals('<a title="\'&lt;&lt;&gt;&gt;">'),
      );
      expect(disinfect('<a title=""">'), equals('<a title>'));
      expect(disinfect('<a h=title="oo">'), equals('<a>'));
      expect(disinfect('<a h= title="oo">'), equals('<a>'));
      expect(
        disinfect('<a title="javascript&colonalert(/xss/)">'),
        equals('<a title="javascript:alert(/xss/)">'),
      );
      expect(
        disinfect('<a title"hell aa="fdfd title="ok">hello</a>'),
        equals('<a>hello</a>'),
      );

      // Single quotes auto-converted to double quotes
      expect(disinfect("<a title='abcd'>"), equals('<a title="abcd">'));
      expect(disinfect("<a title='\"'>"), equals('<a title="&quot;">'));

      // Unquoted attribute values
      expect(disinfect('<a title=home>'), equals('<a title="home">'));
      expect(
        disinfect('<a title=abc("d")>'),
        equals('<a title="abc(&quot;d&quot;)">'),
      );
      expect(
        disinfect("<a title=abc('d')>"),
        equals("<a title=\"abc('d')\">"),
      );

      // Self-closing tags
      expect(disinfect('<img src/>'), equals('<img src />'));
      expect(disinfect('<img src />'), equals('<img src />'));
      expect(disinfect('<img src//>'), equals('<img src />'));
      expect(disinfect('<br/>'), equals('<br />'));
      expect(disinfect('<br />'), equals('<br />'));
      expect(
        disinfect("<img src=x onerror=alert('XSS')"),
        equals('<img src>'),
      );

      // Malformed attribute format
      expect(
        disinfect('<a target = "_blank" title ="bbb">'),
        equals('<a target="_blank" title="bbb">'),
      );
      expect(
        disinfect('<a target = "_blank" title =  title =  "bbb">'),
        equals('<a target="_blank" title="title">'),
      );
      expect(
        disinfect('<img width = 100    height     =200 title="xxx">'),
        equals('<img width="100" height="200" title="xxx">'),
      );
      expect(
        disinfect('<img width = 100    height     =200 title=xxx>'),
        equals('<img width="100" height="200" title="xxx">'),
      );
      expect(
        disinfect('<img width = 100    height     =200 title= xxx>'),
        equals('<img width="100" height="200" title="xxx">'),
      );
      expect(
        disinfect('<img width = 100    height     =200 title= "xxx">'),
        equals('<img width="100" height="200" title="xxx">'),
      );
      expect(
        disinfect("<img width = 100    height     =200 title= 'xxx'>"),
        equals('<img width="100" height="200" title="xxx">'),
      );
      expect(
        disinfect("<img width = 100    height     =200 title = 'xxx'>"),
        equals('<img width="100" height="200" title="xxx">'),
      );
      expect(
        disinfect(
            '<img width = 100    height     =200 title= "xxx" no=yes alt="yyy">'),
        equals('<img width="100" height="200" title="xxx" alt="yyy">'),
      );
      expect(
        disinfect(
            '<img width = 100    height     =200 title= "xxx" no=yes alt="\'yyy\'">'),
        equals('<img width="100" height="200" title="xxx" alt="\'yyy\'">'),
      );
      expect(
        disinfect('<img loading="lazy">'),
        equals('<img loading="lazy">'),
      );

      // Tab/newline separated attributes
      expect(
        disinfect('<img width=100 height=200\nsrc="#"/>'),
        equals('<img width="100" height="200" src="#" />'),
      );
      expect(
        disinfect('<a\ttarget="_blank"\ntitle="bbb">'),
        equals('<a target="_blank" title="bbb">'),
      );
      expect(
        disinfect('<a\ntarget="_blank"\ttitle="bbb">'),
        equals('<a target="_blank" title="bbb">'),
      );
      expect(
        disinfect('<a\n\n\n\ttarget="_blank"\t\t\t\ntitle="bbb">'),
        equals('<a target="_blank" title="bbb">'),
      );
    });

    test('#white list', () {
      // Filter all tags
      expect(
        disinfect('<a title="xx">bb</a>', whiteList: {}),
        equals('&lt;a title="xx"&gt;bb&lt;/a&gt;'),
      );
      expect(disinfect('<hr>', whiteList: {}), equals('&lt;hr&gt;'));
      // Custom whitelist
      expect(
        disinfect('<ooxx yy="ok" cc="no">uu</ooxx>',
            whiteList: {
              'ooxx': ['yy']
            }),
        equals('<ooxx yy="ok">uu</ooxx>'),
      );
    });

    test('#allowList', () {
      expect(
        disinfect('<a title="xx">bb</a>', allowList: {}),
        equals('&lt;a title="xx"&gt;bb&lt;/a&gt;'),
      );
      expect(disinfect('<hr>', allowList: {}), equals('&lt;hr&gt;'));
      expect(
        disinfect('<ooxx yy="ok" cc="no">uu</ooxx>',
            allowList: {
              'ooxx': ['yy']
            }),
        equals('<ooxx yy="ok">uu</ooxx>'),
      );
    });

    test('#XSS_Filter_Evasion_Cheat_Sheet', () {
      expect(
        disinfect(
            '></SCRIPT>"\'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>'),
        equals(
            '&gt;&lt;/SCRIPT&gt;"\'&gt;&lt;SCRIPT&gt;alert(String.fromCharCode(88,83,83))&lt;/SCRIPT&gt;'),
      );

      expect(disinfect(';!--"<XSS>=&{()}'), equals(';!--"&lt;XSS&gt;=&{()}'));

      expect(
        disinfect('<SCRIPT SRC=http://ha.ckers.org/xss.js></SCRIPT>'),
        equals('&lt;SCRIPT SRC=http://ha.ckers.org/xss.js&gt;&lt;/SCRIPT&gt;'),
      );

      expect(
        disinfect('<IMG SRC="javascript:alert(\'XSS\');">'),
        equals('<img src>'),
      );

      expect(
        disinfect("<IMG SRC=javascript:alert('XSS')>"),
        equals('<img src>'),
      );

      expect(
        disinfect("<IMG SRC=JaVaScRiPt:alert('XSS')>"),
        equals('<img src>'),
      );

      expect(
        disinfect('<IMG SRC=`javascript:alert("RSnake says, \'XSS\'")`>'),
        equals('<img src>'),
      );

      expect(
        disinfect('<IMG """><SCRIPT>alert("XSS")</SCRIPT>">'),
        equals('<img>&lt;SCRIPT&gt;alert("XSS")&lt;/SCRIPT&gt;"&gt;'),
      );

      expect(
        disinfect(
            '<IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>'),
        equals('<img src>'),
      );

      expect(
        disinfect(
            '<IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>'),
        equals('<img src>'),
      );

      expect(
        disinfect(
            '<IMG SRC=&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041>'),
        equals('<img src>'),
      );

      expect(
        disinfect(
            '<IMG SRC=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29>'),
        equals('<img src>'),
      );

      expect(
        disinfect('<IMG SRC="jav ascript:alert(\'XSS\');">'),
        equals('<img src>'),
      );

      expect(
        disinfect('<IMG SRC="jav&#x09;ascript:alert(\'XSS\');">'),
        equals('<img src>'),
      );

      expect(
        disinfect('<IMG SRC="jav\nascript:alert(\'XSS\');">'),
        equals('<img src>'),
      );

      expect(
        disinfect('<IMG SRC=java\x00script:alert("XSS")>'),
        equals('<img src>'),
      );

      expect(
        disinfect('<IMG SRC=" &#14;  javascript:alert(\'XSS\');">'),
        equals('<img src>'),
      );

      expect(
        disinfect(
            '<SCRIPT/XSS SRC="http://ha.ckers.org/xss.js"></SCRIPT>'),
        equals(
            '&lt;SCRIPT/XSS SRC="http://ha.ckers.org/xss.js"&gt;&lt;/SCRIPT&gt;'),
      );

      expect(
        disinfect(
            '<BODY onload!#\$%&()*~+-_.,:;?@[/|]^`=alert("XSS")>'),
        equals(
            '&lt;BODY onload!#\$%&()*~+-_.,:;?@[/|]^`=alert("XSS")&gt;'),
      );

      expect(
        disinfect('<<SCRIPT>alert("XSS");//<</SCRIPT>'),
        equals('&lt;&lt;SCRIPT&gt;alert("XSS");//&lt;&lt;/SCRIPT&gt;'),
      );

      expect(
        disinfect('<SCRIPT SRC=http://ha.ckers.org/xss.js?< B >'),
        equals('&lt;SCRIPT SRC=http://ha.ckers.org/xss.js?&lt; B &gt;'),
      );

      expect(
        disinfect('<SCRIPT SRC=//ha.ckers.org/.j'),
        equals('&lt;SCRIPT SRC=//ha.ckers.org/.j'),
      );

      expect(
        disinfect(
            '<\u017Fcript src="https://xss.haozi.me/j.js"></\u017Fcript>'),
        equals(
            '&lt;\u017Fcript src="https://xss.haozi.me/j.js"&gt;&lt;/\u017Fcript&gt;'),
      );

      expect(
        disinfect('<IMG SRC="javascript:alert(\'XSS\')"'),
        equals('&lt;IMG SRC="javascript:alert(\'XSS\')"'),
      );

      expect(
        disinfect('<iframe src=http://ha.ckers.org/scriptlet.html <'),
        equals('&lt;iframe src=http://ha.ckers.org/scriptlet.html &lt;'),
      );

      // Filter javascript: in style
      expect(
        disinfect('<a style="url(\'javascript:alert(1)\')">', whiteList: {
          'a': ['style']
        }),
        equals('<a style>'),
      );
      expect(
        disinfect('<td background="url(\'javascript:alert(1)\')">', whiteList: {
          'td': ['background']
        }),
        equals('<td background>'),
      );

      // Filter expression in style
      expect(
        disinfect('<DIV STYLE="width: \nexpression(alert(1));">',
            whiteList: {
              'div': ['style']
            }),
        equals('<div style>'),
      );
      // Abnormal url
      expect(
        disinfect('<DIV STYLE="background:\n url (javascript:ooxx);">',
            whiteList: {
              'div': ['style']
            }),
        equals('<div style>'),
      );
      expect(
        disinfect('<DIV STYLE="background:url (javascript:ooxx);">',
            whiteList: {
              'div': ['style']
            }),
        equals('<div style>'),
      );
      // Normal url
      expect(
        disinfect('<DIV STYLE="background: url (ooxx);">', whiteList: {
          'div': ['style']
        }),
        equals('<div style="background:url (ooxx);">'),
      );

      expect(
        disinfect('<IMG SRC=\'vbscript:msgbox("XSS")\'>'),
        equals('<img src>'),
      );

      expect(
        disinfect('<IMG SRC="livescript:[code]">'),
        equals('<img src>'),
      );

      expect(
        disinfect('<IMG SRC="mocha:[code]">'),
        equals('<img src>'),
      );

      expect(
        disinfect('<a href="javas/**/cript:alert(\'XSS\');">'),
        equals('<a href>'),
      );

      expect(disinfect('<a href="javascript">'), equals('<a href>'));
      expect(
        disinfect('<a href="/javascript/a">'),
        equals('<a href="/javascript/a">'),
      );
      expect(
        disinfect('<a href="http://aa.com">'),
        equals('<a href="http://aa.com">'),
      );
      expect(
        disinfect('<a href="https://aa.com">'),
        equals('<a href="https://aa.com">'),
      );
      expect(
        disinfect('<a href="mailto:me@ucdok.com">'),
        equals('<a href="mailto:me@ucdok.com">'),
      );
      expect(
        disinfect('<a href="tel:0123456789">'),
        equals('<a href="tel:0123456789">'),
      );
      expect(disinfect('<a href="#hello">'), equals('<a href="#hello">'));
      expect(disinfect('<a href="other">'), equals('<a href>'));

      // HTML comments
      expect(
        disinfect('<!--[if gte IE 4]><SCRIPT>alert(\'XSS\');</SCRIPT><![endif]--> END',
            allowCommentTag: true),
        equals(
            '&lt;!--[if gte IE 4]&gt;&lt;SCRIPT&gt;alert(\'XSS\');&lt;/SCRIPT&gt;&lt;![endif]--&gt; END'),
      );
      expect(
        disinfect(
            '<!--[if gte IE 4]><SCRIPT>alert(\'XSS\');</SCRIPT><![endif]--> END'),
        equals(' END'),
      );

      // HTML5 entities
      expect(
        disinfect('<a href="javascript&colon;alert(/xss/)">'),
        equals('<a href>'),
      );
      expect(
        disinfect('<a href="javascript&colonalert(/xss/)">'),
        equals('<a href>'),
      );
      expect(disinfect('<a href="a&NewLine;b">'), equals('<a href>'));
      expect(disinfect('<a href="a&NewLineb">'), equals('<a href>'));
      expect(
        disinfect('<a href="javasc&NewLine;ript&colon;alert(1)">'),
        equals('<a href>'),
      );

      // data URI
      expect(disinfect('<a href="data:">'), equals('<a href>'));
      expect(disinfect('<a href="d a t a : ">'), equals('<a href>'));
      expect(disinfect('<a href="data: html/text;">'), equals('<a href>'));
      expect(disinfect('<a href="data:html/text;">'), equals('<a href>'));
      expect(disinfect('<a href="data:html /text;">'), equals('<a href>'));
      expect(disinfect('<a href="data: image/text;">'), equals('<a href>'));
      expect(disinfect('<img src="data: aaa/text;">'), equals('<img src>'));
      expect(
        disinfect('<img src="data:image/png; base64; ofdkofiodiofl">'),
        equals('<img src="data:image/png; base64; ofdkofiodiofl">'),
      );

      // HTML comment handling
      expect(
        disinfect('<!--                               -->',
            allowCommentTag: false),
        equals(''),
      );
      expect(
        disinfect('<!--      a           -->', allowCommentTag: false),
        equals(''),
      );
      expect(
        disinfect('<!--sa       -->ss', allowCommentTag: false),
        equals('ss'),
      );
      expect(
        disinfect('<!--                               ', allowCommentTag: false),
        equals(''),
      );
    });

    test('#singleQuotedAttributeValue', () {
      expect(
        disinfect('<a title="xx">not-defined</a>'),
        equals('<a title="xx">not-defined</a>'),
      );
      expect(
        disinfect('<a title="xx">single-quoted</a>',
            singleQuotedAttributeValue: true),
        equals("<a title='xx'>single-quoted</a>"),
      );
      expect(
        disinfect('<a title="xx">double-quoted</a>',
            singleQuotedAttributeValue: false),
        equals('<a title="xx">double-quoted</a>'),
      );
    });

    test('no options mutated', () {
      // Verify creating FilterXss doesn't crash with no options
      disinfect('test');
      Disinfectant();
    });

    test('camel case tag names', () {
      expect(
        disinfect(
          '<animateTransform attributeName="transform"'
          'attributeType="XML"'
          'type="rotate"'
          'repeatCount="indefinite"/>',
          whiteList: {
            'animatetransform': ['attributetype', 'repeatcount'],
          },
        ),
        equals(
            '<animatetransform attributetype="XML" repeatcount="indefinite" />'),
      );
    });
  });
}
