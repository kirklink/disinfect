import 'package:test/test.dart';
import 'package:disinfect/disinfect.dart';

void main() {
  group('test default', () {
    test('#stripCommentTag', () {
      expect(stripCommentTag('<!-- hello -->'), equals(''));
      expect(stripCommentTag('<!--hello-->'), equals(''));
      expect(stripCommentTag('xx <!-- hello --> yy'), equals('xx  yy'));
      expect(stripCommentTag('xx<!--hello-->yy'), equals('xxyy'));
      expect(
        stripCommentTag('<!-- <!-- <!-- hello --> --> -->'),
        equals(' --> -->'),
      );
    });
  });
}
