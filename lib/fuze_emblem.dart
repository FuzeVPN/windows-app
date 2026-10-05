// SPDX-License-Identifier: MPL-2.0
import 'dart:math' as math;

import 'package:flutter/material.dart';

/// The vector emblem used by fuzevpn.com, painted at the actual display size.
class FuzeEmblem extends StatelessWidget {
  const FuzeEmblem({
    super.key,
    required this.color,
    this.width = 32,
    this.height = 36,
  });

  final Color color;
  final double width;
  final double height;

  @override
  Widget build(BuildContext context) => SizedBox(
    width: width,
    height: height,
    child: CustomPaint(painter: _FuzeEmblemPainter(color)),
  );
}

class _FuzeEmblemPainter extends CustomPainter {
  const _FuzeEmblemPainter(this.color);

  final Color color;

  // Geometry from assets/branding/fuzevpn-emblem.svg. The cutouts stay
  // transparent, so the same emblem works on the light and dark surfaces.
  static final Path _emblem = _buildEmblem();
  static const Rect _bounds = Rect.fromLTRB(13, 5, 87, 96);

  static Path _buildEmblem() {
    final shield = Path()
      ..moveTo(50, 5)
      ..lineTo(87, 20)
      ..cubicTo(87, 48, 81, 68, 68, 81)
      ..cubicTo(63, 86, 57, 91, 50, 96)
      ..cubicTo(43, 91, 37, 86, 32, 81)
      ..cubicTo(19, 68, 13, 48, 13, 20)
      ..close();
    final cutouts = Path()
      ..moveTo(50, 18)
      ..lineTo(70, 70)
      ..lineTo(50, 58)
      ..lineTo(30, 70)
      ..close()
      ..moveTo(50, 60)
      ..lineTo(45.5, 64)
      ..lineTo(50, 78)
      ..lineTo(54.5, 64)
      ..close();
    final details = Path()
      ..addOval(Rect.fromCircle(center: const Offset(50, 45), radius: 4.5))
      ..moveTo(48.4, 47)
      ..lineTo(51.6, 47)
      ..lineTo(51.6, 57)
      ..lineTo(70, 70)
      ..lineTo(62, 70)
      ..lineTo(50, 60)
      ..lineTo(38, 70)
      ..lineTo(30, 70)
      ..lineTo(48.4, 57)
      ..close();
    return Path.combine(
      PathOperation.union,
      Path.combine(PathOperation.difference, shield, cutouts),
      details,
    );
  }

  @override
  void paint(Canvas canvas, Size size) {
    // Reserve two logical pixels on every side, including the shield tip.
    // Fit the real silhouette rather than stretching its square source image.
    final scale = math.min(
      math.max(0, size.width - 4) / _bounds.width,
      math.max(0, size.height - 4) / _bounds.height,
    );
    if (scale == 0) return;
    canvas.save();
    canvas.translate(
      (size.width - _bounds.width * scale) / 2 - _bounds.left * scale,
      (size.height - _bounds.height * scale) / 2 - _bounds.top * scale,
    );
    canvas.scale(scale);
    canvas.drawPath(_emblem, Paint()..color = color);
    canvas.restore();
  }

  @override
  bool shouldRepaint(_FuzeEmblemPainter oldDelegate) =>
      oldDelegate.color != color;
}
