// SPDX-License-Identifier: MPL-2.0
import 'dart:convert';
import 'dart:typed_data';

/// Which traffic the listed ranges select.
enum SplitTunnelMode {
  /// Everything uses the VPN except the listed ranges (and, optionally, the
  /// local network).
  exclude,

  /// Only the listed ranges use the VPN.
  include,
}

/// An IPv4 or IPv6 network prefix, normalized so that host bits are zero.
class SplitTunnelRange {
  const SplitTunnelRange._(this.bytes, this.length);

  /// 4 bytes for IPv4, 16 for IPv6, network byte order.
  final Uint8List bytes;
  final int length;

  bool get isIpv6 => bytes.length == 16;
  int get _bits => bytes.length * 8;

  /// Maximum number of ranges per list, matching the native boundary.
  static const maximumCount = 16;

  /// Error keys are French catalogue keys; callers translate them.
  static const invalidError =
      'Saisissez une adresse IP ou une plage CIDR valide.';
  static const reservedError =
      'Cette plage est réservée (boucle locale, multidiffusion ou adresse non routable).';
  static const duplicateError = 'Cette plage figure déjà dans la liste.';
  static const limitError = 'La liste est limitée à 16 plages.';

  /// Parses `address` or `address/length`, zeroing host bits. Returns null
  /// with [error] set to a catalogue key when the text cannot be used.
  static SplitTunnelRange? tryParse(
    String input, {
    void Function(String)? error,
  }) {
    final text = input.trim();
    final slash = text.indexOf('/');
    final addressText = slash < 0 ? text : text.substring(0, slash);
    final lengthText = slash < 0 ? null : text.substring(slash + 1);
    Uint8List? bytes;
    if (addressText.isNotEmpty &&
        !addressText.contains('%') &&
        RegExp(r'^[0-9A-Fa-f:.]+$').hasMatch(addressText)) {
      try {
        bytes = Uint8List.fromList(
          addressText.contains(':')
              ? Uri.parseIPv6Address(addressText)
              : Uri.parseIPv4Address(addressText),
        );
      } on FormatException {
        bytes = null;
      }
    }
    if (bytes == null) {
      error?.call(invalidError);
      return null;
    }
    final bits = bytes.length * 8;
    var length = bits;
    if (lengthText != null) {
      final parsed = RegExp(r'^\d{1,3}$').hasMatch(lengthText)
          ? int.parse(lengthText)
          : null;
      if (parsed == null || parsed > bits) {
        error?.call(invalidError);
        return null;
      }
      length = parsed;
    }
    for (var bit = length; bit < bits; bit++) {
      bytes[bit ~/ 8] &= ~(0x80 >> (bit % 8)) & 0xff;
    }
    final range = SplitTunnelRange._(bytes, length);
    if (length == 0 || _forbidden.any(range.overlaps)) {
      error?.call(reservedError);
      return null;
    }
    return range;
  }

  static final List<SplitTunnelRange> _forbidden = [
    for (final text in const [
      '0.0.0.0/8',
      '127.0.0.0/8',
      '224.0.0.0/4',
      '240.0.0.0/4',
      '::/128',
      '::1/128',
      '::ffff:0:0/96',
      'ff00::/8',
    ])
      _unchecked(text),
  ];

  static SplitTunnelRange _unchecked(String text) {
    final slash = text.indexOf('/');
    final address = text.substring(0, slash);
    return SplitTunnelRange._(
      Uint8List.fromList(
        address.contains(':')
            ? Uri.parseIPv6Address(address)
            : Uri.parseIPv4Address(address),
      ),
      int.parse(text.substring(slash + 1)),
    );
  }

  bool _bit(int index) => (bytes[index ~/ 8] >> (7 - index % 8)) & 1 == 1;

  bool contains(SplitTunnelRange other) {
    if (isIpv6 != other.isIpv6 || length > other.length) return false;
    for (var index = 0; index < length; index++) {
      if (_bit(index) != other._bit(index)) return false;
    }
    return true;
  }

  bool overlaps(SplitTunnelRange other) =>
      contains(other) || other.contains(this);

  /// Canonical text: dotted IPv4, RFC 5952 IPv6, `/length` omitted for hosts.
  @override
  String toString() {
    final address = isIpv6 ? _formatIpv6() : bytes.join('.');
    return length == _bits ? address : '$address/$length';
  }

  /// Always carries the prefix length, as the native boundary expects.
  String get cidr {
    final address = isIpv6 ? _formatIpv6() : bytes.join('.');
    return '$address/$length';
  }

  String _formatIpv6() {
    final groups = [
      for (var index = 0; index < 8; index++)
        (bytes[index * 2] << 8) | bytes[index * 2 + 1],
    ];
    var bestStart = -1;
    var bestLength = 0;
    for (var index = 0; index < 8;) {
      if (groups[index] != 0) {
        index++;
        continue;
      }
      var end = index;
      while (end < 8 && groups[end] == 0) {
        end++;
      }
      if (end - index > bestLength && end - index >= 2) {
        bestStart = index;
        bestLength = end - index;
      }
      index = end;
    }
    final buffer = StringBuffer();
    for (var index = 0; index < 8;) {
      if (index == bestStart) {
        buffer.write('::');
        index += bestLength;
        continue;
      }
      final text = buffer.toString();
      if (text.isNotEmpty && !text.endsWith(':')) buffer.write(':');
      buffer.write(groups[index].toRadixString(16));
      index++;
    }
    return buffer.toString();
  }

  @override
  bool operator ==(Object other) =>
      other is SplitTunnelRange &&
      other.length == length &&
      other.bytes.length == bytes.length &&
      _sameBytes(other.bytes, bytes);

  static bool _sameBytes(Uint8List left, Uint8List right) {
    for (var index = 0; index < left.length; index++) {
      if (left[index] != right[index]) return false;
    }
    return true;
  }

  @override
  int get hashCode => Object.hash(length, Object.hashAll(bytes));
}

/// User split-tunnel preferences. Disabled by default: nothing leaves the
/// tunnel until the user explicitly chooses it.
class SplitTunnelSettings {
  const SplitTunnelSettings({
    required this.enabled,
    required this.mode,
    required this.excludedRanges,
    required this.includedRanges,
    required this.allowLocalNetwork,
  });

  static const disabled = SplitTunnelSettings(
    enabled: false,
    mode: SplitTunnelMode.exclude,
    excludedRanges: [],
    includedRanges: [],
    allowLocalNetwork: false,
  );

  final bool enabled;
  final SplitTunnelMode mode;
  final List<SplitTunnelRange> excludedRanges;
  final List<SplitTunnelRange> includedRanges;
  final bool allowLocalNetwork;

  List<SplitTunnelRange> get ranges =>
      mode == SplitTunnelMode.exclude ? excludedRanges : includedRanges;

  /// The mode the native engines actually apply. An inclusion list that is
  /// empty, or an exclusion with nothing excluded, changes no traffic.
  String get effectiveMode {
    if (!enabled) return 'off';
    return switch (mode) {
      SplitTunnelMode.exclude =>
        excludedRanges.isNotEmpty || allowLocalNetwork ? 'exclude' : 'off',
      SplitTunnelMode.include => includedRanges.isNotEmpty ? 'include' : 'off',
    };
  }

  bool get isActive => effectiveMode != 'off';

  /// Arguments shared by both engines' prepare and connect calls. They must
  /// be identical for both calls: the native policy refuses to promote a
  /// prepared policy whose split settings differ. Empty when inactive, which
  /// the native boundary reads as "off".
  Map<String, Object> get channelArguments {
    final active = effectiveMode;
    if (active == 'off') return const {};
    return {
      'splitTunnelMode': active,
      'splitTunnelRoutes': [for (final range in ranges) range.cidr],
      'splitTunnelLan': active == 'exclude' && allowLocalNetwork,
    };
  }

  SplitTunnelSettings copyWith({
    bool? enabled,
    SplitTunnelMode? mode,
    List<SplitTunnelRange>? excludedRanges,
    List<SplitTunnelRange>? includedRanges,
    bool? allowLocalNetwork,
  }) => SplitTunnelSettings(
    enabled: enabled ?? this.enabled,
    mode: mode ?? this.mode,
    excludedRanges: excludedRanges ?? this.excludedRanges,
    includedRanges: includedRanges ?? this.includedRanges,
    allowLocalNetwork: allowLocalNetwork ?? this.allowLocalNetwork,
  );

  /// Returns the updated list for the current mode, or null with [error] set.
  SplitTunnelSettings? withAddedRange(
    String input, {
    required void Function(String) error,
  }) {
    final range = SplitTunnelRange.tryParse(input, error: error);
    if (range == null) return null;
    if (ranges.contains(range)) {
      error(SplitTunnelRange.duplicateError);
      return null;
    }
    if (ranges.length >= SplitTunnelRange.maximumCount) {
      error(SplitTunnelRange.limitError);
      return null;
    }
    final next = [...ranges, range];
    return mode == SplitTunnelMode.exclude
        ? copyWith(excludedRanges: List.unmodifiable(next))
        : copyWith(includedRanges: List.unmodifiable(next));
  }

  SplitTunnelSettings withoutRange(SplitTunnelRange range) {
    final next = List<SplitTunnelRange>.unmodifiable(
      ranges.where((item) => item != range),
    );
    return mode == SplitTunnelMode.exclude
        ? copyWith(excludedRanges: next)
        : copyWith(includedRanges: next);
  }

  String toStorageValue() => jsonEncode({
    'v': 1,
    'enabled': enabled,
    'mode': mode.name,
    'exclude': [for (final range in excludedRanges) range.cidr],
    'include': [for (final range in includedRanges) range.cidr],
    'lan': allowLocalNetwork,
  });

  /// Null for an unreadable record. Invalid entries are dropped rather than
  /// trusted: the native boundary would reject the whole request otherwise.
  static SplitTunnelSettings? tryParse(String value) {
    final Object? decoded;
    try {
      decoded = jsonDecode(value);
    } on FormatException {
      return null;
    }
    if (decoded is! Map || decoded['v'] != 1) return null;
    final enabled = decoded['enabled'];
    final lan = decoded['lan'];
    final mode = switch (decoded['mode']) {
      'exclude' => SplitTunnelMode.exclude,
      'include' => SplitTunnelMode.include,
      _ => null,
    };
    if (enabled is! bool || lan is! bool || mode == null) return null;
    List<SplitTunnelRange>? ranges(Object? items) {
      if (items is! List) return null;
      final result = <SplitTunnelRange>[];
      for (final item in items) {
        if (item is! String) continue;
        final range = SplitTunnelRange.tryParse(item);
        if (range != null &&
            !result.contains(range) &&
            result.length < SplitTunnelRange.maximumCount) {
          result.add(range);
        }
      }
      return List.unmodifiable(result);
    }

    final excluded = ranges(decoded['exclude']);
    final included = ranges(decoded['include']);
    if (excluded == null || included == null) return null;
    return SplitTunnelSettings(
      enabled: enabled,
      mode: mode,
      excludedRanges: excluded,
      includedRanges: included,
      allowLocalNetwork: lan,
    );
  }
}
