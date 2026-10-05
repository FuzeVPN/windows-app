// SPDX-License-Identifier: MPL-2.0
import 'package:fuzevpn_windows/core/models.dart';

/// Shared contract for local bridge doubles. WFP presence and its full IPv4
/// block are separate values, just as they are in the native lifecycle.
mixin NativeProtectionStatusFixture {
  bool appliedKillSwitch = true;
  bool ownedByAnotherUser = false;
  Future<bool> isNetworkProtectionActive();

  Future<NetworkProtectionStatus> networkProtectionStatus() async {
    final active = await isNetworkProtectionActive();
    return NetworkProtectionStatus(
      active: active,
      killSwitch: appliedKillSwitch,
      phase: active ? 'tunnel' : 'inactive',
      ownedByAnotherUser: ownedByAnotherUser,
    );
  }
}
