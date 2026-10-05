// SPDX-License-Identifier: MPL-2.0
import 'models.dart';

/// Serializes the lifecycle of one native VPN command.
///
/// Every command owns a monotonically increasing identifier. A completion
/// from an invalidated or older command is ignored and therefore cannot
/// overwrite the state produced by a newer user action.
class VpnConnectionStateMachine {
  VpnStatus _state = VpnStatus.disconnected;
  int _generation = 0;
  int? _activeOperationId;

  VpnStatus get state => _state;
  bool get isBusy => _activeOperationId != null;
  int? get activeOperationId => _activeOperationId;

  int begin(VpnStatus initialState) {
    if (_activeOperationId != null) {
      throw StateError('A VPN operation is already active.');
    }
    _apply(initialState);
    final operationId = ++_generation;
    _activeOperationId = operationId;
    return operationId;
  }

  bool owns(int? operationId) => operationId == null
      ? _activeOperationId == null
      : operationId == _activeOperationId;

  bool transition(int? operationId, VpnStatus nextState) {
    if (!owns(operationId)) return false;
    _apply(nextState);
    return true;
  }

  void finish(int operationId) {
    if (_activeOperationId == operationId) {
      _activeOperationId = null;
    }
  }

  void invalidate({VpnStatus? state}) {
    _generation++;
    _activeOperationId = null;
    if (state != null) _state = state;
  }

  /// Used while restoring native state and by existing widget fixtures.
  void restore(VpnStatus state) => _state = state;

  void _apply(VpnStatus nextState) {
    if (nextState == _state) return;
    final allowed = switch (_state) {
      VpnStatus.disconnected => {
        VpnStatus.preparing,
        VpnStatus.connected,
        VpnStatus.blocked,
        VpnStatus.error,
      },
      VpnStatus.preparing => {
        VpnStatus.connecting,
        VpnStatus.disconnecting,
        VpnStatus.disconnected,
        VpnStatus.blocked,
        VpnStatus.error,
      },
      VpnStatus.connecting => {
        VpnStatus.connected,
        VpnStatus.disconnecting,
        VpnStatus.disconnected,
        VpnStatus.blocked,
        VpnStatus.error,
      },
      VpnStatus.connected => {
        VpnStatus.preparing,
        VpnStatus.disconnecting,
        VpnStatus.disconnected,
        VpnStatus.blocked,
        VpnStatus.error,
      },
      VpnStatus.disconnecting => {
        VpnStatus.disconnected,
        VpnStatus.connected,
        VpnStatus.blocked,
        VpnStatus.error,
      },
      VpnStatus.blocked => {
        VpnStatus.preparing,
        VpnStatus.disconnecting,
        VpnStatus.disconnected,
        VpnStatus.connected,
        VpnStatus.error,
      },
      VpnStatus.error => {
        VpnStatus.preparing,
        VpnStatus.disconnecting,
        VpnStatus.disconnected,
        VpnStatus.connected,
        VpnStatus.blocked,
      },
    };
    if (!allowed.contains(nextState)) {
      throw StateError('Invalid VPN transition: $_state -> $nextState.');
    }
    _state = nextState;
  }
}
