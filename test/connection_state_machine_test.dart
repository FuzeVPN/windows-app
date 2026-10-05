// SPDX-License-Identifier: MPL-2.0
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/core/connection_state_machine.dart';
import 'package:fuzevpn_windows/core/models.dart';

void main() {
  test('suit le cycle explicite de connexion et de déconnexion', () {
    final machine = VpnConnectionStateMachine();

    final connect = machine.begin(VpnStatus.preparing);
    expect(machine.transition(connect, VpnStatus.connecting), isTrue);
    expect(machine.transition(connect, VpnStatus.connected), isTrue);
    machine.finish(connect);

    final disconnect = machine.begin(VpnStatus.disconnecting);
    expect(machine.transition(disconnect, VpnStatus.disconnected), isTrue);
    machine.finish(disconnect);

    expect(machine.state, VpnStatus.disconnected);
    expect(machine.isBusy, isFalse);
  });

  test('refuse deux opérations simultanées', () {
    final machine = VpnConnectionStateMachine();
    machine.begin(VpnStatus.preparing);

    expect(() => machine.begin(VpnStatus.preparing), throwsStateError);
  });

  test('ignore la réponse tardive d’une opération invalidée', () {
    final machine = VpnConnectionStateMachine();
    final obsolete = machine.begin(VpnStatus.preparing);
    machine.invalidate(state: VpnStatus.disconnected);
    final current = machine.begin(VpnStatus.preparing);

    expect(machine.transition(obsolete, VpnStatus.connected), isFalse);
    expect(machine.state, VpnStatus.preparing);
    expect(machine.transition(current, VpnStatus.connecting), isTrue);
  });

  test('reste bloqué après un échec puis autorise la déconnexion', () {
    final machine = VpnConnectionStateMachine();
    final reconnect = machine.begin(VpnStatus.preparing);

    expect(machine.transition(reconnect, VpnStatus.connecting), isTrue);
    expect(machine.transition(reconnect, VpnStatus.blocked), isTrue);
    machine.finish(reconnect);

    final disconnect = machine.begin(VpnStatus.disconnecting);
    expect(machine.transition(disconnect, VpnStatus.disconnected), isTrue);
    machine.finish(disconnect);
    expect(machine.state, VpnStatus.disconnected);
  });
}
