// SPDX-License-Identifier: MPL-2.0
// Fixed references confined to windows.support; no paths or configuration data.
final runtimeStorageStages = Set<String>.unmodifiable(<String>{
  'wg_storage_program_data_lookup',
  'wg_storage_directory_open',
  'wg_storage_directory_descriptor',
  for (final target in [
    'ancestor',
    'program_data',
    'fuzevpn',
    'runtime',
    'wireguard',
  ])
    for (final operation in [
      'open',
      'metadata',
      'type',
      'path',
      'security',
      'descriptor',
      'owner',
      'acl',
    ])
      'wg_storage_${target}_$operation',
  for (final target in ['fuzevpn', 'runtime', 'wireguard'])
    'wg_storage_${target}_create',
  for (final operation in ['create', 'write', 'flush', 'close', 'replace'])
    'wg_storage_config_$operation',
});

// Steps of a failed protected-store write or delete ('storage_error').
const secureStoreStages = <String>{
  'secure_store_impersonation',
  'secure_store_path',
  'secure_store_protect',
  'secure_store_directory',
  'secure_store_create',
  'secure_store_write',
  'secure_store_flush',
  'secure_store_replace',
  'secure_store_delete',
};
