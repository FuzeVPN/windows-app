// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_SECURE_STORE_CHANNEL_H_
#define RUNNER_SECURE_STORE_CHANNEL_H_

#include <string>

#ifndef FUZEVPN_SERVICE_PROCESS
#include <flutter/flutter_engine.h>
#endif

#include "protected_store.h"

#ifndef FUZEVPN_SERVICE_PROCESS
void RegisterSecureStoreChannel(flutter::FlutterEngine* engine);
#endif


#endif
