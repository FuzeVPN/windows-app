// SPDX-License-Identifier: MPL-2.0
#ifndef FUZEVPN_TLS_TRUST_CHANNEL_H_
#define FUZEVPN_TLS_TRUST_CHANNEL_H_

#include <windows.h>
#include <flutter/flutter_engine.h>

#include <memory>

inline constexpr UINT kTlsTrustCompletedMessage = WM_APP + 45;

class TlsTrustChannel final {
 public:
  TlsTrustChannel(flutter::FlutterEngine* engine, HWND window);
  ~TlsTrustChannel();
  void ProcessCompletions();

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

#endif  // FUZEVPN_TLS_TRUST_CHANNEL_H_
