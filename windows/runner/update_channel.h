// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_UPDATE_CHANNEL_H_
#define RUNNER_UPDATE_CHANNEL_H_
#include <windows.h>
#include <memory>
#include <flutter/flutter_engine.h>
constexpr UINT kUpdateCompletedMessage = WM_APP + 43;
class UpdateChannel final {
 public:
  UpdateChannel(flutter::FlutterEngine* engine, HWND window);
  ~UpdateChannel();
  void ProcessCompletions();
 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};
#endif
