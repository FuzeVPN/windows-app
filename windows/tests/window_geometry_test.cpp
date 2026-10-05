// SPDX-License-Identifier: MPL-2.0
#include "../runner/window_geometry.h"

#include <cstdlib>
#include <iostream>

namespace {
void Require(bool condition) {
  if (!condition) std::abort();
}

bool Same(const RECT& a, const RECT& b) {
  return a.left == b.left && a.top == b.top && a.right == b.right &&
         a.bottom == b.bottom;
}

bool Inside(const RECT& bounds, const RECT& work) {
  return bounds.left >= work.left && bounds.top >= work.top &&
         bounds.right <= work.right && bounds.bottom <= work.bottom &&
         bounds.right > bounds.left && bounds.bottom > bounds.top;
}
}  // namespace

int main() {
  using fuzevpn_window::FitToWorkArea;
  using fuzevpn_window::InitialBounds;
  // The work area already excludes taskbars, including top/left taskbars.
  const RECT desktop{0, 0, 1920, 1040};
  const RECT initial = InitialBounds(desktop, 1080, 680, 96);
  Require(Same(initial, RECT{420, 180, 1500, 860}));

  const RECT laptop{0, 0, 1366, 728};
  for (UINT dpi : {96U, 120U, 144U, 192U}) {
    Require(Inside(InitialBounds(laptop, 1080, 680, dpi), laptop));
  }
  const RECT high_scale = InitialBounds(laptop, 1080, 680, 192);
  Require(high_scale.right - high_scale.left == 1302);
  Require(high_scale.bottom - high_scale.top == 664);

  const RECT left_monitor{-1280, 40, 0, 1024};
  Require(Inside(InitialBounds(left_monitor, 1080, 680, 144), left_monitor));
  const RECT user_size{-1100, 90, -250, 720};
  Require(Same(FitToWorkArea(user_size, left_monitor), user_size));

  // DPI increases / removed monitors: move and shrink only what no longer fits.
  Require(Same(FitToWorkArea(RECT{1800, 900, 2800, 1700}, desktop),
               RECT{920, 240, 1920, 1040}));
  Require(Same(FitToWorkArea(RECT{-40, -20, 1960, 1100}, desktop), desktop));
  const RECT narrow{70, 50, 870, 550};
  Require(Inside(InitialBounds(narrow, 1080, 680, 192), narrow));
  Require(Inside(InitialBounds(RECT{0, 0, 1, 1}, 1080, 680, 192),
                 RECT{0, 0, 1, 1}));
  Require(Same(InitialBounds(desktop, 1080, 680, 0), initial));
  std::cout << "Window geometry checks passed\n";
}
