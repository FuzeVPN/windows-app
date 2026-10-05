// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_WINDOW_GEOMETRY_H_
#define RUNNER_WINDOW_GEOMETRY_H_

#include <windows.h>

#include <algorithm>

namespace fuzevpn_window {

// Work-area coordinates and window rectangles are physical desktop pixels.
// A fitting user-selected rectangle is returned unchanged.
inline RECT FitToWorkArea(const RECT& bounds, const RECT& work) {
  if (work.right <= work.left || work.bottom <= work.top) return bounds;
  const LONG width = (std::min)((std::max)(1L, bounds.right - bounds.left),
                                work.right - work.left);
  const LONG height = (std::min)((std::max)(1L, bounds.bottom - bounds.top),
                                 work.bottom - work.top);
  const LONG left = (std::clamp)(bounds.left, work.left, work.right - width);
  const LONG top = (std::clamp)(bounds.top, work.top, work.bottom - height);
  return {left, top, left + width, top + height};
}

inline RECT InitialBounds(const RECT& work, LONG logical_width,
                          LONG logical_height, UINT dpi) {
  const LONG work_width = (std::max)(1L, work.right - work.left);
  const LONG work_height = (std::max)(1L, work.bottom - work.top);
  const LONG padding = MulDiv(16, dpi == 0 ? 96 : dpi, 96);
  const LONG inset_x = (std::min)(padding, work_width / 4);
  const LONG inset_y = (std::min)(padding, work_height / 4);
  const LONG width = (std::clamp)(
      static_cast<LONG>(MulDiv(logical_width, dpi == 0 ? 96 : dpi, 96)), 1L,
      work_width - 2 * inset_x);
  const LONG height = (std::clamp)(
      static_cast<LONG>(MulDiv(logical_height, dpi == 0 ? 96 : dpi, 96)), 1L,
      work_height - 2 * inset_y);
  const LONG left = work.left + (work_width - width) / 2;
  const LONG top = work.top + (work_height - height) / 2;
  return {left, top, left + width, top + height};
}

}  // namespace fuzevpn_window

#endif  // RUNNER_WINDOW_GEOMETRY_H_
