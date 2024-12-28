#    TOTP Application on Windows to bypass phone or other device requirements for 2FA
#    Copyright (C) 2024  Maurice Lambert

#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.

#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.

#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.

# To compile on windows with nim 2.0.8:
# nim --app:gui c --stackTrace:off  --lineTrace:off --checks:off --assertions:off -d:release -d=mingw --opt:size --passl:"-s" TotpWinExe.nim

import strutils, times, nimcrypto/hmac, nimcrypto/sha, endians
import winim/lean
import base32

const
  WINDOW_WIDTH = 450
  WINDOW_HEIGHT = 150
  PROGRESS_WIDTH = 410
  PROGRESS_HEIGHT = 20
  MARGE_WIDTH = 20
  MARGE_HEIGHT = 50
  BUTTON_WIDTH = 50
  CODE_WIDTH = 80
  LINE_HEIGHT = 30
  ENTRY_WIDTH = 120
  LABEL_WIDTH = 95

const
  PBM_SETRANGE = WM_USER + 1
  PBM_SETPOS = WM_USER + 2
  PROGRESS_CLASS = "msctls_progress32"

const
  idCopyButton = 1
  idEditSecret = 2
  idTimer = 1  # Unique identifier for the timer
  BUFFER_SIZE = 256
  DURATION = 30
  CHARACTER_NUMBER = 6

proc get_progress(): int32 =
  var now_time = getTime().toUnix()
  var start_time = now_time - (now_time mod DURATION)
  var elapsed_time = now_time - start_time
  return ((elapsed_time / DURATION) * 100).toInt().int32

var
  hInstance: HINSTANCE
  hWindow: HWND
  hProgressBar: HWND
  hEdit: HWND
  hLabel: HWND
  hOutputLabel: HWND
  hCopyButton: HWND
  msg: MSG
  wc: WNDCLASSEX
  progress: int32 = get_progress()
  code: string

const
  DWMWA_USE_IMMERSIVE_DARK_MODE = 20

# Declare the DwmSetWindowAttribute function
proc DwmSetWindowAttribute(hwnd: HWND, attr: int32, value: pointer, size: int32): int32 {.importc: "DwmSetWindowAttribute", dynlib: "dwmapi.dll".}

proc totp() =
  var buffer: array[BUFFER_SIZE, WCHAR]
  let length = GetWindowText(cast[HWND](hEdit), addr buffer[0], int32(BUFFER_SIZE))
  var secret = $cast[WideCString](addr buffer[0])
  if secret.len == 0 or secret.len > 16:
    return
  let remainder = secret.len mod 8
  if remainder == 1 or remainder == 3 or remainder == 6:
    return
  secret = secret.toUpperAscii()
  for char in secret:
    if "0123456789ABCDEFGHIJKLMNOPQRSTUV".find(char) == -1:
      return
  let secret_decoded = decode(secret & repeat('=', (8 - secret.len) mod 8))
  let currentTime = getTime().toUnix()
  let timeCounter = int(currentTime div DURATION)
  let timeBytes = cast[ptr UncheckedArray[byte]](addr timeCounter)

  var littleEndianBytes: array[8, byte]
  for i in 0..<8:
    littleEndianBytes[i] = timeBytes[7 - i]

  let hmacResult = sha1.hmac(cast[ptr byte](addr secret_decoded[0]), uint(len(secret_decoded)), cast[ptr byte](addr littleEndianBytes), uint(sizeof(timeCounter)))

  let index = int(hmacResult.data[19] and 0x0F)
  var value: uint32
  copyMem(addr value, unsafeAddr hmacResult.data[index], 4)
  bigEndian32(addr value, addr value)
  value = value and 0x7FFFFFFF

  code = align($value, CHARACTER_NUMBER, '0')[^CHARACTER_NUMBER..^1]

  SetWindowText(hOutputLabel, code)

proc WindowProc(hwnd: HWND, uMsg: UINT, wParam: WPARAM, lParam: LPARAM): LRESULT {.stdcall.} =
  case uMsg
  of WM_DESTROY:
    PostQuitMessage(0)
    return 0
  of WM_TIMER:
    if progress < 100:
      progress = get_progress()
      SendMessage(hProgressBar, PBM_SETPOS, WPARAM(progress), 0)
    else:
      progress = 0
      totp()
    return 0
  of WM_COMMAND:
    var wmId = LOWORD(wParam);
    var wmEvent = HIWORD(wParam);
    if wmId == idEditSecret and wmEvent == EN_CHANGE:
      totp()
    elif wmId == idCopyButton and wmEvent == BN_CLICKED:
      if OpenClipboard(hwnd):
        EmptyClipboard()
        let hMem = GlobalAlloc(GMEM_MOVEABLE, cast[SIZE_T](code.len + 1))
        if hMem != 0:
          let pMem = GlobalLock(hMem)
          if pMem != nil:
            var code_cstring: array[7, char] = ['0', '0', '0', '0', '0', '0', '0']
            var code_bytes = cast[ptr UncheckedArray[char]](addr code[0])
            for i in 0..<6:
              code_cstring[i] = code_bytes[i * 2]
            copyMem(pMem, addr code_cstring, code.len + 1)
            GlobalUnlock(hMem)
            if SetClipboardData(CF_TEXT, hMem) == 0:
              GlobalFree(hMem)
        CloseClipboard()
    return 0

  of WM_CTLCOLORBTN:
    let hdcButton = cast[HDC](wParam)
    let brush = CreateSolidBrush(DKGRAY_BRUSH)
    SetBkColor(hdcButton, DKGRAY_BRUSH)
    SetTextColor(hdcButton, LTGRAY_BRUSH)
    return cast[LRESULT](brush)

  of WM_PAINT:
    var ps: PAINTSTRUCT
    var hdc = BeginPaint(hwnd, addr ps)
    EndPaint(hwnd, addr ps)
    return 0
  else:
    return DefWindowProc(hwnd, uMsg, wParam, lParam)

proc main() =
  hInstance = GetModuleHandle(nil)

  wc.cbSize = sizeof(WNDCLASSEX).UINT
  wc.style = CS_HREDRAW or CS_VREDRAW
  wc.lpfnWndProc = WindowProc
  wc.hInstance = hInstance
  wc.hCursor = LoadCursor(0, IDC_ARROW)
  # wc.hbrBackground = COLOR_WINDOW + 1
  # wc.hbrBackground = GetStockObject(0x0018dfa5)
  wc.hbrBackground = GetStockObject(DKGRAY_BRUSH)
  wc.lpszClassName = "WindowTOTP"

  if RegisterClassEx(addr wc) == 0:
    MessageBox(0, "Failed to register window class", "Error", MB_ICONERROR)
    return

  hWindow = CreateWindowEx(
    0,
    "WindowTOTP".cstring,
    "TOTP Application".cstring,
    WS_OVERLAPPED or WS_CAPTION or WS_SYSMENU or WS_MINIMIZEBOX,
    CW_USEDEFAULT,
    CW_USEDEFAULT,
    WINDOW_WIDTH,
    WINDOW_HEIGHT,
    0,
    0,
    hInstance,
    nil
  )

  if hWindow == 0:
    MessageBox(0, "Failed to create window", "Error", MB_ICONERROR)
    return

  let enableDarkMode = true.int32()
  let is_enable = DwmSetWindowAttribute(hWindow, DWMWA_USE_IMMERSIVE_DARK_MODE, cast[pointer](addr enableDarkMode), sizeof(enableDarkMode).int32())
  SetWindowPos(hWindow, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE or SWP_NOSIZE)

  # Create Label for "Secret:"
  hLabel = CreateWindowEx(
    0,
    "STATIC".cstring,
    "Secret:".cstring,
    WS_CHILD or WS_VISIBLE,
    WINDOW_WIDTH - (PROGRESS_WIDTH + MARGE_WIDTH), 
    WINDOW_HEIGHT - PROGRESS_HEIGHT - MARGE_HEIGHT * 2,
    LABEL_WIDTH,
    LINE_HEIGHT,
    hWindow,
    0,
    hInstance,
    nil
  )

  if hLabel == 0:
    MessageBox(0, "Failed to create text", "Error", MB_ICONERROR)

  # Create Edit Control for input next to "Secret:"
  hEdit = CreateWindowEx(
    WS_EX_CLIENTEDGE,
    "EDIT".cstring,
    "".cstring,
    WS_CHILD or WS_VISIBLE or ES_AUTOHSCROLL,
    WINDOW_WIDTH - (PROGRESS_WIDTH + MARGE_WIDTH) + LABEL_WIDTH + MARGE_WIDTH, 
    WINDOW_HEIGHT - PROGRESS_HEIGHT - MARGE_HEIGHT * 2,
    ENTRY_WIDTH,
    LINE_HEIGHT, 
    hWindow,
    cast[HMENU](idEditSecret),
    hInstance,
    nil
  )

  if hEdit == 0:
    MessageBox(0, "Failed to create entry", "Error", MB_ICONERROR)

  # Create Output Label next to Edit Control 
  hOutputLabel = CreateWindowEx(
    WS_EX_CLIENTEDGE,
    "STATIC".cstring,
    "".cstring,
    WS_CHILD or WS_VISIBLE,
    WINDOW_WIDTH - (PROGRESS_WIDTH + MARGE_WIDTH) + ENTRY_WIDTH + MARGE_WIDTH + LABEL_WIDTH + MARGE_WIDTH, 
    WINDOW_HEIGHT - PROGRESS_HEIGHT - MARGE_HEIGHT * 2,
    CODE_WIDTH,
    LINE_HEIGHT,
    hWindow,
    0,
    hInstance,
    nil
  )

  if hOutputLabel == 0:
    MessageBox(0, "Failed to create output label", "Error", MB_ICONERROR)

  # Create Copy Button 
  hCopyButton = CreateWindowEx(
    0,
    "BUTTON".cstring,
    "Copy".cstring,
    WS_CHILD or WS_VISIBLE or BS_PUSHBUTTON,
    WINDOW_WIDTH - (PROGRESS_WIDTH + MARGE_WIDTH) + CODE_WIDTH + MARGE_WIDTH + ENTRY_WIDTH + MARGE_WIDTH + LABEL_WIDTH + MARGE_WIDTH, 
    WINDOW_HEIGHT - PROGRESS_HEIGHT - MARGE_HEIGHT * 2,
    BUTTON_WIDTH,
    LINE_HEIGHT,
    hWindow,
    cast[HMENU](idCopyButton),
    hInstance,
    nil
  )

  if hCopyButton == 0:
    MessageBox(0, "Failed to create button", "Error", MB_ICONERROR)

  # Create Progress Bar 
  hProgressBar = CreateWindowEx(
    0,
    PROGRESS_CLASS,
    nil,
    WS_CHILD or WS_VISIBLE,
    (WINDOW_WIDTH - PROGRESS_WIDTH) div 2,
    WINDOW_HEIGHT - PROGRESS_HEIGHT - MARGE_HEIGHT,
    PROGRESS_WIDTH,
    PROGRESS_HEIGHT,
    hWindow,
    0,
    hInstance,
    nil
  )

  if hProgressBar == 0:
    MessageBox(0, "Failed to create progress bar", "Error", MB_ICONERROR)
    return

  SendMessage(hProgressBar, PBM_SETRANGE, WPARAM(get_progress()), MAKELPARAM(0, 100))
  SetTimer(hWindow, idTimer, 300, nil) # Timer for progress bar update

  ShowWindow(hWindow, SW_SHOW)
  UpdateWindow(hWindow)

  while GetMessage(addr msg, 0, 0 ,0) > 0:
    TranslateMessage(addr msg)
    DispatchMessage(addr msg)

when isMainModule:
   main()
