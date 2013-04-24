module TestDescriptions

  TESTDATA = to_binary %q{
    81:C9:00:07:3D:43:3B:B7:82:7A:AC:3D:00:00:00:00:
    00:CB:34:3C:00:00:00:06:10:91:6C:D3:00:00:00:00:
    81:CA:00:06:3D:43:3B:B7:01:10:7A:68:2D:76:71:2D:
    31:2E:77:69:6E:67:6F:2E:63:68:00:00:80:D0:00:06:
    3D:43:3B:B7:3D:43:3B:B7:D5:1C:10:91:6C:D4:02:4B:
    0C:02:00:B2:00:00:00:02:81:CF:00:0F:3D:43:3B:B7:
    06:E0:00:09:82:7A:AC:3D:1E:6F:34:3D:00:00:00:00:
    00:00:00:00:00:00:00:00:00:00:00:15:00:00:00:06:
    00:00:00:05:00:00:00:00:01:00:00:03:82:7A:AC:3D:
    1E:6F:34:3D:55:CC:E0:00
  }

  RECEIVER_REPORT_PACKET = to_binary %q{
    81:C9:00:07:3D:43:3B:B7:82:7A:AC:3D:00:00:00:00:
    00:CB:34:3C:00:00:00:06:10:91:6C:D3:00:00:00:00
  }

  SOURCE_DESCRIPTION_PACKET = to_binary %q{
    81:CA:00:06:3D:43:3B:B7:01:10:72:74:63:70:2E:65:
    78:61:6D:70:6C:65:2E:63:6F:6D:00:00
  }

  EXTENDED_REPORT_PACKET = to_binary %q{
    81:CF:00:0F:3D:43:3B:B7:06:E0:00:09:82:7A:AC:3D:
    1E:6F:34:3D:00:00:00:00:00:00:00:00:00:00:00:00:
    00:00:00:15:00:00:00:06:00:00:00:05:00:00:00:00:
    01:00:00:03:82:7A:AC:3D:1E:6F:34:3D:55:CC:E0:00
  }

  # Extracted from example capture file available at:
  # http://wiki.wireshark.org/RTCP
  # Real-time Transport Control Protocol (Sender Report)
  #
  # Sender SSRC: 0xf3cb2001 (4090175489)
  # MSW and LSW as NTP timestamp: Jan  1, 1970 09:28:01.917999000 UTC
  # RTP timestamp: 37920
  # Sender's packet count: 158
  # Sender's octet count: 39816
  SENDER_REPORT_PACKET = to_binary %q{
    80:c8:00:06:f3:cb:20:01:83:ab:03:a1:eb:02:0b:3a:
    00:00:94:20:00:00:00:9e:00:00:9b:88
  }

  # Extracted from example capture file available at:
  # http://wiki.wireshark.org/RTCP
  # Real-time Transport Control Protocol (Sender Report)
  # 
  # Chunk 1:
  #   Identifier: 0xf3cb2001 (4090175489)
  #   Type: CNAME (user and domain) (1)
  #   Text: outChannel
  SOURCE_DESCRIPTION_PACKET_2 = to_binary %q{
    81:ca:00:05:f3:cb:20:01:01:0a:6f:75:74:43:68:61:
    6e:6e:65:6c:00:00:00:00
  }

  # Extracted from example capture file available at:
  # http://www.wireshark.org/lists/wireshark-dev/200808/msg00050.html
  #
  # Identifier: 0x54857995 (1418033557)
  # Text: mmptest
  BYE_WITH_REASON_PACKET = to_binary %q{
    81:cb:00:03:54:85:79:95:07:6d:6d:70:74:65:73:74
  }

  # Capture from communication between Set-Top Box and VQE-S
  APP_PACKET = to_binary %q{
    81:CC:00:0B:EB:31:1D:FF:50:4C:49:49:06:00:04:00:
    00:00:C8:07:00:04:00:00:0D:2E:0D:00:04:00:00:00:
    01:0F:00:04:00:00:00:00:10:00:04:00:00:00:00:00
  }

  # Capture from communication between Set-Top Box and VQE-S
  PSFB_PACKET = to_binary %q{
    81:CE:00:02:EB:31:1D:FF:00:00:00:00
  }

  # Capture from communication between Set-Top Box and VQE-S
  RSI_PACKET = to_binary %q{
    81:D1:00:03:EB:31:1D:FF:00:00:00:00:93:61:A0:50
  }
end
