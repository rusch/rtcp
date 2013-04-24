module TestDescriptions

  # Extracted from example capture file available at:
  # http://wiki.wireshark.org/RTCP
  # Real-time Transport Control Protocol (Sender Report)
  #
  # Sender SSRC: 0xf3cb2001 (4090175489)
  # MSW and LSW as NTP timestamp: Jan  1, 1970 09:28:01.917999000 UTC
  # RTP timestamp: 37920
  # Sender's packet count: 158
  # Sender's octet count: 39816
  SR_PACKET_1 = to_binary %q{
    80:c8:00:06:f3:cb:20:01:83:ab:03:a1:eb:02:0b:3a:
    00:00:94:20:00:00:00:9e:00:00:9b:88
  }

  # Extracted from example capture file available at:
  # https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=4589
  # MSW and LSW as NTP timestamp: Mar 17, 2010 07:49:41.844999000 UTC
  # RTP timestamp: 342440
  # Sender's packet count: 150
  # Sender's octet count: 25800
  # Source 1:
  #   Identifier: 0xecec92a6 (3974927014)
  SR_PACKET_2 = to_binary %q{
    81:c8:00:0c:d9:de:03:4d:cf:4b:08:15:d8:51:eb:85:
    00:05:39:a8:00:00:00:96:00:00:64:c8:ec:ec:92:a6:
    00:00:00:00:00:00:e5:97:00:00:00:02:00:00:00:00:
    00:00:00:00
  }

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

  XR_PACKET_1 = to_binary %q{
    81:CF:00:0F:3D:43:3B:B7:06:E0:00:09:82:7A:AC:3D:
    1E:6F:34:3D:00:00:00:00:00:00:00:00:00:00:00:00:
    00:00:00:15:00:00:00:06:00:00:00:05:00:00:00:00:
    01:00:00:03:82:7A:AC:3D:1E:6F:34:3D:55:CC:E0:00
  }

  # Extracted from example capture file available at:
  # https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=4589
  XR_PACKET_2 = to_binary %q{
    80:cf:00:1e:ec:ec:92:a6:06:e8:00:09:ec:ec:92:a6:
    1b:49:1c:9d:00:00:00:00:00:00:00:00:00:00:00:00:
    00:00:00:50:00:00:00:04:00:00:00:df:01:02:03:04:
    07:00:00:08:ec:ec:92:a6:00:00:00:00:00:00:1a:90:
    00:00:00:41:2e:33:11:10:7f:7f:7f:7f:0a:00:00:14:
    00:c8:01:f4:08:00:00:09:ec:ec:92:a6:1b:49:1c:9d:
    00:0b:00:0b:00:00:00:0b:00:01:00:0f:00:00:00:00:
    00:00:00:14:00:00:00:14:00:00:00:00
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
