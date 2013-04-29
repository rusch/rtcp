# RSI: Receiver Summary Information Packet
# Documentation: RFC 5760, 7.1.1.
#
#       0                   1                   2                   3
#       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       |V=2|P|reserved |   PT=RSI=209  |             length            |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       |                           SSRC                                |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       |                       Summarized SSRC                         |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       |              NTP Timestamp (most significant word)            |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       |              NTP Timestamp (least significant word)           |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       :                       Sub-report blocks                       :
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       0                   1                   2                   3
#
# Sub-Report-Block Type
#
#        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       |     SRBT      |    Length     |                               |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+      SRBT-specific data       +
#       |                                                               |
#       :                                                               :
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
# Generic Sub-Report Block Fields
#
#        0                   1                   2                   3
#        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#       +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
#       |     SRBT      |    Length     |        NDB            |   MF  |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       |                   Minimum Distribution Value                  |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       |                   Maximum Distribution Value                  |
#       +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
#       |                      Distribution Buckets                     |
#       |                             ...                               |
#       |                             ...                               |
#       +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

class RTCP::RSI < RTCP

  PT_ID = 209

  attr_reader :version, :ssrc, :summarized_ssrc, :ntp_timestamp, :report_blocks

  def decode(packet_data) 
    vp, packet_type, length, @ssrc, @summarized_ssrc, ntp_h, ntp_l =
      packet_data.unpack('CCnN4')
    ensure_packet_type(packet_type)

    @length  = 4 * (length + 1)
    @version = vp >> 6
    @ntp_timestamp = Time.at(ntp_h - 2208988800 + (ntp_l.to_f / 0x100000000))
    @report_blocks = decode_reports(payload_data(packet_data, @length, 20))
    self
  end

  private

  def decode_reports(data)
    blocks = []
    while data && data.length >= 2
      type, len = report_block_data.unpack('CC')
      if data.length < len
        raise DecodeError, "Truncated Packet"
      end
      blocks.push({
        type: type,
        data: data.slice!(0..(len-1))
      })
    end
    blocks
  end

end
