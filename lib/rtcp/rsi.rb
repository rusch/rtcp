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

require_relative 'base'
class RTCP::RSI < RTCP::Base

  PT_ID = 209

  attr_reader :version, :ssrc, :summarized_ssrc, :ntp_timestamp, :report_blocks

  def decode(packet_data) 
    vp, packet_type, length, @ssrc, @summarized_ssrc, ntp_h, ntp_l,
      report_block_data = packet_data.unpack('CCnN4a*')
    ensure_packet_type(packet_type)

    @length  = 4 * (length + 1)
    @version = vp >> 6

    @ntp_timestamp = Time.at(ntp_h - 2208988800 + (ntp_l.to_f / 4294967296))

    if packet_data.length > @length
      report_block_data = report_block_data[0..(@length - 21)]
    end

   @report_blocks = []
    while report_block_data && report_block_data.length >= 2
      type, len = report_block_data.unpack('CC')
      @report_blocks.push({
        type: type,
        data: report_block_data.slice(0..(len-1))
      })
      report_block_data = report_block_data.slice(len..-1)
    end

    self
  end

end
