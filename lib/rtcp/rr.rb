# RR: Receiver Report RTCP Packet
# Documentation: RFC 3550, 6.4.2
#
#         0                   1                   2                   3
#         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# header |V=2|P|    RC   |   PT=RR=201   |             length            |
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#        |                     SSRC of packet sender                     |
#        +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
# report |                 SSRC_1 (SSRC of first source)                 |
# block  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   1    | fraction lost |       cumulative number of packets lost       |
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#        |           extended highest sequence number received           |
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#        |                      interarrival jitter                      |
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#        |                         last SR (LSR)                         |
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#        |                   delay since last SR (DLSR)                  |
#        +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
# report |                 SSRC_2 (SSRC of second source)                |
# block  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   2    :                               ...                             :
#        +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
#        |                  profile-specific extensions                  |
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

require_relative 'base'
class RTCP::RR < RTCP::Base

  PT_ID = 201

  attr_reader :version, :ssrc, :report_blocks, :padding

  def decode(packet_data)
    vprc, packet_type, length, @ssrc, report_block_data =
      packet_data.unpack('CCnNa*')
    ensure_packet_type(packet_type)

    @length  = 4 * (length + 1)
    @version = vprc >> 6
    count    = vprc & 15

    if packet_data.length > @length
      report_block_data = report_block_data[0..(@length - 9)]
    end

    @report_blocks = (1..count).collect do
      report_block = Hash[[
        :ssrc,
        :fraction_lost,
        :absolute_lost,
        :highest_sequence_number,
        :jitter,
        :last_sr,
        :delay_since_last_sr,
      ].zip(report_block_data.unpack('NCa3N4'))]

      # This is a 24bit big endian signed integer :(
      report_block[:absolute_lost] =
        (0.chr + report_block[:absolute_lost]).unpack('l>')[0]

      report_block_data = report_block_data.byteslice(24..-1)

      report_block
    end

    # Padding
    if (vprc & 16 == 16)
      @padding = report_block_data
    elsif (report_block_data != '')
      raise(RTCP::DecodeError, "Packet has undeclared padding")
    end

    self
  end

end
