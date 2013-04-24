# BYE: Goodbye RTCP Packet
# Documentation: RFC 3550, 6.6
#
#        0                   1                   2                   3
#        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       |V=2|P|    SC   |   PT=BYE=203  |             length            |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       |                           SSRC/CSRC                           |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       :                              ...                              :
#       +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
# (opt) |     length    |               reason for leaving            ...
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

class RTCP::BYE < RTCP::Generic

  PT_ID = 203

  attr_reader :version, :length, :ssrcs, :reason, :padding

  def decode(packet_data) 
    vpsc, packet_type, length, bye_data = packet_data.unpack('CCna*')
    ensure_packet_type(packet_type)

    @length  = 4 * (length + 1)
    @version = vpsc >> 6
    count    = vpsc & 15

    if packet_data.length > @length
      bye_data = bye_data[0..(@length - 5)]
    end

    @ssrcs = bye_data.unpack("N#{count}")

    if (4 * count) < bye_data.length
      rlen, data = bye_data.unpack("x#{4 * count}Ca*")
      @reason = data[0..(rlen - 1)]

      # If the string fills the packet to the next 32-bit boundary,
      # the string is not null terminated.  If not, the BYE packet
      # MUST be padded with null octets to the next 32- bit boundary.
      # $TODO: Remove padding?

      # $TODO: Check for/extract packet padding
    end
    self
  end

end
