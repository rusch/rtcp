# APP: Application-Defined RTCP Packet
# Documentation: RFC 3550, 6.7
#
#        0                   1                   2                   3
#        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       |V=2|P| subtype |   PT=APP=204  |             length            |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       |                           SSRC/CSRC                           |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       |                          name (ASCII)                         |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       |                   application-dependent data                ...
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#        0                   1                   2                   3

require_relative 'base'
class RTCP::APP < RTCP::Base

  PT_ID = 204

  attr_reader :version, :subtype, :ssrc, :name, :data

  def decode(packet_data) 
    vpst, packet_type, length, @ssrc, @name, @data = packet_data.unpack('CCnNa4a*')
    ensure_packet_type(packet_type)

    @length  = 4 * (length + 1)
    @version = vpst >> 6
    @subtype = vpst & 31

    if packet_data.length > @length
      @data = @data[0..(@length - 13)]
    end

    self
  end

end
