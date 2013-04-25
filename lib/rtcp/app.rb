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

class RTCP::APP < RTCP

  PT_ID = 204

  attr_reader :version, :subtype, :ssrc, :name, :app_data

  def decode(packet_data) 
    vpst, packet_type, length, @ssrc, @name = packet_data.unpack('CCnNa4')
    ensure_packet_type(packet_type)

    @length  = 4 * (length + 1)
    @version = vpst >> 6
    @subtype = vpst & 31

    @app_data = payload_data(packet_data, @length, 12)

    self
  end

end
