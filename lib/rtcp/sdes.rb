# SDES: Source Description RTCP Packet
# Documentation: RFC 3550, 6.5
#
#         0                   1                   2                   3
#         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# header |V=2|P|    SC   |  PT=SDES=202  |             length            |
#        +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
# chunk  |                          SSRC/CSRC_1                          |
#   1    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#        |                           SDES items                          |
#        |                              ...                              |
#        +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
# chunk  |                          SSRC/CSRC_2                          |
#   2    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#        |                           SDES items                          |
#        |                              ...                              |
#        +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

class RTCP::SDES < RTCP

  PT_ID = 202

  SDES_CHUNK_TYPES = {
    1 => :cname,
    2 => :name,
    3 => :email,
    4 => :phone,
    5 => :loc,
    6 => :tool,
    7 => :note,
    8 => :priv
  }

  attr_reader :version, :chunks

  def decode(packet_data) 
    vprc, packet_type, length = packet_data.unpack('CCn')
    ensure_packet_type(packet_type)

    @length  = 4 * (length + 1)
    @version = vprc >> 6
    count    = vprc & 15

    sdes_data = payload_data(packet_data, @length, 4)

    @chunks = (1..count).collect do
      ssrc, type_id, len = sdes_data.unpack('NCC')
      val, payload = sdes_data.unpack("x6a#{len}a*")

      {
        ssrc: ssrc,
        type: SDES_CHUNK_TYPES[type_id] || type_id,
        data: val
      }
    end
    self
  end

end
