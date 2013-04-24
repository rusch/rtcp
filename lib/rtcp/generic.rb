# Generic RTCP packet

class RTCP::Generic

  PT_ID = 999

  attr_reader :type_id, :length, :data

  def self.decode(packet_data)
    self.new.decode(packet_data)
  end

  def decode(packet_data)
    @type_id, length = packet_data.unpack('xCn')
    @length = 4 * (length + 1)
    @data   = packet_data
    self
  end

  protected

  def ensure_packet_type(packet_type)
    if packet_type != self.class::PT_ID
      raise(RTCP::DecodeError, "Wrong Packet Type. packet_type=#{packet_type}")
    end
  end

end
