class RTCP::Base

  attr_reader :length

  def self.decode(packet_data)
    self.new.decode(packet_data)
  end

  protected

  def ensure_packet_type(packet_type)
    if packet_type != self.class::PT_ID
      raise(RTCP::DecodeError, "Wrong Packet Type. packet_type=#{packet_type}")
    end
  end

end
