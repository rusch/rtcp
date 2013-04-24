require_relative 'rtcp/version'
require_relative 'rtcp/decode_error'
require_relative 'rtcp/enums'
require_relative 'rtcp/generic'
require_relative 'rtcp/sr'
require_relative 'rtcp/rr'
require_relative 'rtcp/sdes'
require_relative 'rtcp/bye'
require_relative 'rtcp/xr'
require_relative 'rtcp/app'

class RTCP

  @@packet_classes = {
    RTCP::Generic::PT_ID => RTCP::Generic,
    RTCP::SR::PT_ID      => RTCP::SR,
    RTCP::RR::PT_ID      => RTCP::RR,
    RTCP::SDES::PT_ID    => RTCP::SDES,
    RTCP::XR::PT_ID      => RTCP::XR,
    RTCP::APP::PT_ID     => RTCP::APP,
  }

  attr_reader :version, :packets, :rr, :sdes, :bye, :app, :rtpfb, :psfb, :xr,
    :avb, :rsi

  # Decodes only the first RTCP packet and returns it
  def self.decode(data)
    raise(RTCP::DecodeError, "Truncated Packet") if (data.length < 4)

    packet_type, length = data.unpack('xCn')
    length = 4 * (length + 1)
    raise(RTCP::DecodeError, "Truncated Packet") if (data.length < length)

    self.packet_class(packet_type).decode(data.slice(0..(length - 1)))
  end

  # Decodes all RTCP packets and returns them in an array
  def self.decode_list(data)
    packets = []
    while data && data.length > 0
      packet = self.decode(data)
      packets.push(packet)
      data = data.slice(packet.length..-1)
    end
    packets
  end

  private

  def self.packet_class(packet_type)
    @@packet_classes[packet_type] || @@packet_classes[999]
  end

end
