require_relative 'rtcp/version'
require_relative 'rtcp/decode_error'
require_relative 'rtcp/sr'
require_relative 'rtcp/rr'
require_relative 'rtcp/sdes'
require_relative 'rtcp/bye'
require_relative 'rtcp/xr'
require_relative 'rtcp/app'
require_relative 'rtcp/rsi'
require_relative 'rtcp/psfb'

class RTCP

  attr_reader :length, :type_id

  @@packet_classes = {}
  self.constants.each do |sym|
    const = self.const_get(sym)
    if const.is_a?(Class) && const <= self
      @@packet_classes[const::PT_ID] = const
    end
  end

  # Decodes the supplied RTCP packet and returns it
  def self.decode(data)
    raise(RTCP::DecodeError, "Truncated Packet") if (data.length < 4)

    packet_type, length = data.unpack('xCn')
    length = 4 * (length + 1)
    raise(RTCP::DecodeError, "Truncated Packet") if (data.length < length)

    self.packet_class(packet_type).new.decode(data.slice(0..(length - 1)))
  end

  # Decodes all RTCP packets in the supplied string returns them in an array
  def self.decode_all(data)
    packets = []
    while data && data.length > 0
      packet = self.decode(data)
      packets.push(packet)
      data = data.slice(packet.length..-1)
    end
    packets
  end

  def decode(packet_data)
    @type_id, length = packet_data.unpack('xCn')
    @length      = 4 * (length + 1)

    @packet_data = packet_data
    self
  end

  # Returns the packet as RTCP data string
  def to_s
    @packet_data
  end

  protected

  # Ensures that the current RTCP Packet object is able to decode the RTCP
  # packet with the given Packet Type ID.
  #
  # Raises an RTCP::DecodeError exception when this is not the case.
  def ensure_packet_type(packet_type)
    if packet_type != self.class::PT_ID
      raise(RTCP::DecodeError, "Wrong Packet Type. packet_type=#{packet_type}")
    end
  end

  # Extracts and returns the payload data from the given packet_data using the
  # supplied packet length and header_length values.
  #
  # It also sets the @packet_data instance variable, which is currently used
  # by the to_s method for returning the packet data.
  #
  # Raises an RTCP::DecodeError exception when the packet_data is shorter
  # than packet_length.
  def payload_data(packet_data, packet_length, header_length)
    if packet_data.length > packet_length
      @packet_data = packet_data[0..packet_length]
    elsif packet_data.length == packet_length
      @packet_data = packet_data
    else
      raise RTCP::DecodeError, "Truncated Packet"
    end

    @packet_data[header_length..-1]
  end

  private

  # Returns the Class to use for handling RTCP packets of the given packet
  # type.
  def self.packet_class(packet_type)
    @@packet_classes[packet_type] || self
  end

end
