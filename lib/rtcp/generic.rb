# Generic RTCP packet
require_relative 'base'
class RTCP::Generic < RTCP::Base

  PT_ID = 999

  attr_reader :type_id, :data

  def decode(packet_data)
    @type_id, length = packet_data.unpack('xCn')
    @length = 4 * (length + 1)
    @data   = packet_data
    self
  end

end
