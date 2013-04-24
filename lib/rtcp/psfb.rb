# PSFB: Payload-specific FB message
# Documentation: RFC 4585, 6.1.
#
#        0                   1                   2                   3
#        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       |V=2|P|   FMT   |       PT      |          length               |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       |                  SSRC of packet sender                        |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       |                  SSRC of media source                         |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       :            Feedback Control Information (FCI)                 :
#       :                                                               :

require_relative 'base'
class RTCP::PSFB < RTCP::Base

  FORMATS = {
    1 => :pli,  # Picture Loss Indication (PLI)
    2 => :sli,  # Slice Loss Indication (SLI)
    3 => :rpsi, # Reference Picture Selection Indication (RPSI)
   15 => :afb,  # Application layer FB (AFB) message
  }

  PT_ID = 206

  attr_reader :version, :format, :sender_ssrc, :source_ssrc, :fci,
    :first_mb, :number, :picture_id

  def decode(packet_data) 
    vpfmt, packet_type, length, @sender_ssrc, @source_ssrc,
      fci_data = packet_data.unpack('CCnN2a*')
    ensure_packet_type(packet_type)

    @length  = 4 * (length + 1)
    @version = vpfmt >> 6
    format  = vpfmt & 31
    @format = FORMATS[format] || format

    if packet_data.length > @length
      fci_data = fci_data[0..(@length - 13)]
    end

    case @format
    when :sli
      pl  = fci.unpack('L')
      @first_mb   = pl >> 19
      @number     = (pl >> 6) & 8191
      @picture_id = pl & 63
    # when :pli # No parameters
    # when :rpsi
    # when :afb
    end
    self
  end

end
