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

class RTCP::PSFB < RTCP

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
    vpfmt, packet_type, length, @sender_ssrc, @source_ssrc =
      packet_data.unpack('CCnN2')
    ensure_packet_type(packet_type)

    @length  = 4 * (length + 1)
    @version = vpfmt >> 6
    format  = vpfmt & 31
    @format = FORMATS[format] || format

    @fci_data = payload_data(packet_data, @length, 12)

    case @format
    when :sli
      pl  = @fci_data.unpack('L')
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
