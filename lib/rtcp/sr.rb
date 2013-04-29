# SR: Sender Report RTCP Packet
# Documentation: RFC 3550, 6.4.1
#
#         0                   1                   2                   3
#         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# header |V=2|P|    RC   |   PT=SR=200   |             length            |
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#        |                         SSRC of sender                        |
#        +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
# sender |              NTP timestamp, most significant word             |
# info   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#        |             NTP timestamp, least significant word             |
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#        |                         RTP timestamp                         |
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#        |                     sender's packet count                     |
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#        |                      sender's octet count                     |
#        +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
# report |                 SSRC_1 (SSRC of first source)                 |
# block  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   1    | fraction lost |       cumulative number of packets lost       |
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#        |           extended highest sequence number received           |
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#        |                      interarrival jitter                      |
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#        |                         last SR (LSR)                         |
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#        |                   delay since last SR (DLSR)                  |
#        +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
# report |                 SSRC_2 (SSRC of second source)                |
# block  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   2    :                               ...                             :
#        +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
#        |                  profile-specific extensions                  |
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

class RTCP::SR < RTCP

  PT_ID = 200

  attr_reader :version, :ssrc, :rtp_timestamp, :ntp_timestamp,
    :packet_count, :octet_count, :report_blocks, :padding

  def decode(packet_data)
    vprc, packet_type, length, @ssrc, ntp_h, ntp_l, @rtp_timestamp,
      @packet_count, @octet_count = packet_data.unpack('CCnN6')
    ensure_packet_type(packet_type)
    @length  = 4 * (length + 1)
    @version, @padding, rc = decode_vprc(vprc, @length - 28)
    @ntp_timestamp = Time.at(ntp_h - 2208988800 + (ntp_l.to_f / 0x100000000))
    @report_blocks = decode_reports(payload_data(packet_data, @length, 28), rc)
    self
  end

  protected

  def decode_reports(data, count)
    (1..count).collect do
      *values, data = data.unpack('NCa3N4a*')
      values[2] = (0.chr + values[2]).unpack('l>')[0]

      Hash[[
        :ssrc,
        :fraction_lost,
        :absolute_lost,
        :highest_sequence_number,
        :jitter,
        :last_sr,
        :delay_since_last_sr,
      ].zip(values)]
    end
  end

  def decode_vprc(vprc, payload_length)
    rc = vprc & 0x1f
    padding = vprc & 0x20 == 0x20
    if !padding && (payload_length > rc * 24)
      raise(RTCP::DecodeError, "Packet has undeclared padding")
    end
    [ (vprc >> 6), padding, rc ]
  end

end
