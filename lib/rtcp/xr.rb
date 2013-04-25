# XR: Extended Report RTCP Packet
# Documentation: RFC 3611, 2.
#
#         0                   1                   2                   3
#         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#        |V=2|P|reserved |   PT=XR=207   |             length            |
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#        |                              SSRC                             |
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#        :                         report blocks                         :
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
# An extended report block has the following format:
#
#         0                   1                   2                   3
#         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#        |      BT       | type-specific |         block length          |
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#        :             type-specific block contents                      :
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
# The Statistics Summary Report Block has the following format:
#
#         0                   1                   2                   3
#         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#        |     BT=6      |L|D|J|ToH|rsvd.|       block length = 9        |
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#        |                        SSRC of source                         |
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#        |          begin_seq            |             end_seq           |
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#        |                        lost_packets                           |
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#        |                        dup_packets                            |
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#        |                         min_jitter                            |
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#        |                         max_jitter                            |
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#        |                         mean_jitter                           |
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#        |                         dev_jitter                            |
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#        | min_ttl_or_hl | max_ttl_or_hl |mean_ttl_or_hl | dev_ttl_or_hl |
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

class RTCP::XR < RTCP

  PT_ID = 207

  attr_reader :version, :ssrc, :report_blocks, :padding

  def decode(packet_data)
    vprc, packet_type, length, @ssrc = packet_data.unpack('CCnN')
    ensure_packet_type(packet_type)

    @version = vprc >> 6
    @length  = 4 * (length + 1)
    @report_blocks = []

    report_block_data = payload_data(packet_data, @length, 8)

    while report_block_data && report_block_data.length >= 4
      bt, length = report_block_data.unpack('Cxn')
      length = 4 * (length + 1)
      @report_blocks.push case bt
      when 1 # Loss RLE Report Block
        decode_loss_rle(report_block_data)
      when 6 # Statistics Summary Report
        decode_ssr(report_block_data)
      else
        {
          type:   bt,
          length: length,
          data:   report_block_data.slice(4..(length-1))
        }
      end

      report_block_data = report_block_data.slice(length..-1)
    end

    # Padding
    if (vprc & 16 == 16)
      @padding = report_block_data
    elsif (report_block_data != '')
      raise(RTCP::DecodeError, "Packet has undeclared padding")
    end

    self
  end

  private

  def decode_loss_rle(report_block_data)
    thinning, length, ssrc, begin_seq, end_seq, *values =
      report_block_data.unpack("xCnNn*")

    thinnig = thinning & 15
    length  = 4 * (length + 1)

    chunks = values.collect do |val|
      if (val && 32768) == 32768
        {
          chunk_type: :run_length,
          run_type:   (val >> 14) & 1,
          run_length: val & 16383,
        }
      else
        {
          chunk_type: :bit_vector,
          run_length: val & 32767,
        }
      end
    end

    return {
      type:      :loss_rle,
      thinning:  thinning,
      begin_seq: begin_seq,
      end_seq:   end_seq,
      chunks:    chunks,
    }
  end

  def decode_ssr(report_block_data)
    x, ssrc, begin_seq, end_seq, lost_packets, dup_packets, *values =
      report_block_data.unpack("xCx2NnnN6C4")

    report_block = {
      ssrc:      ssrc,
      type:      :statistics_summary,
      begin_seq: begin_seq,
      end_seq:   end_seq,
    }
    @report_blocks.push(report_block)

    if (x & 128 == 128)
      report_block[:lost_packets] = lost_packets
    end

    if (x & 64 == 64)
      report_block[:dup_packets] = dup_packets
    end

    if (x &  32 == 32)
      report_block[:min_jitter] = values[0]
      report_block[:max_jitter] = values[1]
      report_block[:mean_jitter] = values[2]
      report_block[:dev_jitter] = values[3]
    end

    case ((x >> 3) & 3)
    when 1 # IPv4 TTL values
      report_block[:min_ttl]  = values[4]
      report_block[:max_ttl]  = values[5]
      report_block[:mean_ttl] = values[6]
      report_block[:dev_ttl]  = values[7]
    when 2 # IPv6 Hop Limit values
      report_block[:min_hl]  = values[4]
      report_block[:max_hl]  = values[5]
      report_block[:mean_hl] = values[6]
      report_block[:dev_hl]  = values[7]
    end
    report_block
  end

end
