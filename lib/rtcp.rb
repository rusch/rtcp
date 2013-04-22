class RTCP

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

  PSFB_MSGS = {
    1 => :pli,  # Picture Loss Indication (PLI)
    2 => :sli,  # Slice Loss Indication (SLI)
    3 => :rpsi, # Reference Picture Selection Indication (RPSI)
   15 => :afb,  # Application layer FB (AFB) message
  }

  RTPFB_MSGS = {
    1 => :nack,
  }

  attr_reader :version, :packets, :rr, :sdes, :bye, :app, :rtpfb, :psfb, :xr,
    :avb, :rsi

  def initialize(args)
    payload = args.delete(:packet)
    if payload
      self.parse(payload)
    end
  end

  def dump
    str = "Version: #{@version}\n"
    @packets.each do |packet|
      str += "  - Type    : #{packet[:type]}\n"
      str += "    SSRC    : #{packet[:ssrc]}\n" if packet[:ssrc]
      (packet.keys - [:type, :ssrc]).each do |key|
        str += "    %-8s: %s\n" % [key.to_s.capitalize, packet[key]]
      end
    end
    return str
  end

  def parse(payload)
    @packets = []
    while payload && (payload.length >= 4)
      count, packet_type, len = payload.unpack('C2n')
      len = 4*(len+1)
      @version = count >> 6
      padding  = count & 16 == 16
      count    &= 15

      data = payload.slice(4..(len-1))
      payload = payload.slice(len..-1)

      @packets.push case packet_type
      # when 200 # SR - Sender Report (RFC 3550)
      when 201 then @rr    = parse_rr(count, data)
      when 202 then @sdes  = parse_sdes(count, data)
      when 203 then @bye   = parse_bye(count, data)
      when 204 then @app   = parse_app(count, data)
      when 205 then @rtpfb = parse_rtpfb(count, data)
      when 206 then @psfb  = parse_psfb(count, data)
      when 207 then @xr    = parse_xr(count, data)
      when 208 then @avb   = parse_avb(count, data)
      when 209 then @rsi   = parse_rsi(count, data)
      else
        {
          type:    packet_type,
          count:   count,
          payload: data
        }
      end

    end
  end

  private

  # RR - Receiver Report (RFC 3550)
  def parse_rr(count, payload)
    ssrc, payload = payload.unpack('Na*')
    reports_data = []
    1.upto(count) do
      report_data = Hash[[
        :ssrc,
        :fraction_lost,
        :cumulative_number_of_lost_packets,
        :extended_highest_sequence_number_received,
        :interarrival_jitter,
        :last_sr,
        :delay_since_last_sr,
      ].zip(payload.unpack('NCa3N4'))]
      payload = payload.slice(24..-1)

      # this is a 24bit big endian signed integer :(
      report_data[:cumulative_number_of_lost_packets] =
        (report_data[:cumulative_number_of_lost_packets] + 0.chr)
          .unpack('l>')[0] >> 8

      reports_data.push(report_data)
    end

    return {
      type:    :rr,
      ssrc:    ssrc,
      reports: reports_data
    }
  end

  # SDES - Source Description (RFC 3550)
  def parse_sdes(count, payload)
    chunks_data = []
    1.upto(count) do
      ssrc, type_id, len = payload.unpack('NCC')
      val, payload = payload.unpack("x6a#{len}a*")
      chunks_data.push({
        type: SDES_CHUNK_TYPES[type_id] || type_id,
        data: val
      })
    end

    if payload.unpack('C')[0] != 0
      # Something went wrong.
      puts "SDES decoding failed. Remainder: #{payload.inspect}"
    end

    return {
      type:    :sdes,
      chunks:  chunks_data
    }
  end

  # BYE - Goodbye (RFC 3550)
  def parse_bye(count, payload)
    ssrcs = payload.unpack("N#{count}C")
    rlen = ssrcs.pop
    bye = {
      type:    :bye,
      ssrcs:   ssrcs,
    }
    if rlen
      offset = (4 * count) + 1
      bye[:reason] = payload.slice(offset..(offset + rlen))
    end
    return bye
  end

  # APP - Application Defined (RFC 3550)
  def parse_app(count, payload)
    ssrc, name, data = payload.unpack('Na4a*')
    return {
      type:    :app,
      ssrc:    ssrc,
      name:    name,
      data:    data.unpack('H*')[0].split(/(..)/).reject { |_| _ == '' }.join(":"),
    }
  end

  # XR - Extended Report (RFC 3611)
  def parse_xr(count, payload)
    ssrc, report_blocks = payload.unpack('Na*')

    blocks = []
    while report_blocks && report_blocks.length >= 4
      bt, x, len = report_blocks.unpack('CCn')
      len = 4 * (len + 1)
      blocks.push case bt
      when 6 # Statistics Summary Report
        loss = x & 128 == 128 # Loss Report Flag
        dupl = x &  64 ==  64 # Duplicate Report Flag
        jitt = x &  32 ==  32 # Jitter Flag
        tohl = x &  24 > 0    # TTL or Hop Limit Flag(s)

        bs, es, lp, dp, *values =
          report_blocks.unpack("x8nnN6C4")

        {
          type: bt,
          len:          len,
          packet_loss:  loss,
          duplicate_packet: dupl,
          jitter:       jitt,
          ttl_hoplim:   tohl,
          begin_seq:    bs,
          end_seq:      es,
          lost_packets: lp,
          jitter:       values[0..3],
          ttl_or_hl:    values[4..7],
        }
      else
        {
          type: bt,
          x:    x,
          len:  len,
          data: report_blocks.slice(4..(len-1))
        }
      end

      # $TODO: parse block itself here
      report_blocks = report_blocks.slice(len..-1)
    end

    return {
      type:    :xr,
      ssrc:    ssrc,
      blocks:  blocks
    }
  end

  # AVB (Audio Video Bridging) Report (IEEE 1733)
  def parse_avb(count, payload)
    return {
      type:    :avbr,
      payload: payload
    }
  end


  # RSI - Receiver Summary Information (RFC 5760)
  def parse_rsi(count, payload)
    ssrc, ssrc_sum, ntph, ntpl, srb = payload.unpack('N4a*')

    srbs = [] # Sub-report blocks
    while srb && srb.length >= 2
      srbt, len = srb.unpack('CC')
      srbs.push({
        type: srbt,
        data: srb.slice(0..(len-1))
      })
      srb = srb.slice(len..-1)
    end

    return {
      type:    :rsi,
      ssrc:    ssrc,
      ssrc_sum: ssrc_sum,
      srbs:    srbs
    }
  end

  # RTPFB - Generic RTP Feedback (RFC 4585)
  def parse_rtpfb(fmt, payload)
    ssrc, ssrc_ms, fci = payload.unpack("NNa*")

    rtpfb = {
      type:    :rtpfb,
      message: RTPFB_MSGS[fmt] || fmt,
      ssrc:    ssrc,
      ssrc_ms: ssrc_ms,
    }

    if fmt == 1
      rtpfb[:pid], rtpfb[:blp] = fci.unpack('nn')
    else
      rtpfb[:fci] = fci
    end

    return rtpfb
  end

  # when 206 # PSFB - Payload-specific feedback (RFC 5760)
  def parse_psfb(fmt, payload)
    ssrc, ssrc_ms, fci = payload.unpack("NNa*")

    fmt = PSFB_MSGS[fmt] || fmt

    psfb = {
      type:    :psfb,
      format:  fmt,
      ssrc:    ssrc
    }

    case fmt
    when :sli
      pl  = fci.unpack('L')
      psfb[:first_mb]   = pl >> 19
      psfb[:number]     = (pl >> 6) & 8191
      psfb[:picture_id] = pl & 63
    # when :pli # No parameters
    # when :rpsi
    # when :afb
    end

    return psfb

  end

end
