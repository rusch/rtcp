class RTCP

  PSFB_MSGS = {
    1 => :pli,  # Picture Loss Indication (PLI)
    2 => :sli,  # Slice Loss Indication (SLI)
    3 => :rpsi, # Reference Picture Selection Indication (RPSI)
   15 => :afb,  # Application layer FB (AFB) message
  }

  RTPFB_MSGS = {
    1 => :nack,
  }

end
