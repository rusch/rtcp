require 'spec_helper'
require 'rtcp/psfb'

describe RTCP::PSFB do
  subject do
    RTCP::PSFB.new
  end

  context '.decode' do
    it 'decodes "Payload-specific FB message" packet' do
      packet = subject.decode(PSFB_PACKET)
      packet.version.should == 2
      packet.length.should == 12
      packet.sender_ssrc.should == 3945864703
      packet.source_ssrc.should == 0
      packet.format.should == :pli
    end

    it 'raises an RTCP::DecodeError when paket type is not "PSFB"' do
      expect { subject.decode(RECEIVER_REPORT_PACKET) }
        .to raise_error(RTCP::DecodeError, /Wrong Packet Type/)
    end

  end
end
