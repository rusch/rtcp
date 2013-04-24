require 'spec_helper'
require 'rtcp'

describe RTCP::BYE do
  subject do
    RTCP::BYE.new
  end

  context '.decode' do
    it 'decodes "Goodbye" packet' do
      packet = subject.decode(BYE_WITH_REASON_PACKET)
      packet.version.should == 2
      packet.length.should == 16
      packet.reason.should == 'mmptest'
      packet.ssrcs.should == [ 1418033557 ]
      packet.padding.should == nil
    end

    it 'raises an RTCP::DecodeError when paket type is not "Goodbye"' do
      expect { subject.decode(RECEIVER_REPORT_PACKET) }
        .to raise_error(RTCP::DecodeError, /Wrong Packet Type/)
    end

  end
end
