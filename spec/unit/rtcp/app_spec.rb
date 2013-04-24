require 'spec_helper'
require 'rtcp'

describe RTCP::APP do
  subject do
    RTCP::APP.new
  end

  context '.decode' do
    it 'decodes "Application-Defined" packet' do
      packet = subject.decode(APP_PACKET)
      packet.version.should == 2
      packet.length.should == 48
      packet.subtype.should == 1
      packet.ssrc.should == 3945864703
      packet.name.should == 'PLII'
      packet.data.should be_kind_of(String)
    end

    it 'raises an RTCP::DecodeError when paket type is not "Application-Defined"' do
      expect { subject.decode(RR_PACKET_1) }
        .to raise_error(RTCP::DecodeError, /Wrong Packet Type/)
    end

  end
end
