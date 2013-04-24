require 'spec_helper'
require 'rtcp'

describe RTCP::RSI do
  subject do
    RTCP::RSI.new
  end

  context '.decode' do
    it 'decodes "Receiver Summary Information" packet' do
      packet = subject.decode(RSI_PACKET)
      packet.version.should == 2
      packet.length.should == 16
      packet.ssrc.should == 3945864703
      packet.summarized_ssrc.should == 0
      packet.ntp_timestamp.should be_kind_of(Time)
      packet.ntp_timestamp.to_f.should == 263659984.0
      packet.report_blocks.should be_kind_of(Array)
      packet.report_blocks.length.should == 0
    end

    it 'raises an RTCP::DecodeError when paket type is not "Application-Defined"' do
      expect { subject.decode(RR_PACKET_1) }
        .to raise_error(RTCP::DecodeError, /Wrong Packet Type/)
    end

  end
end
