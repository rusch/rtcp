require 'spec_helper'
require 'rtcp'

describe RTCP::SR do
  subject do
    RTCP::SR.new
  end

  context '.decode' do
    it 'decodes "Receiver Record" packets' do
      sr = subject.decode(SENDER_REPORT_PACKET)

      sr.version.should == 2
      sr.length.should == 28
      sr.ssrc.should == 4090175489
      sr.padding.should == nil
      sr.report_blocks.should be_kind_of(Array)
      sr.report_blocks.length.should == 0
      sr.rtp_timestamp.should == 37920
      sr.ntp_timestamp.should be_kind_of(Time)
      sr.ntp_timestamp.to_f.should == 34081.91799993673
      sr.packet_count.should == 158
      sr.octet_count.should == 39816
    end

    it 'does not consider the follwing packet to be padding' do
      expect { subject.decode(SENDER_REPORT_PACKET) }
        .not_to raise_error
    end

    it 'raises an RTCP::DecodeError when there is undeclared padding' do
      corrupt_packet = SENDER_REPORT_PACKET.clone + "xxxx"
      corrupt_packet[2] = 0.chr
      corrupt_packet[3] = 6.chr
      expect { subject.decode(corrupt_packet) }
        .to raise_error(RTCP::DecodeError, "Packet has undeclared padding")
    end

    it 'raises an RTCP::DecodeError when paket type is not "Receiver Record"' do
      expect { subject.decode(RECEIVER_REPORT_PACKET) }
        .to raise_error(RTCP::DecodeError, /Wrong Packet Type/)
    end

  end
end
