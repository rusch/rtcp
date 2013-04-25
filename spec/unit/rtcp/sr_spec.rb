require 'spec_helper'
require 'rtcp'

describe RTCP::SR do
  subject do
    RTCP::SR.new
  end

  context '.decode' do
    it 'decodes "Sender Record" packets' do
      sr = subject.decode(SR_PACKET_1)

      sr.version.should == 2
      sr.length.should == 28
      sr.ssrc.should == 4090175489
      sr.padding.should == nil
      sr.report_blocks.should be_kind_of(Array)
      sr.report_blocks.length.should == 0
      sr.rtp_timestamp.should == 37920
      sr.ntp_timestamp.should be_kind_of(Time)
      sr.ntp_timestamp.to_f.round(5).should == 34081.918
      sr.packet_count.should == 158
      sr.octet_count.should == 39816
    end

    it 'decodes "Sender Record" packets wit report blocks' do
      sr = subject.decode(SR_PACKET_2)

      sr.ssrc.should == 3655205709
      sr.report_blocks.should be_kind_of(Array)
      sr.report_blocks.length.should == 1
      sr.report_blocks.first.should == {
        ssrc:                    3974927014,
        fraction_lost:           0,
        absolute_lost:           0,
        highest_sequence_number: 58775,
        jitter:                  2,
        last_sr:                 0,
        delay_since_last_sr:     0,
      }
    end

    it 'does not consider the follwing packet to be padding' do
      expect { subject.decode(SR_PACKET_1) }
        .not_to raise_error
    end

    it 'raises an RTCP::DecodeError when there is undeclared padding' do
      corrupt_packet = SR_PACKET_1.clone + "xxxx"
      corrupt_packet[2] = 0.chr
      corrupt_packet[3] = 6.chr
      expect { subject.decode(corrupt_packet) }
        .to raise_error(RTCP::DecodeError, "Packet has undeclared padding")
    end

    it 'raises an RTCP::DecodeError when paket type is not "Sender Record"' do
      expect { subject.decode(RR_PACKET_1) }
        .to raise_error(RTCP::DecodeError, /Wrong Packet Type/)
    end

  end
end
