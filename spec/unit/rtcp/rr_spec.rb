require 'spec_helper'
require 'rtcp'

describe RTCP::RR do
  subject do
    RTCP::RR.new
  end

  context '.decode' do
    it 'decodes "Receiver Record" packets' do
      rr = subject.decode(RECEIVER_REPORT_PACKET)

      rr.version.should == 2
      rr.length.should == 32
      rr.ssrc.should == 1027816375
      rr.padding.should == nil
      rr.report_blocks.should be_kind_of(Array)
      rr.report_blocks.length.should == 1

      report_block = rr.report_blocks.first
      report_block.should be_kind_of(Hash)
      report_block.keys.sort.should == [
        :absolute_lost,
        :delay_since_last_sr,
        :fraction_lost,
        :highest_sequence_number,
        :jitter,
        :last_sr,
        :ssrc,
      ]
      report_block[:absolute_lost].should == 0
      report_block[:delay_since_last_sr].should == 0
      report_block[:fraction_lost].should == 0
      report_block[:highest_sequence_number].should == 13317180
      report_block[:jitter].should == 6
      report_block[:last_sr].should == 277966035
      report_block[:ssrc].should == 2189077565
    end

    it 'does not consider the follwing packet to be padding' do
      expect { subject.decode(RECEIVER_REPORT_PACKET) }
        .not_to raise_error
    end

    it 'raises an RTCP::DecodeError when there is undeclared padding' do
      corrupt_packet = RECEIVER_REPORT_PACKET.clone + "xxxx"
      corrupt_packet[2] = 0.chr
      corrupt_packet[3] = 8.chr
      expect { subject.decode(corrupt_packet) }
        .to raise_error(RTCP::DecodeError, "Packet has undeclared padding")
    end

    it 'raises an RTCP::DecodeError when paket type is not "Receiver Record"' do
      expect { subject.decode(SOURCE_DESCRIPTION_PACKET) }
        .to raise_error(RTCP::DecodeError, /Wrong Packet Type/)
    end

  end
end
