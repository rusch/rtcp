require 'spec_helper'
require 'rtcp'

describe RTCP::SDES do
  subject do
    RTCP::SDES.new
  end

  context '.decode' do
    it 'decodes "Source Description" packet #1' do
      packet = subject.decode(SOURCE_DESCRIPTION_PACKET)
      packet.version.should == 2
      packet.length.should == 28
      packet.chunks.should be_kind_of(Array)
      packet.chunks.length.should == 1

      sdes_chunk = packet.chunks.first
      sdes_chunk.keys.sort.should == [ :data, :ssrc, :type ]
      sdes_chunk[:ssrc].should == 1027816375
      sdes_chunk[:type].should == :cname
      sdes_chunk[:data].should == 'rtcp.example.com'
    end

    it 'decodes "Source Description" packet #2' do
      packet = subject.decode(SOURCE_DESCRIPTION_PACKET_2)
      packet.version.should == 2
      packet.length.should == 24
      packet.chunks.should be_kind_of(Array)
      packet.chunks.length.should == 1

      sdes_chunk = packet.chunks.first
      sdes_chunk.keys.sort.should == [ :data, :ssrc, :type ]
      sdes_chunk[:ssrc].should == 4090175489
      sdes_chunk[:type].should == :cname
      sdes_chunk[:data].should == 'outChannel'
    end

    it 'raises an RTCP::DecodeError when paket type is not "Source Description"' do
      expect { subject.decode(RECEIVER_REPORT_PACKET) }
        .to raise_error(RTCP::DecodeError, /Wrong Packet Type/)
    end

  end
end
