require 'spec_helper'
require 'rtcp'

describe RTCP do
  context "Detect malformed data" do
    it "raises exception when packet is shorter than a property header" do
      expect { RTCP.decode("Hello") }
        .to raise_error RTCP::DecodeError
    end
  end

  context ".decode_all" do

    it "returns an empty array when there is nothing to decode" do
      rtcps = RTCP.decode_all("")

      rtcps.should == []
    end

    it "returns an array of RTCP:: objects" do
      rtcps = RTCP.decode_all(RR_PACKET_1 +
                              SDES_PACKET_1 +
                              AVB_PACKET +
                              XR_PACKET_1
                              )

      rtcps.should be_kind_of(Array)
      rtcps.length.should == 4 # TEST_DATA contains 4 RTCP packets
      rtcps[0].class.should == RTCP::RR
      rtcps[1].class.should == RTCP::SDES
      rtcps[2].class.should == RTCP
      rtcps[3].class.should == RTCP::XR
    end
  end

  context ".decode" do
    it "decodes the first packet and returns it as an RTCP:: object" do
      rtcp = RTCP.decode(RR_PACKET_1 + SDES_PACKET_1)

      rtcp.should be_kind_of(RTCP::RR)
    end
  end
end
