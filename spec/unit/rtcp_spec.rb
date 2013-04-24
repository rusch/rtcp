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
      rtcps = RTCP.decode_all(TESTDATA)

      rtcps.should be_kind_of(Array)
      rtcps.length.should == 4 # TEST_DATA contains 4 RTCP packets
      rtcps[0].should be_kind_of(RTCP::RR)
      rtcps[1].should be_kind_of(RTCP::SDES)
      rtcps[2].should be_kind_of(RTCP::Generic)
      rtcps[3].should be_kind_of(RTCP::XR)
    end
  end

  context ".decode" do
    it "decodes the first packet and returns it as an RTCP:: object" do
      rtcp = RTCP.decode(RECEIVER_REPORT_PACKET + SOURCE_DESCRIPTION_PACKET)

      rtcp.should be_kind_of(RTCP::RR)
    end
  end
end
