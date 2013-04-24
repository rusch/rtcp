require 'spec_helper'
require 'rtcp/generic'

describe RTCP::Generic do
  subject do
    RTCP::Generic.new
  end

  context '.decode' do
    it 'decodes RTCP packets' do
      packet = subject.decode(SDES_PACKET_1)
      packet.type_id.should == 202
      packet.length.should == 28
      packet.data.should be_kind_of(String)
    end
  end
end
