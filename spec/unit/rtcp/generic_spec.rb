require 'spec_helper'
require 'rtcp'

describe RTCP::Generic do
  subject do
    RTCP::Generic.new
  end

  context '.decode' do
    it 'decodes RTCP packets' do
      packet = subject.decode(SOURCE_DESCRIPTION_PACKET)
      packet.type_id.should == 202
      packet.length.should == 28
      packet.data.should be_kind_of(String)
    end
  end
end
