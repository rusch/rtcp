require 'spec_helper'
require 'rtcp'

describe RTCP::XR do
  subject do
    RTCP::XR.new
  end

  context '.decode' do
    it 'decodes "Extended Record" packets' do
      xr = subject.decode(EXTENDED_REPORT_PACKET)

      xr.version.should == 2
      xr.length.should == 64
      xr.ssrc.should == 1027816375
      xr.report_blocks.should be_kind_of(Array)
      xr.report_blocks.length.should == 3

      xr.report_blocks[0].should == {
        ssrc:         2189077565,
        type:         :statistics_summary,
        begin_seq:    7791,
        end_seq:      13373,
        lost_packets: 0,
        dup_packets:  0,
        jitter:       5
      }

      xr.report_blocks[1].should == {
        ssrc:         2189077565,
        type:         :statistics_summary,
        begin_seq:    7791,
        end_seq:      13373,
        lost_packets: 0,
        dup_packets:  0,
        jitter:       5
      }

      xr.report_blocks[2].should == {
        type:      :loss_rle,
        thinning:  0,
        begin_seq: 7791,
        end_seq:   13373,
        chunks:    [
          {
            chunk_type: :run_length,
            run_type:   1,
            run_length: 5580
          }, {
            chunk_type: :run_length,
            run_type:   1,
            run_length: 8192
          }
        ]
      }
    end
  end
end
