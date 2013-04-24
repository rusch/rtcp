require 'spec_helper'
require 'rtcp'

describe RTCP::XR do
  subject do
    RTCP::XR.new
  end

  context '.decode' do
    it 'decodes "Extended Record" packets' do
      xr = subject.decode(XR_PACKET_1)

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
        min_jitter:   0,
        max_jitter:   21,
        mean_jitter:  6,
        dev_jitter:   5,
      }

      xr.report_blocks[1].should == {
        ssrc:         2189077565,
        type:         :statistics_summary,
        begin_seq:    7791,
        end_seq:      13373,
        lost_packets: 0,
        dup_packets:  0,
        min_jitter:   0,
        max_jitter:   21,
        mean_jitter:  6,
        dev_jitter:   5,
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

    it 'decodes "Extended Record" packets with IPv4 TTL values' do
      xr = subject.decode(XR_PACKET_2)

      xr.version.should == 2
      xr.length.should == 124
      xr.ssrc.should == 3974927014
      xr.report_blocks.should be_kind_of(Array)
      xr.report_blocks.length.should == 4

      # The first report block is of type :statistics_summary and contains
      # the IPv4 TTL values
      xr.report_blocks[0].should == {
        ssrc:         3974927014,
        type:         :statistics_summary,
        begin_seq:    6985,
        end_seq:      7325,
        lost_packets: 0,
        dup_packets:  0,
        max_jitter:   80,
        mean_jitter:  4,
        min_jitter:   0,
        dev_jitter:   223,
        min_ttl:      1,
        max_ttl:      2,
        mean_ttl:     3,
        dev_ttl:      4,

      }
    end

  end
end
