require 'simplecov'
SimpleCov.start do
  add_filter "/spec/"
end

$:.unshift(File.dirname(__FILE__) + '/../lib')

def to_binary(data)
  [ data.gsub(/\s+/,'').split(':').join ].pack('H*')
end

Dir[File.dirname(__FILE__) + "/support/**/*.rb"].each { |f| require f }
include TestDescriptions
