$:.push File.expand_path("../lib", __FILE__)
require 'rtcp/version'

Gem::Specification.new do |s|
  s.name = %q{rtcp}
  s.version = RTCP::VERSION
  s.author = "Christian Rusch"

  s.description = %q{Parse RTCP data into Ruby objects}

  s.email = %{git@rusch.asia}
  s.extra_rdoc_files = Dir.glob("*.rdoc")
  s.files = Dir.glob("{lib,spec}/**/*") + Dir.glob("*.rdoc") +
    %w(Gemfile Rakefile rtcp.gemspec)
  s.homepage = %{http://github.com/rusch/rtcp}
  s.licenses = %w(MIT)
  s.rubygems_version = %q{1.5.2}
  s.summary = %{Parse RTCP data into Ruby objects}
  s.test_files = Dir.glob("spec/**/*")

  s.add_development_dependency 'bundler', "> 1.0.0"
  s.add_development_dependency 'rake'
  s.add_development_dependency 'rspec', ">= 2.6.0"
  s.add_development_dependency 'simplecov', ">= 0.5.0"
end
