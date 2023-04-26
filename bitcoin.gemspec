# -*- encoding: utf-8 -*-
$:.push File.expand_path("../lib", __FILE__)
require "bitcoin/version"

Gem::Specification.new do |s|
  s.name        = "bitcoin"
  s.version     = Bitcoin::VERSION
  s.authors     = ["paradisaeidae"]
  s.email       = ["paradisaeidae@gmail.com"]
  s.homepage    = ""
  s.summary     = %q{bitcoin utils and protocol in ruby}
  s.description = %q{This is a ruby library for interacting with the bitcoin protocol/network}
  s.homepage    = "https://github.com/paradisaeidae/bitcoin"

  s.rubyforge_project = "bitcoin"

  s.files         = `git ls-files`.split("\n")
  s.test_files    = `git ls-files -- {test,spec,features}/*`.split("\n")
  s.executables   = `git ls-files -- bin/*`.split("\n").map{ |f| File.basename(f) }
  s.require_paths = ["lib"]

  s.required_rubygems_version = ">= 3.2.26"

  s.add_runtime_dependency 'ffi'
  s.add_runtime_dependency 'scrypt' # required by Litecoin
  s.add_runtime_dependency 'eventmachine' # required for connection code
end
