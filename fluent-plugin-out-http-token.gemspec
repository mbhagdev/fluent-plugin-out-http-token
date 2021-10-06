
lib = File.expand_path("../lib", __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)

Gem::Specification.new do |spec|
  spec.name          = "fluent-plugin-out-http-token"
  spec.version       = "1.0.0"
  spec.authors       = ["Mahesh Bhagdev"]
  spec.email         = ["Mahesh.Bhagdev@sap.com"]

  spec.summary       = %q{A Fluentd output plugin to send logs to an HTTP endpoint with bearer token auth}
  spec.description   = %q{Fetches the token using the provided token api before calling the endpoint}
  spec.homepage      = "https://github.tools.sap/DataCustodian/starship-proxy"

  # Prevent pushing this gem to RubyGems.org. To allow pushes either set the 'allowed_push_host'
  # to allow pushing to a single host or delete this section to allow pushing to any host.
  if spec.respond_to?(:metadata)
    spec.metadata["allowed_push_host"] = "TODO: Set to 'http://mygemserver.com'"

    spec.metadata["homepage_uri"] = spec.homepage
    spec.metadata["source_code_uri"] = "https://github.tools.sap/DataCustodian/starship-proxy"
  else
    raise "RubyGems 2.0 or newer is required to protect against " \
      "public gem pushes."
  end

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  spec.files         = Dir.chdir(File.expand_path('..', __FILE__)) do
    `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  end
  spec.executables   = spec.files.grep(%r{^bin/}).map{ |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.required_ruby_version  = '>= 2.1.0'

  spec.add_runtime_dependency "yajl-ruby", "~> 1.0"
  spec.add_runtime_dependency "fluentd", [">= 0.14.22", "< 2"]
  spec.add_development_dependency "bundler"
  spec.add_development_dependency "rake"
  spec.add_development_dependency "test-unit", ">= 3.1.0"
  spec.add_development_dependency "webrick"
end
