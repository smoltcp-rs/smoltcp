#!/usr/bin/ruby

require 'yaml'

travis_config = YAML.load_file('.travis.yml')
travis_config['matrix']['include'].each do |env|
  ENV['RUSTUP_TOOLCHAIN'] = env['rust']
  env['env'].scan(/(\w+)=\'(.+?)\'/) do
    ENV[$1] = $2
  end
  travis_config['script'].each do |cmd|
    $stderr.puts('+ ' + cmd.gsub(/\$(\w+)/) { ENV[$1] })
    system(cmd)
    $?.success? or exit 1
  end
  env['env'].scan(/(\w+)=\'(.+?)\'/) do
    ENV.delete $1
  end
end
