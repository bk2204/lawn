require_relative 'spec_helper'

require 'digest'
require 'securerandom'

describe "clipboard" do
  it "should paste nothing when the clipboard is empty" do
    env = TestEnvironment.new
    env.start_server
    data = env.run(%w[lawn clip -o], output: true)
    out, _err = env.output_from_process(data)
    expect(out).to eq ''
  end

  it "should round-trip small amounts of data" do
    env = TestEnvironment.new
    env.start_server
    data = env.run(%w[lawn clip -i], input: "Hello, world!\n")
    env.wait_for_process(data)
    data = env.run(%w[lawn clip -o], output: true)
    out, _err = env.output_from_process(data)
    expect(out).to eq "Hello, world!\n"
  end

  it "should round-trip large amounts of data" do
    env = TestEnvironment.new
    env.start_server
    input = Random.new(42).bytes(1024 * 1024)
    data = env.run(%w[lawn clip -i], input: input, error: true)
    env.wait_for_process(data)
    data = env.run(%w[lawn clip -o], output: true)
    out, _err = env.output_from_process(data)
    expect(out.length).to eq input.length
    expect(out).to eq input
    expect(Digest::SHA256.base64digest(out)).to eq Digest::SHA256.base64digest(input)
  end

  it "should distinguish between the primary and clipboard" do
    env = TestEnvironment.new
    env.start_server
    data = env.run(%w[lawn clip -ip], input: "Hello, world!\n")
    env.wait_for_process(data)
    data = env.run(%w[lawn clip -ib], input: "Hello, New Jersey!\n")
    env.wait_for_process(data)
    data = env.run(%w[lawn clip -op], output: true)
    out, _err = env.output_from_process(data)
    expect(out).to eq "Hello, world!\n"
  end
end
