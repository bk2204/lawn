require_relative 'spec_helper'

describe "commands" do
  it "should close stdin when there's nothing left to read" do
    env = TestEnvironment.new
    env.start_server
    input = Random.new(42).bytes(1024 * 1024)
    data = env.run(%w[lawn run sha256sum], input: input, output: true)
    out, err = env.output_from_process(data)
    expect(out).to eq "5334d94d319d307d99d76d12c4d4c6a46824136485a3ddb222854d3b039b99b8  -\n"
    expect(err).to be_empty
  end

  it "should pass arguements to commands" do
    env = TestEnvironment.new
    env.start_server
    input = Random.new(42).bytes(1024 * 1024)
    data = env.run(%w[lawn run -- sha256sum -b], input: input, output: true)
    out, err = env.output_from_process(data)
    expect(out).to eq "5334d94d319d307d99d76d12c4d4c6a46824136485a3ddb222854d3b039b99b8 *-\n"
    expect(err).to be_empty
  end

  it "should not deadlock on slow pipes" do
    env = TestEnvironment.new
    env.start_server
    input = Random.new(42).bytes(1024)
    data = env.run(%w[lawn run -- stalled-sha256sum], input: input, output: true)
    out, err = env.output_from_process(data)
    expect(out).to eq "3fd55ccb8b82591ff968b38a0684cdc7cff512f66dbff086847a6500b11e840d  -\n"
    expect(err).to be_empty
  end
end
