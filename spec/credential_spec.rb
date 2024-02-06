require_relative 'spec_helper'

describe "credentials" do
  def git_credential_approve(env, input)
    data = env.run([
      "git", "-c", "credential.helper=", "-c", "credential.helper=!lawn credential git", "credential", "approve"
    ], input: input, output: true)
    out, err = env.output_from_process(data)
    expect(out).to be_empty
    expect(err).to be_empty
  end

  def git_credential_reject(env, input)
    data = env.run([
      "git", "-c", "credential.helper=", "-c", "credential.helper=!lawn credential git", "credential", "reject"
    ], input: input, output: true)
    out, err = env.output_from_process(data)
    expect(out).to be_empty
    expect(err).to be_empty
  end

  def git_credential_fill(env, input)
    input = "url=https://git.example.com\n"
    data = env.run([
      "git", "-c", "credential.helper=", "-c", "credential.helper=!lawn credential git", "credential", "fill"
    ], input: input, output: true, env: {"GIT_TERMINAL_PROMPT" => "0"})
    env.output_from_process(data)
  end

  def create_vault(env, vault)
    input = "a01 mkdir #{vault}\n"
    data = env.run(%w[lawn credential script], input: input, output: true)
    out, err = env.output_from_process(data)
    expect(out).to eq "a01 ok mkdir #{vault}\n"
    expect(err).to be_empty
  end

  def cred_helper_test(env, reject_string)
    create_vault(env, "/memory/vault/")
    git_credential_approve(env, "url=https://git.example.com\nusername=foo\npassword=bar\n")

    out, err = git_credential_fill(env, "url=https://git.example.com\n")
    expect(err).to be_empty
    entries = out.chomp.split("\n").map { |ln| ln.split("=", 2) }.to_h
    expected = {"protocol" => "https", "host" => "git.example.com", "username" => "foo", "password" => "bar"}
    expect(entries).to eq expected

    git_credential_reject(env, reject_string)

    out, err = git_credential_fill(env, "url=https://git.example.com\n")
    expect(out).to be_empty
    # Git will try to prompt since the creds don't exist and complain.
    expect(err).to_not be_empty
  end

  it "should save and remove credentials from a Git credential helper using full credentials" do
    env = TestEnvironment.new
    env.start_server

    cred_helper_test(env, "url=https://git.example.com\nusername=foo\npassword=bar\n")
  end

  it "should save and remove credentials from a Git credential helper using just a username and URL" do
    env = TestEnvironment.new
    env.start_server

    cred_helper_test(env, "url=https://git.example.com\nusername=foo\n")
  end

  it "should save and remove credentials from a Git credential helper using just a URL" do
    env = TestEnvironment.new
    env.start_server

    cred_helper_test(env, "url=https://git.example.com\n")
  end
end
