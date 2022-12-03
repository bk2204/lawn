require 'fileutils'
require 'tempfile'

class TestEnvironment
  attr_accessor :dir, :server, :fixtures, :verbose

  class Remover
    def initialize(dir, server, verbose)
      @dir = dir
      @server = server
      @verbose = verbose
    end

    def call(*args)
      FileUtils.remove_dir(@dir)
      unless @server[:pid].nil?
        Process.kill('TERM', @server[:pid])
      end
      if @verbose
        @server[:error].seek(0, :SET)
        $stderr.puts @server[:error].read
      end
    end
  end

  def initialize(**options)
    @dir = Dir.mktmpdir("lawn-spec")
    @server = nil
    @verbose = ENV["LAWN_TEST_DEBUG"] || options[:verbose]
    @fixtures = File.join(File.dirname(__FILE__), "fixtures")
    Dir.mkdir(File.join(@dir, "runtime"))
    Dir.mkdir(File.join(@dir, "mount"))
    Dir.mkdir(File.join(@dir, "clipboard"))
    Dir.mkdir(File.join(@dir, "mount", "client"))
    Dir.mkdir(File.join(@dir, "mount", "server"))
    Dir.mkdir(File.join(@dir, "home"))
    Dir.mkdir(File.join(@dir, "home", ".config"))
    Dir.mkdir(File.join(@dir, "home", ".config", "lawn"))
    Dir.mkdir(File.join(@dir, "tmp"))
    set_finalizer
  end

  def destroy
    ObjectSpace.undefine_finalizer(self)
    Remover.new(@dir, @server, @verbose).call
  end

  def set_finalizer
    ObjectSpace.undefine_finalizer(self)
    ObjectSpace.define_finalizer(self, Remover.new(@dir, @server, @verbose))
  end

  def run(args, **options)
    tmpdir = File.join(dir, "tmp")
    env = {
      "PATH" => "#{File.join(@fixtures, "bin")}:#{ENV["PATH"]}",
      "XDG_CONFIG_HOME" => File.join(dir, "home", ".config"),
      "XDG_RUNTIME_DIR" => File.join(dir, "runtime"),
      "HOME" => File.join(dir, "home"),
      "TMPDIR" => tmpdir,
      "SSH_AUTH_SOCK" => "/dev/null",
      # These two are not actually used by Lawn itself, but exist simply to
      # allow the config file and various helper programs to find the data they
      # need.
      "LAWN_SERVER_MOUNT" => File.join(dir, "mount", "server"),
      "LAWN_BASE_DIR" => dir,
    }
    data = {}
    inp = options.delete(:input)
    outp = options.delete(:output)
    err = options.delete(:error)
    unless inp.nil?
      data[:input] = Tempfile.create("lawn-spec", tmpdir, encoding: "ASCII-8BIT")
      data[:input].write(inp)
      data[:input].seek(0, :SET)
      options[:in] = data[:input]
    end
    if outp || err
      options[:out] = data[:output] = Tempfile.create("lawn-spec", tmpdir, encoding: "ASCII-8BIT")
      options[:err] = data[:error] = Tempfile.create("lawn-spec", tmpdir, encoding: "ASCII-8BIT")
    else
      options[:out] = options[:err] = :close
    end
    data[:pid] = Process.spawn(env, *args, **options)
    data
  end

  def wait_for_process(data)
    Process.wait(data[:pid])
  end

  def output_from_process(data)
    Process.wait(data[:pid])
    data[:output].seek(0, :SET)
    data[:error].seek(0, :SET)
    [data[:output].read, data[:error].read]
  end

  def start_server
    FileUtils.copy_file(File.join(@fixtures, "config.yaml"), File.join(@dir, "home", ".config", "lawn", "config.yaml"))
    data = if @verbose
             run(%w[lawn -vvv --no-detach server], output: true)
           else
             run(%w[lawn --no-detach server])
           end
    self.server = data
    set_finalizer
    while !File.exist?(File.join(@dir, "runtime", "lawn", "server-0.sock"))
      sleep 0.1
    end
  end
end
