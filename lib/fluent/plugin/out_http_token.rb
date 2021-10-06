require 'net/http'
require 'uri'
require 'yajl'
require 'fluent/plugin/output'
require 'tempfile'
require 'openssl'
require 'zlib'
require 'json'

require_relative 'memory_cache'

class Fluent::Plugin::HTTPOutput < Fluent::Plugin::Output
  Fluent::Plugin.register_output('http_token', self)

  class RecoverableResponse < StandardError; end

  helpers :compat_parameters, :formatter

  DEFAULT_BUFFER_TYPE = "memory"
  DEFAULT_FORMATTER = "json"

  attr_accessor :cache
  private :cache


  def initialize
    super
    log.info "initializing #{self} ....."
    @cache = MemoryCache.new(minutes: 4)
  end

  # Endpoint URL ex. http://localhost.local/api/
  config_param :endpoint_url, :string

  # Set Net::HTTP.verify_mode to `OpenSSL::SSL::VERIFY_NONE`
  config_param :ssl_no_verify, :bool, :default => false

  # HTTP method
  config_param :http_method, :enum, list: [:get, :put, :post, :delete], :default => :post

  # form | json | text | raw
  config_param :serializer, :enum, list: [:json, :form, :text, :raw], :default => :form

  # Simple rate limiting: ignore any records within `rate_limit_msec`
  # since the last one.
  config_param :rate_limit_msec, :integer, :default => 0

  # Raise errors that were rescued during HTTP requests?
  config_param :raise_on_error, :bool, :default => true

  # Specify recoverable error codes
  config_param :recoverable_status_codes, :array, value_type: :integer, default: [503]

  # ca file to use for https request
  config_param :cacert_file, :string, :default => ''

  # specify client sertificate
  config_param :client_cert_path, :string, :default => ''

  # specify private key path
  config_param :private_key_path, :string, :default => ''

  # specify private key passphrase
  config_param :private_key_passphrase, :string, :default => '', :secret => true

  # custom headers
  config_param :custom_headers, :hash, :default => nil

  # 'none' | 'basic' | 'jwt' | 'bearer'
  config_param :authentication, :enum, list: [:none, :basic, :jwt, :bearer],  :default => :none
  config_param :username, :string, :default => ''
  config_param :password, :string, :default => '', :secret => true
  config_param :token, :string, :default => ''
  # Switch non-buffered/buffered plugin
  config_param :buffered, :bool, :default => false
  config_param :bulk_request, :bool, :default => false
  # Compress with gzip except for form serializer
  config_param :compress_request, :bool, :default => false

  config_section :buffer do
    config_set_default :@type, DEFAULT_BUFFER_TYPE
    config_set_default :chunk_keys, ['tag']
  end

  config_section :format do
    config_set_default :@type, DEFAULT_FORMATTER
  end

  # Token URL ex. http://localhost.local/api/token
  config_param :token_url, :string

  # Token apikey
  config_param :token_api_key, :string, :secret => true

  #Token password
  config_param :token_password, :string, :secret => true

  def configure(conf)
    compat_parameters_convert(conf, :buffer, :formatter)
    super

    log.info "***Now in configure for out_http***"

    @ssl_verify_mode = if @ssl_no_verify
                         OpenSSL::SSL::VERIFY_NONE
                       else
                         OpenSSL::SSL::VERIFY_PEER
                       end

    @ca_file = @cacert_file
    @last_request_time = nil
    raise Fluent::ConfigError, "'tag' in chunk_keys is required." if !@chunk_key_tag && @buffered

    if @formatter_config = conf.elements('format').first
      @formatter = formatter_create
    end

    if @bulk_request
      class << self
        alias_method :format, :bulk_request_format
      end
      @formatter = formatter_create(type: :json)
      @serializer = :x_ndjson # secret settings for bulk_request
    else
      class << self
        alias_method :format, :split_request_format
      end
    end
  end

  def start
    log.info "Now in start *****"
    super
  end

  def shutdown
    log.info "Now in shutting down *****"
    super
  end

  def format_url(tag, time, record)
    log.info "Now in format_url *****"
    @endpoint_url
  end

  def set_body(req, tag, time, record)
    log.info "Now in set_body ***** #{req} with serializer as #{@serializer}"
    if @serializer == :json
      set_json_body(req, record)
    elsif @serializer == :text
      set_text_body(req, record)
    elsif @serializer == :raw
      set_raw_body(req, record)
    elsif @serializer == :x_ndjson
      set_bulk_body(req, record)
    else
      req.set_form_data(record)
    end
    req
  end

  def set_header(req, tag, time, record)
    log.info "Now in set_header ***** #{req}"
    if @custom_headers
      @custom_headers.each do |k,v|
        req[k] = v
      end
      req
    else
      req
    end
  end

  def compress_body(req, data)
    return unless @compress_request
    gz = Zlib::GzipWriter.new(StringIO.new)
    gz << data

    req['Content-Encoding'] = "gzip"
    req.body = gz.close.string
  end

  def set_json_body(req, data)
    log.info "Now in set_json_body ***** #{data}"
    #req.body = Yajl.dump(data)
    req.body = "[#{Yajl.dump(data)}]"
    req['Content-Type'] = 'application/json'
    compress_body(req, req.body)
  end

  def set_text_body(req, data)
    log.info "Now in set_text_body ***** #{data}"
    req.body = data["message"]
    req['Content-Type'] = 'text/plain'
    compress_body(req, req.body)
  end

  def set_raw_body(req, data)
    log.info "Now in set_raw_body ***** #{data}"
    req.body = data.to_s
    req['Content-Type'] = 'application/octet-stream'
    compress_body(req, req.body)
  end

  def set_bulk_body(req, data)
    log.info "Now in set_bulk_body ***** #{data}"
    req.body = data.to_s
    req['Content-Type'] = 'application/x-ndjson'
    compress_body(req, req.body)
  end

  def create_request(tag, time, record)
    log.info "Now in create_request ***** #{tag} #{record} ** "
    url = format_url(tag, time, record)
    uri = URI.parse(url)
    req = Net::HTTP.const_get(@http_method.to_s.capitalize).new(uri.request_uri)
    set_body(req, tag, time, record)
    set_header(req, tag, time, record)
    log.info "created request with body #{req.body}"
    return req, uri
  end

  def http_opts(uri)
    log.info "Now in http_opts ***** #{uri}"
    opts = {
      :use_ssl => uri.scheme == 'https'
    }
    opts[:verify_mode] = @ssl_verify_mode if opts[:use_ssl]
    opts[:ca_file] = File.join(@ca_file) if File.file?(@ca_file)
    opts[:cert] = OpenSSL::X509::Certificate.new(File.read(@client_cert_path)) if File.file?(@client_cert_path)
    opts[:key] = OpenSSL::PKey.read(File.read(@private_key_path), @private_key_passphrase) if File.file?(@private_key_path)
    opts
  end

  def proxies
    ENV['HTTPS_PROXY'] || ENV['HTTP_PROXY'] || ENV['http_proxy'] || ENV['https_proxy']
  end

  def get_token
    log.info "get_token"
    cache.get("token") do
      refresh_token
    end
  end

  def refresh_token
    req, uri = create_token_request
    log.info("get_token req body = #{req.body}")
    res = Net::HTTP.start(uri.host, uri.port, **http_opts(uri)) {|http| http.request(req) }
    if res.is_a?(Net::HTTPSuccess)
      token_res = JSON.parse(res.body)
      log.info "successfully got token #{token_res["access_token"]}"
      return token_res["access_token"]
    else
      log.error "Unable to fetch token #{res.code} #{res.message} #{res.body}}"
    end
  end

  def create_token_request
    log.info "Now in create_token_request *****"
    uri = URI.parse(@token_url)
    req = Net::HTTP.const_get(@http_method.to_s.capitalize).new(uri.request_uri)
    req['Content-Type'] = 'application/json'
    req.body = get_token_request_body
    set_header(req, nil, nil, nil )
    return req, uri
  end

  def get_token_request_body
    input = {api_key: @token_api_key, password: @token_password}
    return JSON.generate(input)
  end

  def send_request(req, uri)
    log.info "Now in send_request ***** #{uri}"
    is_rate_limited = (@rate_limit_msec != 0 and not @last_request_time.nil?)
    if is_rate_limited and ((Time.now.to_f - @last_request_time) * 1000.0 < @rate_limit_msec)
      log.info('Dropped request due to rate limiting')
      return
    end

    res = nil

    begin
      if @authentication == :basic
        req.basic_auth(@username, @password)
      elsif @authentication == :bearer
        req['authorization'] = "bearer #{get_token}"
      elsif @authentication == :jwt
        req['authorization'] = "jwt #{@token}"
      end
      @last_request_time = Time.now.to_f

      if proxy = proxies
        proxy_uri = URI.parse(proxy)

        res = Net::HTTP.start(uri.host, uri.port,
                              proxy_uri.host, proxy_uri.port, proxy_uri.user, proxy_uri.password,
                              **http_opts(uri)) {|http| http.request(req) }
      else
        log.info "Now calling #{uri.host} with request #{req.body} content type #{req['Content-Type']}"
        res = Net::HTTP.start(uri.host, uri.port, **http_opts(uri)) {|http| http.request(req) }
        log.info "Got the response from ingress as #{res.code} #{res.message} #{res.body} "
      end

    rescue => e # rescue all StandardErrors
      # server didn't respond
      log.warn "Net::HTTP.#{req.method.capitalize} raises exception: #{e.class}, '#{e.message}'"
      raise e if @raise_on_error
    else
      unless res and res.is_a?(Net::HTTPSuccess)
        res_summary = if res
                        "#{res.code} #{res.message} #{res.body}"
                      else
                        "res=nil"
                      end
        if @recoverable_status_codes.include?(res.code.to_i)
          raise RecoverableResponse, res_summary
        else
          log.warn "failed to #{req.method} #{uri} (#{res_summary})"
        end
      end #end unless
    end # end begin
  end # end send_request

  def handle_record(tag, time, record)
    log.info "handle_record(tag, time, record):: #{tag} #{record}"
    if @formatter_config
      record = @formatter.format(tag, time, record)
    end
    req, uri = create_request(tag, time, record)
    send_request(req, uri)
  end

  def handle_records(tag, time, chunk)
    req, uri = create_request(tag, time, chunk.read)
    log.info "::handle_records(tag, time, chunk):: #{req}"
    send_request(req, uri)
  end

  def prefer_buffered_processing
    @buffered
  end

  def format(tag, time, record)
    # For safety.
  end

  def split_request_format(tag, time, record)
    [time, record].to_msgpack
  end

  def bulk_request_format(tag, time, record)
    @formatter.format(tag, time, record)
  end

  def formatted_to_msgpack_binary?
    if @bulk_request
      false
    else
      true
    end
  end

  def multi_workers_ready?
    true
  end

  def process(tag, es)
    log.info "Now in process #### #{tag} #{es}"
    es.each do |time, record|
      log.info "record to process is #{record}"
      handle_record(tag, time, record)
    end
  end

  def write(chunk)
    log.info "Now in write #### #{chunk}"
    tag = chunk.metadata.tag
    @endpoint_url = extract_placeholders(@endpoint_url, chunk)
    if @bulk_request
      time = Fluent::Engine.now
      handle_records(tag, time, chunk)
    else
      chunk.msgpack_each do |time, record|
        handle_record(tag, time, record)
      end
    end
  end
end

