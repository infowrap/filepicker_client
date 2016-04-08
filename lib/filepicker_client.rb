require 'rest-client'
require 'json'
require 'base64'
require 'active_support/hash_with_indifferent_access'

# Client interface for Filepicker's REST API
class FilepickerClient
  FP_FILE_PATH = "https://www.filepicker.io/api/file/"    # Path that Filepicker file handles are located under
  FP_API_PATH = "https://www.filepicker.io/api/store/S3"  # Path to access the Filepicker API

  DEFAULT_POLICY_EXPIRY = 5 * 60  # 5 minutes (short for security, but allows for some wiggle room)

  # Creates a client that will use the given Filepicker key and secret for requests and signing operations
  # @param api_key [String] Filepicker API key
  # @param api_secret [String] Filepicker API secret
  # @param filepicker_cert [OpenSSL::X509::Certificate] Optional certificate for verifying HTTPS connections to Filepicker
  def initialize(api_key, api_secret, filepicker_cert=nil)
    @api_key = api_key
    @api_secret = api_secret
    @filepicker_cert = filepicker_cert
  end

  # Create policies and signatures for Filepicker operations.
  #
  # Allowed Options:
  #
  # * expiration_start - Time from which the expiry value should start
  # * expiry - Seconds until the signature should expire (defaults to DEFAULT_POLICY_EXPIRY)
  # * call - Filepicker calls to allow (String, Symbol or Array of the following: 'read', 'stat', 'convert', 'write', 'writeUrl', 'pick', 'store', 'storeUrl')
  # * handle - Handle of the specific file to grant permissions for
  # * path - Path in the storage that Filepicker uploads to that the operations should be restricted to
  # * min_size - Minimum allowed upload size
  # * max_size - Maximum allowed upload size
  #
  # @param options [Hash] Options for generating the desired signature
  # @return [Hash] The policy generated with the encoded policy and signature for use in Filepicker requests
  def sign(options={})
    options = convert_hash(options)
    options[:expiration_start] ||= Time.now
    options[:expiry] ||= DEFAULT_POLICY_EXPIRY

    policy = {
      'call' => options[:call]
    }

    # Restrict the scope of the operation to either the specified file or the path
    if options[:handle]
      policy['handle'] = options[:handle]
    elsif options[:path]
      policy['path'] = (options[:path] + '/').gsub(/\/+/, '/') # ensure path has a single, trailing '/'
    end

    if options[:min_size]
      policy['minsize'] = options[:min_size].to_i
    end

    if options[:max_size]
      policy['maxsize'] = options[:max_size].to_i
    end

    # Set expiration for <expiry> seconds from expiration start
    policy['expiry'] = (options[:expiration_start] + options[:expiry]).to_i.to_s

    # Generate policy in URL safe base64 encoded JSON
    encoded_policy = Base64.urlsafe_encode64(policy.to_json)

    # Sign policy using our API secret
    signature = OpenSSL::HMAC.hexdigest('sha256', @api_secret, encoded_policy)

    return convert_hash(
      policy: convert_hash(policy),
      encoded_policy: encoded_policy,
      signature: signature
    )
  end

  # Get Filepicker URI for the file with the given handle.
  # @param handle [String] Handle for the file in Filepicker
  # @return [URI] URI for the file in Filepicker
  def file_uri(handle)
    URI.parse(FP_FILE_PATH + handle)
  end

  # Get Filepicker URI for the file with the given handle signed for read and convert calls.
  # The expiry value returned with the URI indicates the time the URI will expire at.
  # @param handle [String] Handle for the file in Filepicker
  # @param expiry [Fixnum] Number of seconds until the URI should expire
  # @return [Hash] Hash with URI signed for read and convert calls (:uri) and the expiry for the URI (:expiry)
  def file_read_uri_and_expiry(handle, expiry=DEFAULT_POLICY_EXPIRY)
    signage = sign(
      expiry: expiry,
      handle: handle,
      call: ['read', 'convert']
    )

    uri = file_uri(handle)
    uri.query = encode_uri_query(
      signature: signage[:signature],
      policy: signage[:encoded_policy]
    )

    return convert_hash(
      uri: uri,
      expiry: signage[:policy]['expiry'].to_i
    )
  end

  # Store the given file at the given storage path through Filepicker.
  # @param path [String] Path the file should be organized under in the destination storage
  # @param file [File] File to upload
  # @return [FilepickerClientFile] Object representing the uploaded file in Filepicker
  def store(file, path=nil)
    signage = sign(path: path, call: :store)

    uri = URI.parse(FP_API_PATH)
    query_params = {
      key: @api_key,
      signature: signage[:signature],
      policy: signage[:encoded_policy]
    }
    query_params[:path] = signage[:policy]['path'] if path
    uri.query = encode_uri_query(query_params)
    resource = get_fp_resource uri

    response = resource.post fileUpload: file

    if response.code == 200
      response_data = JSON.parse response.body
      file = FilepickerClientFile.new(response_data, self)

      return file
    else
      raise FilepickerClientError, "failed to store (code: #{response.code})"
    end
  end

  # Store the file located at the given URL under the target storage path through Filepicker.
  # @param path [String] Path the file should be organized under in the destination storage
  # @param file_url [String] URL to get the file to upload from
  # @return [FilepickerClientFile] Object representing the uploaded file in Filepicker
  def store_url(file_url, path=nil)
    signage = sign(path: path, call: :store)

    uri = URI.parse(FP_API_PATH)
    query_params = {
      key: @api_key,
      signature: signage[:signature],
      policy: signage[:encoded_policy]
    }
    query_params[:path] = signage[:policy]['path'] if path
    uri.query = encode_uri_query(query_params)

    resource = get_fp_resource uri

    response = resource.post url: file_url.to_s

    if response.code == 200
      response_data = JSON.parse response.body
      file = FilepickerClientFile.new response_data, self

      return file
    else
      raise FilepickerClientError, "failed to store (code: #{response.code})"
    end
  end

  # Store a converted version of a file under the target storage path.
  #
  # For all available options, see Filepicker's [Image Conversion API](https://developers.inkfilepicker.com/docs/web/#inkblob-images).
  #
  # @param handle [String] Handle for the original file in Filepicker
  # @param path [String] Path the file should be organized under in the destination storage
  # @param options [Hash]
  # @return [FilepickerClientFile] Object representing the uploaded file in Filepicker
  def convert_and_store(handle, path=nil, options={})
    options = convert_hash(options)

    # Build a convert url for the file
    uri = file_uri(handle)
    uri.path += "/convert"

    # Sign to allow store of a new file under the target path.
    # The handle of the file being read is not required.
    signage = sign(
      expiry: DEFAULT_POLICY_EXPIRY,
      path: path,
      call: ['convert', 'store']
    )

    # Add key, signature, and policy into the query string along
    # with the convert options.
    options = options.merge(
      key: @api_key,
      signature: signage[:signature],
      policy: signage[:encoded_policy],
      storeLocation: 'S3'
    )
    options[:storePath] = signage[:policy]['path'] if path
    uri.query = encode_uri_query(options)

    resource = get_fp_resource uri

    response = resource.post({})  # all data in query string already, empty hash is just to allow this call to be made

    if response.code == 200
      response_data = JSON.parse response.body
      file = FilepickerClientFile.new response_data, self

      return file
    else
      raise FilepickerClientError, "failed to store (code: #{response.code})"
    end
  end

  # Get basic information about a file.
  #
  # Set any of the following keys to true in the options to enable certain fields in the data retrieved:
  # * mimetype
  # * uploaded
  # * container
  # * writeable
  # * filename
  # * location
  # * key
  # * path
  # * size
  # * width
  # * height
  #
  # @param handle [String] Handle for the file in Filepicker
  # @param options [Hash] Options for generating the desired signature
  # @return [Hash] Name, size, and MIME type of the file
  def stat(handle, options={})
    options = convert_hash(options)

    # Build a metadata url for the file
    # (this call returns more information than a HEAD request against the resource)
    uri = file_uri(handle)
    uri.path += "/metadata"

    # Sign to allow store of a new file under the target path.
    # The handle of the file being read is not required.
    signage = sign(
      expiry: DEFAULT_POLICY_EXPIRY,
      call: 'stat'
    )

    # Add key, signature, and policy into the query string along
    # with the metadata options.
    options = options.merge(
      key: @api_key,
      signature: signage[:signature],
      policy: signage[:encoded_policy]
    )
    uri.query = encode_uri_query(options)

    resource = get_fp_resource uri

    response = resource.get

    if response.code == 200
      response_data = JSON.parse(response.body)
      stats = convert_hash(response_data)

      return stats
    else
      raise FilepickerClientError, "failed to get file stats (code: #{response.code})"
    end
  end

  # Get the content of a file.
  # @param handle [String] Handle for the file in Filepicker
  # @return [String] Content of the file
  def read(handle)
    uri = file_read_uri_and_expiry(handle)[:uri]
    resource = get_fp_resource uri

    response = resource.get

    if response.code == 200
      return response
    else
      raise FilepickerClientError, "failed to read file content (code: #{response.code})"
    end
  end

  # Overwrite the file with the given handle using the provided file.
  # @param handle [String] Handle for the file in Filepicker
  # @param file [File] File to upload
  # @return [True] Returns true if successful
  def write(handle, file)
    signage = sign(handle: handle, call: :write)

    uri = file_uri(handle)
    uri.query = encode_uri_query(
      key: @api_key,
      signature: signage[:signature],
      policy: signage[:encoded_policy]
    )

    resource = get_fp_resource uri

    response = resource.put fileUpload: file

    if response.code == 200
      return true
    else
      raise FilepickerClientError, "failed to write (code: #{response.code})"
    end
  end

  # Overwrite the file with the given handle using the file at the provided URL.
  # @param handle [String] Handle for the file in Filepicker
  # @param file_url [String] URL to get the file to upload from
  # @return [True] Returns true if successful
  def write_url(handle, file_url)
    signage = sign(handle: handle, call: :writeUrl)

    uri = file_uri(handle)
    uri.query = encode_uri_query(
      key: @api_key,
      signature: signage[:signature],
      policy: signage[:encoded_policy]
    )

    resource = get_fp_resource uri

    response = resource.put url: file_url.to_s

    if response.code == 200
      return true
    else
      raise FilepickerClientError, "failed to write (code: #{response.code})"
    end
  end

  # Remove a file from Filepicker.
  # @param handle [String] Handle for the file in Filepicker
  # @return [True] Returns true if successful
  def remove(handle)
    signage = sign(handle: handle, call: :remove)

    uri = file_uri(handle)
    uri.query = encode_uri_query(
      key: @api_key,
      signature: signage[:signature],
      policy: signage[:encoded_policy]
    )

    resource = get_fp_resource uri

    response = resource.delete

    if response.code == 200
      return true
    else
      raise FilepickerClientError, "failed to delete (code: #{response.code})"
    end
  end

  private

  def get_fp_resource(uri)
    RestClient::Resource.new(
      uri.to_s,
      verify_ssl: (@filepicker_cert ? OpenSSL::SSL::VERIFY_PEER : OpenSSL::SSL::VERIFY_NONE),
      ssl_client_cert: @filepicker_cert
    )
  end

  def convert_hash(hash)
    HashWithIndifferentAccess.new(hash)
  end

  # Convert a hash of query params into a string.
  # This method does not encode the signature or policy params, as they are
  # already encoded in the format expected by the Filepicker API
  def encode_uri_query(params)
    encodable = {}
    unencodable = {}
    unencodable_params = ["signature", "policy"]
    params.each_pair do |key, value|
      if unencodable_params.include?(key.to_s)
        unencodable[key] = value
      else
        encodable[key] = value
      end
    end
    query = URI.encode_www_form(encodable)
    unless unencodable.empty?
      query << '&' if query.length > 0
      query << unencodable.map{|k,v| "#{k}=#{v}"}.join('&')
    end
    query
  end
end

# Filepicker File Container
class FilepickerClientFile
  attr_accessor :mimetype, :size, :handle, :store_key, :filename, :client

  # Create an object linked to the client to interact with the file in Filepicker
  # @param blob [Hash] Information about the file from Filepicker
  # @param client [FilepickerClient] Client through which actions on this file should be taken
  # @return [FilepickerClientFile]
  def initialize(blob, client)
    @mimetype = blob['type']
    @size = blob['size']
    @handle = URI.parse(blob['url']).path.split('/').last.strip unless blob['url'].nil?
    @store_key = blob['key']
    @filename = blob['filename']

    @client = client

    unless @client
      raise FilepickerClientError, "FilepickerClientFile client required"
    end
  end

  # Get Filepicker URI for this file
  # @return [URI] URI for the file in Filepicker
  def file_uri
    @client.file_uri(@handle)
  end

  # Get Filepicker URI for this file signed for read and convert calls.
  # @param expiry [Fixnum] Expiration for the URI's signature
  # @return [URI] URI for the file in Filepicker signed for read and convert
  def file_read_uri_and_expiry(expiry=FilepickerClient::DEFAULT_POLICY_EXPIRY)
    @client.file_read_uri_and_expiry(@handle, expiry)
  end

  # Get basic information about this file.
  # @return [Hash] Name, size, and MIME type of the file
  def stat
    updated_info = @client.stat @handle
    @mimetype = updated_info[:mimetype]
    @size = updated_info[:size]

    return updated_info
  end

  # Get the content of this file.
  # @return [String] Content of the file
  def read
    @client.read @handle
  end

  # Overwrite this file using the provided file.
  # @param file [File] File to upload
  # @return [True] Returns true if successful
  def write(file)
    @client.write @handle, file
  end

  # Overwrite this file using the file at the provided URL.
  # @param file_url [String] URL to get the file to upload from
  # @return [True] Returns true if successful
  def write_url(file_url)
    @client.write_url @handle, file_url
  end

  # Remove this file from Filepicker.
  # @return [True] Returns true if successful
  def remove
    @client.remove @handle
  end
end

# Client errors
class FilepickerClientError < StandardError
end
