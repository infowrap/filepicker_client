require 'rest-client'
require 'json'
require 'base64'

# Client interface for Filepicker's REST API
class FilepickerClient
	FP_FILE_PATH = "https://www.filepicker.io/api/file/"	# Path that Filepicker file handles are located under
	FP_API_PATH = "https://www.filepicker.io/api/store/S3"	# Path to access the Filepicker API

	DEFAULT_POLICY_EXPIRY = 5 * 60	# 5 minutes (short for security, but allows for some wiggle room)

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
		options[:expiration_start] ||= Time.now
		options[:expiry] ||= DEFAULT_POLICY_EXPIRY

		policy = {
			'call' => options[:call]
		}

		# Restrict the scope of the operation to either the specified file or the path
		if options[:handle]
			policy['handle'] = options[:handle]
		elsif options[:path]
			policy['path'] = (options[:path] + '/').gsub /\/+/, '/'	# ensure path has a single, trailing '/'
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

		return {
			policy: policy,
			encoded_policy: encoded_policy,
			signature: signature
		}
	end

	# Get Filepicker URI for the file with the given handle.
	# @param handle [String] Handle for the file in Filepicker
	# @return [URI] URI for the file in Filepicker
	def file_uri(handle)
		URI.parse(FP_FILE_PATH + handle)
	end

	# Get Filepicker URI for the file with the given handle signed for read and convert calls.
	# @param handle [String] Handle for the file in Filepicker
	# @param expiry [Fixnum] Expiration for the URI's signature
	# @return [URI] URI for the file in Filepicker signed for read and convert
	def file_read_uri(handle, expiry=DEFAULT_POLICY_EXPIRY)
		signage = sign(
			expiry: expiry,
			handle: handle,
			call: ['read', 'convert']
		)

		uri = file_uri(handle)
		uri.query = URI.encode_www_form(
			signature: signage[:signature],
			policy: signage[:encoded_policy]
		)

		return uri
	end

	# Store the given file at the given storage path through Filepicker.
	# @param path [String] Path the file should be organized under in the destination storage
	# @param file [File] File to upload
	# @return [FilepickerClientFile] Object representing the uploaded file in Filepicker
	def store(file, path=nil)
		signage = sign(path: path, call: :store)

		uri = URI.parse(FP_API_PATH)
		uri.query = URI.encode_www_form(
			key: @api_key,
			signature: signage[:signature],
			policy: signage[:encoded_policy],
			path: signage[:policy]['path']
		)

		resource = get_fp_resource uri

		response = resource.post fileUpload: file

		if response.code == 200
			response_data = JSON.parse response.body
			file = FilepickerClientFile.new response_data, self

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
		uri.query = URI.encode_www_form(
			key: @api_key,
			signature: signage[:signature],
			policy: signage[:encoded_policy],
			path: signage[:policy]['path']
		)

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

	# Get basic information about a file.
	# @param handle [String] Handle for the file in Filepicker
	# @return [Hash] Name, size, and MIME type of the file
	def stat(handle)
		uri = file_read_uri(handle)
		resource = get_fp_resource uri

		response = resource.head

		if response.code == 200
			return {
				name: response.headers[:x_file_name].to_s,
				size: response.headers[:content_length].to_i,
				mime_type: response.headers[:content_type].to_s
			}
		else
			raise FilepickerClientError, "failed to get file stats (code: #{response.code})"
		end
	end

	# Get the content of a file.
	# @param handle [String] Handle for the file in Filepicker
	# @return [String] Content of the file
	def read(handle)
		uri = file_read_uri(handle)
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
		uri.query = URI.encode_www_form(
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
		uri.query = URI.encode_www_form(
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
		uri.query = URI.encode_www_form(
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
		resource = RestClient::Resource.new(
			uri.to_s,
			verify_ssl: (@filepicker_cert ? OpenSSL::SSL::VERIFY_PEER : OpenSSL::SSL::VERIFY_NONE),
			ssl_client_cert: @filepicker_cert
		)
	end
end

# Filepicker File Container
class FilepickerClientFile
	attr_accessor :mime_type, :size, :handle, :store_key, :client

	# Create an object linked to the client to interact with the file in Filepicker
	# @param blob [Hash] Information about the file from Filepicker
	# @return [FilepickerClientFile]
	def initialize(blob={}, client=nil)
		@mime_type = blob['type']
		@size = blob['size']
		@handle = URI.parse(blob['url']).path.split('/').last.strip unless blob['url'].nil?
		@store_key = blob['key']

		@client = client
	end

	# Get Filepicker URI for this file
	# @return [URI] URI for the file in Filepicker
	def file_uri
		URI.parse(FP_FILE_PATH + @handle)
	end

	# Get Filepicker URI for this file signed for read and convert calls.
	# @param expiry [Fixnum] Expiration for the URI's signature
	# @return [URI] URI for the file in Filepicker signed for read and convert
	def file_read_uri(expiry=FilepickerClient::DEFAULT_POLICY_EXPIRY)
		client_required

		@client.file_read_uri(@handle, expiry)
	end

	# Get basic information about this file.
	# @return [Hash] Name, size, and MIME type of the file
	def stat
		client_required

		updated_info = @client.stat @handle
		@mime_type = updated_info[:mime_type]
		@size = updated_info[:size]

		return updated_info
	end

	# Get the content of this file.
	# @return [String] Content of the file
	def read
		client_required

		@client.read @handle
	end

	# Overwrite this file using the provided file.
	# @param file [File] File to upload
	# @return [True] Returns true if successful
	def write(file)
		client_required

		@client.write @handle, file
	end

	# Overwrite this file using the file at the provided URL.
	# @param file_url [String] URL to get the file to upload from
	# @return [True] Returns true if successful
	def write_url(file_url)
		client_required

		@client.write_url @handle, file_url
	end

	# Remove this file from Filepicker.
	# @return [True] Returns true if successful
	def remove
		client_required

		@client.remove @handle
	end

	private

	def client_required
		unless @client
			raise FilepickerClientError, "FilepickerClientFile client must be set to use this operation"
		end
	end
end

# Client errors
class FilepickerClientError < StandardError
end
