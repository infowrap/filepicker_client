require 'rest-client'
require 'json'
require 'base64'

class FilepickerClient
	FP_FILE_PATH = "https://www.filepicker.io/api/file/"
	FP_API_PATH = "https://www.filepicker.io/api/store/S3"

	DEFAULT_POLICY_EXPIRY = 5 * 60	# 5 minutes (short for security, but allows for some wiggle room)

	def initialize(api_key, api_secret, filepicker_cert=nil)
		@api_key = api_key
		@api_secret = api_secret
		@filepicker_cert = filepicker_cert
	end

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

	def file_uri(handle)
		URI.parse(FP_FILE_PATH + handle)
	end

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

class FilepickerClientFile
	attr_accessor :mime_type, :size, :handle, :store_key, :client

	def initialize(blob={}, client=nil)
		@mime_type = blob['type']
		@size = blob['size']
		@handle = URI.parse(blob['url']).path.split('/').last.strip unless blob['url'].nil?
		@store_key = blob['key']

		@client = client
	end

	def file_uri
		URI.parse(FP_FILE_PATH + @handle)
	end

	def file_read_uri(expiry=FilepickerClient::DEFAULT_POLICY_EXPIRY)
		client_required

		@client.file_read_uri(@handle, expiry)
	end

	def stat
		client_required

		updated_info = @client.stat @handle
		@mime_type = updated_info[:mime_type]
		@size = updated_info[:size]

		return updated_info
	end

	def read
		client_required

		@client.read @handle
	end

	def write(file)
		client_required

		@client.write @handle, file
	end

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

class FilepickerClientError < StandardError
end
