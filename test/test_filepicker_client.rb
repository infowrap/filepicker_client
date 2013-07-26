require 'test/unit'
require 'tempfile'
require 'filepicker_client'

class TestFilepickerClient < Test::Unit::TestCase
	def setup
		@api_key = ENV['FPAPIKEY']
		@api_secret = ENV['FPAPISECRET']
	end

	def test_fp_uri
		client = FilepickerClient.new 'fake-key', 'fake-secret'
		uri = client.fp_uri('fake-handle')
		assert_equal "https://www.filepicker.io/api/file/fake-handle", uri.to_s
	end

	def test_file
		assert @api_key, "Must set FPAPIKEY for this test"
		assert @api_secret, "Must set FPAPISECRET for this test"

		client = FilepickerClient.new @api_key, @api_secret

		content = "test file content\n" * 10

		store_file = Tempfile.new('test.txt')
		store_file.write content
		store_file.rewind

		update_content = "updated content\n" * 10

		update_file = Tempfile.new('test-update.txt')
		update_file.write update_content
		update_file.rewind

		begin
			# store
			file = client.store(store_file, 'test')

			# info
			info = file.info
			assert_equal content.length, info[:size]
			assert_equal 'text/plain; charset=utf-8', info[:mime_type]

			# get
			downloaded_content = file.get
			assert_equal content, downloaded_content

			# update
			file.update update_file

			downloaded_content = file.get
			assert_equal update_content, downloaded_content

			# destroy
			assert file.destroy

			error_fired = false
			begin
				file.get
			rescue Exception => e
				error_fired = true
			end
			assert error_fired, "no error fired when getting a deleted file"
		rescue Exception => e
			raise e	# reraise to have error reported
		ensure
			store_file.close
			store_file.unlink

			update_file.close
			update_file.unlink
		end
	end
end
