require 'minitest/autorun'
require 'tempfile'
require 'filepicker_client'

class TestFilepickerClient < Minitest::Test
  def setup
    @api_key = ENV['FPAPIKEY']
    @api_secret = ENV['FPAPISECRET']
  end

  def test_file_uri
    client = FilepickerClient.new 'fake-key', 'fake-secret'
    uri = client.file_uri('fake-handle')
    assert_equal "https://www.filepicker.io/api/file/fake-handle", uri.to_s
  end

  def test_client_file_client_required
    begin
      FilepickerClientFile.new({}, nil)
    rescue FilepickerClientError => e
      assert_equal "FilepickerClientFile client required", e.message
      error_fired = true
    end

    assert error_fired, "FilepickerClientFile did not require a client as it should"
  end

  def test_store_string_text_file
    assert @api_key, "Must set FPAPIKEY for this test"
    assert @api_secret, "Must set FPAPISECRET for this test"

    client = FilepickerClient.new @api_key, @api_secret
    content = "test file content\n" * 10

    begin
      # store
      file = client.store_content(content, 'filename.txt', 'test')

      # file attributes
      assert_match(/^filename\.txt/, file.filename)

      #file_uri
      file_uri = file.file_uri
      assert_equal "https://www.filepicker.io/api/file/#{file.handle}", file_uri.to_s

      # stat
      stats = file.stat
      assert_equal content.length, stats[:size]
      assert_equal 'text/plain', stats[:mimetype]

      # read
      downloaded_content = file.read
      assert_equal content, downloaded_content

      #remove test file
      assert file.remove
    rescue Exception => e
      raise e # reraise to have error reported
    end
  end

  def test_store_string_image_file
    assert @api_key, "Must set FPAPIKEY for this test"
    assert @api_secret, "Must set FPAPISECRET for this test"

    client = FilepickerClient.new @api_key, @api_secret

    image_file = File.open('test/image.jpeg')
    content = image_file.read

    begin
      # store
      file = client.store_content(content, 'filename.jpeg', 'test')

      # file attributes
      assert_match(/^filename\.jpeg/, file.filename)

      #file_uri
      file_uri = file.file_uri
      assert_equal "https://www.filepicker.io/api/file/#{file.handle}", file_uri.to_s

      # stat
      stats = file.stat
      assert_equal image_file.size, stats[:size]
      assert_equal 'text/plain', stats[:mimetype]

      # read
      downloaded_content = file.read
      assert_equal content, downloaded_content

      #remove test file
      assert file.remove
    rescue Exception => e
      raise e # reraise to have error reported
    end
  end



  def test_file
    assert @api_key, "Must set FPAPIKEY for this test"
    assert @api_secret, "Must set FPAPISECRET for this test"

    client = FilepickerClient.new @api_key, @api_secret

    content = "test file content\n" * 10

    store_file = Tempfile.new('test.txt')
    store_file.write content
    store_file.rewind

    write_content = "write content\n" * 10

    write_file = Tempfile.new('test-write.txt')
    write_file.write write_content
    write_file.rewind

    begin
      # store
      file = client.store(store_file, 'test')

      # file attributes
      assert_match(/^test\.txt/, file.filename)

      #file_uri
      file_uri = file.file_uri
      assert_equal "https://www.filepicker.io/api/file/#{file.handle}", file_uri.to_s

      # stat
      stats = file.stat
      assert_equal content.length, stats[:size]
      assert_equal 'text/plain', stats[:mimetype]

      # read
      downloaded_content = file.read
      assert_equal content, downloaded_content

      # store_url
      second_file = client.store_url file.file_read_uri_and_expiry[:uri], 'test'
      assert(second_file.handle != file.handle)
      assert_equal second_file.read, content

      # write
      file.write write_file

      downloaded_content = file.read
      assert_equal write_content, downloaded_content

      # write_url
      # - write from second_file to first
      # - first should have write_content then content after write url
      file.write_url second_file.file_read_uri_and_expiry[:uri]
      assert_equal content, file.read

      # remove
      assert file.remove
      assert second_file.remove

      error_fired = false
      begin
        file.read
      rescue Exception => e
        error_fired = true
      end
      assert error_fired, "no error fired when reading a deleted file"
    rescue Exception => e
      raise e # reraise to have error reported
    ensure
      store_file.close
      store_file.unlink

      write_file.close
      write_file.unlink
    end
  end
end
