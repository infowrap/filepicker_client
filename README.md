# Filepicker Client

This library provides a basic interface to the REST API for [https://www.inkfilepicker.com/](https://www.inkfilepicker.com/) (see [REST API Documentation](https://developers.inkfilepicker.com/docs/web/#rest)).

# Installation

In Gemfile:

```
gem 'filepicker_client', git: 'git://github.com/infowrap/filepicker_client.git'
```

# Usage

The FilepickerClient class is used to manage calls to the REST API. You may create a new client object with your Filepicker API key and secret.

```ruby
require 'filepicker_client'

FPAPIKEY=YOUR_API_KEY_HERE
FPAPISECRET=YOUR_API_SECRET_HERE

fp_client = FilepickerClient.new FPAPIKEY, FPAPISECRET
```

## Client Methods

* sign - Generate signatures and policies for various Filepicker operations using your key and secret
* store - Store a file under the specified path through Filepicker
* store_url - Store a file accessible at a URL under the specified path through Filepicker
* stat - Get size and MIME type information about a file
* read - Get a file's content
* write - Overwrite an existing file with a new one
* write_url - Overwrite an existing file with a file accessible at a URL
* remove - Delete a file from Filepicker

## FilepickerClientFile

The client's 'store' method will produce file objects. These are linked to the client object and provide a simple means of making further calls on that file.

* stat
* read
* write
* write_url
* remove

# Testing

Since this library involves operations against the Filepicker service, in order to run the tests, valid API key and secret environment variables must be set. This will allow the test to connect to Filepicker using your credentials and work with files in your storage. Please look over the test code to ensure you are comfortable with it running against your Filepicker account.

Currently each run of the tests will only store two files under the "test" path and attempt to remove them when finished.

```
rake test FPAPIKEY=YOUR_API_KEY_HERE FPAPISECRET=YOUR_API_SECRET_HERE
```
