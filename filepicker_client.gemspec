Gem::Specification.new do |s|
	s.name        = 'filepicker_client'
	s.version     = '0.1.0'
	s.date        = '2013-07-25'
	s.summary     = "Filepicker.io Client"
	s.description = "A simple library for interfacing with Filepicker.io's REST API"
	s.authors     = ["Ada Fairweather"]
	s.email       = 'ada.fairweather@infowrap.com'
	s.files       = ["lib/filepicker_client.rb"]
	s.homepage    = ''

	s.add_dependency 'rest-client', '~> 1.6'
end
