Pod::Spec.new do |s|
  s.name     = 'NSData+Seal'
  s.version  = '0.9.0'
  s.summary  = 'Easily encrypt and decrypt with public and private keys like openssl_seal in PHP.'
  s.homepage = 'https://github.com/CodeReaper/NSData+Seal'
  s.author   = { "Jakob Jensen" => "jakobj@jakobj.dk" }
  s.source   = { :git => "https://github.com/CodeReaper/NSData+Seal.git", :tag => "0.9.1" }
  s.source_files = '*.{h,m}'
  s.social_media_url = "http://twitter.com/jakobjdk"
  s.license          = { :type => "MIT" }
  s.description      = <<-DESC
                      Easily encrypt and decrypt with public and private keys like openssl_seal and openssl_open in PHP to protect your data.
                      DESC
end
