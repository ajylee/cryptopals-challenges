# requires gem sinatra

require 'openssl'
require 'securerandom'
require 'sinatra'

BLOCK_SIZE = 20

class String
  def ^(other)
    raise "Must strxor with equal length string" if other.length != self.length
    self.bytes.zip(other.bytes).map{ |(a, b)| a ^ b }.pack('U*')
  end

  def grouped(size, pad=nil)
    ary = (0 ... self.length).step(size).map {|ii|
      self[ii ... (ii + size)]
    }

    ary[-1] = ->(s) {s + pad * (-s.length % size) }.call(ary[-1])
    return ary
  end

  def unhexlify
    [self].pack('H*')[0]
  end

  def my_unhexlify
    self.grouped(2, "0").map {|s| s.to_i(16).chr}.join
  end
end


configure do
  #set :key, SecureRandom.random_bytes(BLOCK_SIZE)
  set :key, 'abcd'
  set :port, 9567
end


def my_hmac(key, message)
  # could also use Digest::HMAC

  digest = OpenSSL::Digest.new('sha1')

  o_key_pad = ("\x5c" * BLOCK_SIZE) ^ key
  i_key_pad = ("\x36" * BLOCK_SIZE) ^ key
  return digest.digest(
       o_key_pad ^ digest.digest(i_key_pad ^ message))
end


def slow_cmp(s1, s2)
  s1.bytes.zip(s2.bytes).each do |(c1, c2)|
    sleep(0.050)
    if c1 != c2
      return false
    end
  end

  return true
end


get '/test' do
  file, signature = params[:file], params[:signature]

  #logger.info("file: #{file} sig: #{signature}")

  digest = OpenSSL::Digest.new('sha1')
  md_hash = OpenSSL::HMAC.hexdigest(digest, settings.key, File.read(file))

  #logger.info("actual digest: #{md_hash}")

  if slow_cmp(md_hash.unhexlify, signature.unhexlify) then
    return 200
  else
    return 500
  end
end
