# requires gem sinatra

require 'openssl'
require 'securerandom'
require 'sinatra'


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
    [self].pack('H*')
  end

  def my_unhexlify
    self.grouped(2, "0").map {|s| s.to_i(16).chr}.join
  end
end


configure do
  #set :key, SecureRandom.random_bytes(64)
  set :key, 'abcd'
  set :port, 9567
  set :sleep_time, 0.050
end


def my_hmac_hexdigest(digest, key, message)
  # Should be same as Digest::HMAC.hexdigest

  block_length = digest.block_length

  key_block = key + "\x00" * (block_length - key.length)

  o_key_pad = ("\x5c" * block_length) ^ key_block
  i_key_pad = ("\x36" * block_length) ^ key_block
  return digest.hexdigest(
       o_key_pad + digest.digest(i_key_pad + message))
end


def sleepy_cmp(s1, s2)
  s1.bytes.zip(s2.bytes).each do |(c1, c2)|
    sleep(settings.sleep_time)
    if c1 != c2
      return false
    end
  end

  return true
end

get '/set_sleep_time' do
  if params[:sleep_time]
    logger.info("set sleep_time to #{params[:sleep_time].to_f}")
    settings.sleep_time = params[:sleep_time].to_f
  else
    return 500
  end
end

get '/test' do
  file, signature = params[:file], params[:signature]

  digest = OpenSSL::Digest.new('sha1')
  md_hash = my_hmac_hexdigest(digest, settings.key, File.read(file))

  logger.info("actual digest: #{md_hash}")

  if sleepy_cmp(md_hash.unhexlify, signature.unhexlify) then
    return 200
  else
    return 500
  end
end
