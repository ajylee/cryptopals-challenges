
require 'base64'

module BaseConv
  module_function
  def decode16(ss_16)
    ss_16.scan(/../).map{|bb| bb.hex.chr}.join()
  end

  def conv_16_to_64(ss_16)
    Base64.strict_encode64(decode16(ss_16))
  end
end


_input = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'

_desired_output = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'

puts BaseConv.decode16(_input)
puts BaseConv.conv_16_to_64(_input) == _desired_output
