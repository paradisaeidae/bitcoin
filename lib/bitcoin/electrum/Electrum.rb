module Electrum
class WIF  # https://wiki.bitcoinsv.io/index.php/Private_Keys
attr_accessor :pem, :base64, :wif
def initialize(wif)
 if wif.include? '----' then raise 'Expected raw private, not PEM' end
 # uncompressed public keys, they are 51 characters and always start with the number 5 on mainnet (9 on testnet)
 # compressed public keys are 52 characters and start with a capital L or K on mainnet (c on testnet)
 case wif[0, 1]
 when '5'        # mainnet
  if wif.length != 51 || Bitcoin.network != 'mainnet' then raise 'Non commensurate first digit for this network setting or length issue.' end
 when 'L' || 'K' # mainnet compressed
  if wif.length != 52 || Bitcoin.network != 'mainnet' then raise 'Non commensurate first digit for this network setting or length issue.' end
 when '9'        # testnet
  if wif.length != 51 || Bitcoin.network != 'mainnet' then raise 'Non commensurate first digit for this network setting or length issue.' end
 when 'c'        # testnet compressed
  if wif.length != 51 || Bitcoin.network != 'mainnet' then raise 'Non commensurate first digit for this network setting or length issue.' end end
 @wif = wif
 @bin = Base58.decode_base58(wif)
 @private_string = @bin.byteslice(1..-5)
 @hex = private_key.unpack('H*').first
 # Convert private string to Base64 for PEM
  works = 'MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgBm8tETo+73YLviIxpxMyaSu3HQHrHN+cttn7Pn1KeQGhRANCAAT/ok8McP+7yJJBDSwA4PaWZcADk5HPTq1uQaiYdw699zA5k+9vJ2C4CjoXpMxbdFo1zCtiolei8mAZ7Wiy27Lq'
 @pem = to_pem(works)
 @key = OpenSSL::PKey.read @pem
 debugger
 rescue => badThing
  puts badThing.inspect
  debugger end

def to_pem(base64)
 pem = "-----BEGIN EC PRIVATE KEY-----\n" + base64 + "\n-----END EC PRIVATE KEY-----\n"
 @pem = pem end
def from_pem_to_base64(pem); @base64 = pem.split("\n")[1] end end end