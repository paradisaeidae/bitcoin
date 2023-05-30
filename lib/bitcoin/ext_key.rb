module Bitcoin
def self.hmac_sha512(key, data) OpenSSL::HMAC.digest(OpenSSL::Digest.new('SHA512'), key, data) end

# Integers modulo the order of the curve(secp256k1)
CURVE_ORDER = 115792089237316195423570985008687907852837564279074904382605163141518161494337

class ExtKey # BIP32 Extended private key
attr_accessor :depth
attr_accessor :number
attr_accessor :chain_code
attr_accessor :priv_key
attr_accessor :parent_fingerprint

def self.generate_master(seed) # generate master key from seed.
 key = ExtKey.new
 key.depth = key.number = 0
 key.parent_fingerprint = '00000000'
 l = Bitcoin.hmac_sha512('Bitcoin seed', seed)
 left = OpenSSL::BN.from_hex(l[0..31].bth).to_i
 raise 'invalid key' if left >= CURVE_ORDER || left == 0
 key.priv_key = Bitcoin::Key.new(l[0..31].bth)
 key.chain_code = l[32..-1] 
 key end

def ext_pubkey # get ExtPubkey from priv_key
 k = ExtPubkey.new
 k.depth = depth
 k.number = number
 k.parent_fingerprint = parent_fingerprint
 k.chain_code = chain_code
 key = Bitcoin::Key.new(nil, priv_key.pub, compressed: true)
 k.pub_key = key.key.public_key
 k end

def to_payload # serialize extended private key
 Bitcoin.network[:extended_privkey_version].htb << [depth].pack('C') << parent_fingerprint.htb << [number].pack('N') << chain_code << [0x00].pack('C') << priv_key.priv.htb end

def to_base58 # Base58 encoded extended private key
 h = to_payload.bth
 hex = h + Bitcoin.checksum(h)
 Bitcoin.encode_base58(hex) end

def priv()        priv_key.priv end# get private key(hex)
def pub()         priv_key.pub end# get public key(hex)
def addr()        priv_key.addr end# get address
def identifier()  Bitcoin.hash160(priv_key.pub) end# get key identifier
def fingerprint() identifier.slice(0..7) end# get fingerprint

# derive new key
def derive(number)
 new_key = ExtKey.new
 new_key.depth = depth + 1
 new_key.number = number
 new_key.parent_fingerprint = fingerprint
 if number > (2**31 - 1) then data = [0x00].pack('C') << priv_key.priv.htb << [number].pack('N')
 else data = priv_key.pub.htb << [number].pack('N') end
 l = Bitcoin.hmac_sha512(chain_code, data)
 left = OpenSSL::BN.from_hex(l[0..31].bth).to_i
 raise 'invalid key' if left >= CURVE_ORDER
 child_priv = OpenSSL::BN.new((left + OpenSSL::BN.from_hex(priv_key.priv).to_i) % CURVE_ORDER)
 raise 'invalid key ' if child_priv.to_i >= CURVE_ORDER
 new_key.priv_key = Bitcoin::Key.new(child_priv.to_hex.rjust(64, '0'))
 new_key.chain_code = l[32..-1]
 new_key end

# import private key from Base58 private key address
def self.from_base58(address)
 data = StringIO.new(Bitcoin.decode_base58(address).htb)
 key = ExtKey.new
 data.read(4).bth # version
 key.depth = data.read(1).unpack('C').first
 key.parent_fingerprint = data.read(4).bth
 key.number = data.read(4).unpack('N').first
 key.chain_code = data.read(32)
 data.read(1) # 0x00
 key.priv_key = Bitcoin::Key.new(data.read(32).bth)
 key end end

  # BIP-32 Extended public key BIP 32. An extended key is a private key or public key that you can use to derive new keys in a hierarchical deterministic wallet. Therefore, you can have a single extended private key , and use it as the source for all the child private keys and public keys in your wallet.
 class ExtPubkey
 attr_accessor :depth
 attr_accessor :number
 attr_accessor :chain_code
 attr_accessor :pub_key
 attr_accessor :parent_fingerprint

def to_payload # serialize extended pubkey
 Bitcoin.network[:extended_pubkey_version].htb << [depth].pack('C') << parent_fingerprint.htb << [number].pack('N') << chain_code << pub.htb end

def pub # get public key(hex)
 pub_key.group.point_conversion_form = :compressed
 pub_key.to_hex.rjust(66, '0') end

def addr() Bitcoin.hash160_to_address(Bitcoin.hash160(pub)) end # get address
def identifier() Bitcoin.hash160(pub) end # get key identifier
def fingerprint() identifier.slice(0..7) end # get fingerprint

def to_base58 # Base58 encoded extended pubkey
 h = to_payload.bth
 hex = h + Bitcoin.checksum(h)
 Bitcoin.encode_base58(hex) end

def derive(number) # derive child key
 new_key = ExtPubkey.new
 new_key.depth = depth + 1
 new_key.number = number
 new_key.parent_fingerprint = fingerprint
 raise 'hardened key is not support' if number > (2**31 - 1)
 data = pub.htb << [number].pack('N')
 l = Bitcoin.hmac_sha512(chain_code, data)
 left = OpenSSL::BN.from_hex(l[0..31].bth)
 raise 'invalid key' if left.to_i >= CURVE_ORDER
 new_key.pub_key = Bitcoin.bitcoin_elliptic_curve.group.generator.mul(left).ec_add(pub_key)
 new_key.chain_code = l[32..-1]
 new_key end

def self.from_base58(address) # import private key from Base58 private key address
 data = StringIO.new(Bitcoin.decode_base58(address).htb)
 key = ExtPubkey.new
 data.read(4).bth # version
 key.depth = data.read(1).unpack('C').first
 key.parent_fingerprint = data.read(4).bth
 key.number = data.read(4).unpack('N').first
 key.chain_code = data.read(32)
 key.pub_key = OpenSSL::PKey::EC::Point.from_hex(Bitcoin.bitcoin_elliptic_curve.group, data.read(33).bth)
 key end end end