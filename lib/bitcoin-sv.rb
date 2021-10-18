# Bitcoin Utils and Network Protocol in Ruby.
# Previously a check would adjust Integer class according to Ruby version.
# Ruby 3 unifies Fixnum and Bignum to Integer.
['digest/sha2', 'digest/rmd160', 'openssl', 'securerandom'].each {| ment | require ment}
module Bitcoin
autoload :Connection,   'bitcoin-sv/connection'
autoload :Protocol,     'bitcoin-sv/protocol'
autoload :P,            'bitcoin-sv/protocol'
autoload :Script,       'bitcoin-sv/script'
autoload :VERSION,      'bitcoin-sv/version'
autoload :Key,          'bitcoin-sv/key'
autoload :ExtKey,       'bitcoin-sv/ext_key'
autoload :ExtPubkey,    'bitcoin-sv/ext_key'
autoload :Builder,      'bitcoin-sv/builder'
autoload :BloomFilter,  'bitcoin-sv/bloom_filter'
autoload :ContractHash, 'bitcoin-sv/contracthash'

module Trezor
autoload :Mnemonic,   'bitcoin-sv/trezor/mnemonic' end

module Util
def address_version;   Bitcoin.network[:address_version]; end
def version_bytes;     address_version.size / 2; end

# hash160 is a 20 bytes (160bits) rmd610-sha256 hexdigest.
def hash160(hex)
 bytes = [hex].pack("H*")
 Digest::RMD160.hexdigest Digest::SHA256.digest(bytes) end

# checksum is a 4 bytes sha256-sha256 hexdigest.
def checksum(hex)
 b = [hex].pack("H*") # unpack hex
 Digest::SHA256.hexdigest( Digest::SHA256.digest(b) )[0...8] end
# verify base58 checksum for given +base58+ data.

def base58_checksum?(base58)
 hex = decode_base58(base58) rescue nil
 return false unless hex
 checksum(hex[0...(version_bytes + 20) * 2]) == hex[-8..-1] end
alias :address_checksum? :base58_checksum?

# check if given +address+ is valid.
# this means having a correct version byte, length and checksum.
def valid_address?(address)
 address_type(address) != nil end

# check if given +pubkey+ is valid.
def valid_pubkey?(pubkey)
 ::OpenSSL::PKey::EC::Point.from_hex(bitcoin_elliptic_curve.group, pubkey)
 true
rescue OpenSSL::PKey::EC::Point::Error
 false
rescue OpenSSL::BNError
 # Occasionally, a malformed value will fail hex decoding completely and
 # instead of raising an `OpenSSL::PKey::EC::Point::Error` will raise this
 # error. We capture this failure mode here as well.
 false end

# get hash160 for given +address+. returns nil if address is invalid.
# https://learnmeabitcoin.com/technical/public-key-hash
def hash160_from_address(address)
 case address_type(address)
 when :hash160
  start_idx = version_bytes * 2
  stop_idx = start_idx + 40 # 20 bytes (2 chars per byte)
  decode_base58(address)[start_idx...stop_idx] end end

# get type of given +address+.
def address_type(address)
 hex = decode_base58(address) rescue nil
 target_size = (version_bytes + 20 + 4) * 2 # version_bytes + 20 bytes hash + 4 bytes checksum
 if hex && hex.bytesize == target_size && address_checksum?(address)
  case hex[0...(version_bytes * 2)]
  when address_version
  return :hash160 end end
 nil end

def sha256(hex);                     Digest::SHA256.hexdigest([hex].pack("H*")) end
def hash160_to_address(hex);         encode_address hex, address_version end
def encode_address(hex, version);
 hex = version + hex
 encode_base58(hex + checksum(hex)) end
def pubkey_to_address(pubkey);       hash160_to_address( hash160(pubkey) ) end
def pubkeys_to_multisig_address(m, *pubkeys)
 redeem_script = Bitcoin::Script.to_multisig_script(m, *pubkeys).last
 return Bitcoin.hash160_to_address(Bitcoin.hash160(redeem_script.hth)), redeem_script end

def int_to_base58(int_val, leading_zero_bytes=0)
 alpha = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
 base58_val, base = '', alpha.size
 while int_val > 0
  int_val, remainder = int_val.divmod(base)
  base58_val = alpha[remainder] + base58_val end
 base58_val end

def base58_to_int(base58_val)
 alpha = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
 int_val, base = 0, alpha.size
 base58_val.reverse.each_char.with_index do |char,index|
  raise ArgumentError, 'Value not a valid Base58 String.' unless char_index = alpha.index(char)
  int_val += char_index*(base**index) end
 int_val end

def encode_base58(hex)
 leading_zero_bytes  = (hex.match(/^([0]+)/) ? $1 : '').size / 2
 ("1"*leading_zero_bytes) + int_to_base58( hex.to_i(16) ) end

def decode_base58(base58_val)
 s = base58_to_int(base58_val).to_s(16); s = (s.bytesize.odd? ? '0'+s : s)
 s = '' if s == '00'
 leading_zero_bytes = (base58_val.match(/^([1]+)/) ? $1 : '').size
 s = ("00"*leading_zero_bytes) + s  if leading_zero_bytes > 0
 s end

alias_method :base58_to_hex, :decode_base58

# target compact bits (int) to bignum hex
def decode_compact_bits(bits)
 bytes = Array.new(size=((bits >> 24) & 255), 0)
 bytes[0] = (bits >> 16) & 255 if size >= 1
 bytes[1] = (bits >>  8) & 255 if size >= 2
 bytes[2] = (bits      ) & 255 if size >= 3
 bytes.pack("C*").unpack("H*")[0].rjust(64, '0') end

# target bignum hex to compact bits (int)
def encode_compact_bits(target)
 bytes = OpenSSL::BN.new(target, 16).to_mpi
 size = bytes.size - 4
 nbits = size << 24
 nbits |= (bytes[4] << 16) if size >= 1
 nbits |= (bytes[5] <<  8) if size >= 2
 nbits |= (bytes[6]      ) if size >= 3
 nbits end

def decode_target(target_bits)
 case target_bits
 when Bitcoin::Integer
  [ decode_compact_bits(target_bits).to_i(16), target_bits ]
 when String
  [ target_bits.to_i(16), encode_compact_bits(target_bits) ] end end

def bitcoin_elliptic_curve;      ::OpenSSL::PKey::EC.new("secp256k1") end

def generate_key
 key = bitcoin_elliptic_curve.generate_key
 inspect_key( key ) end

def inspect_key(key)
 [ key.private_key_hex, key.public_key_hex ] end

def generate_address
 prvkey, pubkey = generate_key
 [ pubkey_to_address(pubkey), prvkey, pubkey, hash160(pubkey) ] end

def bitcoin_hash(hex)
 Digest::SHA256.digest( Digest::SHA256.digest( [hex].pack("H*").reverse ) ).reverse.bth end

def bitcoin_byte_hash(bytes);       Digest::SHA256.digest(Digest::SHA256.digest(bytes)) end
def bitcoin_mrkl(a, b);             bitcoin_hash(b + a); end
def block_hash(prev_block, mrkl_root, time, bits, nonce, ver)
 h = "%08x%08x%08x%064s%064s%08x" %
  [nonce, bits, time, mrkl_root, prev_block, ver]
 bitcoin_hash(h) end

def block_scrypt_hash(prev_block, mrkl_root, time, bits, nonce, ver)  # DEPRECATE???
 h = "%08x%08x%08x%064s%064s%08x" %
 [nonce, bits, time, mrkl_root, prev_block, ver]
 litecoin_hash(h) end

# get merkle tree for given +tx+ list.
def hash_mrkl_tree(tx)
 return [nil]  if tx != tx.uniq
 chunks = [ tx.dup ]
 while chunks.last.size >= 2
  chunks << chunks.last.each_slice(2).map {|a, b| bitcoin_mrkl( a, b || a ) } end
 chunks.flatten end

# get merkle branch connecting given +target+ to the merkle root of +tx+ list
def hash_mrkl_branch(tx, target)
 return [ nil ]  if tx != tx.uniq
 branch, chunks = [], [ tx.dup ]
 while chunks.last.size >= 2
  chunks << chunks.last.each_slice(2).map {|a, b|
   hash = bitcoin_mrkl( a, b || a )
   next hash  unless [a, b].include?(target)
   branch << (a == target ? (b || a) : a)
   target = hash } end
 branch end

# get merkle root from +branch+ and +target+.
def mrkl_branch_root(branch, target, idx)
 branch.each do |hash|
  a, b = *( idx & 1 == 0 ? [target, hash] : [hash, target] )
  idx >>= 1;
  target = bitcoin_mrkl( a, b ) end
 target end

def sign_data(key, data)
 sig = nil
 loop {
  sig = key.dsa_sign_asn1(data)
  sig = if Script.is_low_der_signature?(sig)
   sig
   else Bitcoin::OpenSSL_EC.signature_to_low_s(sig) end
  buf = sig + [Script::SIGHASH_TYPE[:all]].pack("C") # is_der_signature expects sig + sighash_type format
  if Script.is_der_signature?(buf)
   break
  else p ["Bitcoin#sign_data: invalid der signature generated, trying again.", data.unpack("H*")[0], sig.unpack("H*")[0]] end }
  return sig end

def verify_signature(hash, signature, public_key)
 key = bitcoin_elliptic_curve
 key.public_key = ::OpenSSL::PKey::EC::Point.from_hex(key.group, public_key)
 signature = Bitcoin::OpenSSL_EC.repack_der_signature(signature)
 if signature then key.dsa_verify_asn1(hash, signature)
 else false end
 rescue OpenSSL::PKey::ECError, OpenSSL::PKey::EC::Point::Error, OpenSSL::BNError
 false end

def open_key(private_key, public_key=nil)
 key = bitcoin_elliptic_curve
 key.private_key = ::OpenSSL::BN.from_hex(private_key)
 public_key = regenerate_public_key(private_key) unless public_key
 key.public_key  = ::OpenSSL::PKey::EC::Point.from_hex(key.group, public_key)
 key end

def regenerate_public_key(private_key)
 OpenSSL_EC.regenerate_key(private_key)[1] end

def bitcoin_signed_message_hash(message)
 message = message.dup.force_encoding('binary')
 magic = Bitcoin.network[:message_magic]
 buf = Protocol.pack_var_int(magic.bytesize) + magic
 buf << Protocol.pack_var_int(message.bytesize) + message
 Digest::SHA256.digest(Digest::SHA256.digest(buf)) end

def sign_message(private_key_hex, public_key_hex, message)
 hash = bitcoin_signed_message_hash(message)
 signature = OpenSSL_EC.sign_compact(hash, private_key_hex, public_key_hex)
 { 'address' => pubkey_to_address(public_key_hex), 'message' => message, 'signature' => [ signature ].pack("m0") } end

def verify_message(address, signature, message)
 signature = signature.unpack("m0")[0] rescue nil # decode base64
 return false unless valid_address?(address)
 return false unless signature
 return false unless signature.bytesize == 65
 hash = bitcoin_signed_message_hash(message)
 pubkey = OpenSSL_EC.recover_compact(hash, signature)
 pubkey_to_address(pubkey) == address if pubkey end

# block count when the next retarget will take place.
def block_next_retarget(block_height)
 (block_height + (RETARGET_INTERVAL-block_height.divmod(RETARGET_INTERVAL).last)) - 1 end

# current difficulty as a multiple of the minimum difficulty (highest target).
def block_difficulty(target_nbits)
 # max_target      = 0x00000000ffff0000000000000000000000000000000000000000000000000000
 # current_target  = Bitcoin.decode_compact_bits(target_nbits).to_i(16)
 # "%.7f" % (max_target / current_target.to_f)
 bits, max_body, scaland = target_nbits, Math.log(0x00ffff), Math.log(256)
 "%.7f" % Math.exp(max_body - Math.log(bits&0x00ffffff) + scaland * (0x1d - ((bits&0xff000000)>>24))) end
# Calculate new difficulty target. Note this takes in details of the preceeding
# block, not the current one.
#
# prev_height is the height of the block before the retarget occurs
# prev_block_time "time" field from the block before the retarget occurs
# prev_block_bits "bits" field from the block before the retarget occurs (target as a compact value)
# last_retarget_time is the "time" field from the block when a retarget last occurred
def block_new_target(prev_height, prev_block_time, prev_block_bits, last_retarget_time)
 # target interval - what is the ideal interval between the blocks
 retarget_time = Bitcoin.network[:retarget_time]
 actual_time = prev_block_time - last_retarget_time
 min = retarget_time / 4
 max = retarget_time * 4
 actual_time = min if actual_time < min
 actual_time = max if actual_time > max
 # It could be a bit confusing: we are adjusting difficulty of the previous block, while logically
 # we should use difficulty of the previous retarget block
 prev_target = decode_compact_bits(prev_block_bits).to_i(16)
 new_target = prev_target * actual_time / retarget_time
 if new_target < Bitcoin.decode_compact_bits(Bitcoin.network[:proof_of_work_limit]).to_i(16)
  encode_compact_bits(new_target.to_s(16))
 else Bitcoin.network[:proof_of_work_limit] end end

# average number of hashes required to win a block with the current target. (nbits)
def block_hashes_to_win(target_nbits)
 current_target  = decode_compact_bits(target_nbits).to_i(16)
 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff / current_target end

# probability of a single hash solving a block with the current difficulty.
def block_probability(target_nbits)
 current_target  = decode_compact_bits(target_nbits).to_i(16)
 "%.55f" % (current_target.to_f / 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff) end

# average time to find a block in seconds with the current target. (nbits)
def block_average_hashing_time(target_nbits, hashes_per_second)
 block_hashes_to_win(target_nbits) / hashes_per_second end

# average mining time (in days) using Mh/s to get btc
def block_average_mining_time(block_nbits, block_height, mega_hashes_per_second, target_btc=1.0)
 seconds = block_average_hashing_time(block_nbits, mega_hashes_per_second * 1_000_000)
 reward  = block_creation_reward(block_height) / COIN # satoshis to btc
 (days = seconds / 60 / 60 / 24) * (target_btc / reward) end

# shows the total number of Bitcoins in circulation, reward era and reward in that era.
def blockchain_total_btc(height)
 reward, interval = Bitcoin.network[:reward_base], Bitcoin.network[:reward_halving]
 total_btc = reward
 reward_era, remainder = (height).divmod(interval)
 reward_era.times{
  total_btc += interval * reward
  reward = reward / 2 }
 total_btc += remainder * reward
 [total_btc, reward_era+1, reward, height] end

def block_creation_reward(block_height)
 Bitcoin.network[:reward_base] / (2 ** (block_height / Bitcoin.network[:reward_halving].to_f).floor) end end

extend Util
module  BinaryExtensions     
def bth; unpack("H*")[0]; end     # bin-to-hex
def htb; [self].pack("H*"); end   # hex-to-bin
def htb_reverse; htb.reverse; end
def hth; unpack("H*")[0]; end
def reverse_hth; reverse.hth; end end

class ::String
include Bitcoin::BinaryExtensions end

module ::OpenSSL
class BN
def self.from_hex(hex); new(hex, 16); end
def to_hex; to_i.to_s(16); end
def to_mpi; to_s(0).unpack("C*"); end end

class PKey::EC
def private_key_hex; private_key.to_hex.rjust(64, '0') end
def public_key_hex;  public_key.to_hex.rjust(130, '0') end
def pubkey_compressed?; public_key.group.point_conversion_form == :compressed; end end

class PKey::EC::Point
def self.from_hex(group, hex); new(group, BN.from_hex(hex)) end
def to_hex; to_bn.to_hex; end
def self.bn2mpi(hex) BN.from_hex(hex).to_mpi; end
def ec_add(point); self.class.new(group, OpenSSL::BN.from_hex(OpenSSL_EC.ec_add(self, point))) end end end

autoload :OpenSSL_EC, "bitcoin/ffi/openssl"
autoload :Secp256k1, "bitcoin/ffi/secp256k1"
autoload :BitcoinConsensus, "bitcoin/ffi/bitcoinconsensus"
@network = :bitcoin
def self.network; @network_options ||= NETWORKS[@network].dup end
 # Store the copy of network options so we can modify them in tests without breaking the defaults

def self.network_name; @network ||= nil end
def self.network_project; @network_project ||= nil end

def self.network=(name)
 raise "Network descriptor '#{name}' not found." unless NETWORKS[name.to_sym]
 @network_options = nil # clear cached parameters
 @network = name.to_sym
 @network_project = network[:project] rescue nil
 @network end

[:bitcoin, :bitcoin_testnet].each do |n| instance_eval "def #{n}?; network_project == :#{n}; end" end
# maximum size of a block (in bytes)
MAX_BLOCK_SIZE = 1_000_000
# soft limit for new blocks
MAX_BLOCK_SIZE_GEN = MAX_BLOCK_SIZE/2
# maximum number of signature operations in a block
MAX_BLOCK_SIGOPS = MAX_BLOCK_SIZE / 50
# maximum number of orphan transactions to be kept in memory
MAX_ORPHAN_TRANSACTIONS = MAX_BLOCK_SIZE/100
# Threshold for lock_time: below this value it is interpreted as block number, otherwise as UNIX timestamp.
LOCKTIME_THRESHOLD = 500000000 # Tue Nov  5 00:53:20 1985 UTC
# maximum integer value
UINT32_MAX = 0xffffffff
INT_MAX = 0xffffffff # deprecated name, left here for compatibility with existing users.
# number of confirmations required before coinbase tx can be spent
COINBASE_MATURITY = 100
# interval (in blocks) for difficulty retarget
RETARGET_INTERVAL = 2016
RETARGET = 2016 # deprecated constant
# interval (in blocks) for mining reward reduction
REWARD_DROP = 210_000
CENT =   1_000_000
COIN = 100_000_000
MIN_FEE_MODE     = [ :block, :relay, :send ]
# https://medium.com/renproject/the-multichain-53e5f925ac2e Not needed.
# https://github.com/bitcoin/bips/blob/master/bip-0034.mediawiki
# https://en.bitcoin.it/wiki/Genesis_block?fbclid=IwAR1YlCeA-zRM2I4SDJ-8gx_5i9n9xgY2HQuzwcwKeQflEvZQxqXLs6YxM7g
# https://bitcoin.stackexchange.com/questions/75733/why-does-bitcoin-no-longer-have-checkpoints
NETWORKS = {
 bitcoin: {
  project: :bitcoin,
  magic_head: "\xF9\xBE\xB4\xD9",
  message_magic: "Bitcoin Signed Message:\n",
  address_version: "00",
  privkey_version: "80",
  extended_privkey_version: "0488ade4",
  extended_pubkey_version: "0488b21e",
  default_port: 8333,
  protocol_version: 70001,
  coinbase_maturity: 100,
  reward_base: 50 * COIN,
  reward_halving: 210_000,
  retarget_interval: 2016,
  retarget_time: 1209600, # 2 weeks
  target_spacing: 600, # block interval
  max_money: 21_000_000 * COIN,
  min_tx_fee: 10_000,
  min_relay_tx_fee: 10_000,
  free_tx_bytes: 1_000,
  dust: CENT,
  per_dust_fee: false,
  bip34_height: 227931,
  dns_seeds: [ "seed.bitcoin.sipa.be", "dnsseed.bluematt.me", "dnsseed.bitcoin.dashjr.org", "bitseed.xf2.org", "dnsseed.webbtc.com", ],
   genesis_hash: "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
   proof_of_work_limit: 0x1d00ffff,
   known_nodes: [ 'relay.eligius.st',   'mining.bitcoin.cz',   'blockchain.info',   'blockexplorer.com',   'webbtc.com', ],
   checkpoints: {}}}
NETWORKS[:testnet] = NETWORKS[:bitcoin].merge({
 magic_head: "\xFA\xBF\xB5\xDA",
 address_version: "6f",
 privkey_version: "ef",
 extended_privkey_version: "04358394",
 extended_pubkey_version: "043587cf",
 default_port: 18333,
 bip34_height: 21111,
 dns_seeds: [ ],
 genesis_hash: "00000007199508e34a9ff81e6ec0c477a4cccff2a4767a8eee39c11db367b008",
 proof_of_work_limit: 0x1d07fff8,
 known_nodes: [],
 checkpoints: {},  })
NETWORKS[:regtest] = NETWORKS[:testnet].merge({
 default_port: 18444,
 genesis_hash: "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
 proof_of_work_limit: 0x207fffff,
 bip34_height: 0, })
NETWORKS[:testnet3] = NETWORKS[:regtest].merge({
 magic_head: "\x0B\x11\x09\x07",
 no_difficulty: true, # no good. add right testnet3 difficulty calculation instead
 genesis_hash: "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943",
 proof_of_work_limit: 0x1d00ffff,
 dns_seeds: ["testnet-seed.alexykot.me", "testnet-seed.bitcoin.schildbach.de", "testnet-seed.bitcoin.petertodd.org",
  "testnet-seed.bluematt.me", "dnsseed.test.webbtc.com",],
   known_nodes: ["test.webbtc.com"],
   checkpoints: {} }) end