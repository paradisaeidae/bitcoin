# Bitcoin Utils and Network Protocol in Ruby.
# Previously a check would adjust Integer class according to Ruby version.
# Ruby 3 unifies Fixnum and Bignum to Integer.
# https://github.com/bitcoin-sv/bitcoin-sv/blob/master/src/script/script.cpp
['digest/sha2', 'digest/rmd160', 'ffi', 'openssl', 'securerandom', 'debug', 'ecdsa', 'money-tree', 'bindata', 'base58-alphabets','rbnacl'].each {| ment | require ment}
require_relative './bitcoin/wallets/electrum'  #autoload :Electrum, 'bitcoin/wallets/electrum'
require_relative './bitcoin/builder'
require_relative './bitcoin/ffi/openssl-3.0'
require_relative './bitcoin/ffi/secp256k1' #'rbsecp256k1' contains schnoor.
require_relative "./bitcoin/ffi/bitcoinconsensus.rb"
#autoload :OpenSSL_EC,       "bitcoin/ffi/openssl"
#autoload :Secp256k1,        "bitcoin/ffi/secp256k1"
#autoload :BitcoinConsensus, "bitcoin/ffi/bitcoinconsensus"
module Bitcoin
mods =  [:Connection, :Protocol,    :P,        :Script,  :VERSION,  :Key,  :ExtKey,   :ExtPubkey, :Builder, :BloomFilter,    :ContractHash, ]
codes = ['connection', 'protocol', 'protocol', 'script', 'version', 'key', 'ext_key', 'ext_key',  'builder', 'bloom_filter', 'contracthash']
mods.each_with_index { | mod, code | autoload mod, 'bitcoin/' + codes[code] }
BSV = Struct.new(:name, :magic_head, :message_magic, :address_version, :p2sh_version, :privkey_version,\
      :extended_privkey_version, :extended_pubkey_version).new(
      :bsv, 'e3e1f3e8', 'Bitcoin SV', '00', '05', '80', '0488ade4', '0488b21e', 0x0b110907 )

module Util
 def address_version() Bitcoin.network[:address_version] end
 def version_bytes() address_version.size / 2 end

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
  hex = base58_to_hex(base58) rescue nil
  return false unless hex
  checksum(hex[0...(version_bytes + 20) * 2]) == hex[-8..-1] end
 alias :address_checksum? :base58_checksum? # Should DEPRECATE! one of them.

 # check if given +address+ is valid.
 # this means having a correct version byte, length and checksum.
 def valid_address?(address) address_type(address) != nil end

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
   base58_to_hex(address)[start_idx...stop_idx] end end

 def address_type(address) # get type of given +address+.
  hex = base58_to_hex(address) rescue nil
  target_size = (version_bytes + 20 + 4) * 2 # version_bytes + 20 bytes hash + 4 bytes checksum
  if hex && hex.bytesize == target_size && address_checksum?(address)
   case hex[0...(version_bytes * 2)]
   when address_version
   return :hash160 end end
  nil end

 def sha256(hex) Digest::SHA256.hexdigest([hex].pack("H*")) end
 def hash160_to_address(hex) encode_address hex, address_version end
 def pubkey_to_address(pubkey) hash160_to_address( hash160(pubkey) ) end

 def encode_address(hex, version);
  hex = version + hex
  encode_base58(hex + checksum(hex)) end

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

 def base58_to_hex(base58_val)
  s = base58_to_int(base58_val).to_s(16)
  s = (s.bytesize.odd? ? '0' + s : s)
  s = '' if s == '00'
  leading_zero_bytes = (base58_val.match(/^([1]+)/) ? $1 : '').size
  s = ("00"*leading_zero_bytes) + s  if leading_zero_bytes > 0
  s end

 def decode_compact_bits(bits) # target compact bits (int) to bignum hex
  bytes = Array.new(size=((bits >> 24) & 255), 0)
  bytes[0] = (bits >> 16) & 255 if size >= 1
  bytes[1] = (bits >>  8) & 255 if size >= 2
  bytes[2] = (bits      ) & 255 if size >= 3
  bytes.pack("C*").unpack("H*")[0].rjust(64, '0') end

 def encode_compact_bits(target) # target bignum hex to compact bits (int)
  bytes = OpenSSL::BN.new(target, 16).to_mpi
  size = bytes.size - 4
  nbits = size << 24
  nbits |= (bytes[4] << 16) if size >= 1
  nbits |= (bytes[5] <<  8) if size >= 2
  nbits |= (bytes[6]      ) if size >= 3
  nbits end

 def decode_target(target_bits)
  case target_bits
  when Integer; [ decode_compact_bits(target_bits).to_i(16), target_bits ]
  when String;  [ target_bits.to_i(16), encode_compact_bits(target_bits) ] end end

 def bitcoin_elliptic_curve() ::OpenSSL::PKey::EC.new("secp256k1") end
 def inspect_key(key)         [ key.private_key_hex, key.public_key_hex ] end

 def generate_key
  key = bitcoin_elliptic_curve.generate_key
  inspect_key( key ) end

 def generate_address
  prvkey, pubkey = generate_key
  [ pubkey_to_address(pubkey), prvkey, pubkey, hash160(pubkey) ] end

 def bitcoin_hash(hex)        Digest::SHA256.digest( Digest::SHA256.digest( [hex].pack("H*").reverse ) ).reverse.bth end
 def bitcoin_byte_hash(bytes) Digest::SHA256.digest( Digest::SHA256.digest(bytes)) end

 def bitcoin_mrkl(a, b) bitcoin_hash(b + a) end

 def block_hash(prev_block, mrkl_root, time, bits, nonce, ver)
  h = "%08x%08x%08x%064s%064s%08x" %
   [nonce, bits, time, mrkl_root, prev_block, ver]
  bitcoin_hash(h) end

 def block_scrypt_hash(prev_block, mrkl_root, time, bits, nonce, ver)  # DEPRECATE???
  h = "%08x%08x%08x%064s%064s%08x" %
  [nonce, bits, time, mrkl_root, prev_block, ver]
  litecoin_hash(h) end

 def hash_mrkl_tree(tx) # get merkle tree for given +tx+ list.
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

 def mrkl_branch_root(branch, target, idx) # get merkle root from +branch+ and +target+.
  branch.each do |hash|
   a, b = *( idx & 1 == 0 ? [target, hash] : [hash, target] )
   idx >>= 1;
   target = bitcoin_mrkl( a, b ) end
  target end

 def sign_data(key, data)
  sig = nil
  loop {
   sig = key.dsa_sign_asn1(data)
   #sig = ::Bitcoin::Secp256k1.sign([data].pack("H*"), key.private_key.to_s) # sig = key.dsa_sign_asn1(data)
   if Script.is_low_der_signature?(sig) then sig
    else sig end #::Bitcoin::Secp256k1.normalize(sig) end Normaization is broken,
   buf = sig + [Script::SIGHASH_TYPE[:all]].pack("C") # is_der_signature expects sig + sighash_type format
   if Script.is_der_signature?(buf) then break
   else p ["Bitcoin#sign_data: invalid der signature generated, trying again.", data.unpack("H*")[0], sig.unpack("H*")[0]] end }
  return sig end

 def verify_signature(pubkey, signature, hash) # Verifies signature matches public key and data.
  return ::Bitcoin::Secp256k1.verify(hash, signature, pubkey) # Use the ffi! Which is traceable. rbsecp256k1 gem has schnorr infection.
  rescue => badThing
   raise 'Verification rescued due to: ' + badThing.inspect end

 def ossl_pub_key(hex_66) # From public hex66
  sequence = OpenSSL::ASN1::Sequence([ OpenSSL::ASN1::Integer(1), OpenSSL::ASN1::OctetString(OpenSSL::BN.new(hex_66, 16).to_s(2)), OpenSSL::ASN1::ObjectId("secp256k1", 0, :EXPLICIT)])
  pub = OpenSSL::PKey::EC.new(sequence.to_der)
  end

=begin
 def verify_signature_prev(data, signature, public_key) #
  debugger
  # Build the OpenSSL.3 pubkey.
  OpenSSL::PKey.read public_key
  public_key.verify_raw(nil, signature, data, options)
  # Cannot assign key
  key = bitcoin_elliptic_curve
  key.public_key = ::OpenSSL::PKey::EC::Point.from_hex(key.group, public_key)
  signature = Bitcoin::OpenSSL_EC.repack_der_signature(signature)
  if signature then key.dsa_verify_asn1(hash, signature)
  else false end
  rescue OpenSSL::PKey::ECError, OpenSSL::PKey::EC::Point::Error, OpenSSL::BNError
  false end
=end

 def base64_to_hex(base64_string) base64_string.scan(/.{4}/).map do |b| b.unpack('m0').first.unpack('H') end.join end
 def hex_to_base64_digest(hexdigest) [[hexdigest].pack("H*")].pack("m0") end

 def open_key(private_key_hex, public_key=nil) # https://www.rfc-editor.org/rfc/rfc5915pem
  # openssl ecparam -out ecc_private_key.key -name secp521k1 -genkey
  # openssl genpkey   -outform PEM
  # Nope: OpenSSL::PKey.read('-----BEGIN EC PRIVATE KEY-----MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgBm8tETo+73YLviIxpxMyaSu3HQHrHN+cttn7Pn1KeQGhRANCAAT/ok8McP+7yJJBDSwA4PaWZcADk5HPTq1uQaiYdw699zA5k+9vJ2C4CjoXpMxbdFo1zCtiolei8mAZ7Wiy27Lq-----END EC PRIVATE KEY-----')
  # Yep:  OpenSSL::PKey.read("-----BEGIN EC PRIVATE KEY-----\nMIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgBm8tETo+73YLviIxpxMyaSu3HQHrHN+cttn7Pn1KeQGhRANCAAT/ok8McP+7yJJBDSwA4PaWZcADk5HPTq1uQaiYdw699zA5k+9vJ2C4CjoXpMxbdFo1zCtiolei8mAZ7Wiy27Lq\n-----END EC PRIVATE KEY-----\n')
  begin
  openssl_version_string = OpenSSL::OPENSSL_VERSION
  openssl_version_number = openssl_version_string.scan(/\d+\.\d+\.\d+/).first

  if openssl_version_number.to_i < 3 then raise 'Minimum SSL is now 3.0.2' end
  if !OpenSSL::PKey.respond_to?(:read) then raise 'Found OpenSSL with no PKey.read function!' end
  if private_key_hex.match(/-----BEGIN/) then raise 'Found BEGIN in key.' end
  private_key_bytes = [private_key_hex].pack('H*')
  private_key_base64 = Base64.encode64(private_key_bytes).chomp
  pem = "-----BEGIN EC PRIVATE KEY-----\n" << private_key_base64 << "\n-----END EC PRIVATE KEY-----\n"
  private_key = OpenSSL::PKey.read(pem)

  public_key = private_key.public_key !!!
  group = private_key.group
  new_key = OpenSSL::PKey::EC.new(group)
  new_key.copy_key_material(private_key)
  new_key.set_public_key(public_key)
  return new_key
  rescue OpenSSL::PKey::PKeyError => badThing
   puts 'Pbbly unsupported due to format error.' << badThing.inspect
   raise 'Issue with reading private key' end end

 def regenerate_public_key(private_key) OpenSSL_EC.regenerate_key(private_key)[1] end

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
 def block_next_retarget(block_height) (block_height + (RETARGET_INTERVAL-block_height.divmod(RETARGET_INTERVAL).last)) - 1 end

 # current difficulty as a multiple of the minimum difficulty (highest target).
 def block_difficulty(target_nbits)
  # max_target      = 0x00000000ffff0000000000000000000000000000000000000000000000000000
  # current_target  = Bitcoin.decode_compact_bits(target_nbits).to_i(16)
  # "%.7f" % (max_target / current_target.to_f)
  bits, max_body, scaland = target_nbits, Math.log(0x00ffff), Math.log(256)
  "%.7f" % Math.exp(max_body - Math.log(bits&0x00ffffff) + scaland * (0x1d - ((bits&0xff000000)>>24))) end

 # Calculate new difficulty target. Note this takes in details of the preceeding
 # block, not the current one._____________
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
 def block_average_hashing_time(target_nbits, hashes_per_second) block_hashes_to_win(target_nbits) / hashes_per_second end

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
 def bth()         unpack("H*")[0]   end   # bin-to-hex
 def htb()         [self].pack("H*") end   # hex-to-bin
 def htb_reverse() htb.reverse       end
 def hth()         unpack("H*")[0]   end
 def reverse_hth() reverse.hth end end

class ::String; include Bitcoin::BinaryExtensions end
 @network = []
 def self.network() @network_options ||= NETWORKS[@network].dup end
  # Store the copy of network options so we can modify them in tests without breaking the defaults
 def self.network_name() @network ||= nil end
 def self.network_project() @network_project ||= nil end

 def self.network=(name)
  raise "Network descriptor '#{name}' not found." unless NETWORKS[name.to_sym]
  @network_options = nil # clear cached parameters
  @network = name.to_sym
  @network_project = network[:project] rescue nil
  @network end

 [:main, :stn, :test, :regtest].each do |n| instance_eval "def #{n}?; network_project == :#{n}; end" end

 MAX_BLOCK_SIZE = 4_294_967_296 # maximum size of a block (in bytes)
 MAX_BLOCK_SIZE_GEN = MAX_BLOCK_SIZE/2 # soft limit for new blocks
 MAX_BLOCK_SIGOPS = MAX_BLOCK_SIZE / 50 # maximum number of signature operations in a block
 MAX_ORPHAN_TRANSACTIONS = MAX_BLOCK_SIZE/100 # maximum number of orphan transactions to be kept in memory
 LOCKTIME_THRESHOLD = 500000000 # Threshold for lock_time: below this value it is interpreted as block number, else UNIX timestamp. Tue Nov  5 00:53:20 1985 UTC
 UINT32_MAX        = 0xffffffff # maximum integer value
 INT_MAX           = 0xffffffff # deprecated name, left here for compatibility with existing users.
 COINBASE_MATURITY = 100 # number of confirmations required before coinbase tx can be spent
 RETARGET_INTERVAL = 2016 # interval (in blocks) for difficulty retarget
 RETARGET          = 2016 # deprecated constant
 REWARD_DROP       = 210_000 # interval (in blocks) for mining reward reduction
 CENT              =   1_000_000
 COIN              = 100_000_000
 MIN_FEE_MODE      = [ :block, :relay, :send ]
 # https://medium.com/renproject/the-multichain-53e5f925ac2e Not needed.
 # https://github.com/bitcoin/bips/blob/master/bip-0034.mediawiki
 # https://en.bitcoin.it/wiki/Genesis_block?fbclid=IwAR1YlCeA-zRM2I4SDJ-8gx_5i9n9xgY2HQuzwcwKeQflEvZQxqXLs6YxM7g
 # https://bitcoin.stackexchange.com/questions/75733/why-does-bitcoin-no-longer-have-checkpoints
 # Removed, not used:  bip34_height

 NETWORKS = {}
 NETWORKS[:main] = {
  project: :main,
  magic_head: "\xE8\xF3\xE1\xE3",
  message_magic: "Bitcoin Signed Message:\n",
  address_version: "00",
  privkey_version: "80",
  extended_privkey_version: "0488ade4",
  extended_pubkey_version: "0488b21e",
  default_port: 8333,
  protocol_version: 70015,
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
  dns_seeds: [ '???' ],
  genesis_hash: "0x000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
  proof_of_work_limit: 0x1d00ffff,
  known_nodes: [ '???' ],
  checkpoints: {}}
 NETWORKS[:stn] = {
  project: :test,
  known_nodes: [ '????' ],
  default_port: 9333,
  magic_head: "\xE3\xE1\xF3\xE8",
  address_version: "6f",
  privkey_version: "ef",
  extended_privkey_version: "04358394",
  extended_pubkey_version: "043587cf",
  dns_seeds: [ ],
  genesis_hash: "0x000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
  proof_of_work_limit: 0x1d7fffff,
  checkpoints: {} }
 NETWORKS[:test] = {
  project: :test,
  known_nodes: [ '????' ],
  default_port: 18332 ,
  magic_head: "\xF4\xE5\xF3\xF4",
  address_version: "6f",
  privkey_version: "ef",
  extended_privkey_version: "04358394",
  extended_pubkey_version: "043587cf",
  dns_seeds: [ ],
  genesis_hash: "00000007199508e34a9ff81e6ec0c477a4cccff2a4767a8eee39c11db367b008",
  proof_of_work_limit: 0x1d7fffff,
  checkpoints: {} }
 NETWORKS[:regtest] = {
  project: :regtest,
  known_nodes: ['elsdk'],
  default_port: 18332 ,
  genesis_hash: "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
  magic_head: "\xFA\x1A\xF9\xBF",
  address_version: "6f",
  privkey_version: "ef",
  extended_privkey_version: "04358394",
  extended_pubkey_version: "043587cf",
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
  proof_of_work_limit: 0x207fffff,
  #proof_of_work_limit: 0x1d07fff8,
  dns_seeds: [ ],
  checkpoints: {} } end


=begin
  # https://github.com/etscrivner/rbsecp256k1/blob/master/documentation/index.md
  # https://b10c.me/blog/006-evolution-of-the-bitcoin-signature-length/
  # https://www.rubydoc.info/gems/rbnacl/5.0.0
  context =    ::Secp256k1::Context.create # This is rbsecp256k1 gem which has schnorr
  public_key = ::Secp256k1::PublicKey.from_data( pubkey )

  _64 =    ::Secp256k1::Signature.from_der_encoded(signature)
  p context.verify(_64, public_key, hash) # nope
  sig_64 = ::Secp256k1::Signature.from_compact(_64.compact )
  p context.verify(sig_64, public_key, hash) # nope

  p Bitcoin::Secp256k1.verify(hash, signature, pubkey) # nope
  compact_signature = [signature].pack('H*')
  signature = ::RbNaCl::Signatures::Ed25519.signature_unpack(compact_signature)
  r = signature[0..31].unpack('H*')[0]
  s = signature[32..-1].unpack('H*')[0]
  signature_64_bytes = [r, s].join('').scan(/../).map { |x| x.hex }.pack('c*')
  p context.verify(signature_64_bytes, public_key.public_key, hash)


 context = ::Secp256k1::Context.create
 key_pair = context.generate_key_pair
 p key_pair.public_key.compressed
 require 'digest'

 context = Secp256k1::Context.create
 key_pair = context.generate_key_pair
 hash = Digest::SHA256.digest("test message")

 signature = context.sign(key_pair.private_key, hash)

 # 1. Verify signature against matching message
 context.verify(signature, key_pair.public_key, hash)


  Openssl attempts.
  # repacked = Bitcoin::OpenSSL_EC.repack_der_signature(signature) OpenSSL 1.0.1k handling of DER signatures
  ec_key = OpenSSL::PKey::EC.new(group)
  point = OpenSSL::PKey::EC::Point.new(ec_key.group, value)
  point.group.point_conversion_form = :compressed
  oct_str = OpenSSL::ASN1::OctetString pubkey
  sequence = OpenSSL::ASN1::Sequence([ OpenSSL::ASN1::Integer(1), oct_str, OpenSSL::ASN1::ObjectId("secp256k1", 0, :EXPLICIT)])
  pub = OpenSSL::PKey::EC.new(sequence.to_der)
  ossl_pub = ossl_pub_key(pubkey)
  public_key.verify_raw(nil, repacked, hash)

 key = OpenSSL::PKey::EC.new('secp256k1')
 key.generate_key
 public_key_string = "04" + key.public_key.to_bn.to_s(16)
 public_key = OpenSSL::PKey::EC.new(public_key_string)

 OpenSSL::PKey::EC.new("-----BEGIN EC PUBLIC KEY-----\n" + Base64.strict_encode64(pubkey) + "\n-----END EC PUBLIC KEY-----\n")

 value = "\xDE\xE1\xBB\x1Dw\x19v\xCBuO\x1F\x0F\xCE$8\xBA\xF0\xB5\xFC\xD1\xBC\xC9-\x80\x86\xED1f\xE3\xF2\t\xB0"
 group = "secp256k1" # choose an elliptic curve group
 ec_key = OpenSSL::PKey::EC.new(group) # create an EC object with the group
 ec_key.group.point_conversion_form = :compressed
 point = OpenSSL::PKey::EC::Point.new(ec_key.group, value) # create a point object with the value and the group
 ec_key.public_key = point # set the public key of the EC object to the point object

 "-----BEGIN EC PUBLIC KEY-----\n3uG7HXcZdst1Tx8PziQ4uvC1/NG8yS2Ahu0xZuPyCbA=\n-----END EC PUBLIC KEY-----\n" unsupported
 "-----BEGIN PUBLIC KEY-----\n3uG7HXcZdst1Tx8PziQ4uvC1/NG8yS2Ahu0xZuPyCbA=\n-----END PUBLIC KEY-----\n" unsupported

 openssl ecparam -genkey -name secp256k1 -out ec_key.pem -param_enc explicit
 OpenSSL::PKey::EC.generate("secp256k1").public_key
 OpenSSL::PKey::EC.generate("secp256k1").public_key.to_bn
 https://stackoverflow.com/questions/22293864/ruby-openssl-convert-elliptic-curve-point-octet-string-into-opensslpkeyec
 openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 > foo.priv

   private1 = OpenSSL::PKey::EC.generate("secp256k1")
   key = OpenSSL::PKey::EC.new('secp256k1')
   key1 = key.dup
   OpenSSL::PKey::EC::Point.new(key.group, OpenSSL::BN.new(hex66))
  hex_string = "02a474c529904d5dd2e15a9afac5d4c4d41fa365c683c62ed70d3052b3a308fdbf"
  OpenSSL::PKey::EC::Point#octet_string_to_point hex_string
  bin_string = [::Base64.decode64(hex_66)].pack('H*')
  asn1 = OpenSSL::ASN1.decode(bin_string)
  ec_key = OpenSSL::PKey::EC.new(asn1)
=end
