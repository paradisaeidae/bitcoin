require_relative '../bitcoin-sv'
require_relative 'opcodes'
class Bitcoin::Script
# create a new script. +bytes+ is typically input_script + output_script
def initialize(input_script, previous_output_script=nil)
 @raw_byte_sizes = [input_script.bytesize, previous_output_script ? previous_output_script.bytesize : 0]
 @input_script, @previous_output_script = input_script, previous_output_script
 @parse_invalid = nil
 @script_codeseparator_index = nil
 @raw = if @previous_output_script
  @input_script + [ Bitcoin::Script::OP_CODESEPARATOR ].pack("C") + @previous_output_script
  else @input_script end
 @chunks = parse(@input_script)
 if previous_output_script
  @script_codeseparator_index = @chunks.size
  @chunks << Bitcoin::Script::OP_CODESEPARATOR
  @chunks += parse(@previous_output_script) end
 @stack, @stack_alt, @exec_stack = [], [], []
 @last_codeseparator_index = 0
 @do_exec = true
 rescue => badThing
  debugger end

class ::String
 attr_accessor :bitcoin_pushdata
 attr_accessor :bitcoin_pushdata_length end

def parse(bytes, offset=0) # parse raw script
 program = bytes.unpack("C*")
 chunks = []
 until program.empty?
  opcode = program.shift
  if (opcode > 0) && (opcode < OP_PUSHDATA1)
   len, tmp = opcode, program[0]
   chunks << program.shift(len).pack("C*")   # 0x16 = 22 due to OP_2_16 from_string parsing
   if len == 1 && tmp && tmp <= 22
    chunks.last.bitcoin_pushdata = OP_PUSHDATA0
    chunks.last.bitcoin_pushdata_length = len
   else raise "invalid OP_PUSHDATA0 len != chunks.last.bytesize" if len != chunks.last.bytesize end
  elsif (opcode == OP_PUSHDATA1)
   len = program.shift(1)[0]
   chunks << program.shift(len).pack("C*")
   unless len > OP_PUSHDATA1 && len <= 0xff
    chunks.last.bitcoin_pushdata = OP_PUSHDATA1
    chunks.last.bitcoin_pushdata_length = len
   else raise "invalid OP_PUSHDATA1 len != chunks.last.bytesize" if len != chunks.last.bytesize end
  elsif (opcode == OP_PUSHDATA2)
   len = program.shift(2).pack("C*").unpack("v")[0]
   chunks << program.shift(len).pack("C*")
   unless len > 0xff && len <= 0xffff
    chunks.last.bitcoin_pushdata = OP_PUSHDATA2
    chunks.last.bitcoin_pushdata_length = len
   else raise "invalid OP_PUSHDATA2 len != chunks.last.bytesize" if len != chunks.last.bytesize end
  elsif (opcode == OP_PUSHDATA4)
   len = program.shift(4).pack("C*").unpack("V")[0]
   chunks << program.shift(len).pack("C*")
   unless len > 0xffff # && len <= 0xffffffff
    chunks.last.bitcoin_pushdata = OP_PUSHDATA4
    chunks.last.bitcoin_pushdata_length = len
   else raise "invalid OP_PUSHDATA4 len != chunks.last.bytesize" if len != chunks.last.bytesize end
  else chunks << opcode end end
 chunks
 rescue => badThing
  # bail out! #run returns false but serialization roundtrips still create the right payload.
  puts badThing
  chunks.pop if badThing.message.include?("invalid OP_PUSHDATA")
  @parse_invalid = true
  c = bytes.unpack("C*").pack("C*")
  c.bitcoin_pushdata = OP_PUSHDATA_INVALID
  c.bitcoin_pushdata_length = c.bytesize
  chunks << c end #   raise badThing 

def to_string(chunks=nil) # string representation of the script
 string = ""
 (chunks || @chunks).each.with_index{ |i, idx |
  string << " " unless idx == 0
  string << case i
  when Integer
   if opcode = OPCODES_PARSE_BINARY[i] then opcode
   else "(opcode-#{i})" end
  when String
   if i.bitcoin_pushdata then "#{i.bitcoin_pushdata}:#{i.bitcoin_pushdata_length}:".force_encoding('binary') + i.unpack("H*")[0]
   else i.unpack("H*")[0] end end }
 string end

def to_binary(chunks=nil)
 (chunks || @chunks).map{ |chunk|
  case chunk
  when Integer; [chunk].pack("C*")
  when String; self.class.pack_pushdata(chunk) end
 }.join end

alias :to_payload :to_binary

def to_binary_without_signatures(drop_signatures, chunks=nil)
  buf = []
  (chunks || @chunks).each.with_index{|chunk,idx|
   if chunk == OP_CODESEPARATOR and idx <= @last_codeseparator_index
    buf.clear
   elsif chunk == OP_CODESEPARATOR
    if idx == @script_codeseparator_index
     break
     else
       # skip
     end
   elsif drop_signatures.none?{|e| e == chunk }
    buf << chunk end }
  to_binary(buf) end

# Returns a script that deleted the script before the index specified by separator_index.
def subscript_codeseparator(separator_index)
 buf = []
 process_separator_index = 0
 (chunks || @chunks).each{|chunk|
  buf << chunk if process_separator_index == separator_index
  process_separator_index += 1 if chunk == OP_CODESEPARATOR and process_separator_index < separator_index }
 to_binary(buf) end

# Adds opcode (OP_0, OP_1, ... OP_CHECKSIG etc.) Returns self.
def append_opcode(opcode)
 raise "Opcode should be an integer" if !opcode.is_a?(Integer)
 if opcode >= OP_0 && opcode <= 0xff then @chunks << opcode
 else raise "Opcode should be within [0x00, 0xff]" end 
 self end

def append_number(number) # Adds the opcode corresponding to the given number. Returns self.
 opcode =
  case number
  when -1 then OP_1NEGATE
  when 0 then OP_0
  when 1 then OP_1
  when 2..16 then OP_2 + (16 - number)
  end
 raise "No opcode for number #{number}" if opcode.nil?
 append_opcode(opcode) end

# Adds binary string as pushdata. Pushdata will be encoded in the most compact form
# (unless the string contains internal info about serialization that's added by Script class)
# Returns self.
def append_pushdata(pushdata_string)
  raise "Pushdata should be a string" if !pushdata_string.is_a?(String)
  @chunks << pushdata_string
  self end

def self.pack_pushdata(data)
 size = data.bytesize
 if data.bitcoin_pushdata
  size = data.bitcoin_pushdata_length
  pack_pushdata_align(data.bitcoin_pushdata, size, data)
 else
  head = if size < OP_PUSHDATA1
  [size].pack("C")
 elsif size <= 0xff
  [OP_PUSHDATA1, size].pack("CC")
 elsif size <= 0xffff
  [OP_PUSHDATA2, size].pack("Cv")
  #elsif size <= 0xffffffff
  else [OP_PUSHDATA4, size].pack("CV") end
 head + data end end

def self.pack_pushdata_align(pushdata, len, data)
 case pushdata
 when OP_PUSHDATA1
  [OP_PUSHDATA1, len].pack("CC") + data
 when OP_PUSHDATA2
  [OP_PUSHDATA2, len].pack("Cv") + data
 when OP_PUSHDATA4
  [OP_PUSHDATA4, len].pack("CV") + data
 when OP_PUSHDATA_INVALID
  data
 else # OP_PUSHDATA0
  [len].pack("C") + data end end

def self.from_string(input_script, previous_output_script=nil) # script object of a string representation
 if previous_output_script then new(binary_from_string(input_script), binary_from_string(previous_output_script))
 else new(binary_from_string(input_script)) end end

class ScriptOpcodeError < StandardError; end

def self.binary_from_string(script_string) # raw script binary of a string representation
 buf = ""
 script_string.split(" ").each{ |i|
  i = if opcode = OPCODES_PARSE_STRING[i] then opcode
  else
   case i
   when /OP_PUSHDATA/             # skip
   when /OP_(.+)$/;               raise ScriptOpcodeError, "#{i} not defined!"
   when /\(opcode\-(\d+)\)/;      $1.to_i
   when "(opcode";                # skip  # fix invalid opcode parsing
   when /^(\d+)\)/;               $1.to_i # fix invalid opcode parsing
   when /(\d+):(\d+):(.+)?/
    pushdata, len, data = $1.to_i, $2.to_i, $3
    pack_pushdata_align(pushdata, len, [data].pack("H*"))
   else
    data = [i].pack("H*")
    pack_pushdata(data) end end
  buf << if i.is_a?(Integer) # Integer
   i < 256 ? [i].pack("C") : [OpenSSL::BN.new(i.to_s,10).to_hex].pack("H*")
   else i
   end if i }
 buf end

def invalid?
 @script_invalid ||= false end

# run the script. +check_callback+ is called for OP_CHECKSIG operations
def run(block_timestamp=Time.now.to_i, opts={}, &check_callback)
 return false if @parse_invalid
 @script_invalid = true if @raw_byte_sizes.any?{ | size | size > 10_000 }
 @last_codeseparator_index = 0 # 1333238400
 @debug = []
 @chunks.each.with_index{| chunk, idx |
  break if invalid?
  @chunk_last_index = idx
  @debug << @stack.map{ |i| i.unpack("H*") rescue i }
  @do_exec = @exec_stack.count(false) == 0 ? true : false
  #p [@stack, @do_exec]
  case chunk
  when Integer
   if DISABLED_OPCODES.include?(chunk)
    @script_invalid = true
    @debug << "DISABLED_#{OPCODES[chunk]}"
    break end
   next @debug.pop  unless (@do_exec || (OP_IF <= chunk && chunk <= OP_ENDIF))
   case chunk
   when *OPCODES_METHOD.keys
    m = method( n=OPCODES_METHOD[chunk] )
    @debug << n.to_s.upcase
    case m.arity # invoke opcode method
    when 0
     m.call
    when 1
     m.call(check_callback)
    when -2 # One fixed parameter, one optional
     m.call(check_callback, opts)
    else puts "Bitcoin::Script: opcode #{name} method parameters invalid" end
   when *OP_2_16
    @stack << OP_2_16.index(chunk) + 2
    @debug << "OP_#{chunk-80}"
   else
    name = OPCODES[chunk] || chunk
    puts "Bitcoin::Script: opcode #{name} unkown or not implemented\n#{to_string.inspect}"
    raise "opcode #{name} unkown or not implemented" end
  when String
   if @do_exec
    @debug << "PUSH DATA #{chunk.unpack("H*")[0]}"
    @stack << chunk
   else @debug.pop end end }
 @debug << @stack.map{ |i| i.unpack("H*") rescue i } #if @do_exec
 if @script_invalid
  @stack << 0
  @debug << "INVALID TRANSACTION" end
 @debug << "RESULT"
 return false if @stack.empty?
 return false if cast_to_bool(@stack.pop) == false
 true end

def invalid
 @script_invalid = true; nil end

def self.drop_signatures(script_pubkey, drop_signatures)
 script = new(script_pubkey).to_string.split(" ").delete_if{|c| drop_signatures.include?(c) }.join(" ")
 script_pubkey = binary_from_string(script) end

def is_standard? # check if script is in one of the recognized standard formats
 is_pubkey? || is_hash160? || is_multisig? || is_op_return? end

def is_pubkey? # is this a pubkey script
 return false if @chunks.size != 2
 (@chunks[1] == OP_CHECKSIG) && @chunks[0] && (@chunks[0].is_a?(String)) && @chunks[0] != OP_RETURN end
alias :is_send_to_ip? :is_pubkey?

def is_hash160? # is this a hash160 (address) script
 return false if @chunks.size != 5
 (@chunks[0..1] + @chunks[-2..-1]) ==
  [OP_DUP, OP_HASH160, OP_EQUALVERIFY, OP_CHECKSIG] &&
  @chunks[2].is_a?(String) && @chunks[2].bytesize == 20 end

def is_multisig? # is this a multisig script
 return false  if @chunks.size < 4 || !@chunks[-2].is_a?(Integer)
 @chunks[-1] == OP_CHECKMULTISIG and get_multisig_pubkeys.all?{|c| c.is_a?(String) } end

def is_op_return? # is this an op_return script
 @chunks[0] == OP_RETURN && @chunks.size <= 2 end

# Verify the script is only pushing data onto the stack
def is_push_only?(script_data=nil)
 check_pushes(true, false, (script_data||@input_script)) end

# Make sure opcodes used to push data match their intended length ranges
def pushes_are_canonical?(script_data=nil)
 check_pushes(false, true, (script_data||@raw)) end

def check_pushes(push_only=true, canonical_only=false, buf)
 program = buf.unpack("C*")
 until program.empty?
  opcode = program.shift
  if opcode > OP_16
   return false if push_only
   next end
  if opcode < OP_PUSHDATA1 && opcode > OP_0
   # Could have used an OP_n code, rather than a 1-byte push.
   return false if canonical_only && opcode == 1 && program[0] <= 16
   program.shift(opcode) end
  if opcode == OP_PUSHDATA1
   len = program.shift(1)[0]
   # Could have used a normal n-byte push, rather than OP_PUSHDATA1.
   return false if canonical_only && len < OP_PUSHDATA1
   program.shift(len) end
  if opcode == OP_PUSHDATA2
   len = program.shift(2).pack("C*").unpack("v")[0]
   # Could have used an OP_PUSHDATA1.
   return false if canonical_only && len <= 0xff
   program.shift(len) end
  if opcode == OP_PUSHDATA4
   len = program.shift(4).pack("C*").unpack("V")[0]
   # Could have used an OP_PUSHDATA2.
   return false if canonical_only && len <= 0xffff
   program.shift(len) end end
 true
 rescue => badThing
  puts badThing.inspect
  # catch parsing errors
  false end

# get type of this tx
def type
 if    is_hash160?;              :hash160
 elsif is_pubkey?;               :pubkey
 elsif is_multisig?;             :multisig
 elsif is_op_return?;            :op_return
 else;                           :unknown end end

# get the public key for this pubkey script
def get_pubkey
 return @chunks[0].unpack("H*")[0] if @chunks.size == 1
 is_pubkey? ? @chunks[0].unpack("H*")[0] : nil end

# get the pubkey address for this pubkey script
def get_pubkey_address
 Bitcoin.pubkey_to_address(get_pubkey) end

# get the hash160 for this hash160
def get_hash160
 return @chunks[2..-3][0].unpack("H*")[0]  if is_hash160?
 return Bitcoin.hash160(get_pubkey)        if is_pubkey? end

# get the hash160 address for this hash160 script
def get_hash160_address
 Bitcoin.hash160_to_address(get_hash160) end

# get the public keys for this multisig script
def get_multisig_pubkeys
 1.upto(@chunks[-2] - 80).map{|i| @chunks[i] } end

# get the pubkey addresses for this multisig script
def get_multisig_addresses
 get_multisig_pubkeys.map{|pub|
  begin
  Bitcoin::Key.new(nil, pub.unpack("H*")[0]).addr
  rescue OpenSSL::PKey::ECError, OpenSSL::PKey::EC::Point::Error
  end } end

# get the data possibly included in an OP_RETURN script
def get_op_return_data
 return nil  unless is_op_return?
 cast_to_string(@chunks[1]).unpack("H*")[0]  if @chunks[1] end
 
# get all addresses this script corresponds to (if possible)
def get_addresses
 return [get_pubkey_address]    if is_pubkey?
 return [get_hash160_address]   if is_hash160?
 return get_multisig_addresses  if is_multisig?
 [] end

# get single address, or first for multisig script
def get_address
 addrs = get_addresses
 addrs.is_a?(Array) ? addrs[0] : addrs end

# generate pubkey tx script for given +pubkey+. returns a raw binary script of the form:
#  <pubkey> OP_CHECKSIG
def self.to_pubkey_script(pubkey)
 pack_pushdata([pubkey].pack("H*")) + [ OP_CHECKSIG ].pack("C") end

# generate hash160 tx for given +address+. returns a raw binary script of the form:
#  OP_DUP OP_HASH160 <hash160> OP_EQUALVERIFY OP_CHECKSIG
def self.to_hash160_script(hash160)
 return nil unless hash160
 #  DUP   HASH160  length  hash160    EQUALVERIFY  CHECKSIG
 [ ["76", "a9",    "14",   hash160,   "88",        "ac"].join ].pack("H*") end

# generate p2wpkh tx for given +address+. returns a raw binary script of the form:
# 0 <hash160>
#def self.to_witness_hash160_script(hash160) # DEPRECATE
# return nil  unless hash160
# to_witness_script(0, hash160) end

# generate hash160 depending on the type of the given +address+.
# see #to_hash160_script
def self.to_address_script(address)
 hash160 = Bitcoin.hash160_from_address(address)
 case Bitcoin.address_type(address)
 when :hash160; to_hash160_script(hash160) end end

# generate multisig output script for given +pubkeys+, expecting +m+ signatures.
# returns a raw binary script of the form:
#  <m> <pubkey> [<pubkey> ...] <n_pubkeys> OP_CHECKMULTISIG
def self.to_multisig_script(m, *pubkeys)
 raise "invalid m-of-n number" unless [m, pubkeys.size].all?{|i| (0..20).include?(i) }
 raise "invalid m-of-n number" if pubkeys.size < m
 pubs = pubkeys.map{|pk| pack_pushdata([pk].pack("H*")) }
 m = m > 16 ?              pack_pushdata([m].pack("C"))              : [80 + m.to_i].pack("C")
 n = pubkeys.size > 16 ?   pack_pushdata([pubkeys.size].pack("C"))   : [80 + pubs.size].pack("C")
 [ m, *pubs, n, [OP_CHECKMULTISIG].pack("C")].join end

# generate OP_RETURN output script with given data. returns a raw binary script of the form: OP_RETURN <data>
def self.to_op_return_script(data = nil)
 buf = [ OP_RETURN ].pack("C")
 return buf unless data
 return buf + pack_pushdata( [data].pack("H*") ) end

# generate input script sig spending a pubkey output with given +signature+ and +pubkey+.
# returns a raw binary script sig of the form:  <signature> [<pubkey>]
def self.to_pubkey_script_sig(signature, pubkey, hash_type = SIGHASH_TYPE[:all])
 buf = pack_pushdata(signature + [hash_type].pack("C"))
 return buf unless pubkey
 expected_size = case pubkey[0]
  when "\x04";         65
  when "\x02", "\x03"; 33 end
 raise "pubkey is not in escaped hex, binary form: #{pubkey.inspect}" if !expected_size || pubkey.bytesize != expected_size
 return buf + pack_pushdata(pubkey) end # returns a raw binary script sig of the form:  <signature> [<pubkey>]

# alias for #to_pubkey_script_sig
def self.to_signature_pubkey_script(*a)
 puts 'DEPRECATED alias: to_signature_pubkey_script'
 to_pubkey_script_sig(*a) end

# generate input script sig spending a multisig output script.
# returns a raw binary script sig of the form:  OP_0 <sig> [<sig> ...]
def self.to_multisig_script_sig(*sigs)
 hash_type = sigs.last.is_a?(Numeric) ? sigs.pop : SIGHASH_TYPE[:all]
 partial_script = [OP_0].pack("C*")
 sigs.reverse_each{ |sig| partial_script = add_sig_to_multisig_script_sig(sig, partial_script, hash_type) }
 partial_script end

# take a multisig script sig and add
# another signature to it after the OP_0. Used to sign a tx by
# multiple parties. Signatures must be in the same order as the
# pubkeys in the output script being redeemed.
def self.add_sig_to_multisig_script_sig(sig, script_sig, hash_type = SIGHASH_TYPE[:all])
 signature = sig + [hash_type].pack("C*")
 offset = script_sig.empty? ? 0 : 1
 script_sig.insert(offset, pack_pushdata(signature)) end

# generate input script sig spending a multisig output script.
# returns a raw binary script sig of the form: OP_0 <sig> [<sig> ...] <redeem_script>
def self.to_multisig_script_sig(redeem_script, *sigs)
 to_multisig_script_sig(*sigs.flatten) + pack_pushdata(redeem_script) end

# Sort signatures in the given +script_sig+ according to the order of pubkeys in
# the redeem script. Also needs the +sig_hash+ to match signatures to pubkeys.
def self.sort_multisig_signatures script_sig, sig_hash
 script = new(script_sig)
 redeem_script = new(script.chunks[-1])
 pubkeys = redeem_script.get_multisig_pubkeys
 # find the pubkey for each signature by trying to verify it
 sigs = Hash[ script.chunks[1...-1].map.with_index do |sig, idx|
  pubkey = pubkeys.map { |key|
   Bitcoin::Key.new(nil, key.hth).verify(sig_hash, sig) ? key : nil }.compact.first
  raise "Key for signature ##{idx} not found in redeem script!"  unless pubkey
  [pubkey, sig]
 end ]
 [OP_0].pack("C*") + pubkeys.map {|k| sigs[k] ? pack_pushdata(sigs[k]) : nil }.join +
  pack_pushdata(redeem_script.raw) end

def get_signatures_required
 return false unless is_multisig?
 @chunks[0] - 80 end

def get_keys_provided
 return false  unless is_multisig?
 @chunks[-2] - 80 end

def codeseparator_count
 @chunks.select{|c|c == Bitcoin::Script::OP_CODESEPARATOR}.length end

# This matches CScript::GetSigOpCount(bool fAccurate)
# Note: this does not cover P2SH script which is to be unserialized
#  and checked explicitly when validating blocks.
def sigops_count_accurate(is_accurate)
 count = 0
 last_opcode = nil
 @chunks.each do |chunk| # pushdate or opcode
  if chunk == OP_CHECKSIG || chunk == OP_CHECKSIGVERIFY then count += 1
  elsif chunk == OP_CHECKMULTISIG || chunk == OP_CHECKMULTISIGVERIFY
   # Accurate mode counts exact number of pubkeys required (not signatures, but pubkeys!).
   # Only used in P2SH scripts.
   # Inaccurate mode counts every multisig as 20 signatures.
   if is_accurate && last_opcode && last_opcode.is_a?(Integer) && last_opcode >= OP_1 && last_opcode <= OP_16
    count += ::Bitcoin::Script.decode_OP_N(last_opcode)
   else count += 20 end end
  last_opcode = chunk end
 count end

def pop_int(count=nil)
 return cast_to_bignum(@stack.pop) unless count
 @stack.pop(count).map{|i| cast_to_bignum(i) } end

def pop_string(count=nil)
 return cast_to_string(@stack.pop) unless count
 @stack.pop(count).map{|i| cast_to_string(i) } end

def cast_to_bignum(buf)
 return (invalid; 0) unless buf
 case buf
 when Numeric
  invalid if OpenSSL::BN.new(buf.to_s).to_s(0).unpack("N")[0] > 4
  buf
 when String
  invalid if buf.bytesize > 4
  OpenSSL::BN.new([buf.bytesize].pack("N") + buf.reverse, 0).to_i
 else; raise TypeError, 'cast_to_bignum: failed to cast: %s (%s)' % [buf, buf.class] end end

def cast_to_string(buf)
 return (invalid; "") unless buf
 case buf
 when Numeric; OpenSSL::BN.new(buf.to_s).to_s(0)[4..-1].reverse
 when String; buf;
 else; raise TypeError, 'cast_to_string: failed to cast: %s (%s)' % [buf, buf.class] end end

def cast_to_bool(buf)
 buf = cast_to_string(buf).unpack("C*")
 size = buf.size
 buf.each.with_index{|byte,index|
  if byte != 0   # Can be negative zero
   if (index == (size-1)) && byte == 0x80 then return false
   else return true end end }
 return false end

def codehash_script(opcode)
 # CScript scriptCode(pbegincodehash, pend);
 script    = to_string(@chunks[(@codehash_start||0)...@chunks.size-@chunks.reverse.index(opcode)])
 checkhash = Bitcoin.hash160(Bitcoin::Script.binary_from_string(script).unpack("H*")[0])
 [script, checkhash] end

# do a CHECKSIG operation on the current stack,
# asking +check_callback+ to do the actual signature verification.
# This is used by Protocol::Tx#verify_input_signature
def op_checksig(check_callback, opts={})
 return invalid if @stack.size < 2
 pubkey = cast_to_string(@stack.pop)
 return (@stack << 0) unless Bitcoin::Script.check_pubkey_encoding?(pubkey, opts)
 drop_sigs = [ cast_to_string(@stack[-1]) ]
 signature = cast_to_string(@stack.pop)
 return invalid unless Bitcoin::Script.check_signature_encoding?(signature, opts)
 return (@stack << 0) if signature == ""
 sig, hash_type = parse_sig(signature)
 subscript = sighash_subscript(drop_sigs, opts)
 if check_callback == nil # for tests
  @stack << 1
 else @stack << ((check_callback.call(pubkey, sig, hash_type, subscript) == true) ? 1 : 0) end end # real signature check callback

def sighash_subscript(drop_sigs, opts = {})
 if opts[:fork_id]
  drop_sigs.reject! do |signature|
   if signature && signature.size > 0
    _, hash_type = parse_sig(signature) # The underscore adds as a placeholder for the variable matching inside Ruby. It is just as greedy as any named variable, but as it is not named, you cannot access it later on. 
    (hash_type&SIGHASH_TYPE[:forkid]) != 0 end end end
 if inner_p2sh? && @inner_script_code
  ::Bitcoin::Script.new(@inner_script_code).to_binary_without_signatures(drop_sigs)
 else to_binary_without_signatures(drop_sigs) end end

def self.check_pubkey_encoding?(pubkey, opts={})
 return false if opts[:verify_strictenc] && !is_compressed_or_uncompressed_pub_key?(pubkey)
 true end

def self.is_compressed_or_uncompressed_pub_key?(pubkey)
 return false if pubkey.bytesize < 33 # "Non-canonical public key: too short"
 case pubkey[0]
 when "\x04"
  return false if pubkey.bytesize != 65 # "Non-canonical public key: invalid length for uncompressed key"
 when "\x02", "\x03"
  return false if pubkey.bytesize != 33 # "Non-canonical public key: invalid length for compressed key"
 else
  return false end # "Non-canonical public key: compressed nor uncompressed" 
 true end

# Loosely matches CheckSignatureEncoding()
def self.check_signature_encoding?(sig, opts={})
 return true  if sig.bytesize == 0
 return false if (opts[:verify_dersig] || opts[:verify_low_s] || opts[:verify_strictenc]) and !is_der_signature?(sig)
 return false if opts[:verify_low_s] && !is_low_der_signature?(sig)
 if opts[:verify_strictenc]
  return false unless is_defined_hashtype_signature?(sig)
  hash_type = sig.unpack('C*')[-1]
  uses_forkid = (hash_type&SIGHASH_TYPE[:forkid]) != 0
  return false if opts[:fork_id] && !uses_forkid
  return false if !opts[:fork_id] && uses_forkid end
 true end

# Loosely correlates with IsDERSignature() from interpreter.cpp
def self.is_der_signature?(sig)
 return false if sig.bytesize < 9  # Non-canonical signature: too short
 return false if sig.bytesize > 73 # Non-canonical signature: too long
 s = sig.unpack("C*")
 return false if s[0] != 0x30     # Non-canonical signature: wrong type
 return false if s[1] != s.size-3 # Non-canonical signature: wrong length marker
 length_r = s[3]
 return false if (5 + length_r) >= s.size # Non-canonical signature: S length misplaced
 length_s = s[5+length_r]
 return false if (length_r + length_s + 7) != s.size # Non-canonical signature: R+S length mismatch
 return false if s[2] != 0x02  # Non-canonical signature: R value type mismatch
 return false if length_r == 0 # Non-canonical signature: R length is zero
 r_val = s.slice(4, length_r)
 return false if r_val[0] & 0x80 != 0 # Non-canonical signature: R value negative
 return false if length_r > 1 && (r_val[0] == 0x00) && !(r_val[1] & 0x80 != 0) # Non-canonical signature: R value excessively padded
 s_val = s.slice(6 + length_r, length_s)
 return false if s[6 + length_r - 2] != 0x02 # Non-canonical signature: S value type mismatch
 return false if length_s == 0               # Non-canonical signature: S length is zero
 return false if (s_val[0] & 0x80) != 0      # Non-canonical signature: S value negative
 return false if length_s > 1 && (s_val[0] == 0x00) && !(s_val[1] & 0x80) # Non-canonical signature: S value excessively padded
 true end

def self.compare_big_endian(c1, c2) # Compares two arrays of bytes
 c1, c2 = c1.dup, c2.dup            # Clone the arrays
 while c1.size > c2.size
  return 1 if c1.shift > 0 end
 while c2.size > c1.size
  return -1 if c2.shift > 0 end
 c1.size.times{|idx| return c1[idx] - c2[idx] if c1[idx] != c2[idx] }
 0 end

def self.is_low_der_signature?(sig) # Loosely correlates with IsLowDERSignature() from interpreter.cpp
 s = sig.unpack("C*")
 length_r = s[3]
 length_s = s[5+length_r]
 s_val = s.slice(6 + length_r, length_s)
 # If the S value is above the order of the curve divided by two, its
 # complement modulo the order could have been used instead, which is
 # one byte shorter when encoded correctly.
 max_mod_half_order = [
  0x7f,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
  0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
  0x5d,0x57,0x6e,0x73,0x57,0xa4,0x50,0x1d,
  0xdf,0xe9,0x2f,0x46,0x68,0x1b,0x20,0xa0]
 compare_big_endian(s_val, [0]) > 0 &&
  compare_big_endian(s_val, max_mod_half_order) <= 0 end

def self.is_defined_hashtype_signature?(sig)
 return false if sig.empty?
 s = sig.unpack("C*")
 hash_type = s[-1] & (~(SIGHASH_TYPE[:anyonecanpay] | SIGHASH_TYPE[:forkid]))
 return false if hash_type < SIGHASH_TYPE[:all] || hash_type > SIGHASH_TYPE[:single] # Non-canonical signature: unknown hashtype byte
 true end

private
def parse_sig(sig)
 hash_type = sig[-1].unpack("C")[0]
 sig = sig[0...-1]
 return sig, hash_type end end