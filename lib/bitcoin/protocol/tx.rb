module Bitcoin;module Protocol
# https://en.bitcoin.it/wiki/Protocol_documentation#tx Ignore the segwits.
# https://github.com/bitcoin-sv-specs/protocol/pull/16/commits/a28bd53735bb4e14ff5db4acd4ebdb5b20a1df75
# https://duckduckgo.com/?q=P2SH+Script+BSV&t=ffcm&ia=web https://coingeek.com/what-is-p2sh-and-why-must-it-go/
# https://ruby-doc.org/core-3.0.2/Array.html#method-i-pack

def inpoint_from_io(buf)
 txin = Protocol::InPoint.new()
 txin.parse_data_from_io(buf)
 txin end

def tx_from_file(path) Prtocol::Tx.new(Protocol.read_binary_file(path)) end
module_function :inpoint_from_io, :tx_from_file

class Tx
MARKER = 0;FLAG = 1;SIGHASH_TYPE = ::Bitcoin::Script::SIGHASH_TYPE
# transaction hash, inputs (Array of InPoint), outputs (Array of OutPoint), raw protocol payload
attr_reader :hash, :inputs, :outputs, :payload, :scripts # parsed / evaluated input scripts cached for later use
attr_accessor :ver, :locktime, :marker, :flag # version (usually 1), lock time

def initialize(raw_bin = nil) # create tx from raw binary.
 @ver = 1
 @locktime = 0
 @inputs, @outputs, @scripts = [], [], []
 @ossl_pub_keys = {}
 parse_data_from_io(raw_bin) if raw_bin end

def ==(other);                 @hash == other.hash end # compare to another tx
def binary_hash;               @binary_hash ||= [@hash].pack('H*').reverse end # return the tx hash in binary format
def hash_from_payload(payload) Digest::SHA256.digest(Digest::SHA256.digest(payload)).reverse_hth end # generate the tx hash for given +payload+ in hex format
def refresh_hash;              @hash = hash_from_payload(to_payload) end # refresh_hash recalculates the tx hash and sets it on the instance
def add_in(input)              (@inputs  ||= []) << input  end
def add_out(output)            (@outputs ||= []) << output end
#alias inputs  in
#alias outputs out

def parse_data_from_io(raw_bin) # parse raw binary. Regular transactions with 0 inputs are coinbase.
  buf = raw_bin.is_a?(String) ? StringIO.new(raw_bin) : raw_bin
  @ver = buf.read(4).unpack('V')[0]
  return false if buf.eof?
  @marker = buf.read(1).unpack('c').first
  @flag   = buf.read(1).unpack('c').first
  buf.seek(buf.pos - 2)
  in_size = Protocol.unpack_var_int_from_io(buf)
  @inputs = []
  in_size.times do
   break if buf.eof?
   @inputs << Protocol.inpoint_from_io(buf) end
  return false if buf.eof?
  out_size = Protocol.unpack_var_int_from_io(buf)
  @outputs = []
  out_size.times do
   break if buf.eof?
   @outputs << Protocol.outpoint_from_io(buf) end
  return false if buf.eof?
  @locktime = buf.read(4).unpack('V')[0]
  @hash = hash_from_payload(to_payload)
  @payload = to_payload
  if buf.eof? then true else raw_bin.is_a?(StringIO) ? buf : buf.read end end

#alias parse_data parse_data_from_io

def to_payload
 pins, pouts = '', ''
 @inputs.each  { |input | pins  << input.to_payload  }
 @outputs.each { |output| pouts << output.to_payload }
 payload = [@ver].pack('V') << Protocol.pack_var_int(@inputs.size) << pins << Protocol.pack_var_int(@outputs.size) << pouts << [@locktime].pack('V')
 return payload
 rescue => badThing
  puts badThing.inspect
  debugger end

  # https://github.com/bitcoin-sv/bitcoin-sv/blob/e071a3f6c06f41068ad17134189a4ac3073ef76b/script.cpp#L834
  # http://code.google.com/p/bitcoinj/source/browse/trunk/src/com/google/bitcoin/core/Script.java#318
  # https://en.bitcoin.it/wiki/OP_CHECKSIG#How_it_works
  # https://github.com/bitcoin-sv/bitcoin-sv/blob/c2e8c8acd8ae0c94c70b59f55169841ad195bb99/src/script.cpp#L1058
  # https://wiki.bitcoinsv.io/index.php/SIGHASH_flags

 # generate a signature hash for input  +idx+. Pass the +outpoint_tx+ with the pt.idx or the +script_pubkey+ directly.
 # SIGHASH_ALL 	                 	all inputs and outputs
 # SIGHASH_NONE 	               	all inputs and no output
 # SIGHASH_SINGLE                 	all inputs and the output with the same index
 # SIGHASH_ALL | ANYONECANPAY     	its own input and all outputs
 # SIGHASH_NONE | ANYONECANPAY 	    its own input and no output
 # SIGHASH_SINGLE | ANYONECANPAY 	its own input and the output with the same index
 def signature_hash_for_input( idx, lock_scr, sHASHF)
  _32_Hzeros = "\x00".ljust(32, "\x00");  _4_Hzeros  = "\x00\x00\x00\x00"
  return _32_Hzeros if idx >= @inputs.size
  pin = @inputs.map.with_index do | input, idx_ | # @inputs is loaded with inbound spending vouts, represented as InPoints
   if idx == idx_
    if lock_scr.class == Bitcoin::P::InPoint then lock_scr = lock_scr.script_sig end
    parsed_lock_scr = Script.new(lock_scr)
    parsed_lock_scr.chunks.delete(Script::OP_CODESEPARATOR) # Remove OP_CODESEPARATORs
    lock_scr = parsed_lock_scr.to_binary
    input.to_payload(lock_scr)
   else
    case ( sHASHF & 0x1f ) # bitwise against 00011111 0x1f == 31 decimal.
     when SIGHASH_TYPE[:none];   input.to_payload('', _4_Hzeros) # all inputs and no output
     when SIGHASH_TYPE[:single]; input.to_payload('', _4_Hzeros) # all inputs and the output with the same index
     else input.to_payload('') end end end

  pout     = @outputs.map( &:to_payload )
  in_size  = P.pack_var_int(@inputs.size )
  out_size = P.pack_var_int(@outputs.size)

  case ( sHASHF & 0x1f )
  when SIGHASH_TYPE[:none]; pout = ''; out_size = P.pack_var_int(0)  # no output
  when SIGHASH_TYPE[:single]                                         # output with the same index
   return _32_Hzeros if idx >= @outputs.size
   pout = @outputs[0...(idx + 1)].map.with_index do | out, idx_ |
    idx_ == idx ? out.to_payload : out.to_null_payload end.join
   out_size = P.pack_var_int(idx + 1) end # of case

  if ( sHASHF & SIGHASH_TYPE[:anyonecanpay] ) != 0 # its own input and all outputs
   in_size = P.pack_var_int(1)
   pin = [pin[idx]] end

  buff = [ [@ver].pack('V'), in_size, pin, out_size, pout, [@locktime, sHASHF].pack('VV') ].join # 32-bit unsigned, VAX (little-endian) byte order
  Digest::SHA256.digest(Digest::SHA256.digest(buff))
 rescue => badThing; puts badThing.inspect; puts badThing.backtrace; debugger end

# verify input signature +in_idx+ against the corresponding output in +outpoint_tx+ outpoint.
# This arg can be a Script or OutPoint.
# options are: verify_sigpushonly, verify_minimaldata, verify_cleanstack, verify_dersig, verify_low_s, verify_strictenc
def verify_input_signature(in_idx, outpoint)
 blocktimestamp = Time.now.to_i
 opts={} #:verify_dersig=> true, :verify_low_s=> true, :verify_strictenc => true}
 op_idx        = @inputs[in_idx].prev_out_index
 op_scr_sig    = @inputs[in_idx].script_sig
 amount        = outpoint.value  # amount_from_outpoint_data(outpoint, op_idx)
 script_pubkey = outpoint.pk_scr # script_pubkey_from_outpoint_data(outpoint, op_idx)
 raise 'nil from amount_from_outpoint_data' if amount.nil?
 @scripts[in_idx] = Bitcoin::Script.new(op_scr_sig, script_pubkey)
 return false if opts[:verify_sigpushonly] && !@scripts[in_idx].is_push_only?(op_scr_sig)
 return false if opts[:verify_minimaldata] && !@scripts[in_idx].pushes_are_canonical?
 sig_valid = @scripts[in_idx].run( blocktimestamp, opts ) do | pubkey, sig, sHASHF, subscript |
   # This block is used by script call(pubkey, sig, sHASHF, subscript) in Tx  def op_checksig(check_callback, opts={})
   hash = signature_hash_for_input(in_idx, subscript, sHASHF)
   puts pubkey.inspect, sig.inspect, hash.inspect; debugger
   Bitcoin.verify_signature(pubkey, sig, hash) end
 puts @scripts[in_idx].stack.inspect
 return false if opts[:verify_cleanstack] && !@scripts[in_idx].stack.empty?
 sig_valid
 rescue => badThing
  puts badThing.inspect
  debugger end

def to_hasH(options = {}) # convert to ruby hasH (see also #from_hash)
 @hash ||= hash_from_payload(to_payload)
 h = {
  'hash' => @hash,         'ver' => @ver, # 'nid' => normalized_hash,
  'vin_sz' => @inputs.size,    'vout_sz' => @outputs.size,
  'locktime' => @locktime, 'size' => (@payload ||= to_payload).bytesize,
  'in'  =>  @inputs.map { |i| i.to_hasH(options) },
  'out' => @outputs.map { |o| o.to_hasH(options) } }
 h['nid'] = normalized_hash if options[:with_nid]
 h end

def to_json(options = { space: '' }, *_a) # generates rawblock json as seen in the block explorer.
 JSON.pretty_generate(to_hash(options), options) end

def to_json_file(path); File.open(path, 'wb') { |f| f.print to_json; } end

def self.from_hasH(this_h, do_raise = true) # parse ruby hash (see also #to_hash) ["txid", "hash", "version", "size", "locktime", "vin", "vout", "hex"]
 tx = new(nil)
 tx.ver = this_h['version']
 tx.locktime = this_h['locktime']
 ins  = this_h['vin']
 outs = this_h['vout']
 ins.each  { |input | tx.add_in  InPoint.new().from_hasH (input) } # WIP Refactoring
 outs.each { |output| tx.add_out OutPoint.from_hasH(output) }
 tx.instance_eval do
  @hash = hash_from_payload(to_payload)
  @payload = to_payload end # Using instance_eval so as to be working on @inputs and @out code smell??
 if this_h['hash'] && (this_h['hash'] != tx.hash) && do_raise
  raise "Tx hash mismatch! Claimed: #{this_h['hash']}, Actual: #{tx.hash}" end
 tx end

def self.binary_from_hasH(h)           # convert ruby hasH to raw binary
 tx = from_hash(h)
 tx.to_payload end

def self.from_json(json_string)         from_hash(JSON.parse(json_string)) end
def self.binary_from_json(json_string)  from_json(json_string).to_payload end
#def self.from_file(path)                new(Bitcoin::Protocol.read_binary_file(path)) end
def self.from_json_file(path)           from_json(Bitcoin::Protocol.read_binary_file(path)) end
def size()                              payload.bytesize end

def is_final?(block_height, blocktime) # rubocop:disable Naming/PredicateName
 warn '[DEPRECATION] `Tx.is_final?` is deprecated. Use `final?` instead.'
 final?(block_height, blocktime) end

# Checks if transaction is final taking into account height and time
# of a block in which it is located (or about to be included if it's unconfirmed tx).
def final?(block_height, blocktime)
 return true if locktime.zero?  # No time lock - tx is final.
 # Time based nLockTime implemented in 0.1.6
 # If locktime is below the magic threshold treat it as a block height.
 # If locktime is above the threshold, it's a unix timestamp.
 lock_threshold = locktime < Bitcoin::LOCKTIME_THRESHOLD ? block_height : blocktime
 return true if locktime < lock_threshold
 inputs.each { |input| return false unless input.final? }
 true end

def legacy_sigops_count
 # Note: input scripts normally never have any opcodes since every input script
 # can be statically reduced to a pushdata-only script.
 # However, anyone is allowed to create a non-standard transaction with any opcodes in the inputs.
 count = 0
 self.in.each do |txin | count += Bitcoin::Script.new(txin.script_sig).sigops_count_accurate(false) end
 out.each     do |txout| count += Bitcoin::Script.new(txout.pk_scr).sigops_count_accurate(false) end
 count end

=begin We are not a node.
DEFAULT_BLOCK_PRIORITY_SIZE = 27_000

def minimum_relay_fee() calculate_minimum_fee(true, :relay) end
def minimum_block_fee() calculate_minimum_fee(true, :block) end

def calculate_minimum_fee(allow_free = true, mode = :block)
 # Base fee is either nMinTxFee or nMinRelayTxFee
 base_fee = if mode == :relay then Bitcoin.network[:min_relay_tx_fee]
  else Bitcoin.network[:min_tx_fee] end
 tx_size = to_payload.bytesize
 min_fee = (1 + tx_size / 1_000) * base_fee
 if allow_free
  # There is a free transaction area in blocks created by most miners,
  # * If we are relaying we allow transactions up to DEFAULT_BLOCK_PRIORITY_SIZE - 1000
  #   to be considered to fall into this category. We don't want to encourage sending
  #   multiple transactions instead of one big transaction to avoid fees.
  # * If we are creating a transaction we allow transactions up to 1,000 bytes
  #   to be considered safe and assume they can likely make it into this section.
  min_free_size = if mode == :block then Bitcoin.network[:free_tx_bytes]
   else DEFAULT_BLOCK_PRIORITY_SIZE - 1_000 end
  min_fee = 0 if tx_size < min_free_size end
 # This code can be removed after enough miners have upgraded to version 0.9.
 # Until then, be safe when sending and require a fee if any output is less than CENT
 if min_fee < base_fee && mode == :block
  outputs.each do |output|
   if output.value < Bitcoin.network[:dust]
   # If per dust fee, then we add min fee for each output less than dust.
   # Otherwise, we set to min fee if there is any output less than dust.
   if Bitcoin.network[:per_dust_fee] then min_fee += base_fee
   else min_fee = base_fee
    break end end end end
 min_fee = Bitcoin.network[:max_money] unless min_fee.between?( 0, Bitcoin.network[:max_money] )
 min_fee end
=end

def coinbase?()       inputs.size == 1 && inputs.first.coinbase? end
def normalized_hash() signature_hash_for_input( -1, nil, SIGHASH_TYPE[:all]).reverse.hth end

# sort transaction inputs and outputs under BIP 69
# https://github.com/bitcoin/bips/blob/master/bip-0069.mediawiki This is interesting.
def lexicographical_sort!
 inputs.sort_by!  { |i| [i.previous_output, i.prev_out_index] }
 outputs.sort_by! { |o| [o.amount,          o.pk_scr.bth]  } end

private

def script_pubkey_from_outpoint_data(outpoint, op_idx)
 if    outpoint.respond_to?(:out) then outpoint.out[op_idx].pk_scr # Given an entire previous transaction, take the script from it
 elsif outpoint.respond_to?(:pk_scr) then outpoint.pk_scr # If given an transaction output, take the script
 else  outpoint end end # Otherwise, we assume it's already a script.

def amount_from_outpoint_data(outpoint, op_idx)
 if    outpoint.respond_to?(:out) then outpoint.out[op_idx].amount # Given an entire previous trans, take the amount from the output at the op_idx
 elsif outpoint.respond_to?(:pk_scr) then outpoint.amount end end end end end # If given an transaction output, take the amount

=begin

def bitcoinconsensus_verify_script( in_idx, outpoint, blocktimestamp = Time.now.to_i, opts = {} )
 consensus_available = Bitcoin::BitcoinConsensus.lib_available?
 puts 'Bitcoin::BitcoinConsensus shared library not found' unless consensus_available
 op_idx  = @inputs[in_idx].prev_out_index
 script_pubkey = script_pubkey_from_outpoint_data(outpoint, op_idx)
 flags  = Bitcoin::BitcoinConsensus::SCRIPT_VERIFY_NONE
 flags |= Bitcoin::BitcoinConsensus::SCRIPT_VERIFY_SIGPUSHONLY if opts[:verify_sigpushonly]
 flags |= Bitcoin::BitcoinConsensus::SCRIPT_VERIFY_MINIMALDATA if opts[:verify_minimaldata]
 flags |= Bitcoin::BitcoinConsensus::SCRIPT_VERIFY_CLEANSTACK  if opts[:verify_cleanstack]
 flags |= Bitcoin::BitcoinConsensus::SCRIPT_VERIFY_LOW_S       if opts[:verify_low_s]
 payload ||= to_payload
 Bitcoin::BitcoinConsensus.verify_script(in_idx, script_pubkey, payload, flags) end

  if fork_id && (sHASHF & SIGHASH_TYPE[:forkid]) != 0
   raise 'SIGHASH_FORKID is enabled, so prev_out_value is required' if prev_out_value.nil?
   # According to the spec, we should modify the sighash by replacing the 24 most significant
   # bits with the fork ID. However, Bitcoin ABC does not currently implement this since the
   # fork_id is an implicit 0 and it would make the sighash JSON tests fail. Will leave as a
   # TODO for now.
   raise NotImplementedError, 'fork_id must be 0' unless fork_id.zero?
   script_code = Bitcoin::Protocol.pack_var_string(subscript)
   return signature__hash_for_input_bip143(input_idx, script_code, prev_out_value, sHASHF) end

def signature__hash_for_input_bip143(input_idx, script_code, prev_out_value, sHASHF) # DEPR segwit
 # https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
 hash_prevouts = Digest::SHA256.digest( Digest::SHA256.digest( @inputs.map { |i| [i.prev_out_hash, i.prev_out_index].pack('a32V') }.join ) )
 hash_sequence = Digest::SHA256.digest(Digest::SHA256.digest(@inputs.map(&:sequence).join))
 outpoint = [@inputs[input_idx].prev_out_hash, @inputs[input_idx].prev_out_index].pack('a32V')
 amount = [prev_out_value].pack('Q')
 nsequence = @inputs[input_idx].sequence
 hash_outputs = Digest::SHA256.digest(Digest::SHA256.digest(@outputs.map(&:to_payload).join))
 case (sHASHF & 0x1f)
 when SIGHASH_TYPE[:single]
  hash_outputs = if input_idx >= @outputs.size
   _32_Hzeros
   else Digest::SHA256.digest(Digest::SHA256.digest(@outputs[input_idx].to_payload)) end
  hash_sequence = _32_Hzeros
 when SIGHASH_TYPE[:none]
  hash_sequence = hash_outputs = _32_Hzeros end
 if (sHASHF & SIGHASH_TYPE[:anyonecanpay]) != 0
  hash_prevouts = hash_sequence = _32_Hzeros end
 buff = [[@ver].pack('V'), hash_prevouts, hash_sequence, outpoint, script_code,
        amount, nsequence, hash_outputs, [@locktime, sHASHF].pack('VV')].join
 Digest::SHA256.digest(Digest::SHA256.digest(buff)) end

  if fork_id && (sHASHF & SIGHASH_TYPE[:forkid]) != 0
   raise 'SIGHASH_FORKID is enabled, so prev_out_value is required' if prev_out_value.nil?
   # According to spec, should modify sighash by replacing the 24 msb with fork ID. ABC does not currently implement this since the
   # fork_id is an implicit 0 and it would make the sighash JSON tests fail. Will leave as a TODO for now.
   raise NotImplementedError, 'fork_id must be 0' unless fork_id.zero?
   script_code = Bitcoin::P.pack_var_string(subscript)
   return signature_hash_for_input_bip143(input_idx, script_code, prev_out_value, sHASHF) end
def signature_hash_for_input_bip143(idx, script_code, prev_out_value, sHASHF) # https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
 _32_Hzeros = "\x00".ljust(32, "\x00")
 hash_prevouts = Digest::SHA256.digest(Digest::SHA256.digest( @inputs.map { |i| [i.prev_out_hash, i.prev_out_index].pack('a32V') }.join ) )
 hash_sequence = Digest::SHA256.digest(Digest::SHA256.digest( @inputs.map(&:sequence).join))
 outpoint = [@inputs[idx].prev_out_hash, @inputs[idx].prev_out_index].pack('a32V')
 amount = [prev_out_value].pack('Q')
 nsequence = @inputs[idx].sequence
 hash_outputs = Digest::SHA256.digest(Digest::SHA256.digest(@outputs.map(&:to_payload).join))
 case ( sHASHF & 0x1f )
 when SIGHASH_TYPE[:none]
  hash_sequence = hash_outputs = _32_Hzeros
 when SIGHASH_TYPE[:single]
  hash_outputs = if idx >= @outputs.size then _32_Hzeros else Digest::SHA256.digest(Digest::SHA256.digest(@outputs[idx].to_payload)) end
  hash_sequence = _32_Hzeros end
 if (SIGHASH_TYPE[:anyonecanpay] & sHASHF ) != 0 then hash_prevouts = hash_sequence = _32_Hzeros end
 buff = [[@ver].pack('V'), hash_prevouts, hash_sequence, outpoint, script_code, amount, nsequence, hash_outputs, [@locktime, sHASHF].pack('VV')].join
 Digest::SHA256.digest(Digest::SHA256.digest(buff)) end

=end
