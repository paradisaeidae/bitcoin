require_relative '../script'
require_relative '../opcodes'
require 'stringio'
module Bitcoin;module Protocol
# https://en.bitcoin.it/wiki/Protocol_documentation#tx Ignore the segwits.
# https://github.com/bitcoin-sv-specs/protocol/pull/16/commits/a28bd53735bb4e14ff5db4acd4ebdb5b20a1df75
# https://duckduckgo.com/?q=P2SH+Script+BSV&t=ffcm&ia=web https://coingeek.com/what-is-p2sh-and-why-must-it-go/
# https://ruby-doc.org/core-3.0.2/Array.html#method-i-pack
class Tx
MARKER = 0;FLAG = 1;SIGHASH_TYPE = ::Bitcoin::Script::SIGHASH_TYPE
# transaction hash, inputs (Array of TxIn), outputs (Array of TxOut), raw protocol payload
attr_reader :hash, :in, :out, :payload, :scripts # parsed / evaluated input scripts cached for later use
attr_accessor :ver, :locktime, :marker, :flag # version (usually 1), lock time

def initialize(raw_bin = nil) # create tx from raw binary.
 @ver = 1
 @locktime = 0
 @in, @out, @scripts = [], [], []
 @ossl_pub_keys = {}
 @enable_bitcoinconsensus = false #!ENV['USE_BITCOINCONSENSUS'].nil? # https://bitcoinabc.org/doc/dev/bitcoinconsensus_8h.html#a16af7b253440dadd46a80a4b9fddba4daeb2831cb788b35ef8556ce30bfee016f
 parse_data_from_io(raw_bin) if raw_bin end

def ==(other);   @hash == other.hash end # compare to another tx
def binary_hash; @binary_hash ||= [@hash].pack('H*').reverse end # return the tx hash in binary format
def hash_from_payload(payload); Digest::SHA256.digest(Digest::SHA256.digest(payload)).reverse_hth end # generate the tx hash for given +payload+ in hex format
def refresh_hash;    @hash = hash_from_payload(to_payload) end # refresh_hash recalculates the tx hash and sets it on the instance
def add_in(input);   (@in ||= []) << input end
def add_out(output); (@out ||= []) << output end
alias inputs  in
alias outputs out

def parse_data_from_io(raw_bin) # parse raw binary. It is possible to parse 0 input transactions. Regular transactions with 0 inputs are coinbase
  buf = raw_bin.is_a?(String) ? StringIO.new(raw_bin) : raw_bin
  @ver = buf.read(4).unpack('V')[0]
  return false if buf.eof?
  @marker = buf.read(1).unpack('c').first
  @flag   = buf.read(1).unpack('c').first
  buf.seek(buf.pos - 2)
  in_size = Protocol.unpack_var_int_from_io(buf)
  @in = []
  in_size.times do
   break if buf.eof?
   @in << TxIn.from_io(buf) end
  return false if buf.eof?
  out_size = Protocol.unpack_var_int_from_io(buf)
  @out = []
  out_size.times do
   break if buf.eof?
   @out << TxOut.from_io(buf) end
  return false if buf.eof?
  @locktime = buf.read(4).unpack('V')[0]
  @hash = hash_from_payload(to_payload)
  @payload = to_payload
  if buf.eof? then true
  else raw_bin.is_a?(StringIO) ? buf : buf.read end end

alias parse_data parse_data_from_io

def to_payload # was to_old_payload due to witness 'protection'! https://github.com/lian/bitcoin-ruby/blob/f9b817c946b3ef99c7652c318c155200aadc6489/lib/bitcoin/protocol/tx.rb#L152
 pins, pouts = '', ''
 @in.each  { |input | pins  << input.to_payload  }
 @out.each { |output| pouts << output.to_payload }
 [@ver].pack('V') << Protocol.pack_var_int(@in.size) \
  << pins << Protocol.pack_var_int(@out.size) << pouts << [@locktime].pack('V') 
 rescue => badThing
  puts badThing.inspect
  debugger end

  # https://github.com/bitcoin-sv/bitcoin-sv/blob/e071a3f6c06f41068ad17134189a4ac3073ef76b/script.cpp#L834
  # http://code.google.com/p/bitcoinj/source/browse/trunk/src/com/google/bitcoin/core/Script.java#318
  # https://en.bitcoin.it/wiki/OP_CHECKSIG
  # https://en.bitcoin.it/wiki/OP_CHECKSIG#How_it_works
  # https://github.com/bitcoin-sv/bitcoin-sv/blob/c2e8c8acd8ae0c94c70b59f55169841ad195bb99/src/script.cpp#L1058
  # https://wiki.bitcoinsv.io/index.php/SIGHASH_flags
  # NOTE: Currently all BitcoinSV transactions require an additional SIGHASH flag called SIGHASH_FORKID which is 0x40
  # A SIGHASH flag is used to indicate which part of the transaction is signed by the ECDSA signature. 
  # https://github.com/Bitcoin-ABC/bitcoin-abc/blob/master/doc/abc/replay-protected-sighash.md
 # generate a signature hash for input  +input_idx+.
 # either pass the +outpoint_tx+ or the +script_pubkey+ directly.
 def signature_hash_for_input( input_idx, redeem_scr, hash_type = nil, prev_out_value = nil, fork_id = nil)
  hash_type ||= SIGHASH_TYPE[:all]
  raise 'SIGHASH_FORKID is required by BSV.' unless (hash_type & SIGHASH_TYPE[:forkid])
  return "\x01".ljust(32, "\x00") if input_idx >= @in.size
  pin = @in.map.with_index do | input, idx |
   if idx == input_idx    # legacy api (outpoint_tx)
    redeem_scr = redeem_scr.outputs[input.prev_out_index].script if redeem_scr.respond_to?(:out)
    parsed_redeem_scr = Script.new(redeem_scr)
    parsed_redeem_scr.chunks.delete(Script::OP_CODESEPARATOR) # Remove all instances of OP_CODESEPARATOR from the script.
    redeem_scr = parsed_redeem_scr.to_binary
    input.to_payload(redeem_scr)
   else
    case (hash_type & 0x1f)
    when SIGHASH_TYPE[:none]   then input.to_payload('', "\x00\x00\x00\x00")
    when SIGHASH_TYPE[:single] then input.to_payload('', "\x00\x00\x00\x00")
    else input.to_payload('') end end end

  pout = @out.map( &:to_payload )
  in_size =  Protocol.pack_var_int(@in.size)
  out_size = Protocol.pack_var_int(@out.size)

  case (hash_type & 0x1f)
  when SIGHASH_TYPE[:none]
   pout = ''
   out_size = Protocol.pack_var_int(0)
  when SIGHASH_TYPE[:single]
   return "\x01".ljust(32, "\x00") if input_idx >= @out.size # ERROR: SignatureHash() : input_idx=%d out of range (SIGHASH_SINGLE)
   pout = @out[0...(input_idx + 1)].map.with_index do |out, idx|
    idx == input_idx ? out.to_payload : out.to_null_payload end.join
   out_size = Protocol.pack_var_int(input_idx + 1) end

  if (hash_type & SIGHASH_TYPE[:anyonecanpay]) != 0
   in_size = Protocol.pack_var_int(1)
   pin = [pin[input_idx]] end
  buff = [ [@ver].pack('V'), in_size, pin, out_size, pout, [@locktime, hash_type].pack('VV') ].join # 32-bit unsigned, VAX (little-endian) byte order
  Digest::SHA256.digest(Digest::SHA256.digest(buff)) end
# verify input signature +in_idx+ against the corresponding output in +outpoint_tx+ outpoint.
# This arg can also be a Script or TxOut.
# options are: verify_sigpushonly, verify_minimaldata, verify_cleanstack,
#              verify_dersig, verify_low_s, verify_strictenc, fork_id
def verify_input_signature(in_idx, outpoint_data, blocktimestamp = Time.now.to_i, opts = {})
 # if @enable_bitcoinconsensus then return bitcoinconsensus_verify_script(in_idx, outpoint_data, blocktimestamp, opts) end
 # If FORKID is enabled, we also ensure strict encoding.
 opts[:verify_strictenc] ||= !opts[:fork_id].nil?
 outpoint_idx  = @in[in_idx].prev_out_index
 script_sig    = @in[in_idx].script_sig
 #pubkey        = @in[in_idx].ossl_pubkey
 amount = amount_from_outpoint_data(outpoint_data, outpoint_idx)
 script_pubkey = script_pubkey_from_outpoint_data(outpoint_data, outpoint_idx)
 if opts[:fork_id] && amount.nil?
  raise 'verify_input_signature must be called with a previous transaction or transaction output if SIGHASH_FORKID is enabled' end
 @scripts[in_idx] = Bitcoin::Script.new(script_sig, script_pubkey)
 return false if opts[:verify_sigpushonly] && !@scripts[in_idx].is_push_only?(script_sig)
 return false if opts[:verify_minimaldata] && !@scripts[in_idx].pushes_are_canonical?
 sig_valid = @scripts[in_idx].run( blocktimestamp, opts ) do | pubkey, sig, hash_type, subscript |
  hash = signature_hash_for_input(in_idx, subscript, hash_type, amount, opts[:fork_id])
  Bitcoin.verify_signature( hash, sig, pubkey.unpack('H*')[0])  end #
 return false if opts[:verify_cleanstack] && !@scripts[in_idx].stack.empty? # BIP62 rule #6
 sig_valid
 rescue => badThing
  puts badThing.inspect
  debugger end

def bitcoinconsensus_verify_script( in_idx, outpoint_data, blocktimestamp = Time.now.to_i, opts = {} )
 consensus_available = Bitcoin::BitcoinConsensus.lib_available?
 puts 'Bitcoin::BitcoinConsensus shared library not found' unless consensus_available
 outpoint_idx  = @in[in_idx].prev_out_index
 script_pubkey = script_pubkey_from_outpoint_data(outpoint_data, outpoint_idx)
 flags  = Bitcoin::BitcoinConsensus::SCRIPT_VERIFY_NONE
 flags |= Bitcoin::BitcoinConsensus::SCRIPT_VERIFY_SIGPUSHONLY if opts[:verify_sigpushonly]
 flags |= Bitcoin::BitcoinConsensus::SCRIPT_VERIFY_MINIMALDATA if opts[:verify_minimaldata]
 flags |= Bitcoin::BitcoinConsensus::SCRIPT_VERIFY_CLEANSTACK  if opts[:verify_cleanstack]
 flags |= Bitcoin::BitcoinConsensus::SCRIPT_VERIFY_LOW_S       if opts[:verify_low_s]
 payload ||= to_payload
 Bitcoin::BitcoinConsensus.verify_script(in_idx, script_pubkey, payload, flags) end

def to_hash(options = {}) # convert to ruby hash (see also #from_hash)
 @hash ||= hash_from_payload(to_payload)
 h = {
  'hash' => @hash,         'ver' => @ver, # 'nid' => normalized_hash,
  'vin_sz' => @in.size,    'vout_sz' => @out.size,
  'locktime' => @locktime, 'size' => (@payload ||= to_payload).bytesize,
  'in'  =>  @in.map { |i| i.to_hash(options) },
  'out' => @out.map { |o| o.to_hash(options) } }
 h['nid'] = normalized_hash if options[:with_nid]
 h end

def to_json(options = { space: '' }, *_a) # generates rawblock json as seen in the block explorer.
 JSON.pretty_generate(to_hash(options), options) end
def to_json_file(path); File.open(path, 'wb') { |f| f.print to_json; } end

def self.from_hash(this_h, do_raise = true) # parse ruby hash (see also #to_hash) ["txid", "hash", "version", "size", "locktime", "vin", "vout", "hex"]
 tx = new(nil)
 tx.ver = this_h['version']
 tx.locktime = this_h['locktime']
 ins  = this_h['vin']
 outs = this_h['vout']
 ins.each  { |input | tx.add_in  TxIn.from_hash (input)  }
 outs.each { |output| tx.add_out TxOut.from_hash(output) }
 tx.instance_eval do
  @hash = hash_from_payload(to_payload)
  @payload = to_payload end # Using instance_eval so as to be working on @in and @out code smell??
 if this_h['hash'] && (this_h['hash'] != tx.hash) && do_raise
  raise "Tx hash mismatch! Claimed: #{this_h['hash']}, Actual: #{tx.hash}" end
 tx end

def self.binary_from_hash(h)           # convert ruby hash to raw binary
 tx = from_hash(h)
 tx.to_payload end

def self.from_json(json_string); from_hash(JSON.parse(json_string)) end
def self.binary_from_json(json_string); from_json(json_string).to_payload end
def self.from_file(path); new(Bitcoin::Protocol.read_binary_file(path)) end
def self.from_json_file(path); from_json(Bitcoin::Protocol.read_binary_file(path)) end
def size; payload.bytesize end

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
 # However, anyone is allowed to create a non-standard transaction
 # with any opcodes in the inputs.
 count = 0
 self.in.each do |txin | count += Bitcoin::Script.new(txin.script_sig).sigops_count_accurate(false) end
 out.each     do |txout| count += Bitcoin::Script.new(txout.pk_script).sigops_count_accurate(false) end
 count end

DEFAULT_BLOCK_PRIORITY_SIZE = 27_000

def minimum_relay_fee; calculate_minimum_fee(true, :relay) end
def minimum_block_fee; calculate_minimum_fee(true, :block) end

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

def coinbase?; inputs.size == 1 && inputs.first.coinbase? end
def normalized_hash; signature_hash_for_input( -1, nil, SIGHASH_TYPE[:all]).reverse.hth end

# sort transaction inputs and outputs under BIP 69
# https://github.com/bitcoin/bips/blob/master/bip-0069.mediawiki This is interesting.
def lexicographical_sort!
 inputs.sort_by!  { |i| [i.previous_output, i.prev_out_index] }
 outputs.sort_by! { |o| [o.amount, o.pk_script.bth]           } end

private

def script_pubkey_from_outpoint_data(outpoint_data, outpoint_idx)
 if outpoint_data.respond_to?(:out)  # If given an entire previous transaction, take the script from it
  outpoint_data.out[outpoint_idx].pk_script
 elsif outpoint_data.respond_to?(:pk_script) # If given an transaction output, take the script
  outpoint_data.pk_script
 else outpoint_data end end # Otherwise, we assume it's already a script.

def amount_from_outpoint_data(outpoint_data, outpoint_idx)
 if outpoint_data.respond_to?(:out)
  # If given an entire previous transaction, take the amount from the
  # output at the outpoint_idx
  outpoint_data.out[outpoint_idx].amount
 elsif outpoint_data.respond_to?(:pk_script)  # If given an transaction output, take the amount
  outpoint_data.amount end end end end end

=begin

  if fork_id && (hash_type & SIGHASH_TYPE[:forkid]) != 0
   raise 'SIGHASH_FORKID is enabled, so prev_out_value is required' if prev_out_value.nil?
   # According to the spec, we should modify the sighash by replacing the 24 most significant
   # bits with the fork ID. However, Bitcoin ABC does not currently implement this since the
   # fork_id is an implicit 0 and it would make the sighash JSON tests fail. Will leave as a
   # TODO for now.
   raise NotImplementedError, 'fork_id must be 0' unless fork_id.zero?
   script_code = Bitcoin::Protocol.pack_var_string(subscript)
   return signature__hash_for_input_bip143(input_idx, script_code, prev_out_value, hash_type) end

def signature__hash_for_input_bip143(input_idx, script_code, prev_out_value, hash_type) # DEPR segwit
 # https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
 hash_prevouts = Digest::SHA256.digest( Digest::SHA256.digest( @in.map { |i| [i.prev_out_hash, i.prev_out_index].pack('a32V') }.join ) )
 hash_sequence = Digest::SHA256.digest(Digest::SHA256.digest(@in.map(&:sequence).join))
 outpoint = [@in[input_idx].prev_out_hash, @in[input_idx].prev_out_index].pack('a32V')
 amount = [prev_out_value].pack('Q')
 nsequence = @in[input_idx].sequence
 hash_outputs = Digest::SHA256.digest(Digest::SHA256.digest(@out.map(&:to_payload).join))
 case (hash_type & 0x1f)
 when SIGHASH_TYPE[:single]
  hash_outputs = if input_idx >= @out.size
   "\x00".ljust(32, "\x00")
   else Digest::SHA256.digest(Digest::SHA256.digest(@out[input_idx].to_payload)) end
  hash_sequence = "\x00".ljust(32, "\x00")
 when SIGHASH_TYPE[:none]
  hash_sequence = hash_outputs = "\x00".ljust(32, "\x00") end
 if (hash_type & SIGHASH_TYPE[:anyonecanpay]) != 0
  hash_prevouts = hash_sequence = "\x00".ljust(32, "\x00") end
 buff = [[@ver].pack('V'), hash_prevouts, hash_sequence, outpoint, script_code,
        amount, nsequence, hash_outputs, [@locktime, hash_type].pack('VV')].join
 Digest::SHA256.digest(Digest::SHA256.digest(buff)) end
=end