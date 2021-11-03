module Bitcoin
module Protocol
# TxIn section of https://en.bitcoin.it/wiki/Protocol_documentation#tx
class TxIn
attr_accessor :prev_out_hash # previous output hash
alias prev_out prev_out_hash

def prev_out=(hash)
 @prev_out_hash = hash end
attr_accessor :prev_out_index # previous output index
attr_reader :script_sig # script_sig input Script (signature)
attr_accessor :script_sig_length
# signature hash and the address of the key that needs to sign it
# (used when dealing with unsigned or partly signed tx)
attr_accessor :sig_hash, :sig_address
alias script script_sig
alias script_length script_sig_length

attr_accessor :sequence # sequence
DEFAULT_SEQUENCE = "\xff\xff\xff\xff".freeze
NULL_HASH = "\x00" * 32
COINBASE_INDEX = 0xffffffff

def initialize(*args)
 @prev_out_hash, @prev_out_index, @script_sig_length,
 @script_sig, @sequence = *args
 @script_sig_length ||= 0
 @script_sig ||= ''
 @sequence ||= DEFAULT_SEQUENCE end

def ==(other) # compare to another txout
 @prev_out_hash == other.prev_out_hash &&
  @prev_out_index == other.prev_out_index &&
   @script_sig == other.script_sig &&
    @sequence == other.sequence
 rescue StandardError
  false end

def is_final? # rubocop:disable Naming/PredicateName
 warn '[DEPRECATION] `TxIn.is_final?` is deprecated. Use `final?` instead.'
 final? end

def final? # returns true if the sequence number is final (DEFAULT_SEQUENCE)
 sequence == DEFAULT_SEQUENCE end

def parse_data(data) # parse raw binary data for transaction input
 buf = data.is_a?(String) ? StringIO.new(data) : data
 parse_data_from_io(buf)
 buf.pos end

def self.from_io(buf)
 txin = new
 txin.parse_data_from_io(buf)
 txin end

def parse_data_from_io(buf)
 @prev_out_hash, @prev_out_index = buf.read(36).unpack('a32V')
 @script_sig_length = Protocol.unpack_var_int_from_io(buf)
 @script_sig = buf.read(@script_sig_length)
 @sequence = buf.read(4) end

def parsed_script
 @parsed_script ||= Bitcoin::Script.new(script_sig) end

def to_payload(script = @script_sig, sequence = @sequence)
 [@prev_out_hash, @prev_out_index].pack('a32V') << Protocol.pack_var_int(script.bytesize) \
                                                << script << (sequence || DEFAULT_SEQUENCE) end

def to_hash(_options = {})
 t = { 'prev_out' => { 'hash' => @prev_out_hash.reverse_hth, 'n' => @prev_out_index } }
 if coinbase? then t['coinbase']  = @script_sig.unpack('H*')[0]
 else t['scriptSig'] = Bitcoin::Script.new(@script_sig).to_string end # coinbase tx
 t['sequence'] = @sequence.unpack('V')[0] unless @sequence == "\xff\xff\xff\xff"
 t end

def self.from_hash(input)
 previous_hash         = input['previous_transaction_hash'] || input['prev_out']['hash']
 previous_output_index = input['output_index'] || input['prev_out']['n']
 txin = TxIn.new([previous_hash].pack('H*').reverse, previous_output_index)
 txin.script_sig = if input['coinbase']
                    [input['coinbase']].pack('H*')
                   else
                    Script.binary_from_string(input['scriptSig'] || input['script']) end
 txin.sequence = [input['sequence'] || 0xffffffff].pack('V')
 txin end

def self.from_hex_hash(hash, index)
 TxIn.new([hash].pack('H*').reverse, index, 0) end

def previous_output # previous output in hex
 @prev_out_hash.reverse_hth end

def coinbase? # check if input is coinbase
 (@prev_out_index == COINBASE_INDEX) && (@prev_out_hash == NULL_HASH) end

def script_sig=(script_sig) # set script_sig and script_sig_length
 @script_sig_length = script_sig.bytesize
 @script_sig = script_sig end

alias script= script_sig=
def add_signature_pubkey_script(sig, pubkey_hex)
 self.script = Bitcoin::Script.to_signature_pubkey_script(sig, [pubkey_hex].pack('H*')) end end end end