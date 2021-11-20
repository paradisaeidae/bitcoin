module Bitcoin # https://github.com/lian/bitcoin-ruby/blob/master/lib/bitcoin/protocol/txin.rb
module Protocol
# TxIn section of https://en.bitcoin.it/wiki/Protocol_documentation#tx
class TxIn
attr_reader :script_sig # script_sig input Script (signature)
# signature hash and the address of the key that needs to sign it
# (used when dealing with unsigned or partly signed tx)
attr_accessor :sig_hash, :sig_address, :script_sig_length, :prev_out_hash, :prev_out_index

alias prev_out prev_out_hash  # alias, real

def prev_out=(hash)             # Will this overide the @prev_out= created by attr_accessor aliased??
 @prev_out_hash = hash end

alias script script_sig
alias script_length script_sig_length

attr_accessor :sequence # sequence
DEFAULT_SEQUENCE = "\xff\xff\xff\xff".freeze
NULL_HASH = "\x00" * 32
COINBASE_INDEX = 0xffffffff

def initialize(*args)
 @prev_out_hash, @prev_out_index, @script_sig_length, @script_sig, @sequence = *args
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
 #    a         | String  | arbitrary binary string (null padded, count is width)
 #    V         | Integer | 32-bit unsigned, VAX (little-endian) byte order
 [@prev_out_hash, @prev_out_index].pack('a32V') << Protocol.pack_var_int(script.bytesize) \
                                                << script << (sequence || DEFAULT_SEQUENCE) end
def to_hash(_options = {})
 if !@prev_out_hash.nil? then
  trans_h = { 'prev_out' => { 'hash' => @prev_out_hash.reverse_hth, 'n' => @prev_out_index } }
 else trans_h = {} end # else coinbase tx
 trans_h['scriptSig'] = Bitcoin::Script.new(@script_sig).to_string
 trans_h['sequence'] = @sequence.unpack('V')[0] unless @sequence == "\xff\xff\xff\xff"
 trans_h end

def to_hash_ORIG(_options = {})
 trans_h = { 'prev_out' => { 'hash' => @prev_out_hash.reverse_hth, 'n' => @prev_out_index } }
 if coinbase? then trans_h['coinbase']  = @script_sig.unpack('H*')[0]
 else trans_h['scriptSig'] = Bitcoin::Script.new(@script_sig).to_string end # coinbase tx
 trans_h['sequence'] = @sequence.unpack('V')[0] unless @sequence == "\xff\xff\xff\xff"
 trans_h end

def self.from_hash(input)
 # "vin"=>  [{"txid"=>"2a4bb8bc9c9e4dca72b657d32982cc49b2bd2e9d7fb84df7148bb5f11f5f9f15", "vout"=>0,
 # https://bitcoin.stackexchange.com/questions/69817/transaction-inputs-does-not-have-prev-out-field
 # The input sufficiently describes where and how to get the bitcoin amount to be redeemed.
 # If it is the (only) input of the first transaction of a block, it is called the Coinbase message and
 #  includes information about which block it was mined in and a miner configurable data element.
 # The definition of transaction hash remains the same as txid for non-witness transactions (non Segwit). 
 if !input.includes? 'vout' then previous_output_index = 0
  else previous_output_index = input['vout']['n'] end
 previous_hash         = input['txid']
 txin = TxIn.new([previous_hash].pack('H*').reverse, previous_output_index)
 # What is the string???
 txin.script_sig = input['scriptSig']['hex']    #Script.binary_from_string(input['scriptSig']) !!!???
 txin.sequence =  [input['sequence'] || 0xffffffff].pack('V')
 txin end

def self.from_hash_ORIG(input)
 previous_hash         = input['previous_transaction_hash'] || input['prev_out']['hash']
 previous_output_index = input['output_index'] || input['prev_out']['n']
 txin = TxIn.new([previous_hash].pack('H*').reverse, previous_output_index)
 txin.script_sig = if input['coinbase'] then [input['coinbase']].pack('H*') # interprets the string as hex numbers
                   else Script.binary_from_string(input['scriptSig'] || input['script']) end
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

=begin
Integer       | Array   |
Directive     | Element | Meaning
----------------------------------------------------------------------------
C             | Integer | 8-bit unsigned (unsigned char)
S             | Integer | 16-bit unsigned, native endian (uint16_t)
L             | Integer | 32-bit unsigned, native endian (uint32_t)
Q             | Integer | 64-bit unsigned, native endian (uint64_t)
J             | Integer | pointer width unsigned, native endian (uintptr_t)
              |         | (J is available since Ruby 2.3.)
              |         |
c             | Integer | 8-bit signed (signed char)
s             | Integer | 16-bit signed, native endian (int16_t)
l             | Integer | 32-bit signed, native endian (int32_t)
q             | Integer | 64-bit signed, native endian (int64_t)
j             | Integer | pointer width signed, native endian (intptr_t)
              |         | (j is available since Ruby 2.3.)
              |         |
S_ S!         | Integer | unsigned short, native endian
I I_ I!       | Integer | unsigned int, native endian
L_ L!         | Integer | unsigned long, native endian
Q_ Q!         | Integer | unsigned long long, native endian (ArgumentError
              |         | if the platform has no long long type.)
              |         | (Q_ and Q! is available since Ruby 2.1.)
J!            | Integer | uintptr_t, native endian (same with J)
              |         | (J! is available since Ruby 2.3.)
              |         |
s_ s!         | Integer | signed short, native endian
i i_ i!       | Integer | signed int, native endian
l_ l!         | Integer | signed long, native endian
q_ q!         | Integer | signed long long, native endian (ArgumentError
              |         | if the platform has no long long type.)
              |         | (q_ and q! is available since Ruby 2.1.)
j!            | Integer | intptr_t, native endian (same with j)
              |         | (j! is available since Ruby 2.3.)
              |         |
S> s> S!> s!> | Integer | same as the directives without ">" except
L> l> L!> l!> |         | big endian
I!> i!>       |         | (available since Ruby 1.9.3)
Q> q> Q!> q!> |         | "S>" is same as "n"
J> j> J!> j!> |         | "L>" is same as "N"
              |         |
S< s< S!< s!< | Integer | same as the directives without "<" except
L< l< L!< l!< |         | little endian
I!< i!<       |         | (available since Ruby 1.9.3)
Q< q< Q!< q!< |         | "S<" is same as "v"
J< j< J!< j!< |         | "L<" is same as "V"
              |         |
n             | Integer | 16-bit unsigned, network (big-endian) byte order
N             | Integer | 32-bit unsigned, network (big-endian) byte order
v             | Integer | 16-bit unsigned, VAX (little-endian) byte order
V             | Integer | 32-bit unsigned, VAX (little-endian) byte order
              |         |
U             | Integer | UTF-8 character
w             | Integer | BER-compressed integer

Float        | Array   |
Directive    | Element | Meaning
---------------------------------------------------------------------------
D d          | Float   | double-precision, native format
F f          | Float   | single-precision, native format
E            | Float   | double-precision, little-endian byte order
e            | Float   | single-precision, little-endian byte order
G            | Float   | double-precision, network (big-endian) byte order
g            | Float   | single-precision, network (big-endian) byte order

String       | Array   |
Directive    | Element | Meaning
---------------------------------------------------------------------------
A            | String  | arbitrary binary string (space padded, count is width)
a            | String  | arbitrary binary string (null padded, count is width)
Z            | String  | same as ``a'', except that null is added with *
B            | String  | bit string (MSB first)
b            | String  | bit string (LSB first)
H            | String  | hex string (high nibble first)
h            | String  | hex string (low nibble first)
u            | String  | UU-encoded string
M            | String  | quoted printable, MIME encoding (see also RFC2045)
             |         | (text mode but input must use LF and output LF)
m            | String  | base64 encoded string (see RFC 2045)
             |         | (if count is 0, no line feed are added, see RFC 4648)
             |         | (count specifies input bytes between each LF,
             |         | rounded down to nearest multiple of 3)
P            | String  | pointer to a structure (fixed-length string)
p            | String  | pointer to a null-terminated string

Misc.        | Array   |
Directive    | Element | Meaning
---------------------------------------------------------------------------
@            | ---     | moves to absolute position
X            | ---     | back up a byte
x            | ---     | null byte
=end