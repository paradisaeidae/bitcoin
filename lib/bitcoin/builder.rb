module Bitcoin
# Optional DSL to help create blocks and transactions.
# see also BlockBuilder, TxBuilder, TxInBuilder, TxOutBuilder, ScriptBuilder
module Builder
 # build a Bitcoin::Protocol::Block matching the given +target+. See BlockBuilder for details.
 def build_block(target = '00'.ljust(64, 'f'))
  c = BlockBuilder.new
  yield c
  c.block(target) end

 # build a Bitcoin::Protocol::Tx. See TxBuilder for details.
 def build_tx(opts = {})
  c = TxBuilder.new
  yield c
  c.tx opts end

 # build a Bitcoin::Script. See ScriptBuilder for details.
 def script
  c = ScriptBuilder.new
  yield c
  c.script end

 # DSL to create a Bitcoin::Protocol::Block used by Builder#create_block.
 #  block = blk("00".ljust(32, 'f')) do |b|
 #   b.prev_block "\x00"*32
 #   b.tx do |t|
 #    t.input {|i| i.coinbase }
 #    t.output do |o|
 #     o.value 5000000000;
 #     o.to Bitcoin::Key.generate.addr end end end
 #
 # See Bitcoin::Builder::TxBuilder for details on building transactions.
 class BlockBuilder
 attr_writer :prev_block, :time, :version
 def initialize() @block = P::Block.new(nil) end

 # specify block version. this is usually not necessary. defaults to 1.
 def version(v) @version = v end
 # set the hash of the previous block.
 def prev_block(hash) @prev_block = hash end
 # set the block timestamp (defaults to current time).
 def time(time) @time = time end

 # add transactions to the block (see TxBuilder).
 def tx(tx = nil)
  tx ||= begin
   c = TxBuilder.new
   yield c
   c.tx end
  @block.tx << tx
  tx end

 # create the block according to values specified via DSL.
 def block(target)
  @version ||= nil
  @mrkl_root ||= nil
  @time ||= nil
  @block.ver = @version || 1
  @block.prev_block = @prev_block.htb.reverse
  @block.mrkl_root = @mrkl_root
  @block.time = @time || Time.now.to_i
  @block.nonce = 0
  @block.mrkl_root = Bitcoin.hash_mrkl_tree(@block.tx.map(&:hash)).last.htb.reverse
  find_hash(target)
  block = P::Block.new(@block.to_payload)
  raise 'Payload Error' unless block.to_payload == @block.to_payload
  block  end

 private
 # increment nonce/time to find a block hash matching the +target+.
 def find_hash(target)
  @block.bits = Bitcoin.encode_compact_bits(target)
  t = Time.now
  @block.recalc_block_hash
  until @block.hash.to_i(16) < target.to_i(16)
   @block.nonce += 1
   @block.recalc_block_hash
   next unless @block.nonce == 100_000
   if t
    tt = 1 / ((Time.now - t) / 100_000) / 1000
    print format("\r%.2f khash/s", tt) end
   t = Time.now
   @block.time = Time.now.to_i
   @block.nonce = 0
   $stdout.flush end end end
#______________________________________________________________

# DSL to create Bitcoin::Protocol::Tx used by Builder#build_tx.
#  tx = tx do |t|
#   t.input do |i|
#    i.prev_out prev_tx, 0
#    i.signature_key key end
#   t.output do |o|
#    o.value 12345 # 0.00012345 BTC
#    o.to key.addr end end
#
# Signs every input that has a signature key and where the previous outputs
# pk_script is known. If unable to sign, the resulting txin will include
# the #sig_hash that needs to be signed.
#
# See TxInBuilder and TxOutBuilder for details on how to build in/outputs.
class TxBuilder
 def initialize
  @tx = P::Tx.new(nil)
  @tx.ver = 1
  @tx.lock_time = 0
  @ins = []
  @outs = [] end

 # specify tx version. this is usually not necessary. defaults to 1.
 def version(n)   @tx.ver = n end
 # specify tx lock_time. this is usually not necessary. defaults to 0.
 def lock_time(n) @tx.lock_time = n end

 # add an input to the transaction (see TxInBuilder).
 def input
  c = TxInBuilder.new
  yield c
  @ins << c end

 # add an output to the transaction (see TxOutBuilder).
 def output(value = nil, recipient = nil, type = :address)
  c = TxOutBuilder.new
  c.value(value)  if value
  c.to(recipient, type) if recipient
  yield c if block_given?
  @outs << c end

 # Create the transaction according to values specified via DSL.
 # Sign each input that has a signature key specified. If there is
 # no key, store the sig_hash in the input, so it can easily be
 # signed later.
 #
 # When :change_address and :input_value options are given, it will
 # automatically create a change output sending the remaining funds
 # to the given address. The :leave_fee option can be used in this
 # case to specify a tx fee that should be left unclaimed by the
 # change output.
 # rubocop:disable CyclomaticComplexity,PerceivedComplexity
 def tx(opts = {})
  return @tx if @tx.hash
  if opts[:change_address] && !opts[:input_value] then raise "Must give 'input_value' when auto-generating change output!" end
  @ins.each  { |i| @tx.add_in(i.txin) }
  @outs.each { |o| @tx.add_out(o.txout) }
  if opts[:change_address]
   output_value = @tx.out.map(&:value).inject(:+) || 0
   change_value = opts[:input_value] - output_value
   if opts[:leave_fee] then fee = @tx.minimum_block_fee + (opts[:extra_fee] || 0)
    if change_value >= fee then change_value -= fee else change_value = 0 end end
   if change_value > 0
    script = Script.to_address_script(opts[:change_address])
    @tx.add_out(P::TxOut.new(change_value, script)) end end
  @ins.each_with_index do |inc, i| sign_input(i, inc) end
  # run our tx through an encode/decode cycle to make sure that the binary format is sane
  raise 'Payload Error' unless P::Tx.new(@tx.to_payload) == @tx.to_payload
  @tx.instance_eval do
   @payload = to_payload
   @hash = hash_from_payload(@payload) end
  @tx end

 # coinbase inputs don't need to be signed, they only include the given +coinbase_data+
 def include_coinbase_data(i, inc)
  script_sig = [inc.coinbase_data].pack('H*')
  @tx.in[i].script_sig_length = script_sig.bytesize
  @tx.in[i].script_sig = script_sig end

 def sig_hash_and_all_keys_exist?(inc, sig_script)
  return false unless @sig_hash && inc.keys?
  script = Bitcoin::Script.new(sig_script)
  return true if script.is_hash160? || script.is_pubkey?
  if script.is_multisig?
   return inc.multiple_keys? && inc.key.size >= script.get_signatures_required end
  raise 'Script type must be hash160, pubkey or multisig' end

 def add_empty_script_sig_to_input(i)
  @tx.in[i].script_sig_length = 0
  @tx.in[i].script_sig = ''
  # add the sig_hash that needs to be signed, so it can be passed on to a signing device
  @tx.in[i].sig_hash = @sig_hash
  # add the address the sig_hash needs to be signed with as a convenience for the signing device
  @tx.in[i].sig_address = Script.new(@prev_script).get_address if @prev_script end

 def get_script_sig(inc, hash_type)
  if inc.multiple_keys?  # multiple keys given, generate signature for each one
   sigs = inc.sign(@sig_hash)
   redeem_script = inc.instance_eval { @redeem_script }
   if redeem_script then script_sig = Script.to_multisig_script_sig(*sigs) end
  else # when no redeem_script is given, do a regular multisig spend
   sig = inc.sign(@sig_hash) # only one key given, generate signature and script_sig
   script_sig = Script.to_pubkey_script_sig(sig, [inc.key.pub].pack('H*'), hash_type) end
  script_sig end

 # Sign input number +i+ with data from given +inc+ object (a TxInBuilder).
 def sign_input(i, inc)
  return include_coinbase_data(i, inc) if @tx.in[i].coinbase?
  @prev_script = inc.instance_variable_get(:@prev_out_script)
  # get the signature script; use +redeem_script+ if given, otherwise use the prev_script
  sig_script = inc.instance_eval { @redeem_script }
  sig_script ||= @prev_script
  hash_type = if inc.prev_out_forkid then Script::SIGHASH_TYPE[:all] | Script::SIGHASH_TYPE[:forkid]
              else Script::SIGHASH_TYPE[:all] end
  if sig_script # when a sig_script was found, generate the sig_hash to be signed
   script = Script.new(sig_script)
   @sig_hash = if inc.prev_out_forkid then @tx.signature_hash_for_inputs( i, sig_script, hash_type, inc.value, inc.prev_out_forkid )
    else @tx.signature_hash_for_inputs(i, sig_script) end end

  # when there is a sig_hash and one or more signature_keys were specified
  if sig_hash_and_all_keys_exist?(inc, sig_script) # add the script_sig to the txin
   @tx.in[i].script_sig = get_script_sig(inc, hash_type)
   # double-check that the script_sig is valid to spend the given prev_script
   if @prev_script && !inc.prev_out_forkid
    verified = @tx.verify_input_signature(i, @prev_script)
    raise 'Signature error' unless verified end
  elsif inc.multiple_keys? then raise 'Keys missing for multisig signing'
  else add_empty_script_sig_to_input(i) end end  # no sig_hash, add an empty script_sig.

 # Randomize the outputs using SecureRandom
 def randomize_outputs() @outs.sort_by! { SecureRandom.random_bytes(4).unpack('I')[0] } end end
#______________________________________________________________________

# Create a Bitcoin::Protocol::TxIn used by TxBuilder#input.
#
# Inputs need the transaction hash and the index of the output they spend.
# You can pass either the transaction, or just its hash (in hex form).
# To sign the input, builder also needs the pk_script of the previous output.
# If you specify a tx hash instead of the whole tx, you need to specify the
# output script separately.
#
#  t.input do |i|
#   i.prev_out prev_tx  # previous transaction
#   i.prev_out_index 0  # index of previous output
#   i.signature_key key # Bitcoin::Key used to sign the input end
#
#  t.input {|i| i.prev_out prev_tx, 0 }
#
# DEPR If you want to spend a p2sh output, you also need to specify the +redeem_script+.
#
#  t.input do |i|  i.prev_out prev_tx, 0
#   i.redeem_script prev_out.redeem_script end
#
# If you want to spend a multisig output, just provide an array of keys to #signature_key.
class TxInBuilder
 attr_reader :coinbase_data, :key, :prev_out_forkid, :prev_script, :prev_tx
 attr_writer :prev_out_script, :prev_out_value, :redeem_script, :sequence
 def initialize
  @txin = P::TxIn.new
  @prev_out_hash = "\x00" * 32
  @prev_out_index = 0
  @redeem_script = nil
  @key = nil end

 # Previous transaction that contains the output we want to use.
 # You can either pass the transaction, or just the tx hash.
 # If you pass only the hash, you need to pass the previous output's
 # +script+ separately if you want the txin to be signed.
 def prev_out(tx, idx = nil, script = nil, prev_value = nil, prev_forkid = nil)
  @prev_out_forkid = prev_forkid
  if tx.is_a?(Bitcoin::P::Tx)
   @prev_tx = tx
   @prev_out_hash = tx.binary_hash
   @prev_out_script = tx.out[idx].pk_script if idx
  else @prev_out_hash = tx.htb.reverse end
  @prev_out_script = script if script
  @prev_out_index = idx if idx
  @prev_out_value = prev_value if prev_value end

 # Index of the output in the #prev_out transaction.
 def prev_out_index(i)
  @prev_out_index = i
  @prev_out_script = @prev_tx.out[i].pk_script if @prev_tx end

 # Previous output's +pk_script+. Needed when only the tx hash is specified as #prev_out.
 def prev_out_script(script) @prev_out_script = script end

 # Previous output's +value+. Needed when only spend segwit utxo.
 # DEPRECATION def prev_out_value(value) @prev_out_value = value end

 def value() @prev_out_value end

 # Redeem script for P2SH output. To spend from a P2SH output, you need to provide
 # the script with a hash matching the P2SH address.
 # DEPRECATION def redeem_script(script) @redeem_script = script end

 # Specify sequence. This is usually not needed.
 def sequence(s) @sequence = s end

 # Bitcoin::Key used to sign the signature_hash for the input.
 # see Bitcoin::Script.signature_hash_for_inputs and Bitcoin::Key.sign.
 def signature_key(key) @key = key end

 # Specify that this is a coinbase input. Optionally set +data+.
 # If this is set, no other options need to be given.
 def coinbase(data = nil)
  @coinbase_data = data || OpenSSL::Random.random_bytes(32)
  @prev_out_hash = "\x00" * 32
  @prev_out_index = 4_294_967_295 end

 def txin # Create the txin according to specified values
  @sequence ||= nil
  @txin.prev_out = @prev_out_hash
  @txin.prev_out_index = @prev_out_index
  @txin.sequence = @sequence || "\xff\xff\xff\xff"
  @txin end

 def has_multiple_keys?
  warn '[DEPRECATION] `TxInBuilder.has_multiple_keys?` is deprecated. Use `multiple_keys?` instaed.'
  multiple_keys? end

 def multiple_keys?() @key.is_a?(Array) end
 def keys?() @key && (multiple_keys? ? @key.all?(&:priv) : @key.priv) end

 def has_keys?
  warn '[DEPRECATION] `TxInBuilder.has_keys?` is deprecated. Use `keys?` instead.'
  keys? end

 def sign(sig_hash)
  if multiple_keys? then @key.map { |k| k.sign(sig_hash) }
  else @key.sign(sig_hash) end end end

# Create a Bitcoin::Script used by TxOutBuilder#script.
class ScriptBuilder
attr_reader :script, :redeem_script
 def initialize
  @type = :address
  @script = nil end

 # Script type (:pubkey, :address/hash160, :multisig). Defaults to :address.
 def type(type) @type = type.to_sym end

 # Recipient(s) of the script.
 # Depending on the #type, this should be an address, a hash160 pubkey,
 # or an array of multisig pubkeys.
 def recipient(*data) @script, @redeem_script = *Script.send("to_#{@type}_script", *data) end end

 # Create a Bitcoin::Protocol::TxOut used by TxBuilder#output.
 #
 #  t.output 12345, address
 #  t.output 12345, p2sh_address, :script_hash
 #
 #  t.output {|o| o.value 12345; o.to address }
 #
 #  t.output do |o|
 #    o.value 12345
 #    o.script {|s| s.recipient address }  end
 #
 #  t.output {|o| o.to "deadbeef", :op_return }
class TxOutBuilder
 attr_reader :txout
 def initialize() @txout = P::TxOut.new(0) end
 def value(value) @txout.value = value end # Set output value (in base units / "satoshis")

 def to(recipient, type = :address) # Set recipient address and script type (defaults to :address).
  @txout.pk_script, @txout.redeem_script = *Bitcoin::Script.send( "to_#{type}_script", *recipient ) end

 def script # Add a script to the output (see ScriptBuilder).
  c = ScriptBuilder.new
  yield c
  @txout.pk_script = c.script
  @txout.redeem_script = c.redeem_script end end end end
