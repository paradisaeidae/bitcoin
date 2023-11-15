=begin
A Bitcoin transaction consists of a Locking Script and an Unlocking Script.
Murray refers to the Locking Script (also called “scriptPubKey”) as the combination on a padlock.
The Unlocking Script (called “scriptSig”) is the solution to the Locking Script.
 https://wiki.bitcoinsv.io/index.php/Bitcoin_Transactions
 https://wschae.github.io/build/editor.html

 The deep explainer: https://learnmeabitcoin.com/technical/ecdsa
 Original: https://gist.github.com/charleyhine/62c35021d2a63338121d
https://gist.github.com/Sjors/5574485

 scriptSig_p2pkH = 'OP_DUP OP_HASH160 ' + (fr_address_hex.size / 2).to_s(16) + ' ' + fr_address_hex + ' OP_EQUALVERIFY OP_CHECKSIG'
https://protobuf.dev/
https://www.rubydoc.info/gems/varint/0.1.1/Varint#encode-instance_method
https://www.twostack.org/developer-guide/transactions/signature-schemes/
http://www.righto.com/2014/02/bitcoins-hard-way-using-raw-bitcoin.html
https://bitcoin.stackexchange.com/questions/3374/how-to-redeem-a-basic-tx
Verification: https://en.bitcoin.it/w/images/en/7/70/Bitcoin_OpCheckSig_InDetail.png
https://wiki.bitcoinsv.io/index.php/SIGHASH_flags
https://gchq.github.io/CyberChef
https://apidock.com/ruby/Array/pack
=end
['open-uri', 'json', 'digest/sha2', 'bigdecimal', 'bitcoin', 'dotenv/load', 'faraday', 'bitcoin/script' ].each { | ment | "#{ment}: #{require ment}" }
SATOSHI_PER_BITCOIN = BigDecimal(100_000_000) # We use BigDecimal as that will allow us to do fractions of Satoshi.
ONE_SAT = 1  #BigDecimal(0.00_00_00_01, 8)         # 1 / SATOSHI_PER_BITCOIN 0.00000001
def sect_1
 begin
 puts "Loading ENV from: #{ARGV[0]}"
 Dotenv.load(ARGV[0])
 
 ###### SETUP #######
 @to_address   = ENV['to_address']
 @from_address = ENV['from_address']
 @private_key  = ENV['private_key'] # Wallet import format (starts with a 5)
 @c_p_wif_raw  = ENV['c_p_wif_raw']
 @amount       = ONE_SAT
 #@transaction_fee = @amount >= BigDecimal("0.01") ? BigDecimal("0") : BigDecimal("0.0001") # Previous estimataion.
 @transaction_fee = ONE_SAT # 1 Sat / 1000 bytes TAAL recent 
 
 puts "About to send #{@amount.to_s} Bc from #{@from_address[0..5]}... to #{@to_address[0..5]}... " + (@transaction_fee > 0 ? "plus a #{@transaction_fee.to_s} transaction fee." : "")
 
 ###### PREP API ACCESS ######
 Bitcoin.network = :test if ENV['network'] == 'test'
 Bitcoin.network = :main if ENV['network'] == 'main'
 @api_net = Bitcoin.network[:project]
 @taal_mapi_F = Faraday.new(url: 'https://mapi.taal.com')        do | builder | builder.adapter Faraday::Adapter::NetHttp end
 @woc_F =       Faraday.new(url: 'https://api.whatsonchain.com') do | builder | builder.adapter Faraday::Adapter::NetHttp end # https://docs.taal.com/core-products/whatsonchain
 @from_info_Res    = @woc_F.get do | req | req.url "/v1/bsv/#{@api_net}/address/#{@from_address}/info"    end
 @from_balance_Res = @woc_F.get do | req | req.url "/v1/bsv/#{@api_net}/address/#{@from_address}/balance" end
 @from_utxos_Res   = @woc_F.get do | req | req.url "/v1/bsv/#{@api_net}/address/#{@from_address}/unspent" end
 
 ###### BALANCE ###### https://test.whatsonchain.com/address/....
 puts "Fetching balance for #{@from_address[1..5]}: #{JSON.parse(@from_balance_Res.body)['confirmed']} confirmed"
 
 @balance = JSON.parse(@from_balance_Res.body)['confirmed'] #BigDecimal(confirmed) / SATOSHI_PER_BITCOIN
 puts  "Current balance of sender: #{@balance} satoshi"
 raise "Insuffient funds" if @balance < @amount + @transaction_fee
 
 ###### Prep UNSPENTS ######
 input_total = 0 # BigDecimal('0')
 @unspent_outpoints = JSON.parse(@from_utxos_Res.body)
 @unspent_2use = []
 @unspent_outpoints.each do | outpoint |
  trans = @woc_F.get do | req | req.url "/v1/bsv/#{@api_net}/tx/hash/#{outpoint['tx_hash']}" end
  unspent_lock = JSON.parse(trans.body)['vout'][0]['scriptPubKey']['hex'] # The asm Useful for checking if P2PKH
  @unspent_2use << { previousTx: outpoint['tx_hash'], index: outpoint['tx_pos'], scriptSig: unspent_lock }
  amount = outpoint["value"]
  puts "Using #{amount.to_s} from outpoint #{outpoint['tx_pos']} of transaction #{outpoint['tx_hash'][0..5]}..."
  puts "unspent_lock: #{unspent_lock}"
  input_total += amount
  break if input_total >= @amount + @transaction_fee end
 
 @change = input_total - @transaction_fee - @amount 
 puts "Spend #{@amount.to_s} and return #{@change.to_s} as change."
 raise "Unable to process inputs for transaction" if input_total < @amount + @transaction_fee || @change < 0
 
 #### Prep KEY ######
 mover_wif = Electrum::Wif.new @c_p_wif_raw
 @mover_ossl_key_pair = mover_wif.p_key.ec_key
 raise 'Invalid keypair' unless @mover_ossl_key_pair.check_key
 pub_key_MT = MoneyTree::PublicKey.new mover_wif.p_key
 Digest::SHA256.hexdigest([pub_key_MT.key].pack("H*"))
 raise 'Issue with key' if ENV['public_key'] != pub_key_MT.key

 ##### P2PK OUTPOINTS ######
 fr_address_hex = Bitcoin.base58_to_hex(@from_address)
 to_address_hex = Bitcoin.base58_to_hex(@to_address)    # le_pkey_length = little_end(pub_key_MT.key.bytesize / 2, 1)
 lock_scr = pub_key_MT.key + ' OP_CHECKSIG' # Will be expanded when serialized.
 @outpoints = [ { sats: @amount, scriptPubKey: lock_scr}] # Amount to transfer 'OP_DUP OP_HASH160 ' + to_address_hex + ' OP_EQUALVERIFY OP_CHECKSIG' }]
 @outpoints <<  { sats: @change, scriptPubKey: lock_scr} unless @change == 0  # Any sats not specified in an output goes to the miners (transaction fee)

 @unspent_2use.collect!{ | inpoint | {
  previousTx:   inpoint[:previousTx], index: inpoint[:index],  # scriptLength: inpoint[:scriptSig].bytesize / 2,
  scriptSig:    inpoint[:scriptSig],  # Dummy entry while signing.
  sequence_no: 'ffffffff' }} # 'ff..' is disabled. Will be le when serialized. Ignored with type 1 trans. Usable with type 2 trans.

 #### Prep TRANSACTION ###### # Use version 2 so that sequence number may be used.
 @transaction = { version: 1, in_counter: @unspent_2use.count, inputs: @unspent_2use,
  out_counter: @outpoints.count, outputs: @outpoints, lock_time: '00000000',
  hash_code_type: '41000000' } # LE hex bytes. 4 bytes during the signing. '41' is SIGHASH_ALL

 rescue => badThing;  puts badThing;  debugger end

 begin # Serialize and create the input signature/s. Then add these signature/s back into the transaction and serialize it again.
 @utx = serialize_transaction(@transaction).gsub(' ', '')
 sha_first =  (Digest::SHA2.new << [@utx].pack("H*")).to_s
 sha_second = (Digest::SHA2.new << [sha_first].pack("H*")).to_s # Twice Sha256
 puts "Hash that we're going to sign: #{sha_second}"
 signed_bin = Bitcoin::Secp256k1.sign([sha_second].pack("H*"), @mover_ossl_key_pair.private_key.to_s)  # and sign, low-S encoding!
 puts 'Bad DER for secp256k1_sign!' unless Bitcoin::Script.is_der_signature?(signed_bin + [Bitcoin::Script::SIGHASH_TYPE[:all]].pack("C")) == true

 # Once signed build the unlocking script for P2PKH: https://xiaohuiliu.medium.com/a-step-by-step-guide-to-developing-bitcoin-smart-contracts-e43f00f42f05
 # scriptSig = <Signature> <Public Key>

 unlockSsig = signed_bin.unpack('H*')[0] + pub_key_MT.key
 puts "unlockSsig: #{unlockSsig}"
 
 @transaction[:inputs].collect!{ | inpoint | # Replace unlockSsig for each of the inpoints:
  {previousTx:   inpoint[:previousTx],
   index:        inpoint[:index],  # scriptLength: unlockSsig.bytesize / 2,
   scriptSig:    unlockSsig,
   sequence_no:  inpoint[:sequence_no] }}
 
 @transaction[:hash_code_type] = '' # After signing.
 @tx_ = serialize_transaction(@transaction)
 @tx = @tx_.gsub(" ", "") # Remove spaces
 
 puts "Signed transaction hex: (#{ @tx.size / 2 } bytes)"
 puts @tx_
 raise 'Over 1_000 bytes needs more than one sat @ TAAL' if @tx.size / 2 > 1000
 #puts @tx
  # Broadcast the signed transaction to the network using a BSV node or a BSV API
  # https://docs.taal.com/core-products/whatsonchain/transaction#broadcast-transaction
  decoded_Res = @woc_F.post do | req | req.url "/v1/bsv/#{@api_net}/tx/decode"
   req.headers['Authorization'] = ENV['taal_mapi_Authorization']
   req.headers['Content-Type']  = 'application/json'
   req.body = JSON.generate({ :txhex => @tx }) end

  if decoded_Res.status != 200 then puts decoded_Res.body.inspect; debugger; exit end
  puts JSON.parse(decoded_Res.body)['vin'][0]['scriptSig']['asm']
  debugger if JSON.parse(decoded_Res.body)['vin'][0]['scriptSig']['asm'].include? 'OP_UNKNOWN'
  debugger if JSON.parse(decoded_Res.body)['vin'][0]['scriptSig']['asm'].include? 'error'
  debugger

  raw_tc_P = @woc_F.post do | req | req.url "/v1/bsv/#{@api_net}/tx/raw"
   req.headers['Authorization'] = ENV['taal_mapi_Authorization']
   req.headers['Content-Type']  = 'application/json'
   req.body = JSON.generate({ :txhex => @tx }) end
  puts raw_tc_P.body
  puts "_____________#{raw_tc_P.status}__________________"
 
  raise 'Issue!' if raw_tc_P.status != 200

 rescue => badThing
  puts badThing
  debugger end end

def serialize_transaction(trans)
 tx = little_end(trans[:version], 4) + ' '
 tx << Bitcoin::P.pack_var_int(trans[:in_counter]).unpack("H*")[0] + ' ' # Up to 9 bytes.
 trans[:inputs].each do |input|
  tx << [input[:previousTx]].pack("H*").reverse.unpack("H*")[0] + ' '
  tx << [input[:index     ]].pack('V').unpack("H*")[0]          + ' ' # 4 Bytes LE
  tx << Bitcoin::P.pack_var_int(input[:scriptSig].bytesize / 2).unpack("H*")[0] + ' ' # Recalc scriptSig bytesize.
  tx << input[:scriptSig] + ' '
  tx << input[:sequence_no] + ' ' end # little_end (already ffffffff)

 tx << Bitcoin::P.pack_var_int(trans[:out_counter]).unpack("H*")[0] + ' ' # Up to 9 bytes.# tx << little_end(trans[:out_counter], 1) + ' ' # Number of outputs
 trans[:outputs].each do |output|
  tx << little_end((output[:sats]), 8) + ' '
  pkey = output[:scriptPubKey].split(' ')[0]
  lock_scr = Bitcoin::P.pack_var_int((pkey.bytesize + 2) / 2).unpack("H*")[0] + ' ' + pkey + 'ac ' # Add two bytes for the 'ac' opcode.
  puts "lock_scr (scriptPubKey) : #{lock_scr}" 
  tx << lock_scr end

 tx << trans[:lock_time] + ' ' # little_end (already '00000000')
 tx << trans[:hash_code_type] unless trans[:hash_code_type].length < 2 # This is '' after signing
 tx
 rescue => badThing
  puts badThing
  debugger end

def little_end(i, n) i.to_s(16).rjust(n * 2, "0").scan(/(..)/).reverse.join() end
def opcodeify(script) script.gsub("OP_DUP", "76").gsub("OP_HASH160", "a9").gsub("OP_EQUALVERIFY", "88").gsub("OP_CHECKSIG", "ac").gsub("OP_RETURN", "6a") end

sect_1

def check_pub_key # Check that the prior transaction pubKey matches the private key (valid signature)
 #### CHECK PUBkey gives expected address ####
 step_0 = (Digest::SHA2.new   << [pub_key_MT.key].pack("H*")).to_s     # -> "4647...4c9be" Digest works on the binary
 step_1 = (Digest::RMD160.new << [step_0].pack("H*")).to_s             # -> "8363...84e58df" Reduce any misreading opportunities.
 step_2 = "6f" + step_1                                                # -> "7183...e58df"   '00' for the mainnet and "6f" for the testnet.
 step_2 = "00" + step_1 if Bitcoin.network[:project] == :main 
 step_3 = (Digest::SHA2.new << [step_2].pack("H*")).to_s               # Double Hash
 step_4 = (Digest::SHA2.new << [step_3].pack("H*")).to_s               # 
 checksum = step_4[0..7]                                               # Check sum -> b18a9aba
 step_5 = step_2 + checksum                                            # -> 00233760...b18a9aba
 step_6 = Base58.encode_hex(step_5)                                    # -> 14DCzMe... which is the bitcoin address
 debugger if @from_address != step_6 # "Public key does not match expected address!"
 puts "Public key matches private key, so we can sign the transaction..." end

def local_bc_sign
 script_bin = Bitcoin.sign_data(@mover_ossl_key_pair, [sha_second].pack("H*"))
 script_sign_issues = Bitcoin::Script.is_der_signature? script_bin + [Bitcoin::Script::SIGHASH_TYPE[:all]].pack("C")
 puts 'Bad DER for script_sign: ' + script_sign_issues unless script_sign_issues == true
 debugger if (script_sign_issues != true) || (secp25_sign_ok != true) end