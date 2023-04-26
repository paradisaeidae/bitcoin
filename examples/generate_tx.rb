gem 'faraday', '1.8.0'  #'2.5.2',  2.2.0 has issue with uninitialized constant Faraday::Request::Retry (NameError)
['nutrun-string', 'certified',  'faraday', 'json',  'ffi', 'rjr/nodes/tcp', \
 'digest/sha2', 'bigdecimal', 'bitcoin', 'bitcoin-client', 'faraday/detailed_logger', 'pry'].each {| ment | require ment }
require 'stringio'
require '/k0.io/2007/Tests/BSV/payment_utils'

prep_network :testnet
# p Bitcoin.generate_address # returns address, privkey, pubkey, hash160

#prev_tx = Bitcoin::Protocol::Tx.from_json_file('baedb362adba39753a7d2c58fd3dc4897a1b479859f707a819f096696f3facad.json')
 raw_tc = File.open("/k0.io/2007/Tests/BSV/2265703f5f712d428165bcae5866f10d6d234693dfd5ee1835de7c68c9026e2c.hex", 'rb') { |f| f.read }
 prev_tx   = Bitcoin::Protocol::Tx.new([raw_tc].pack('H*'))
 # redeeming transaction input fetched by for example simple_network_monitor_and_util.rb
prev_tx_output_index = 0
value = prev_tx.outputs[prev_tx_output_index].value
#value = 1337 # maybe change the value (eg subtract for fees)

new_tx =       Bitcoin::Protocol::Tx.new
new_tx.add_in  Bitcoin::Protocol::TxIn.new(prev_tx.binary_hash, prev_tx_output_index, 0) # return the tx hash in binary format
new_tx.add_out Bitcoin::Protocol::TxOut.value_to_address(value, "msVfS4Wp754gZYjwn4H5XrDz5P4BsjjkLS") # <- dest address

 test_addy_one_c_p_wif = 'cNTJxDk91bYc8r34niXbeHSNHhAsEjVh9M9qtUnQHTBEKoWysxu7'
 key =      Bitcoin::Key.from_base58(test_addy_one_c_p_wif)
 key_pair = Bitcoin.open_key(key.key.private_key_hex)

# if all in and outputs are defined, start signing inputs.
#key_pair = Bitcoin.open_key("9b2f08ebc186d435ffc1d10f3627f05ce4b983b72c76b0aee4fcce99e57b0342") # <- privkey

sig = Bitcoin.sign_data(key_pair, new_tx.signature_hash_for_input(0, prev_tx.outputs[prev_tx_output_index].pk_script))
new_tx.inputs[0].script_sig = Bitcoin::Script.to_signature_pubkey_script(sig, [key_pair.public_key_hex].pack("H*"))
#new_tx.in[0].add_signature_pubkey_script(sig, key.public_key_hex)

# finish check
new_tx = Bitcoin::Protocol::Tx.new( new_tx.to_payload )
p new_tx.hash
p new_tx.verify_input_signature(0, prev_tx.outputs[prev_tx_output_index].pk_script) == true
binding.pry

puts "json:\n"
puts new_tx.to_json # json
puts "\nhex:\n"
puts new_tx.to_payload.unpack("H*")[0] # hex binary

# use this json file for example with `ruby simple_network_monitor_and_util.rb send_tx=<filename>` to push/send it to the network
File.open(new_tx.hash + ".json", 'wb'){ | f | f.print new_tx.to_json }