# -*- coding: utf-8 -*- 
# https://github.com/dougal/base58 https://github.com/GemHQ/money-tree/blob/2d0ba66441ec035e364482690bfe395ca7bf64b8/lib/money-tree/key.rb#L60
# https://ozanyurtseven.wordpress.com/2015/04/29/hierarchical-deterministic-wallets-bip0032bip0044-in-ruby/
module Electrum
class Wif_rec < ::BinData::Record
 #attr_accessor :network, :p_key_str, :compression, :checksum
 endian :big
 uint8  :network,     length: 1    # Can test against decimal. 239 for testnet
 string :p_key_str,   length: 32   # 256-bit integer (32 bytes)
 uint8  :compression, length: 1    # BSV public keys are always compressed.
 string :checksum,    length: 4
 def each_pair() end
 def to_s() Base58.encode(to_binary_s) end end # Convert the WIF fields to a WIF string

class Wif  # https://wiki.bitcoinsv.io/index.php/Private_Keys
attr_accessor :pem, :base64, :wif_rec, :p_key

def initialize(wif)
 decoded_58 = ::Base58::Bitcoin.decode_hex(wif) # https://github.com/dougal/base58
 @wif_rec = Wif_rec.read([decoded_58].pack('H*'))
 puts 'Length not 32' if wif_rec.p_key_str.bytesize != 32
 p_key_bn = ECDSA::Format::IntegerOctetString.decode(wif_rec.p_key_str)
 raise 'Not on Secp256k1 curve' unless p_key_bn > 1 && p_key_bn < ECDSA::Group::Secp256k1.order # Check that the private key is within the valid range
 @p_key = ::MoneyTree::PrivateKey.new(key: wif) # Imports, creates openssl key using ASN1 datasequence.
 @p_key.calculate_public_key(:compressed => true)
 rescue => badThing
  puts badThing.inspect; puts badThing.backtrace; raise 'Issue reading in wif' end

def to_pem(base64) @pem = "-----BEGIN EC PRIVATE KEY-----\n" + base64 + "\n-----END EC PRIVATE KEY-----\n" end

def check_wif(wif)
 raise 'Expecting wif to be UTF-8' if wif.encoding != 'UTF-8'
 if wif.include? '----' then raise 'Expected raw private, not PEM' end
 netw = ::Bitcoin.network[:project]
 case wif[0, 1] # Network indicator
 when '5'
  if wif.length != 51 || netw != :mainnet then raise 'Not on mainnet or length issue.' end # mainnet
  bytes_at_end = -4
 when 'L' || 'K'
  if wif.length != 51 || netw != :mainnet then raise 'Not on mainnet or length issue.' end # mainnet compressed
  bytes_at_end = -5
 when '9'
  if wif.length != 52 || netw != :testnet then raise 'Not on testnet or length issue.' end # testnet
  bytes_at_end = -4
 when 'c'
  if wif.length != 52 || netw != :testnet then raise 'Not on testnet or length issue.' end # testnet compressed
  bytes_at_end = -5 end
 puts "wif                  : #{wif}    #{wif.encoding}  length: #{wif.length}" end

def from_pem_to_base64(pem); @base64 = pem.split("\n")[1] end end end

module MoneyTree
NETWORKS = begin
 hsh = Hash.new do |_, key| raise "#{key} is not a valid network!" end.merge(
  bitcoin: {
   address_version: "00",
   privkey_version: "80",
   privkey_compression_flag: "01",
   extended_privkey_version: "0488ade4",
   extended_pubkey_version: "0488b21e",
   compressed_wif_chars: %w(K L),
   uncompressed_wif_chars: %w(5),
   protocol_version: 70001,
   human_readable_part: "bc" },
  bitcoin_testnet: {
   address_version: "6f",
   privkey_version: "ef",
   privkey_compression_flag: "01",
   extended_privkey_version: "04358394",
   extended_pubkey_version: "043587cf",
   compressed_wif_chars: %w(c),
   uncompressed_wif_chars: %w(9),
   protocol_version: 70001,
   human_readable_part: "tb" } )
 hsh[:testnet3] = hsh[:bitcoin_testnet]
 hsh[:stn]      = hsh[:bitcoin_testnet]
 hsh[:regtest]  = hsh[:bitcoin_testnet]
 hsh end end