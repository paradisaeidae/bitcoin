# encoding: ascii-8bit
module Bitcoin;module Protocol # OutPoint section of https://en.bitcoin.it/wiki/Protocol_documentation#tx
class OutPoint_rec < ::BinData::Record
 # https://developer.bitcoin.org/reference/transactions.html
end
def outpoint_from_io(buf)
 outpoint = Bitcoin::Protocol::OutPoint.new
 outpoint.parse_data_from_io(buf)
 outpoint end

def outpoint_from_hasH(output)
 value = output['value']   # ? output['value'].delete('.').to_i : output['amount']
 pk_scr = Script.binary_from_string(output['scriptPubKey']['asm'] ) #  || output['script'])
 Bitcoin::Protocol::OutPoint.new(value, pk_scr) end
module_function :outpoint_from_io, :outpoint_from_hasH

class OutPoint # Basically a pointer back to where some sats came from: outpoint.
attr_accessor :value, :redeem_script      # output value (in base units; "satoshi")
attr_reader :pk_scr, :pk_scr_length # pk_scr output Script

def initialize(*args)
 if args.size == 2 # from outpoint_from_hasH
  @value = args[0]
  @pk_scr_length = args[1].bytesize
  @pk_scr = args[1]
 else @value, @pk_scr_length, @pk_scr = *args end end # init to zeros for def outpoint_from_io(buf)

def ==(other)
 @value == other.value && @pk_scr == other.pk_scr
 rescue StandardError; false end

def parse_data(data) # parse raw binary data for transaction output
 buf = data.is_a?(String) ? StringIO.new(data) : data
 parse_data_from_io(buf)
 buf.pos end

def self.from_io(buf)
 outpoint = new
 outpoint.parse_data_from_io(buf)
 outpoint end

def parse_data_from_io(buf) # parse raw binary data for transaction output
 clear_parsed_script_cache
 @value = buf.read(8).unpack('Q')[0]
 @pk_scr_length = Protocol.unpack_var_int_from_io(buf)
 @pk_scr = buf.read(@pk_scr_length) end

alias parse_payload parse_data

def parsed_script()             @parsed_script ||= Bitcoin::Script.new(pk_scr) end
def clear_parsed_script_cache() remove_instance_variable(:@parsed_script) if defined?(@parsed_script) end
def to_payload()
 [@value].pack('Q') << Protocol.pack_var_int(@pk_scr_length) << @pk_scr
 rescue => badThing; debugger end

def to_null_payload() self.class.new(-1, '').to_payload end

def to_hash(options = {})
 h = { 'value' => format('%.8f', (@value / 100_000_000.0)), 'scriptPubKey' => parsed_script.to_string }
 if options[:with_address]
  addrs = parsed_script.get_addresses
  h['address'] = addrs.first if addrs.size == 1 end
 h end

def self.from_hasH(output)
 value = output['value']   # ? output['value'].delete('.').to_i : output['amount']
 pk_scr = Script.binary_from_string(output['scriptPubKey']['asm'] ) #  || output['script'])
 new(value, pk_scr) end

def pk_scr=(pk_scr) # set pk_scr and pk_scr_length
 clear_parsed_script_cache
 @pk_scr_length = pk_scr.bytesize
 @pk_scr = pk_scr end

def self.value_to_address(value, address) # create output spending +value+ btc (base units) to +address+
 pk_scr = Bitcoin::Script.to_address_script(address)
 raise "Script#pk_scr nil with address #{address}" unless pk_scr
 new(value, pk_scr) end end end end
