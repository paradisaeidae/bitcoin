module Bitcoin
module Protocol
# TxWitness section of https://en.bitcoin.it/wiki/Protocol_documentation#tx
class ScriptWitness # witness stack
attr_reader :stack
def initialize
 @stack = [] end

def empty? # check empty
 stack.empty? end

def to_payload # output script in raw binary format
 payload = Bitcoin::Protocol.pack_var_int(stack.size)
 payload << stack.map { |e| Bitcoin::Protocol.pack_var_int(e.bytesize) << e }.join end end end end