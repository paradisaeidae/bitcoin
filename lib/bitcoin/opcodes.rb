=begin
https://github.com/bitcoin-sv-specs
https://ramonquesada.com/glossary/opcodes-used-in-bitcoin-script/
https://github.com/bitcoin-sv/bitcoin-sv/blob/master/src/script/opcodes.cpp
https://github.com/bitcoin-sv/bitcoin-sv/blob/master/src/script/opcodes.cpp

November 2018 additions:
Word 	OpCode 	Hex 	Input 	Output 	Description
OP_CAT   	126 	0x7e 	x1 x2 	out 	Concatenates two byte sequences
OP_SPLIT 	127 	0x7f 	x n 	x1 x2 	Split byte sequence x at position n
OP_AND  	132 	0x84 	x1 x2 	out 	Boolean AND between each bit of the inputs
OP_OR   	133 	0x85 	x1 x2 	out 	Boolean OR between each bit of the inputs
OP_XOR  	134 	0x86 	x1 x2 	out 	Boolean EXCLUSIVE OR between each bit of the inputs
OP_DIV 	    150 	0x96 	a b 	out 	a is divided by b
OP_MOD  	151 	0x97 	a b 	out 	return the remainder after a is divided by b
OP_NUM2BIN 	128 	0x80 	a b 	out 	convert numeric value a into byte sequence of length b
OP_BIN2NUM 	129 	0x81 	x 	out 	convert byte sequence x into a numeric value
=end
=begin
Bitcoin ABC, the full node implementation developed by Amaury Séchet and currently used by most miners, 
has announced plans to activate, among other changes, two new opcodes during the protocol’s November hard fork 
— OP_CHECKDATASIG and OP_CHECKDATASIGVERIFY — as well as implement canonical transaction ordering.
These proposals have been met with strong resistance by Wright and Ayre, who have argued that,
 among other things, these opcodes could lead to “unlicensed gambling” since they can be used to 
implement “oracle” services such as those that make decentralized prediction markets possible.
 Ayre, incidentally, made his fortune through an online gambling empire, though it is Wright in particular
 who has used this as an argument against these opcodes.
=end

# do a CHECKMULTISIG operation on the current stack,
# asking +check_callback+ to do the actual signature verification.
#
# CHECKMULTISIG does a m-of-n signatures verification on scripts of the form:
#  0 <sig1> <sig2> | 2 <pub1> <pub2> 2 OP_CHECKMULTISIG
#  0 <sig1> <sig2> | 2 <pub1> <pub2> <pub3> 3 OP_CHECKMULTISIG
#  0 <sig1> <sig2> <sig3> | 3 <pub1> <pub2> <pub3> 3 OP_CHECKMULTISIG
#
# see https://en.bitcoin.it/wiki/BIP_0011 for details.
# see https://github.com/bitcoin-sv/bitcoin-sv/blob/master/src/script.cpp#L931
#
# TODO: validate signature order
# TODO: take global opcode count

class Bitcoin::Script
OP_0           = 0
OP_FALSE       = 0
OP_1           = 81
OP_TRUE        = 81
OP_2           = 0x52
OP_3           = 0x53
OP_4           = 0x54
OP_5           = 0x55
OP_6           = 0x56
OP_7           = 0x57
OP_8           = 0x58
OP_9           = 0x59
OP_10          = 0x5a
OP_11          = 0x5b
OP_12          = 0x5c
OP_13          = 0x5d
OP_14          = 0x5e
OP_15          = 0x5f
OP_16          = 0x60
OP_PUSHDATA0   = 0
OP_PUSHDATA1   = 76
OP_PUSHDATA2   = 77
OP_PUSHDATA4   = 78
OP_PUSHDATA_INVALID = 238 # 0xEE
OP_NOP         = 97
OP_DUP         = 118
OP_HASH160     = 169
OP_EQUAL       = 135
OP_VERIFY      = 105
OP_EQUALVERIFY = 136
OP_CHECKSIG    = 172
OP_CHECKSIGVERIFY      = 173
OP_CHECKMULTISIG       = 174
OP_CHECKMULTISIGVERIFY = 175
OP_TOALTSTACK   = 107
OP_FROMALTSTACK = 108
OP_TUCK         = 125
OP_SWAP         = 124
OP_BOOLAND      = 154
OP_ADD          = 147
OP_SUB          = 148
OP_GREATERTHANOREQUAL = 162
OP_DROP         = 117
OP_HASH256      = 170
OP_SHA256       = 168
OP_SHA1         = 167
OP_RIPEMD160    = 166
OP_NOP1         = 176
OP_NOP2         = 177
OP_NOP3         = 178
OP_NOP4         = 179
OP_NOP5         = 180
OP_NOP6         = 181
OP_NOP7         = 182
OP_NOP8         = 183
OP_NOP9         = 184
OP_NOP10        = 185
OP_CODESEPARATOR = 171
OP_MIN          = 163
OP_MAX          = 164
OP_2OVER        = 112
OP_2ROT         = 113
OP_2SWAP        = 114
OP_IFDUP        = 115
OP_DEPTH        = 116
OP_1NEGATE      = 79
OP_WITHIN         = 165
OP_NUMEQUAL       = 156
OP_NUMEQUALVERIFY = 157
OP_LESSTHAN     = 159
OP_LESSTHANOREQUAL = 161
OP_GREATERTHAN  = 160
OP_NOT            = 145
OP_0NOTEQUAL = 146
OP_ABS = 144
OP_1ADD = 139
OP_1SUB = 140
OP_NEGATE = 143
OP_BOOLOR = 155
OP_NUMNOTEQUAL = 158
OP_RETURN = 106
OP_OVER = 120
OP_IF = 99
OP_NOTIF = 100
OP_ELSE = 103
OP_ENDIF = 104
OP_PICK = 121
OP_SIZE = 130
OP_VER = 98
OP_ROLL = 122
OP_ROT = 123
OP_2DROP = 109
OP_2DUP = 110
OP_3DUP = 111
OP_NIP = 119
OP_CAT = 126
OP_SUBSTR = 127 # DEPR
OP_SPLIT = 127
OP_LEFT = 128 # DEPR
OP_RIGHT = 129 # DEPR
OP_INVERT = 131
OP_AND = 132
OP_OR = 133
OP_XOR = 134
OP_2MUL = 141
OP_2DIV = 142
OP_MUL = 149
OP_DIV = 150
OP_MOD = 151
OP_LSHIFT = 152
OP_RSHIFT = 153
OP_INVALIDOPCODE = 0xff
OPCODES = Hash[*constants.grep(/^OP_/).map{|i| [const_get(i), i.to_s] }.flatten]
OPCODES[0] = "0"
OPCODES[81] = "1"
OPCODES_ALIAS = {
 "OP_TRUE"  => OP_1,
 "OP_FALSE" => OP_0,
 "OP_EVAL" => OP_NOP1,
 "OP_CHECKHASHVERIFY" => OP_NOP2, }
DISABLED_OPCODES = [
 OP_CAT, OP_SUBSTR, OP_LEFT, OP_RIGHT,
 OP_AND, OP_OR, OP_XOR, OP_2MUL, OP_2DIV,
 OP_DIV, OP_MOD ] #  OP_MUL, OP_LSHIFT, OP_RSHIFT, and OP_INVERT Restored
OP_2_16 = (82..96).to_a
OPCODES_PARSE_BINARY = {}
OPCODES.each{|k,v|       OPCODES_PARSE_BINARY[k] = v }
OP_2_16.each{|i|         OPCODES_PARSE_BINARY[i] = (OP_2_16.index(i)+2).to_s }
OPCODES_PARSE_STRING = {}
OPCODES.each{|k,v|       OPCODES_PARSE_STRING[v] = k }
OPCODES_ALIAS.each{|k,v| OPCODES_PARSE_STRING[k] = v }
2.upto(16).each{|i|      OPCODES_PARSE_STRING["OP_#{i}"] = OP_2_16[i-2] }
2.upto(16).each{|i|      OPCODES_PARSE_STRING["#{i}"   ] = OP_2_16[i-2] }
[1,2,4].each{|i|         OPCODES_PARSE_STRING.delete("OP_PUSHDATA#{i}") }
SIGHASH_TYPE = {
 all: 1,
 none: 2,
 single: 3,
 forkid: 64,
 anyonecanpay: 128
}.freeze
attr_reader :raw, :chunks, :debug, :stack

# Converts OP_{0,1,2,...,16} into 0, 1, 2, ..., 16.
# Returns nil for other opcodes.
def self.decode_OP_N(opcode)
 if opcode == OP_0
  return 0 end
 if opcode.is_a?(Bitcoin::Integer) && opcode >= OP_1 && opcode <= OP_16
  return opcode - (OP_1 - 1);
 else nil end end

=begin
Additionally, the first release of Bitcoin SV will restore four “Satoshi opcodes” — 
scripting operations that had originally been included in Bitcoin but were disabled in later software updates. 
These opcodes are: OP_MUL, OP_LSHIFT, OP_RSHIFT, and OP_INVERT. 
Additionally, Bitcoin SV will remove the limit of 201 opcodes per individual script.
=end

## OPCODES Does nothing
def op_nop;   end
def op_nop1;  end
def op_nop2;  end
def op_nop3;  end
def op_nop4;  end
def op_nop5;  end
def op_nop6;  end
def op_nop7;  end
def op_nop8;  end
def op_nop9;  end
def op_nop10; end
def op_nop11;  end
def op_nop12;  end
def op_nop13;  end
def op_nop14;  end
def op_nop15;  end
def op_nop16;  end

def op_dup # Duplicates the top stack item.
 @stack << (@stack[-1].dup rescue @stack[-1]) end

def op_sha256 # The input is hashed using SHA-256.
 buf = pop_string
 @stack << Digest::SHA256.digest(buf) end

def op_sha1 # The input is hashed using SHA-1.
 buf = pop_string
 @stack << Digest::SHA1.digest(buf) end

# The input is hashed twice: first with SHA-256 and then with RIPEMD-160.
def op_hash160
 buf = pop_string
 @stack << Digest::RMD160.digest(Digest::SHA256.digest(buf)) end

def op_ripemd160 # The input is hashed using RIPEMD-160.
 buf = pop_string
 @stack << Digest::RMD160.digest(buf) end

def op_hash256 # The input is hashed two times with SHA-256.
 buf = pop_string
 @stack << Digest::SHA256.digest(Digest::SHA256.digest(buf)) end

# Puts the input onto the top of the alt stack. Removes it from the main stack.
def op_toaltstack
 @stack_alt << @stack.pop end

# Puts the input onto the top of the main stack. Removes it from the alt stack.
def op_fromaltstack
 @stack << @stack_alt.pop end

# The item at the top of the stack is copied and inserted before the second-to-top item.
def op_tuck
 @stack[-2..-1] = [ @stack[-1], *@stack[-2..-1] ] end

def op_swap # The top two items on the stack are swapped.
 @stack[-2..-1] = @stack[-2..-1].reverse if @stack[-2] end

def op_booland # If both a and b are not 0, the output is 1. Otherwise 0.
 a, b = pop_int(2)
 @stack << (![a,b].any?{|n| n == 0 } ? 1 : 0) end

def op_boolor # If a or b is not 0, the output is 1. Otherwise 0.
 a, b = pop_int(2)
 @stack << ( (a != 0 || b != 0) ? 1 : 0 ) end

def op_add # a is added to b.
 a, b = pop_int(2)
 @stack << a + b end

def op_sub # b is subtracted from a.
 a, b = pop_int(2)
 @stack << a - b end

def op_lessthan # Returns 1 if a is less than b, 0 otherwise.
 a, b = pop_int(2)
 @stack << (a < b ? 1 : 0) end

def op_lessthanorequal # Returns 1 if a is less than or equal to b, 0 otherwise.
 a, b = pop_int(2)
 @stack << (a <= b ? 1 : 0) end

def op_greaterthan # Returns 1 if a is greater than b, 0 otherwise.
 a, b = pop_int(2)
 @stack << (a > b ? 1 : 0) end

def op_greaterthanorequal # Returns 1 if a is greater than or equal to b, 0 otherwise.
 a, b = pop_int(2)
 @stack << (a >= b ? 1 : 0) end

def op_not # If the input is 0 or 1, it is flipped. Otherwise the output will be 0.
 a = pop_int
 @stack << (a == 0 ? 1 : 0) end

def op_0notequal
 a = pop_int
 @stack << (a != 0 ? 1 : 0) end

def op_abs # The input is made positive.
 a = pop_int
 @stack << a.abs end

def op_2div # The input is divided by 2. Currently disabled.
 a = pop_int
 @stack << (a >> 1) end

def op_2mul # The input is multiplied by 2. Currently disabled.
 a = pop_int
 @stack << (a << 1) end

def op_1add # 1 is added to the input.
 a = pop_int
 @stack << (a + 1) end

def op_1sub # 1 is subtracted from the input.
 a = pop_int
 @stack << (a - 1) end

def op_negate # The sign of the input is flipped.
 a = pop_int
 @stack << -a end

def op_drop # Removes the top stack item.
 @stack.pop end

def op_equal # Returns 1 if the inputs are exactly equal, 0 otherwise.
 a, b = pop_string(2)
 @stack << (a == b ? 1 : 0) end

# Marks transaction as invalid if top stack value is not true. True is removed, but false is not.
def op_verify
 res = pop_int
 if cast_to_bool(res) == false
  @stack << res
  @script_invalid = true # raise 'transaction invalid' ?
 else @script_invalid = false end end

def op_equalverify # Same as OP_EQUAL, but runs OP_VERIFY afterward.
 op_equal
 op_verify end

def op_0 # An empty array of bytes is pushed onto the stack.
 @stack << "" end # []

def op_1 # The number 1 is pushed onto the stack. Same as OP_TRUE
 @stack << 1 end

def op_min # Returns the smaller of a and b.
 @stack << pop_int(2).min end

def op_max # Returns the larger of a and b.
 @stack << pop_int(2).max end

def op_2over # Copies the pair of items two spaces back in the stack to the front.
 @stack << @stack[-4]
 @stack << @stack[-4] end

def op_2swap # Swaps the top two pairs of items.
 p1 = @stack.pop(2)
 p2 = @stack.pop(2)
 @stack += p1 += p2 end

def op_ifdup # If the input is true, duplicate it.
 if cast_to_bool(@stack.last) == true
  @stack << @stack.last end end

def op_1negate # The number -1 is pushed onto the stack.
 @stack << -1 end

def op_depth # Puts the number of stack items onto the stack.
 @stack << @stack.size end

# Returns 1 if x is within the specified range (left-inclusive), 0 otherwise.
def op_within
 bn1, bn2, bn3 = pop_int(3)
 @stack << ( (bn2 <= bn1 && bn1 < bn3) ? 1 : 0 ) end

def op_numequal # Returns 1 if the numbers are equal, 0 otherwise.
 a, b = pop_int(2)
 @stack << (a == b ? 1 : 0) end

def op_numnotequal # Returns 1 if the numbers are not equal, 0 otherwise.
 a, b = pop_int(2)
 @stack << (a != b ? 1 : 0) end

def op_return # Marks transaction as invalid.
  @script_invalid = true; nil end

def op_over # Copies the second-to-top stack item to the top.
 item = @stack[-2]
 @stack << item if item end

# If the top stack value is not 0, the statements are executed. The top stack value is removed.
def op_if
 value = false
 if @do_exec
  (invalid; return) if @stack.size < 1
  value = cast_to_bool(pop_string) == false ? false : true end
 @exec_stack << value end

# If the top stack value is 0, the statements are executed. The top stack value is removed.
def op_notif
 value = false
 if @do_exec
  (invalid; return) if @stack.size < 1
  value = cast_to_bool(pop_string) == false ? true : false end
 @exec_stack << value end

# If the preceding OP_IF or OP_NOTIF or OP_ELSE was not executed then these statements are and if the preceding OP_IF or OP_NOTIF or OP_ELSE was executed then these statements are not.
def op_else
 return if @exec_stack.empty?
 @exec_stack[-1] = !@exec_stack[-1] end

def op_endif # Ends an if/else block.
 return if @exec_stack.empty?
 @exec_stack.pop end

def op_pick # The item n back in the stack is copied to the top.
 return invalid if @stack.size < 2
 pos = pop_int
 return invalid if (pos < 0) || (pos >= @stack.size)
 item = @stack[-(pos+1)]
 @stack << item if item end

def op_2rot # The fifth and sixth items back are moved to the top of the stack.
 return invalid if @stack.size < 6
 @stack[-6..-1] = [ *@stack[-4..-1], *@stack[-6..-5] ] end

def op_roll # The item n back in the stack is moved to the top.
 return invalid if @stack.size < 2
 pos = pop_int
 return invalid if (pos < 0) || (pos >= @stack.size)
 idx = -(pos+1)
 item = @stack[idx]
 if item
  @stack.delete_at(idx)
  @stack << item if item end end

def op_rot # The top three items on the stack are rotated to the left.
 return if @stack.size < 3
 @stack[-3..-1] = [ @stack[-2], @stack[-1], @stack[-3] ] end

def op_2drop # Removes the top two stack items.
 @stack.pop(2) end

def op_2dup # Duplicates the top two stack items.
 @stack.push(*@stack[-2..-1]) end

def op_3dup # Duplicates the top three stack items.
 @stack.push(*@stack[-3..-1]) end

def op_nip # Removes the second-to-top stack item.
 @stack.delete_at(-2) end

# Returns the length of the input string.
def op_size
 item = @stack[-1]
 size = case item
  when String; item.bytesize
  when Numeric; OpenSSL::BN.new(item.to_s).to_mpi.size - 4 end
 @stack << size end

# Transaction is invalid unless occuring in an unexecuted OP_IF branch
def op_ver
 invalid if @do_exec end

# Same as OP_NUMEQUAL, but runs OP_VERIFY afterward.
def op_numequalverify
 op_numequal
 op_verify end

# All of the signature checking words will only match signatures
# to the data after the most recently-executed OP_CODESEPARATOR.
def op_codeseparator
 @codehash_start = @chunks.size - @chunks.reverse.index(OP_CODESEPARATOR)
 @last_codeseparator_index = @chunk_last_index end


# Same as OP_CHECKSIG, but OP_VERIFY is executed afterward.
def op_checksigverify(check_callback, opts={})
 op_checksig(check_callback, opts)
 op_verify end

def op_checkmultisig(check_callback, opts={})
 return invalid if @stack.size < 1
 n_pubkeys = pop_int
 return invalid  unless (0..20).include?(n_pubkeys)
 #return invalid  if (nOpCount += n_pubkeys) > 201 # Bitcoin SV removes the limit of 201 opcodes per individual script.
 return invalid if @stack.size < n_pubkeys
 pubkeys = pop_string(n_pubkeys)
 return invalid if @stack.size < 1
 n_sigs = pop_int
 return invalid if n_sigs < 0 || n_sigs > n_pubkeys
 return invalid if @stack.size < n_sigs
 sigs = pop_string(n_sigs)
 drop_sigs = sigs.dup
 # Bitcoin-core removes an extra item from the stack
 @stack.pop
 subscript = sighash_subscript(drop_sigs, opts)
 success = true
 while success && n_sigs > 0
  sig, pub = sigs.pop, pubkeys.pop
  return (@stack << 0) unless Bitcoin::Script.check_pubkey_encoding?(pub, opts)
  return invalid unless Bitcoin::Script.check_signature_encoding?(sig, opts)
  unless sig && sig.size > 0
   success = false
   break end
  signature, hash_type = parse_sig(sig)
  if pub.size > 0 && check_callback.call(pub, signature, hash_type, subscript)
   n_sigs -= 1
  else sigs << sig end
  n_pubkeys -= 1
  success = false if n_sigs > n_pubkeys end
 @stack << (success ? 1 : 0) end

# Same as OP_CHECKMULTISIG, but OP_VERIFY is executed afterward.
def op_checkmultisigverify(check_callback, opts={})
 op_checkmultisig(check_callback, opts)
 op_verify end

OPCODES_METHOD = Hash[*instance_methods.grep(/^op_/).map{|m|
 [ (OPCODES.find{|k,v| v == m.to_s.upcase }.first rescue nil), m ]
  }.flatten]
OPCODES_METHOD[0]  = :op_0
OPCODES_METHOD[81] = :op_1 end