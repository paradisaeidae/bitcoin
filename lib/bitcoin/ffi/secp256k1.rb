# encoding: ascii-8bit
module Bitcoin; module Secp256k1
 extend FFI::Library
 SECP256K1_FLAGS_TYPE_MASK = ((1 << 8) - 1)
 SECP256K1_FLAGS_TYPE_CONTEXT = (1 << 0)
 SECP256K1_FLAGS_TYPE_COMPRESSION = (1 << 1)
 # The higher bits contain the actual data. Do not use directly.
 SECP256K1_FLAGS_BIT_CONTEXT_VERIFY = (1 << 8)
 SECP256K1_FLAGS_BIT_CONTEXT_SIGN = (1 << 9)
 SECP256K1_FLAGS_BIT_COMPRESSION = (1 << 8)
 # Flags to pass to secp256k1_context_create.
 SECP256K1_CONTEXT_VERIFY = (SECP256K1_FLAGS_TYPE_CONTEXT | SECP256K1_FLAGS_BIT_CONTEXT_VERIFY)
 SECP256K1_CONTEXT_SIGN   = (SECP256K1_FLAGS_TYPE_CONTEXT | SECP256K1_FLAGS_BIT_CONTEXT_SIGN)
 # Flag to pass to secp256k1_ec_pubkey_serialize and secp256k1_ec_privkey_export.
 SECP256K1_EC_COMPRESSED = (SECP256K1_FLAGS_TYPE_COMPRESSION | SECP256K1_FLAGS_BIT_COMPRESSION)
 SECP256K1_EC_UNCOMPRESSED = SECP256K1_FLAGS_TYPE_COMPRESSION

 def self.ffi_load_functions(file)
  class_eval <<-RUBY # rubocop:disable Style/EvalWithLocation
  ffi_lib [ %[#{file}] ]
  ##
  # source: https://github.com/bitcoin-core/secp256k1/blob/master/include/secp256k1.h
  ##
  # secp256k1_context* secp256k1_context_create(unsigned int flags)
  attach_function :secp256k1_context_create, [:uint], :pointer
  # void secp256k1_context_destroy(secp256k1_context* ctx)
  attach_function :secp256k1_context_destroy, [:pointer], :void
  # int secp256k1_context_randomize(secp256k1_context* ctx, const unsigned char *seed32)
  attach_function :secp256k1_context_randomize, [:pointer, :pointer], :int
  # int secp256k1_ec_seckey_verify(const secp256k1_context* ctx, const unsigned char *seckey)
  attach_function :secp256k1_ec_seckey_verify, [:pointer, :pointer], :int
  # int secp256k1_ec_pubkey_create(const secp256k1_context* ctx, secp256k1_pubkey *pubkey, const unsigned char *seckey)
  attach_function :secp256k1_ec_pubkey_create, [:pointer, :pointer, :pointer], :int
  # int secp256k1_ec_pubkey_serialize(const secp256k1_context* ctx, unsigned char *output, size_t *outputlen, const secp256k1_pubkey* pubkey, unsigned int flags)
  attach_function :secp256k1_ec_pubkey_serialize, [:pointer, :pointer, :pointer, :pointer, :uint], :int
  # int secp256k1_ecdsa_sign_recoverable(const secp256k1_context* ctx, secp256k1_ecdsa_recoverable_signature *sig, const unsigned char *msg32, const unsigned char *seckey, secp256k1_nonce_function noncefp, const void *ndata)
  # attach_function :secp256k1_ecdsa_sign_recoverable, [:pointer, :pointer, :pointer, :pointer, :pointer, :pointer], :int
  # int secp256k1_ecdsa_recoverable_signature_serialize_compact(const secp256k1_context* ctx, unsigned char *output64, int *recid, const secp256k1_ecdsa_recoverable_signature* sig)
  # attach_function :secp256k1_ecdsa_recoverable_signature_serialize_compact, [:pointer, :pointer, :pointer, :pointer], :int
  # int secp256k1_ecdsa_recoverable_signature_parse_compact(const secp256k1_context* ctx, secp256k1_ecdsa_recoverable_signature* sig, const unsigned char *input64, int recid)
  # attach_function :secp256k1_ecdsa_recoverable_signature_parse_compact, [:pointer, :pointer, :pointer, :int], :int
  # int secp256k1_ecdsa_recover(const secp256k1_context* ctx, secp256k1_pubkey *pubkey, const secp256k1_ecdsa_recoverable_signature *sig, const unsigned char *msg32)
  # attach_function :secp256k1_ecdsa_recover, [:pointer, :pointer, :pointer, :pointer], :int
  # int secp256k1_ecdsa_sign(const secp256k1_context* ctx, secp256k1_ecdsa_signature *sig, const unsigned char *msg32, const unsigned char *seckey, secp256k1_nonce_function noncefp, const void *ndata)
  attach_function :secp256k1_ecdsa_sign, [:pointer, :pointer, :pointer, :pointer, :pointer, :pointer], :int
  # int secp256k1_ecdsa_signature_serialize_der(const secp256k1_context* ctx, unsigned char *output, size_t *outputlen, const secp256k1_ecdsa_signature* sig)
  attach_function :secp256k1_ecdsa_signature_serialize_der, [:pointer, :pointer, :pointer, :pointer], :int
  # int secp256k1_ec_pubkey_parse(const secp256k1_context* ctx, secp256k1_pubkey* pubkey, const unsigned char *input, size_t inputlen)
  attach_function :secp256k1_ec_pubkey_parse, [:pointer, :pointer, :pointer, :size_t], :int
  # int secp256k1_ecdsa_signature_normalize(const secp256k1_context* ctx, secp256k1_ecdsa_signature *sigout, const secp256k1_ecdsa_signature *sigin)
  attach_function :secp256k1_ecdsa_signature_normalize, [:pointer, :pointer, :pointer], :int
  # int secp256k1_ecdsa_verify(const secp256k1_context* ctx, const secp256k1_ecdsa_signature *sig, const unsigned char *msg32, const secp256k1_pubkey *pubkey)
  attach_function :secp256k1_ecdsa_verify, [:pointer, :pointer, :pointer, :pointer], :int
  # int secp256k1_ecdsa_signature_parse_der(const secp256k1_context* ctx, secp256k1_ecdsa_signature* sig, const unsigned char *input, size_t inputlen)
  attach_function :secp256k1_ecdsa_signature_parse_der, [:pointer, :pointer, :pointer, :size_t], :int

  # TODO: add or port
  # # int ecdsa_signature_parse_der_lax(const secp256k1_context* ctx, secp256k1_ecdsa_signature* sig, const unsigned char *input, size_t inputlen)
  # attach_function :ecdsa_signature_parse_der_lax, [:pointer, :pointer, :pointer, :size_t], :int
RUBY
 end

 def self.init
  @loaded ||= false
  return if @loaded
  #lib_path = [ ENV['SECP256K1_LIB_PATH'], 'libsecp256k1.so' ].find { |f| File.exist?(f.to_s) }
  libsecp256 =  File.dirname(__dir__).gsub!('/lib/bitcoin','') + '/lib/libsecp256k1/lib/libsecp256k1.so'
  raise 'Cannot find SECP lib' unless File.exist?(libsecp256)
  puts 'Default Linux install, loading libsecp256 from: ' + libsecp256
  ffi_load_functions(libsecp256)
  @loaded = true
  rescue
  debugger end

 def self.with_context(flags = nil, seed = nil)
  init
  flags ||= (SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
  context = secp256k1_context_create(flags)
  ret = 0
  tries = 0
  max = 20
  while ret != 1
   raise 'secp256k1_context_randomize failed.' if tries >= max
   tries += 1
   ret = secp256k1_context_randomize( context, FFI::MemoryPointer.from_string(seed || SecureRandom.random_bytes(32)) ) end
  yield(context) if block_given?
  ensure secp256k1_context_destroy(context) end

 def self.generate_key_pair(compressed = true)
  with_context do |context|
   ret = 0
   tries = 0
   max = 20
   while ret != 1
    raise 'secp256k1_ec_seckey_verify in generate_key_pair failed.' if tries >= max
    tries += 1
    seckey = FFI::MemoryPointer.new(:uchar, 32).put_bytes(0, SecureRandom.random_bytes(32))
    ret = secp256k1_ec_seckey_verify(context, seckey)  end

   internal_pubkey = FFI::MemoryPointer.new(:uchar, 64)
   result = secp256k1_ec_pubkey_create(context, internal_pubkey, seckey)
   raise 'error creating pubkey' unless result == 1

   pubkey = FFI::MemoryPointer.new(:uchar, 65)
   pubkey_len = FFI::MemoryPointer.new(:uint64)
   result = if compressed
    pubkey_len.put_uint64(0, 33)
    secp256k1_ec_pubkey_serialize( context, pubkey, pubkey_len, internal_pubkey, SECP256K1_EC_COMPRESSED )
    else
     pubkey_len.put_uint64(0, 65)
     secp256k1_ec_pubkey_serialize( context, pubkey, pubkey_len, internal_pubkey, SECP256K1_EC_UNCOMPRESSED ) end
   raise 'error serialize pubkey' unless (result == 1) || pubkey_len.read_uint64 > 0
   [seckey.read_string(32), pubkey.read_string(pubkey_len.read_uint64)] end end

 def self.generate_key(compressed = true)
  priv, pub = generate_key_pair(compressed)
  Bitcoin::Key.new(priv.unpack('H*')[0], pub.unpack('H*')[0]) end

 def self.sign(data, priv_key)
  with_context do |context|
   seckey = FFI::MemoryPointer.new(:uchar, priv_key.bytesize).put_bytes(0, priv_key)
   raise 'priv_key invalid' unless secp256k1_ec_seckey_verify(context, seckey) == 1
   internal_signature = FFI::MemoryPointer.new(:uchar, 64)
   msg32 = FFI::MemoryPointer.new(:uchar, 32).put_bytes(0, data)
   ret = 0
   tries = 0
   max = 20
   while ret != 1
    raise 'secp256k1_ecdsa_sign failed.' if tries >= max
    tries += 1
    ret = secp256k1_ecdsa_sign(context, internal_signature, msg32, seckey, nil, nil) end
   signature     = FFI::MemoryPointer.new(:uchar, 72)
   signature_len = FFI::MemoryPointer.new(:uint64).put_uint64(0, 72)
   result = secp256k1_ecdsa_signature_serialize_der( context, signature, signature_len, internal_signature )
   raise 'secp256k1_ecdsa_signature_serialize_der failed' unless result == 1
   signature.read_string(signature_len.read_uint64) end end

  def self.verify(data, sig, pub_key)
   puts "secp256 verify data: #{data} sig: #{sig.length} pub_key: #{pub_key.length}\n"
   with_context do |context| return false if data.bytesize.zero?

    pubkey = FFI::MemoryPointer.new(:uchar, pub_key.bytesize).put_bytes(0, pub_key)
    internal_pubkey = FFI::MemoryPointer.new(:uchar, 64)
    result = secp256k1_ec_pubkey_parse(context, internal_pubkey, pubkey, pubkey.size)
    return 'pubkey_parse issue' unless result == 1

    signature = FFI::MemoryPointer.new(:uchar, sig.bytesize).put_bytes(0, sig)
    internal_signature = FFI::MemoryPointer.new(:uchar, 64)
    result = secp256k1_ecdsa_signature_parse_der( context, internal_signature, signature, signature.size )
    # result = ecdsa_signature_parse_der_lax( context, internal_signature, signature, signature.size )
    return 'parse_der issue' unless result == 1

    # libsecp256k1's ECDSA verification requires lower-S signatures, which are enforced in Bitcoin, normalize them first.
    secp256k1_ecdsa_signature_normalize(context, internal_signature, internal_signature)

    msg32 = FFI::MemoryPointer.new(:uchar, 32).put_bytes(0, data)
    result = secp256k1_ecdsa_verify(context, internal_signature, msg32, internal_pubkey)

    return result == 1 end end

  def self.normalize(sig)
   with_context do |context| return false if sig.bytesize.zero?
    signature = FFI::MemoryPointer.new(:uchar, sig.bytesize).put_bytes(0, sig)
    secp256k1_ecdsa_signature_normalize(context, signature, signature)
    return signature.read_string end end

 def self.sign_compact(message, priv_key, compressed = true) # DEPRECATABLE
  with_context do |context|
   seckey = FFI::MemoryPointer.new(:uchar, priv_key.bytesize).put_bytes(0, priv_key)
   raise 'priv_key invalid' unless secp256k1_ec_seckey_verify(context, seckey) == 1
   msg32 = FFI::MemoryPointer.new(:uchar, 32).put_bytes(0, message)
   internal_recoverable_signature = FFI::MemoryPointer.new(:uchar, 65)
   rec_id = FFI::MemoryPointer.new(:int).put_int(0, -1)
   ret = 0
   tries = 0
   max = 20
   while ret != 1
    raise 'secp256k1_ecdsa_sign_recoverable failed.' if tries >= max
    tries += 1
    ret = secp256k1_ecdsa_sign_recoverable( context, internal_recoverable_signature, msg32, seckey, nil, nil ) end
   recoverable_signature = FFI::MemoryPointer.new(:uchar, 64)
   result = secp256k1_ecdsa_recoverable_signature_serialize_compact(context, recoverable_signature, rec_id, internal_recoverable_signature )
   error_str = 'secp256k1_ecdsa_recoverable_signature_serialize_compact failed'
   raise error_str unless result == 1
   raise error_str unless rec_id.read_int != -1
   header = [27 + rec_id.read_int + (compressed ? 4 : 0)].pack('C')
   [header, recoverable_signature.read_string(64)].join end end

 def self.recover_compact(message, signature) # DEPRECATABLE
  with_context do |context| return nil if signature.bytesize != 65
   version = signature.unpack('C')[0]
   return nil if version < 27 || version > 34

   compressed = version >= 31
   flag = compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED
   version -= 4 if compressed

   recid = version - 27
   msg32 = FFI::MemoryPointer.new(:uchar, 32).put_bytes(0, message)
   recoverable_signature = FFI::MemoryPointer.new(:uchar, 64).put_bytes(0, signature[1..-1])

   internal_recoverable_signature = FFI::MemoryPointer.new(:uchar, 65)
   result = secp256k1_ecdsa_recoverable_signature_parse_compact( context, internal_recoverable_signature, recoverable_signature, recid )
   return nil unless result == 1

   internal_pubkey = FFI::MemoryPointer.new(:uchar, 64)
   result = secp256k1_ecdsa_recover( context, internal_pubkey, internal_recoverable_signature, msg32 )
   return nil unless result == 1

   pubkey = FFI::MemoryPointer.new(:uchar, 65)
   pubkey_len = FFI::MemoryPointer.new(:uint64).put_uint64(0, 65)
   result = secp256k1_ec_pubkey_serialize(context, pubkey, pubkey_len, internal_pubkey, flag)
   raise 'error serialize pubkey' unless (result == 1) || pubkey_len.read_uint64 > 0

   pubkey.read_string(pubkey_len.read_uint64) end end end end


=begin bindings for secp256k1 inside bitcoin (https://github.com/bitcoin-core/secp256k1)
 wget https://github.com/bitcoin-core/secp256k1/archive/refs/tags/v0.4.0.tar.gz
 tar -zxvf v0.4.0.tar.gz
 cd secp256k1-0.4.0
 ./autogen.sh
 ./configure --enable-module-recovery
 nm -D .libs/libsecp256k1.so | grep secp
 export SECP256K1_LIB_PATH=/path/to/bitcoin/src/secp256k1/.libs/libsecp256k1.so.2.0.1
context_clone
context_create
context_destroy
context_no_precomp
context_preallocated_clone
context_preallocated_clone_size
context_preallocated_create
context_preallocated_destroy
context_preallocated_size
context_randomize
context_set_error_callback
context_set_illegal_callback
context_static
ecdh
ecdh_hash_function_default
ecdh_hash_function_sha256
ecdsa_sign
ecdsa_signature_normalize
ecdsa_signature_parse_compact
ecdsa_signature_parse_der
ecdsa_signature_serialize_compact
ecdsa_signature_serialize_der
ecdsa_verify
ec_privkey_negate
ec_privkey_tweak_add
ec_privkey_tweak_mul
ec_pubkey_cmp
ec_pubkey_combine
ec_pubkey_create
ec_pubkey_negate
ec_pubkey_parse
ec_pubkey_serialize
ec_pubkey_tweak_add
ec_pubkey_tweak_mul
ec_seckey_negate
ec_seckey_tweak_add
ec_seckey_tweak_mul
ec_seckey_verify
keypair_create
keypair_pub
keypair_sec
keypair_xonly_pub
keypair_xonly_tweak_add
nonce_function_bip340
nonce_function_default
nonce_function_rfc6979
schnorrsig_sign
schnorrsig_sign32
schnorrsig_sign_custom
schnorrsig_verify
scratch_space_create
scratch_space_destroy
selftest
tagged_sha256
xonly_pubkey_cmp
xonly_pubkey_from_pubkey
xonly_pubkey_parse
xonly_pubkey_serialize
xonly_pubkey_tweak_add
xonly_pubkey_tweak_add_check
=end
