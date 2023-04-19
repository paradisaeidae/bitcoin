puts "ffi required: #{require 'ffi'}"
module Bitcoin
# binding for src/.libs/bitcoinconsensus.so (https://github.com/bitcoin-sv/bitcoin-sv)
# tag: v0.11.0
module BitcoinConsensus
SCRIPT_VERIFY_NONE      = 0
SCRIPT_VERIFY_STRICTENC = (1 << 1)
SCRIPT_VERIFY_DERSIG    = (1 << 2)
SCRIPT_VERIFY_LOW_S     = (1 << 3)
SCRIPT_VERIFY_NULLDUMMY = (1 << 4)
SCRIPT_VERIFY_SIGPUSHONLY = (1 << 5)
SCRIPT_VERIFY_MINIMALDATA = (1 << 6)
SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS = (1 << 7)
SCRIPT_VERIFY_CLEANSTACK = (1 << 8)
ERR_CODES = { 0 => :ok, 1 => :tx_index, 2 => :tx_size_mismatch, 3 => :tx_deserialize }.freeze
extend FFI::Library

def self.ffi_load_functions(file)
 class_eval <<~CONSENSUS
  ffi_lib_flags :now, :global
  ffi_lib [ %[#{file}] ]
  attach_function :bitcoinconsensus_version, [], :uint
  # int bitcoinconsensus_verify_script(const unsigned char *scriptPubKey, unsigned int scriptPubKeyLen,
  #                                    const unsigned char *txTo        , unsigned int txToLen,
  #                                    unsigned int nIn, unsigned int flags, bitcoinconsensus_error* err);
  attach_function :bitcoinconsensus_verify_script, [:pointer, :uint, :pointer, :uint, :uint, :uint, :pointer], :int
CONSENSUS
 rescue => badThing
  debugger
 end

def self.lib_available?   # rubocop:disable Naming/MemoizedInstanceVariableName
 @__lib_path = ENV['BITCOINCONSENSUS_LIB_PATH'] + 'libbitcoinconsensus.so'
 puts "Looking for libbitcoinconsensus.so here: #{@__lib_path}"
 File.exist?(@__lib_path.to_s)
 @__lib_path.to_s end

def self.init
 return if @bitcoin_consensus
 lib_path = lib_available?
 ffi_load_functions(lib_path)
 @bitcoin_consensus = true end

def self.version # api version
 init
 bitcoinconsensus_version end

def self.verify_script(input_index, script_pubkey, tx_payload, script_flags)
 init
 script_pub_key = FFI::MemoryPointer.new( :uchar, script_pubkey.bytesize ).put_bytes(0, script_pubkey)
 tx_to = FFI::MemoryPointer.new(:uchar, tx_payload.bytesize).put_bytes(0, tx_payload)
 error_ret = FFI::MemoryPointer.new(:uint)
 ret = bitcoinconsensus_verify_script(
  script_pub_key, script_pub_key.size, tx_to, tx_to.size, input_index, script_flags, error_ret)
 case ret
 when 0
  false
 when 1
  ERR_CODES[error_ret.read_int] == :ok
 else raise 'error invalid result' end end end end

=begin
# https://github.com/bitcoin-sv/bitcoin-sv
# https://bitcoinsv.io/documentation/miners/installation/bitcoind/export
# /k1.io/BSV/current/bin/bitcoind -conf=/k1.io/BSV/bitcoin-data/bitcoin.conf -datadir=/k1.io/BSV/bitcoin-da>
BCvers=$1
#export SSL_LIBS=-L/k1.io/dependencies/OPENSSL/current
#export PKG_CONFIG_PATH=/k1.io/dependencies/OPENSSL/current
#export PKG_CONFIG_PATH=/k1.io/BSV/BUILD/openssl
#export SSL_LIBS=/k1.io/BSV/BUILD/openssl
#export SSL_LIBS=/k0.io/dependencies/OPENSSL/1.1.1i/
# apt-get install libboost-all-dev
#export PATH=$PATH:/k0.io/dependencies/OPENSSL/1.1.1n/
#export LD_LIBRARY_PATH=/k0.io/BSV/BUILD/openssl/lib
#export PATH=$PATH:/k0.io/BSV/BUILD/openssl/lib
#export PATH=$PATH:/k0.io/BSV/BUILD/openssl/
export OPENSSL_LIBS=/k0.io/dependencies/OPENSSL/3.1.0
 #/k1.io/BSV/BUILD/openssl/ #  https://stackoverflow.com/questions/4352573/linking-openssl-libraries-to-a-p>
export PKG_CONFIG_PATH=$PKG_CONFIG_PATH:/k0.io/dependencies/OPENSSL/3.1.0/lib/pkgconfig/

        linux-vdso.so.1 (0x00007ffeb11ea000)
        librt.so.1 => /lib/x86_64-linux-gnu/librt.so.1 (0x00007f8d8b923000)
        libstdc++.so.6 => /lib/x86_64-linux-gnu/libstdc++.so.6 (0x00007f8d8b1d6000)
        libm.so.6 => /lib/x86_64-linux-gnu/libm.so.6 (0x00007f8d8b0ef000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f8d8aec7000)
        libgcc_s.so.1 => /lib/x86_64-linux-gnu/libgcc_s.so.1 (0x00007f8d8b903000)
        /lib64/ld-linux-x86-64.so.2 (0x00007f8d8b939000)
=end