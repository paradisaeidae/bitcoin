# frozen_string_literal: true
require 'spec_helper'

describe Bitcoin::Protocol::Tx do
 let(:payloads) do [
  fixtures_file('rawtx-01.bin'),
  fixtures_file('rawtx-02.bin'),
  fixtures_file('rawtx-03.bin') ] end # p2wpkh deleted
 let(:json) do  [
  fixtures_file('rawtx-01.json'),
  fixtures_file('rawtx-02.json'),
  fixtures_file('rawtx-03.json')] end # p2wpkh deleted

  describe '#new' do
    it 'does not raise an error for valid payloads' do
     Bitcoin::Protocol::Tx.new(nil)
     payloads.each { |payload| Bitcoin::Protocol::Tx.new(payload) } end

    it 'raises an error for an invalid payload' do
     expect do
      Bitcoin::Protocol::Tx.new(payloads[0][0..20])
     end.to raise_error(NoMethodError, /undefined method `unpack'/) end

    it 'correctly deserializes a new, empty transaction' do
      Bitcoin::Protocol::Tx.new(Bitcoin::Protocol::Tx.new.to_payload) end end

  describe '#parse_data' do
   let(:tx) { Bitcoin::Protocol::Tx.new(nil) }

    it 'correctly parses payloads' do
     expect(tx.hash).to be_nil
     expect(tx.parse_data(payloads[0])).to be true
     expect(tx.hash.size).to eq(64)
     expect(tx.payload).to eq(payloads[0]) end

    it 'parses additional payload data' do
     expect(tx.parse_data(payloads[0] + 'AAAA')).to eq('AAAA')
     expect(tx.hash.size).to eq(64)
     expect(tx.payload).to eq(payloads[0]) end end

  describe '#hash' do
   it 'produces the expected hash and binary hash' do
    tx = Bitcoin::Protocol::Tx.new(payloads[0])
    expect(tx.hash.size).to eq(64)
    expect(tx.hash)
      .to eq('6e9dd16625b62cfcd4bf02edb89ca1f5a8c30c4b1601507090fb28e59f2d02b4')
    expect(tx.binary_hash)
      .to eq("\xB4\x02-\x9F\xE5(\xFB\x90pP\x01\x16K\f\xC3\xA8\xF5\xA1\x9C" \
             "\xB8\xED\x02\xBF\xD4\xFC,\xB6%f\xD1\x9Dn")
    tx = Bitcoin::Protocol::Tx.new(payloads[3])
    expect(tx.hash.size).to eq(64)
    expect(tx.hash)
     .to eq('f22f5168cf0bc55a31003b0fc532152da551e1ec4289c4fd92e7ec512c6e87a0') end end

  describe '#witness_hash' do
   it 'produces the expected witness hash' do
    tx = Bitcoin::Protocol::Tx.new(payloads[3])
    expect(tx.witness_hash.size).to eq(64)
    expect(tx.witness_hash)
     .to eq('c9609ed4d7e60ebcf4cce2854568b54a855a12b5bda15433ca96e72cd445a5cf') end end

  describe '#normalized_hash' do
   it 'produces the expected normalized hash' do
    tx = Bitcoin::Protocol::Tx.new(payloads[0])
    expect(tx.normalized_hash.size).to eq(64)
    expect(tx.normalized_hash)
      .to eq('393a12b91d5b5e2449f2d27a22ffc0af937c3796a08c8213cc37690b10302e40')
    new_tx = JSON.parse(tx.to_json)
    script = Bitcoin::Script.from_string(new_tx['in'][0]['scriptSig'])
    script.chunks[0].bitcoin_pushdata = Bitcoin::Script::OP_PUSHDATA2
    script.chunks[0].bitcoin_pushdata_length = script.chunks[0].bytesize
    new_tx['in'][0]['scriptSig'] = script.to_string
    new_tx = Bitcoin::Protocol::Tx.from_hasH(new_tx, false)
    expect(new_tx.hash).not_to eq(tx.hash)
    expect(new_tx.normalized_hash.size).to eq(64)
    expect(new_tx.normalized_hash)
      .to eq('393a12b91d5b5e2449f2d27a22ffc0af937c3796a08c8213cc37690b10302e40') end end

  describe '#to_payload' do
   it 'produces the expected payloads' do
    tx = Bitcoin::Protocol::Tx.new(payloads[0])
    expect(tx.to_payload.size).to eq(payloads[0].size)
    expect(tx.to_payload).to eq(payloads[0]) end end

  describe '#to_witness_payload' do
   it 'produces the expected payloads' do
    tx = Bitcoin::Protocol::Tx.new(payloads[3])
    expect(tx.to_witness_payload.size).to eq(payloads[3].size)
    expect(tx.to_witness_payload).to eq(payloads[3]) end end

  it '#to_hash' do
    tx = Bitcoin::Protocol::Tx.new(payloads[0])
    expect(tx.to_hasH.keys)
      .to eq(%w[hash ver vin_sz vout_sz lock_time size in out])

    # witness tx
    tx = Bitcoin::Protocol::Tx.new(payloads[3])
    expect(tx.to_hasH.keys)
      .to eq(%w[hash ver vin_sz vout_sz lock_time size in out]) end

  it '.from_hasH' do
    orig_tx = Bitcoin::Protocol::Tx.new(payloads[0])
    tx = Bitcoin::Protocol::Tx.from_hasH(orig_tx.to_hasH)
    expect(tx.payload).to eq(payloads[0])
    expect(tx.to_payload.size).to eq(payloads[0].size)
    expect(tx.to_payload).to eq(payloads[0])
    expect(tx.to_hasH).to eq(orig_tx.to_hasH)
    expect(Bitcoin::Protocol::Tx.binary_from_hasH(orig_tx.to_hasH))
      .to eq(payloads[0])

    h = orig_tx.to_hasH.merge('ver' => 123)
    expect do
      Bitcoin::Protocol::Tx.from_hasH(h) end.to raise_error(Exception,
                       'Tx hash mismatch! Claimed: ' \
                       '6e9dd16625b62cfcd4bf02edb89ca1f5a8c30c4b1601507090fb2' \
                       '8e59f2d02b4, Actual: 395cd28c334ac84ed125ec5ccd5bc29ea' \
                       'dcc96b79c337d0a87a19df64ea3b548') end   # witness tx(P2WPKH) deleted

  it '.binary_from_hash' do
    orig_tx = Bitcoin::Protocol::Tx.new(payloads[0])
    expect(Bitcoin::Protocol::Tx.binary_from_hasH(orig_tx.to_hasH).size).to eq(payloads[0].size)
    expect(Bitcoin::Protocol::Tx.binary_from_hasH(orig_tx.to_hasH)).to eq(payloads[0])

    orig_tx = Bitcoin::Protocol::Tx.new(payloads[3])
    expect(Bitcoin::Protocol::Tx.binary_from_hasH(orig_tx.to_hasH).size).to eq(payloads[3].size)
    expect(Bitcoin::Protocol::Tx.binary_from_hasH(orig_tx.to_hasH)).to eq(payloads[3]) end

  it '#to_json' do
    tx = Bitcoin::Protocol::Tx.new(payloads[0])
    expect(tx.to_json).to eq(json[0])

    tx = Bitcoin::Protocol::Tx.new(payloads[1])
    expect(tx.to_json).to eq(json[1])

    tx = Bitcoin::Protocol::Tx.new(payloads[2])
    expect(tx.to_json).to eq(json[2])

    tx = Bitcoin::Protocol::Tx.new(
      fixtures_file('rawtx-2f4a2717ec8c9f077a87dde6cbe0274d5238793a3f3f492b63c744837285e58a.bin') )
    expect(tx.to_json)
      .to eq(fixtures_file(
               'rawtx-2f4a2717ec8c9f077a87dde6cbe0274d5238793a3f3f492b63c744837285e58a.json' ))

    tx = Bitcoin::Protocol::Tx.new(payloads[3])
    expect(tx.to_json).to eq(json[3]) end

  it '.from_json' do
    json_string = fixtures_file(
      'rawtx-2f4a2717ec8c9f077a87dde6cbe0274d5238793a3f3f492b63c744837285e58a.json' )
    tx = Bitcoin::Protocol::Tx.from_json(json_string)
    expect(tx.to_json).to eq(json_string)

    json_string = fixtures_file(
      'rawtx-testnet-a220adf1902c46a39db25a24bc4178b6a88440f977a7e2cabfdd8b5c1dd35cfb.json' )
    tx = Bitcoin::Protocol::Tx.from_json(json_string)
    expect(tx.to_json).to eq(json_string)

    json_string = fixtures_file(
      'rawtx-testnet-e232e0055dbdca88bbaa79458683195a0b7c17c5b6c524a8d146721d4d4d652f.json' )
    binary_string = fixtures_file(
      'rawtx-testnet-e232e0055dbdca88bbaa79458683195a0b7c17c5b6c524a8d146721d4d4d652f.bin' )
    tx = Bitcoin::Protocol::Tx.from_json(json_string)
    expect(tx.to_payload).to eq(binary_string)
    expect(tx.to_json).to eq(json_string)

    tx = Bitcoin::Protocol::Tx.from_json(
      fixtures_file(
        'rawtx-ba1ff5cd66713133c062a871a8adab92416f1e38d17786b2bf56ac5f6ffdfdf5.json' ) )
    expect(Bitcoin::Protocol::Tx.new(tx.to_payload).to_json)
      .to eq(tx.to_json)
    expect(tx.hash)
      .to eq('ba1ff5cd66713133c062a871a8adab92416f1e38d17786b2bf56ac5f6ffdfdf5')

    # coinbase tx with non-default sequence
    json_string = fixtures_file(
      '0961c660358478829505e16a1f028757e54b5bbf9758341a7546573738f31429.json' )
    tx = Bitcoin::Protocol::Tx.from_json(json_string)
    expect(Bitcoin::Protocol::Tx.new(tx.to_payload).to_json).to eq(json_string) end

  it '.binary_from_json' do
    json_string = fixtures_file(
      'rawtx-2f4a2717ec8c9f077a87dde6cbe0274d5238793a3f3f492b63c744837285e58a.json' )
    binary_string = fixtures_file(
      'rawtx-2f4a2717ec8c9f077a87dde6cbe0274d5238793a3f3f492b63c744837285e58a.bin' )
    expect(Bitcoin::Protocol::Tx.binary_from_json(json_string))
      .to eq(binary_string) end

  describe '.compare_big_endian' do
    it 'compares arrays of bytes' do
      # This function is used in validating an ECDSA signature's S value
      c1 = [];  c2 = []
      expect(Bitcoin::Script.compare_big_endian(c1, c2)).to eq(0)
      c1 = [0]; c2 = []
      expect(Bitcoin::Script.compare_big_endian(c1, c2)).to eq(0)
      c1 = [];  c2 = [0]
      expect(Bitcoin::Script.compare_big_endian(c1, c2)).to eq(0)
      c1 = [5]; c2 = [5]
      expect(Bitcoin::Script.compare_big_endian(c1, c2)).to eq(0)
      c1 = [4]; c2 = [5]
      expect(Bitcoin::Script.compare_big_endian(c1, c2)).to eq(-1)
      c1 = [4]; c2 = [5]
      expect(Bitcoin::Script.compare_big_endian(c1, c2)).to eq(-1)
      c1 = [5]; c2 = [4]
      expect(Bitcoin::Script.compare_big_endian(c1, c2)).to eq(1)
      c1 = [5]; c2 = [4]
      expect(Bitcoin::Script.compare_big_endian(c1, c2)).to eq(1) end end

  describe '.is_der_signature?' do
    it 'validates ECDSA signature format' do
      # TX 3da75972766f0ad13319b0b461fd16823a731e44f6e9de4eb3c52d6a6fb6c8ae
      sig_orig = [
        '304502210088984573e3e4f33db7df6aea313f1ce67a3ef3532ea89991494c7f0182' \
        '58371802206ceefc9291450dbd40d834f249658e0f64662d52a41cf14e20c9781144' \
        'f2fe0701'
      ].pack('H*')
      expect(Bitcoin::Script.is_der_signature?(sig_orig)).to be true
      expect(Bitcoin::Script.is_defined_hashtype_signature?(sig_orig)).to be true

      # Trimmed to be too short
      sig = sig_orig.slice(0, 8)
      expect(Bitcoin::Script.is_der_signature?(sig)).to be false

      # Zero-padded to be too long
      sig = String.new(sig_orig)
      sig << 0x00
      sig << 0x00
      expect(Bitcoin::Script.is_der_signature?(sig)).to be false

      # Wrong first byte
      sig_bytes = sig_orig.unpack('C*')
      sig_bytes[0] = 0x20
      sig = sig_bytes.pack('C*')
      expect(Bitcoin::Script.is_der_signature?(sig)).to be false

      # Length byte broken
      sig_bytes = sig_orig.unpack('C*')
      sig_bytes[1] = 0x20
      sig = sig_bytes.pack('C*')
      expect(Bitcoin::Script.is_der_signature?(sig)).to be false

      # Incorrect R value type
      sig_bytes = sig_orig.unpack('C*')
      sig_bytes[2] = 0x03
      sig = sig_bytes.pack('C*')
      expect(Bitcoin::Script.is_der_signature?(sig)).to be false

      # R value length infeasibly long
      sig_bytes = sig_orig.unpack('C*')
      sig_bytes[3] = sig_orig.size - 4
      sig = sig_bytes.pack('C*')
      expect(Bitcoin::Script.is_der_signature?(sig)).to be false

      # Negative R value
      sig_bytes = sig_orig.unpack('C*')
      sig_bytes[4] = 0x80 | sig_bytes[4]
      sig = sig_bytes.pack('C*')
      expect(Bitcoin::Script.is_der_signature?(sig)).to be false

      # R value excessively padded
      sig_bytes = sig_orig.unpack('C*')
      sig_bytes[5] = 0x00
      sig = sig_bytes.pack('C*')
      expect(Bitcoin::Script.is_der_signature?(sig)).to be false

      # Incorrect S value type
      sig_bytes = sig_orig.unpack('C*')
      sig_bytes[37] = 0x03
      sig = sig_bytes.pack('C*')
      expect(Bitcoin::Script.is_der_signature?(sig)).to be false

      # Zero S length
      sig_bytes = sig_orig.unpack('C*')
      sig_bytes[38] = 0x00
      sig = sig_bytes.pack('C*')
      expect(Bitcoin::Script.is_der_signature?(sig)).to be false

      # Negative S value
      sig_bytes = sig_orig.unpack('C*')
      sig_bytes[39] = 0x80 | sig_bytes[39]
      sig = sig_bytes.pack('C*')
      expect(Bitcoin::Script.is_der_signature?(sig)).to be false end end

  it '#verify_input_signature' do
    # transaction-2 of block-170
    tx = Bitcoin::Protocol::Tx.new(
      fixtures_file(
        'rawtx-f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16.bin' ) )
    expect(tx.hash)
      .to eq('f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16')

    # transaction-1 (coinbase) of block-9
    outpoint_tx = Bitcoin::Protocol::Tx.new(
      fixtures_file(
        'rawtx-0437cd7f8525ceed2324359c2d0ba26006d92d856a9c20fa0241106ee5a597c9.bin' ) )
    expect(outpoint_tx.hash)
      .to eq('0437cd7f8525ceed2324359c2d0ba26006d92d856a9c20fa0241106ee5a597c9')

    expect(tx.verify_input_signature(0, outpoint_tx)).to be true

    # Only one test where we provide the TxOut is needed since when providing
    # the full outpoint_tx the verification logic doesn't change.
    expect(tx.verify_input_signature(0, outpoint_tx.out[0])).to be true

    tx = Bitcoin::Protocol::Tx.from_json(
      fixtures_file(
        'rawtx-c99c49da4c38af669dea436d3e73780dfdb6c1ecf9958baa52960e8baee30e73.json' ) )
    expect(tx.hash)
      .to eq('c99c49da4c38af669dea436d3e73780dfdb6c1ecf9958baa52960e8baee30e73')

    outpoint_tx = Bitcoin::Protocol::Tx.from_json(
      fixtures_file(
        'rawtx-406b2b06bcd34d3c8733e6b79f7a394c8a431fbf4ff5ac705c93f4076bb77602.json' ) )
    expect(outpoint_tx.hash)
      .to eq('406b2b06bcd34d3c8733e6b79f7a394c8a431fbf4ff5ac705c93f4076bb77602')
    expect(tx.verify_input_signature(0, outpoint_tx)).to be true

    tx = Bitcoin::Protocol::Tx.from_json(
      fixtures_file(
        '0f24294a1d23efbb49c1765cf443fba7930702752aba6d765870082fe4f13cae.json' ) )
    expect(tx.hash)
      .to eq('0f24294a1d23efbb49c1765cf443fba7930702752aba6d765870082fe4f13cae')
    outpoint_tx = Bitcoin::Protocol::Tx.from_json(
      fixtures_file(
        'aea682d68a3ea5e3583e088dcbd699a5d44d4b083f02ad0aaf2598fe1fa4dfd4.json' ) )
    expect(outpoint_tx.hash)
      .to eq('aea682d68a3ea5e3583e088dcbd699a5d44d4b083f02ad0aaf2598fe1fa4dfd4')
    expect(tx.verify_input_signature(0, outpoint_tx)).to be true

    # SIGHASH_ANYONECANPAY transaction
    tx = Bitcoin::Protocol::Tx.from_json(
      fixtures_file(
        '51bf528ecf3c161e7c021224197dbe84f9a8564212f6207baa014c01a1668e1e.json' ) )
    expect(tx.hash)
      .to eq('51bf528ecf3c161e7c021224197dbe84f9a8564212f6207baa014c01a1668e1e')
    outpoint_tx = Bitcoin::Protocol::Tx.from_json(
      fixtures_file(
        '761d8c5210fdfd505f6dff38f740ae3728eb93d7d0971fb433f685d40a4c04f6.json' ) )
    expect(outpoint_tx.hash)
      .to eq('761d8c5210fdfd505f6dff38f740ae3728eb93d7d0971fb433f685d40a4c04f6')
    expect(tx.verify_input_signature(0, outpoint_tx)).to be true

    # BIP12/OP_EVAL does't exist.
    tx = Bitcoin::Protocol::Tx.from_json(
      fixtures_file(
        '03d7e1fa4d5fefa169431f24f7798552861b255cd55d377066fedcd088fb0e99.json' ) )
    expect(tx.hash)
      .to eq('03d7e1fa4d5fefa169431f24f7798552861b255cd55d377066fedcd088fb0e99')
    outpoint_tx = Bitcoin::Protocol::Tx.from_json(
      fixtures_file(
        'f003f0c1193019db2497a675fd05d9f2edddf9b67c59e677c48d3dbd4ed5f00b.json' ) )
    expect(outpoint_tx.hash)
      .to eq('f003f0c1193019db2497a675fd05d9f2edddf9b67c59e677c48d3dbd4ed5f00b')
    expect(tx.verify_input_signature(0, outpoint_tx)).to be true

    # (SIGHASH_ANYONECANPAY | SIGHASH_SINGLE) p2sh transaction
    tx = Bitcoin::Protocol::Tx.from_json(
      fixtures_file(
        '7208e5edf525f04e705fb3390194e316205b8f995c8c9fcd8c6093abe04fa27d.json' ) )
    expect(tx.hash)
      .to eq('7208e5edf525f04e705fb3390194e316205b8f995c8c9fcd8c6093abe04fa27d')
    outpoint_tx = Bitcoin::Protocol::Tx.from_json(
      fixtures_file(
        '3e58b7eed0fdb599019af08578effea25c8666bbe8e200845453cacce6314477.json' ) )
    expect(outpoint_tx.hash)
      .to eq('3e58b7eed0fdb599019af08578effea25c8666bbe8e200845453cacce6314477')
    expect(tx.verify_input_signature(0, outpoint_tx)).to be true

    # SIGHHASH_SINGLE - https://bitcointalk.org/index.php?topic=260595.0
    tx = Bitcoin::Protocol::Tx.from_json(
      fixtures_file(
        '315ac7d4c26d69668129cc352851d9389b4a6868f1509c6c8b66bead11e2619f.json' ) )
    expect(tx.hash)
      .to eq('315ac7d4c26d69668129cc352851d9389b4a6868f1509c6c8b66bead11e2619f')
    outpoint_tx = Bitcoin::Protocol::Tx.from_json(
      fixtures_file(
        '69216b8aaa35b76d6613e5f527f4858640d986e1046238583bdad79b35e938dc.json' ) )
    expect(outpoint_tx.hash)
      .to eq('69216b8aaa35b76d6613e5f527f4858640d986e1046238583bdad79b35e938dc')
    expect(tx.verify_input_signature(0, outpoint_tx)).to be true
    expect(tx.verify_input_signature(1, outpoint_tx)).to be true

    # 0:1:01 <signature> 0:1:01 0:1:00 <pubkey> OP_SWAP OP_1ADD OP_CHECKMULTISIG
    tx = Bitcoin::Protocol::Tx.from_json(
      fixtures_file(
        'cd874fa8cb0e2ec2d385735d5e1fd482c4fe648533efb4c50ee53bda58e15ae2.json' ) )
    expect(tx.hash)
      .to eq('cd874fa8cb0e2ec2d385735d5e1fd482c4fe648533efb4c50ee53bda58e15ae2')
    outpoint_tx = Bitcoin::Protocol::Tx.from_json(
      fixtures_file(
        '514c46f0b61714092f15c8dfcb576c9f79b3f959989b98de3944b19d98832b58.json' ) )
    expect(outpoint_tx.hash)
      .to eq('514c46f0b61714092f15c8dfcb576c9f79b3f959989b98de3944b19d98832b58')
    expect(tx.verify_input_signature(0, outpoint_tx)).to be true

    # OP_CHECKSIG with OP_0 from mainnet
    # a6ce7081addade7676cd2af75c4129eba6bf5e179a19c40c7d4cf6a5fe595954 output 0
    tx = Bitcoin::Protocol::Tx.from_json(
      fixtures_file(
        'tx-9fb65b7304aaa77ac9580823c2c06b259cc42591e5cce66d76a81b6f51cc5c28.json' ) )
    expect(tx.hash)
      .to eq('9fb65b7304aaa77ac9580823c2c06b259cc42591e5cce66d76a81b6f51cc5c28')
    outpoint_tx = Bitcoin::Protocol::Tx.from_json(
      fixtures_file(
        'tx-a6ce7081addade7676cd2af75c4129eba6bf5e179a19c40c7d4cf6a5fe595954.json' ) )
    expect(outpoint_tx.hash)
      .to eq('a6ce7081addade7676cd2af75c4129eba6bf5e179a19c40c7d4cf6a5fe595954')
    expect(tx.verify_input_signature(0, outpoint_tx)).to be true

    # drop OP_CODESEPARATOR in subscript for signature_hash_for_inputs
    tx = Bitcoin::Protocol::Tx.from_json(
      fixtures_file(
        'tx-46224764c7870f95b58f155bce1e38d4da8e99d42dbb632d0dd7c07e092ee5aa.json' ) )
    expect(tx.hash)
      .to eq('46224764c7870f95b58f155bce1e38d4da8e99d42dbb632d0dd7c07e092ee5aa')
    outpoint_tx = Bitcoin::Protocol::Tx.from_json(
      fixtures_file(
        'tx-bc7fd132fcf817918334822ee6d9bd95c889099c96e07ca2c1eb2cc70db63224.json' ) )
    expect(outpoint_tx.hash)
      .to eq('bc7fd132fcf817918334822ee6d9bd95c889099c96e07ca2c1eb2cc70db63224')
    expect(tx.verify_input_signature(0, outpoint_tx)).to be true

    # drop OP_CODESEPARATOR in subscript for signature_hash_for_inputs
    tx = Bitcoin::Protocol::Tx.from_json(
      fixtures_file(
        'tx-aab7ef280abbb9cc6fbaf524d2645c3daf4fcca2b3f53370e618d9cedf65f1f8.json' ) )
    expect(tx.hash)
      .to eq('aab7ef280abbb9cc6fbaf524d2645c3daf4fcca2b3f53370e618d9cedf65f1f8')
    outpoint_tx = Bitcoin::Protocol::Tx.from_json(
      fixtures_file(
        'tx-326882a7f22b5191f1a0cc9962ca4b878cd969cf3b3a70887aece4d801a0ba5e.json' ) )
    expect(outpoint_tx.hash)
      .to eq('326882a7f22b5191f1a0cc9962ca4b878cd969cf3b3a70887aece4d801a0ba5e')
    expect(tx.verify_input_signature(0, outpoint_tx)).to be true

    # drop multisig OP_CODESEPARATOR in subscript for signature_hash_for_inputs
    tx = Bitcoin::Protocol::Tx.from_json(
      fixtures_file(
        'tx-6327783a064d4e350c454ad5cd90201aedf65b1fc524e73709c52f0163739190.json' ) )
    expect(tx.hash)
      .to eq('6327783a064d4e350c454ad5cd90201aedf65b1fc524e73709c52f0163739190')
    outpoint_tx = Bitcoin::Protocol::Tx.from_json(
      fixtures_file(
        'tx-a955032f4d6b0c9bfe8cad8f00a8933790b9c1dc28c82e0f48e75b35da0e4944.json' ) )
    expect(outpoint_tx.hash)
      .to eq('a955032f4d6b0c9bfe8cad8f00a8933790b9c1dc28c82e0f48e75b35da0e4944')
    expect(tx.verify_input_signature(0, outpoint_tx)).to be true

    # drop multisig OP_CODESEPARATOR in subscript for signature_hash_for_inputs
    # when used in ScriptSig
    tx = Bitcoin::Protocol::Tx.from_json(
      fixtures_file(
        'tx-eb3b82c0884e3efa6d8b0be55b4915eb20be124c9766245bcc7f34fdac32bccb.json' ) )
    expect(tx.hash)
      .to eq('eb3b82c0884e3efa6d8b0be55b4915eb20be124c9766245bcc7f34fdac32bccb')
    outpoint_tx = Bitcoin::Protocol::Tx.from_json(
      fixtures_file(
        'tx-b8fd633e7713a43d5ac87266adc78444669b987a56b3a65fb92d58c2c4b0e84d.json' ) )
    expect(outpoint_tx.hash)
      .to eq('b8fd633e7713a43d5ac87266adc78444669b987a56b3a65fb92d58c2c4b0e84d')
    expect(tx.verify_input_signature(1, outpoint_tx)).to be true

    # OP_DUP OP_HASH160
    tx = Bitcoin::Protocol::Tx.from_json(
      fixtures_file(
        'tx-5df1375ffe61ac35ca178ebb0cab9ea26dedbd0e96005dfcee7e379fa513232f.json' ) )
    expect(tx.hash)
      .to eq('5df1375ffe61ac35ca178ebb0cab9ea26dedbd0e96005dfcee7e379fa513232f')
    outpoint_tx = Bitcoin::Protocol::Tx.from_json(
      fixtures_file(
        'tx-b5b598de91787439afd5938116654e0b16b7a0d0f82742ba37564219c5afcbf9.json' ) )
    expect(outpoint_tx.hash)
      .to eq('b5b598de91787439afd5938116654e0b16b7a0d0f82742ba37564219c5afcbf9')
    expect(tx.verify_input_signature(0, outpoint_tx)).to be true
    outpoint_tx = Bitcoin::Protocol::Tx.from_json(
      fixtures_file(
        'tx-ab9805c6d57d7070d9a42c5176e47bb705023e6b67249fb6760880548298e742.json' ) )
    expect(outpoint_tx.hash)
      .to eq('ab9805c6d57d7070d9a42c5176e47bb705023e6b67249fb6760880548298e742')
    expect(tx.verify_input_signature(1, outpoint_tx)).to be true

    # testnet3 e335562f7e297aadeed88e5954bc4eeb8dc00b31d829eedb232e39d672b0c009
    tx = Bitcoin::Protocol::Tx.from_json(
      fixtures_file(
        'tx-e335562f7e297aadeed88e5954bc4eeb8dc00b31d829eedb232e39d672b0c009.json' ) )
    expect(tx.hash)
      .to eq('e335562f7e297aadeed88e5954bc4eeb8dc00b31d829eedb232e39d672b0c009')
    prev_txs = {}

    tx.in.map(&:previous_output).uniq.each do |i|
      prev_txs[i] = Bitcoin::Protocol::Tx.from_json(
        fixtures_file("tx-#{i}.json")) end

    tx.in.each.with_index do |i, idx|
      expect(
        tx.verify_input_signature(idx, prev_txs[i.previous_output])
      ).to be true end end end
    # P2SH-P2WPKH    # P2SH-P2WSH transactions deleted.

  describe '#signature_hash_for_inputs' do
    it 'sighash_all' do
      prev_tx = Bitcoin::Protocol::Tx.new(
       fixtures_file('rawtx-2f4a2717ec8c9f077a87dde6cbe0274d5238793a3f3f492b63c744837285e58a.bin' ) )
      expect(prev_tx.hash)
        .to eq('2f4a2717ec8c9f077a87dde6cbe0274d5238793a3f3f492b63c744837285e58a')

      pubkey = '04324c6ebdcf079db6c9209a6b715b955622561262cde13a8a1df8ae0ef030eaa155' \
               '2e31f8be90c385e27883a9d82780283d19507d7fa2e1e71a1d11bc3a52caf3'
      key = Bitcoin.open_key( '56e28a425a7b588973b5db962a09b1aca7bdc4a7268cdd671d03c52a997255dc', pubkey )
      new_tx = Bitcoin::Protocol::Tx.new(nil)
      new_tx.add_in( Bitcoin::Protocol::TxIn.new(prev_tx.binary_hash, 0, 0))
      new_tx.add_out(Bitcoin::Protocol::TxOut.value_to_address( 1_000_000,  '1BVJWLTCtjA8wRivvrCiwjNdL6KjdMUCTZ' ) )
      signature_hash = new_tx.signature_hash_for_inputs(0, prev_tx)
      sig = Bitcoin.sign_data(key, signature_hash)
      new_tx.in[0].script_sig = Bitcoin::Script.to_pubkey_script_sig( sig, [pubkey].pack('H*') )

      new_tx = Bitcoin::Protocol::Tx.new(new_tx.to_payload)
      expect(new_tx.hash).not_to be_nil
      expect(new_tx.verify_input_signature(0, prev_tx)).to be true

      prev_tx = Bitcoin::Protocol::Tx.new(
        fixtures_file('rawtx-14be6fff8c6014f7c9493b4a6e4a741699173f39d74431b6b844fcb41ebb9984.bin' ) )
      expect(prev_tx.hash)
        .to eq('14be6fff8c6014f7c9493b4a6e4a741699173f39d74431b6b844fcb41ebb9984')
      pubkey =
        '0409d103127d26ce93ee41f1b9b1ed4c1c243acf48e31eb5c4d88ad0342ccc010a1a' \
        '8d838846cf7337f2b44bc73986c0a3cb0568fa93d068b2c8296ce8d47b1545'
      key = Bitcoin.open_key('115ceda6c1e02d41ce65c35a30e82fb325fe3f815898a09e1a5d28bb1cc92c6e', pubkey )
      new_tx = Bitcoin::Protocol::Tx.new(nil)
      new_tx.add_in(Bitcoin::Protocol::TxIn.new(prev_tx.binary_hash, 0, 0))
      pk_script = Bitcoin::Script.to_address_script('1FEYAh1x5jeKQMPPuv3bKnKvbgVAqXvqjW' )
      new_tx.add_out( Bitcoin::Protocol::TxOut.new(1_000_000, pk_script) )
      signature_hash = new_tx.signature_hash_for_inputs(0, prev_tx)
      sig = Bitcoin.sign_data(key, signature_hash)
      new_tx.in[0].script_sig = Bitcoin::Script.to_pubkey_script_sig( sig, [pubkey].pack('H*') )

      new_tx = Bitcoin::Protocol::Tx.new(new_tx.to_payload)
      expect(new_tx.hash).not_to be_nil
      expect(new_tx.verify_input_signature(0, prev_tx)).to be true

      prev_tx = Bitcoin::Protocol::Tx.new(
        fixtures_file( 'rawtx-b5d4e8883533f99e5903ea2cf001a133a322fa6b1370b18a16c57c946a40823d.bin' ) )
      expect(prev_tx.hash)
        .to eq('b5d4e8883533f99e5903ea2cf001a133a322fa6b1370b18a16c57c946a40823d')

      pubkey = '04324c6ebdcf079db6c9209a6b715b955622561262cde13a8a1df8ae0ef03' \
               '0eaa1552e31f8be90c385e27883a9d82780283d19507d7fa2e1e71a1d11bc3a52caf3'
      key = Bitcoin.open_key('56e28a425a7b588973b5db962a09b1aca7bdc4a7268cdd671d03c52a997255dc', pubkey )
      new_tx = Bitcoin::Protocol::Tx.new(nil)
      new_tx.add_in(  Bitcoin::Protocol::TxIn.new(prev_tx.binary_hash, 0, 0) )
      new_tx.add_out( Bitcoin::Protocol::TxOut.value_to_address(
          1_000_000, '14yz7fob6Q16hZu4nXfmv1kRJpSYaFtet5' ) )
      signature_hash = new_tx.signature_hash_for_inputs(0, prev_tx)
      sig = Bitcoin.sign_data(key, signature_hash)
      new_tx.in[0].script_sig = Bitcoin::Script.to_pubkey_script_sig(
        sig, [pubkey].pack('H*') )

      new_tx = Bitcoin::Protocol::Tx.new(new_tx.to_payload)
      expect(new_tx.hash).not_to be_nil
      expect(new_tx.verify_input_signature(0, prev_tx)).to be true end

    it 'sighash JSON tests' do
      test_cases = JSON.parse(fixtures_file('sighash.json'))

      test_cases.each do |test_case|
        # Single element arrays in tests are comments.
        next if test_case.length == 1
        transaction = Bitcoin::Protocol::Tx.new(test_case[0].htb)
        subscript = test_case[1].htb
        input_index = test_case[2].to_i
        hash_type = test_case[3]
        amount = 0
        expected_sighash = test_case[4].htb_reverse
        actual_sighash = transaction.signature_hash_for_inputs( input_index, subscript, hash_type, amount, 0 )
        expect(actual_sighash).to eq(expected_sighash) end end


  it '#legacy_sigops_count' do
    expect(Bitcoin::Protocol::Tx.new(payloads[0]).legacy_sigops_count).to eq(2)
    expect(Bitcoin::Protocol::Tx.new(payloads[1]).legacy_sigops_count).to eq(2)
    expect(Bitcoin::Protocol::Tx.new(payloads[2]).legacy_sigops_count).to eq(2)

    # Test sig ops count in inputs too.
    tx = Bitcoin::Protocol::Tx.new
    txin = Bitcoin::Protocol::TxIn.new
    txin.script_sig = Bitcoin::Script.from_string( '10 OP_CHECKMULTISIGVERIFY OP_CHECKSIGVERIFY' ).to_binary
    tx.add_in(txin)
    txout = Bitcoin::Protocol::TxOut.new
    txout.pk_script = Bitcoin::Script.from_string( '5 OP_CHECKMULTISIG OP_CHECKSIG' ).to_binary
    tx.add_out(txout)

    expect(tx.legacy_sigops_count).to eq(20 + 1 + 20 + 1) end

  describe 'Tx - final?' do
    it 'should be final if lock_time == 0' do
      tx = Bitcoin::Protocol::Tx.new
      tx.lock_time = 0
      expect(tx.final?(0, 0)).to be true

      # even if has non-final input:
      txin = Bitcoin::Protocol::TxIn.new
      txin.sequence = "\x01\x00\x00\x00"
      tx.add_in(txin)
      expect(tx.final?(0, 0)).to be true end

    it 'should be final if lock_time is below block_height' do
      tx = Bitcoin::Protocol::Tx.new
      txin = Bitcoin::Protocol::TxIn.new
      txin.sequence = "\x01\x00\x00\x00"
      tx.add_in(txin)
      tx.lock_time = 6543

      expect(tx.final?(6000, 0)).to be false
      # when equal to block height, still not final
      expect(tx.final?(6543, 0)).to be false
      expect(tx.final?(6544, 0)).to be true
      expect(tx.final?(9999, 0)).to be true end

    it 'should be final if lock_time is below timestamp' do
      tx = Bitcoin::Protocol::Tx.new
      txin = Bitcoin::Protocol::TxIn.new
      txin.sequence = "\xff\xff\xff\xff"
      tx.add_in(txin)
      txin = Bitcoin::Protocol::TxIn.new
      txin.sequence = "\x01\x00\x00\x00"
      tx.add_in(txin)
      tx.lock_time = Bitcoin::LOCKTIME_THRESHOLD # when equal, interpreted as threshold
      expect(tx.final?(0, Bitcoin::LOCKTIME_THRESHOLD - 1)).to be false
      # when equal to timestamp, still not final
      expect(tx.final?(0, Bitcoin::LOCKTIME_THRESHOLD)).to be false
      expect(tx.final?(0, Bitcoin::LOCKTIME_THRESHOLD + 1)).to be true

      tx.lock_time = Bitcoin::LOCKTIME_THRESHOLD + 666
      expect(tx.final?(0, Bitcoin::LOCKTIME_THRESHOLD + 1)).to be false
      # when equal to timestamp, still not final
      expect(tx.final?(0, Bitcoin::LOCKTIME_THRESHOLD + 666)).to be false
      expect(tx.final?(0, Bitcoin::LOCKTIME_THRESHOLD + 667)).to be true end

    it 'should be final if all inputs are finalized regardless of lock_time' do
      tx = Bitcoin::Protocol::Tx.new
      txin = Bitcoin::Protocol::TxIn.new
      txin.sequence = "\xff\xff\xff\xff"
      tx.add_in(txin)
      txin = Bitcoin::Protocol::TxIn.new
      txin.sequence = "\xff\xff\xff\xff"
      tx.add_in(txin)

      tx.lock_time = 6543
      expect(tx.final?(6000, 0)).to be true
      expect(tx.final?(6543, 0)).to be true
      expect(tx.final?(6544, 0)).to be true
      expect(tx.final?(9999, 0)).to be true

      tx.lock_time = Bitcoin::LOCKTIME_THRESHOLD
      expect(tx.final?(0, Bitcoin::LOCKTIME_THRESHOLD - 1)).to be true
      expect(tx.final?(0, Bitcoin::LOCKTIME_THRESHOLD)).to be true
      expect(tx.final?(0, Bitcoin::LOCKTIME_THRESHOLD + 1)).to be true

      tx.lock_time = Bitcoin::LOCKTIME_THRESHOLD + 666
      expect(tx.final?(0, Bitcoin::LOCKTIME_THRESHOLD + 1)).to be true
      expect(tx.final?(0, Bitcoin::LOCKTIME_THRESHOLD + 666)).to be true
      expect(tx.final?(0, Bitcoin::LOCKTIME_THRESHOLD + 667)).to be true end end

  it '#calculate_minimum_fee' do
    tx = Bitcoin::Protocol::Tx.new(
      fixtures_file( 'rawtx-b5d4e8883533f99e5903ea2cf001a133a322fa6b1370b18a16c57c946a40823d.bin' ) )
    expect(tx.minimum_relay_fee).to eq(0)
    expect(tx.minimum_block_fee).to eq(0)
    tx = Bitcoin::Protocol::Tx.from_json(
      fixtures_file( 'bc179baab547b7d7c1d5d8d6f8b0cc6318eaa4b0dd0a093ad6ac7f5a1cb6b3ba.json' ) )
    expect(tx.minimum_relay_fee).to eq(0)
    expect(tx.minimum_block_fee).to eq(10_000) end

  it '#calculate_minimum_fee for litecoin' do
    tx = Bitcoin::Protocol::Tx.from_json(
      fixtures_file( 'litecoin-tx-f5aa30f574e3b6f1a3d99c07a6356ba812aabb9661e1d5f71edff828cbd5c996.json' ) )
    expect(tx.minimum_relay_fee).to eq(0)
    expect(tx.minimum_block_fee).to eq(30_000)

    Bitcoin.network = :litecoin # change to litecoin
    expect(tx.minimum_relay_fee).to eq(0)
    expect(tx.minimum_block_fee).to eq(100_000) end

  it 'should compare transactions' do
    tx1 = Bitcoin::Protocol::Tx.new(payloads[0])
    tx2 = Bitcoin::Protocol::Tx.new(payloads[1])

    expect(Bitcoin::Protocol::Tx.from_json(tx1.to_json)).to eq(tx1)
    expect(tx1).not_to eq(tx2)
    expect(tx1).not_to be_nil end

  describe 'Tx - BIP Scripts' do
    it 'should do OP_CHECKMULTISIG' do
      # checkmultisig without checkhashverify
      tx = Bitcoin::Protocol::Tx.from_json(
        fixtures_file( '23b397edccd3740a74adb603c9756370fafcde9bcc4483eb271ecad09a94dd63.json' ) )
      prev_tx = Bitcoin::Protocol::Tx.from_json(
        fixtures_file( '60a20bd93aa49ab4b28d514ec10b06e1829ce6818ec06cd3aabd013ebcdc4bb1.json' ) )
      expect(tx.verify_input_signature(0, prev_tx)).to be true

      # p2sh + multisig transaction from mainnet
      tx = Bitcoin::Protocol::Tx.from_json(
        fixtures_file( 'rawtx-ba1ff5cd66713133c062a871a8adab92416f1e38d17786b2bf56ac5f6ffdfdf5.json' ) )
      prev_tx = Bitcoin::Protocol::Tx.from_json(
        fixtures_file( 'rawtx-de35d060663750b3975b7997bde7fb76307cec5b270d12fcd9c4ad98b279c28c.json' ) )
      expect(tx.verify_input_signature(0, prev_tx)).to be true

      # checkmultisig for testnet3 tx:
      # 2c63aa814701cef5dbd4bbaddab3fea9117028f2434dddcdab8339141e9b14d1 input
      # index 1
      tx = Bitcoin::Protocol::Tx.from_json(
        fixtures_file( 'tx-2c63aa814701cef5dbd4bbaddab3fea9117028f2434dddcdab8339141e9b14d1.json' ) )
      prev_tx = Bitcoin::Protocol::Tx.from_json(
        fixtures_file( 'tx-19aa42fee0fa57c45d3b16488198b27caaacc4ff5794510d0c17f173f05587ff.json' ) )
      expect(tx.verify_input_signature(1, prev_tx)).to be true end

     'should do P2SH with inner OP_CHECKMULTISIG (BIP 0016)' # deleted

     'should do P2SH with inner OP_CHECKSIG'  # deleted

    it 'should do OP_CHECKMULTISIG with OP_0 used as a pubkey' do
      tx = Bitcoin::Protocol::Tx.from_json(
        fixtures_file(
          'tx-6606c366a487bff9e412d0b6c09c14916319932db5954bf5d8719f43f828a3ba.json' ) )
      expect(tx.hash)
        .to eq('6606c366a487bff9e412d0b6c09c14916319932db5954bf5d8719f43f828a3ba')
      prev_tx = Bitcoin::Protocol::Tx.from_json(
        fixtures_file(
          'tx-4142ee4877eb116abf955a7ec6ef2dc38133b793df762b76d75e3d7d4d8badc9.json' ) )
      expect(prev_tx.hash)
        .to eq('4142ee4877eb116abf955a7ec6ef2dc38133b793df762b76d75e3d7d4d8badc9')
      expect(tx.verify_input_signature(0, prev_tx)).to be true end end

  it 'lexicographical_sort' do
    tx = Bitcoin::Protocol::Tx.from_json( fixtures_file(
      'tx-0a6a357e2f7796444e02638749d9611c008b253fb55f5dc88b739b230ed0c4c3.json' ) )
    expect(tx.hash).to eq('0a6a357e2f7796444e02638749d9611c008b253fb55f5dc88b739b230ed0c4c3')

    tx.lexicographical_sort!
    expect(tx.in[0].previous_output)
      .to eq('0e53ec5dfb2cb8a71fec32dc9a634a35b7e24799295ddd5278217822e0b31f57')
    expect(tx.in[1].previous_output)
      .to eq('26aa6e6d8b9e49bb0630aac301db6757c02e3619feb4ee0eea81eb1672947024')
    expect(tx.in[2].previous_output)
      .to eq('28e0fdd185542f2c6ea19030b0796051e7772b6026dd5ddccd7a2f93b73e6fc2')
    expect(tx.in[3].previous_output)
      .to eq('381de9b9ae1a94d9c17f6a08ef9d341a5ce29e2e60c36a52d333ff6203e58d5d')
    expect(tx.in[4].previous_output)
      .to eq('3b8b2f8efceb60ba78ca8bba206a137f14cb5ea4035e761ee204302d46b98de2')
    expect(tx.in[5].previous_output)
      .to eq('402b2c02411720bf409eff60d05adad684f135838962823f3614cc657dd7bc0a')
    expect(tx.in[6].previous_output)
      .to eq('54ffff182965ed0957dba1239c27164ace5a73c9b62a660c74b7b7f15ff61e7a')
    expect(tx.in[7].previous_output)
      .to eq('643e5f4e66373a57251fb173151e838ccd27d279aca882997e005016bb53d5aa')
    expect(tx.in[8].previous_output)
      .to eq('6c1d56f31b2de4bfc6aaea28396b333102b1f600da9c6d6149e96ca43f1102b1')
    expect(tx.in[9].previous_output)
      .to eq('7a1de137cbafb5c70405455c49c5104ca3057a1f1243e6563bb9245c9c88c191')
    expect(tx.in[10].previous_output)
      .to eq('7d037ceb2ee0dc03e82f17be7935d238b35d1deabf953a892a4507bfbeeb3ba4')
    expect(tx.in[11].previous_output)
      .to eq('a5e899dddb28776ea9ddac0a502316d53a4a3fca607c72f66c470e0412e34086')
    expect(tx.in[12].previous_output)
      .to eq('b4112b8f900a7ca0c8b0e7c4dfad35c6be5f6be46b3458974988e1cdb2fa61b8')
    expect(tx.in[13].previous_output)
      .to eq('bafd65e3c7f3f9fdfdc1ddb026131b278c3be1af90a4a6ffa78c4658f9ec0c85')
    expect(tx.in[14].previous_output)
      .to eq('de0411a1e97484a2804ff1dbde260ac19de841bebad1880c782941aca883b4e9')
    expect(tx.in[15].previous_output)
      .to eq('f0a130a84912d03c1d284974f563c5949ac13f8342b8112edff52971599e6a45')
    expect(tx.in[16].previous_output)
      .to eq('f320832a9d2e2452af63154bc687493484a0e7745ebd3aaf9ca19eb80834ad60')
    expect(tx.out[0].value).to eq(400_057_456)
    expect(tx.out[1].value).to eq(40_000_000_000)

    tx = Bitcoin::Protocol::Tx.from_json(
     fixtures_file( 'tx-28204cad1d7fc1d199e8ef4fa22f182de6258a3eaafe1bbe56ebdcacd3069a5f.json' ) )
    expect(tx.hash).to eq('28204cad1d7fc1d199e8ef4fa22f182de6258a3eaafe1bbe56ebdcacd3069a5f')

    tx.lexicographical_sort!
    expect(tx.in[0].previous_output)
      .to eq('35288d269cee1941eaebb2ea85e32b42cdb2b04284a56d8b14dcc3f5c65d6055')
    expect(tx.in[0].prev_out_index).to eq(0)
    expect(tx.in[1].previous_output)
      .to eq('35288d269cee1941eaebb2ea85e32b42cdb2b04284a56d8b14dcc3f5c65d6055')
    expect(tx.in[1].prev_out_index).to eq(1)
    expect(tx.out[0].value).to eq(100_000_000)
    expect(tx.out[1].value).to eq(2_400_000_000)

    tx = Bitcoin::Protocol::Tx.new
    tx.add_out(Bitcoin::Protocol::TxOut.new(500, 'bbbbbbbb'.htb))
    tx.add_out(Bitcoin::Protocol::TxOut.new(500, 'aaaaaaaa'.htb))
    tx.add_out(Bitcoin::Protocol::TxOut.new(500, 'cccccccc'.htb))

    tx.lexicographical_sort!
    expect(tx.out[0].pk_script.bth).to eq('aaaaaaaa')
    expect(tx.out[1].pk_script.bth).to eq('bbbbbbbb')
    expect(tx.out[2].pk_script.bth).to eq('cccccccc') end

  describe 'verify_input_signature' do
    # rubocop:disable Metrics/CyclomaticComplexity
    def parse_script(script_str)
      script = Bitcoin::Script.new('')
      # Disabling the below rubocop check since the proposed fix does not work
      # on Ruby versions < 2.3. If we ever drop support for these then it can be fixed
      buf = ''.dup
      script_str.split.each do |token|
        opcode = Bitcoin::Script::OPCODES_PARSE_STRING[token] || Bitcoin::Script::OPCODES_PARSE_STRING['OP_' + token]
        if opcode
         buf << [opcode].pack('C')
         next end
        data =
         case token
         when /\A-?\d+\z/
          i = token.to_i
          opcode =
           case i
           when -1 then Bitcoin::Script::OP_1NEGATE
           when 0 then Bitcoin::Script::OP_0
           when 1 then Bitcoin::Script::OP_1
           when 2..16 then Bitcoin::Script::OP_2 + i - 2 end
          if opcode then [opcode].pack('C')
          else Bitcoin::Script.pack_pushdata(script.cast_to_string(i)) end
         when /\A'(.*)'\z/ then
          Bitcoin::Script.pack_pushdata(Regexp.last_match(1))
         when /\A0x([0-9a-fA-F]+)\z/ then Regexp.last_match(1).htb
         else raise "Unexpected token #{token}" end
        buf << data end
      buf end

    def parse_flags(flags_str)
     flags_str.split(',').each_with_object({}) do |flag_str, opts|
      case flag_str.to_sym
      when :STRICTENC      then opts[:verify_strictenc] = true
      when :DERSIG         then opts[:verify_dersig] = true
      when :LOW_S          then opts[:verify_low_s] = true
      when :SIGPUSHONLY    then opts[:verify_sigpushonly] = true
      when :MINIMALDATA    then opts[:verify_minimaldata] = true
      when :CLEANSTACK     then opts[:verify_cleanstack] = true end end end
   #BSV   when :SIGHASH_FORKID then opts[:fork_id] = 0
    # rubocop:enable Metrics/CyclomaticComplexity

    it 'script JSON tests' do
      test_cases = JSON.parse(fixtures_file('script_tests.json'))

      test_cases.each do |test_case|
        # Single element arrays in tests are comments.
        next if test_case.length == 1

        value =
          if test_case[0].is_a?(Array) then (test_case.shift[0] * 10**8).to_i
          else 0 end

        # TODO: Implement these opcodes correctly
        # NOTE: Need to use `match` instead of `match?` because Ruby < 2.4 does
        # not support the latter function.

        # rubocop:disable Performance/RedundantMatch
        if test_case[0].match(
          /CHECKLOCKTIMEVERIFY|CHECKSEQUENCEVERIFY|RESERVED|0x50|VERIF|VERNOTIF/ )
          next end

        if test_case[1].match(
          /CHECKLOCKTIMEVERIFY|CHECKSEQUENCEVERIFY|RESERVED|0x50|VERIF|VERNOTIF/ )
          next end
        # rubocop:enable Performance/RedundantMatch

        script_sig = parse_script(test_case[0])
        script_pubkey = parse_script(test_case[1])
        opts = parse_flags(test_case[2])
        expect_success = test_case[3] == 'OK'

        # A lot of the test cases are failing, so for now we only test the
        # SIGHASH_FORKID ones.
        # TODO: Get this spec passing without this line.
        # next unless opts[:fork_id]

        crediting_tx = Bitcoin::Protocol::Tx.new
        crediting_tx.add_in(Bitcoin::Protocol::TxIn.new)
        crediting_tx.in[0].prev_out_hash = Bitcoin::Protocol::TxIn::NULL_HASH
        crediting_tx.in[0].prev_out_index = Bitcoin::Protocol::TxIn::COINBASE_INDEX
        crediting_tx.in[0].script_sig = parse_script('0 0')
        crediting_tx.add_out(Bitcoin::Protocol::TxOut.new)
        crediting_tx.out[0].value = value
        crediting_tx.out[0].pk_script = script_pubkey
        crediting_tx.refresh_hash

        spending_tx = Bitcoin::Protocol::Tx.new
        spending_tx.add_in(Bitcoin::Protocol::TxIn.new)
        spending_tx.in[0].prev_out_hash = crediting_tx.binary_hash
        spending_tx.in[0].prev_out_index = 0
        spending_tx.in[0].script_sig = script_sig
        spending_tx.add_out(Bitcoin::Protocol::TxOut.new)
        spending_tx.out[0].value = value
        spending_tx.out[0].pk_script = ''
        spending_tx.refresh_hash

        success = spending_tx.verify_input_signature(
          0, crediting_tx, Time.now.to_i, opts )
        expect(success).to eq(expect_success) end end end end
