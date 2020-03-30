/* eslint-disable require-jsdoc */
import TransportNodeHid from '@ledgerhq/hw-transport-node-hid';
import * as cfdjs from 'cfd-js';
import {LedgerLiquidWrapper} from './src/ledger-liquid-lib';
import * as ledgerLibDefine from './src/ledger-liquid-lib-defines';

// process.on('unhandledRejection', console.dir);

async function example() {
  const transport = await TransportNodeHid.open('');
  // transport.setDebugMode(true);

  const liquidLib = new LedgerLiquidWrapper(transport,
      ledgerLibDefine.NetworkType.LiquidV1);

  const addr1 = await liquidLib.getWalletPublicKey('44\'/0\'/0\'/0');
  console.log(addr1);
  const addr2 = await liquidLib.getWalletPublicKey('44\'/0\'/0\'/0/0');
  console.log(addr2);
  const addr3 = await liquidLib.getWalletPublicKey('44\'/0\'/0\'/0/1');
  console.log(addr3);
  const addr4 = await liquidLib.getWalletPublicKey('44\'/0\'/0\'/0/2');
  console.log(addr4);

  const extkey = cfdjs.CreateExtkeyFromParentKey({
    network: 'mainnet',
    parentKey: addr1.publicKey,
    parentDepth: 4,
    parentChainCode: addr1.chainCode,
    childNumber: 0,
  });
  console.log(extkey);
  const keyInfo = cfdjs.GetExtkeyInfo(extkey);
  console.log(keyInfo);

  const pubkey = await liquidLib.getWalletPublicKey('44\'/0\'/0\'/0');
  console.log('pubkey1 ->', pubkey);

  const pubkey1 = addr1.publicKey;
  const pubkey2 = addr2.publicKey;
  const pubkey3 = addr3.publicKey;
  const pubkey4 = addr4.publicKey;
  console.log('pubkey1 => ', pubkey1);
  console.log('pubkey2 => ', pubkey2);
  console.log('pubkey3 => ', pubkey3);
  console.log('pubkey4 => ', pubkey4);

  // const authPubkey = '04b85b0e5f5b41f1a95bbf9a83edd95c741223c6d9dc5fe607de18f015684ff56ec359705fcf9bbeb1620fb458e15e3d99f23c6f5df5e91e016686371a65b16f0c';
  // const setupRet = await liquidLib.setupHeadlessAuthorization(authPubkey);
  // console.log('--HEADLESS LIQUID SEND AUTHORIZATION PUBLIC KEY --\n', setupRet);

  // eslint-disable-next-line prefer-const
  let hashType = 'p2wsh';
  const pubkeyHashType = 'p2sh-p2wpkh';

  const address2 = cfdjs.CreateAddress({
    'keyData': {
      'hex': pubkey2,
      'type': 'pubkey',
    },
    'network': 'liquidv1',
    'isElements': true,
    'hashType': pubkeyHashType,
  });
  console.log('address2 => ', address2);
  const address3 = cfdjs.CreateAddress({
    'keyData': {
      'hex': pubkey3,
      'type': 'pubkey',
    },
    'network': 'liquidv1',
    'isElements': true,
    'hashType': pubkeyHashType,
  });
  console.log('address3 => ', address3);

  let isScriptHash = false;
  let redeemScript;
  let scriptSigSegwit;
  let address;
  if ((hashType === 'p2sh-p2wpkh') || (hashType === 'p2wpkh')) {
    const address4 = cfdjs.CreateAddress({
      'keyData': {
        'hex': pubkey4,
        'type': 'pubkey',
      },
      'network': 'liquidv1',
      'isElements': true,
      'hashType': hashType,
    });
    console.log('address4 => ', address4);
    const address4Legacy = cfdjs.CreateAddress({
      keyData: {
        hex: pubkey4,
        type: 'pubkey',
      },
      network: 'liquidv1',
      isElements: true,
      hashType: 'p2pkh',
    });
    const address4Segwit = cfdjs.CreateAddress({
      keyData: {
        hex: pubkey4,
        type: 'pubkey',
      },
      network: 'liquidv1',
      isElements: true,
      hashType: 'p2wpkh',
    });
    // const confKeyRet = await liquidGetPublicBlindingKey(transport, address4.lockingScript);
    // console.log('--LIQUID GET PUBLIC BLINDING KEY 4--\n', confKeyRet);

    address = address4;
    redeemScript = address4Legacy.lockingScript;
    scriptSigSegwit = address4Segwit.lockingScript;
  } else if ((hashType === 'p2sh-p2wsh') || (hashType === 'p2wsh')) {
    isScriptHash = true;

    const multisigAddr = cfdjs.CreateMultisig({
      nrequired: 2,
      keys: [
        pubkey4,
        pubkey3,
      ],
      network: 'liquidv1',
      hashType: hashType,
      isElements: true,
    });

    redeemScript = multisigAddr.witnessScript;
    if (hashType === 'p2sh-p2wsh') {
      address = {
        address: multisigAddr.address,
      };
      scriptSigSegwit = multisigAddr.redeemScript;
    } else if (hashType === 'p2wsh') {
      address = {
        address: multisigAddr.address,
      };
    }
  }
  if (!address) {
    throw new Error('address undefined');
  }

  const tx1 = cfdjs.ElementsCreateRawTransaction({
    version: 2,
    locktime: 0,
    txins: [{
      txid: '7461b02405414d79e79a5050684a333c922c1136f4bdff5fb94b551394edebbd', // dummy
      vout: 0,
      sequence: 4294967295,
    }],
    txouts: [{
      address: address.address,
      amount: 10000000n,
      asset: '5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225',
    }],
    fee: {
      amount: 500000n,
      asset: '5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225',
    },
  });
  const dectx1 = cfdjs.ElementsDecodeRawTransaction({hex: tx1.hex, network: 'liquidv1', mainchainNetwork: 'mainnet'});
  console.log('*** blind dectx2 ***\n', JSON.stringify(dectx1, null, '  '));

  // txid: '5aa98b1387374708629307f66f460c08e6f822ef121da1255c71264e07bb8c43',
  // const dectx1 = cfdjs.ElementsDecodeRawTransaction({hex: tx1.hex, network: 'liquidv1', mainchainNetwork: 'mainnet'})
  // console.log('*** dectx1 ***\n', dectx1);

  const utxo = {txid: dectx1.txid, vout: 0, amount: 10000000n};

  const tx2 = cfdjs.ElementsCreateRawTransaction({
    version: 2,
    locktime: 0,
    txins: [{
      txid: utxo.txid,
      vout: utxo.vout,
      sequence: 4294967295,
    }],
    txouts: [{
      address: address2.address,
      amount: 9000000n,
      asset: '5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225',
    }, {
      address: address3.address,
      amount: 990000n,
      asset: '5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225',
    }],
    fee: {
      amount: 10000n,
      asset: '5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225',
    },
  });
  console.log('*** tx2 ***\n', tx2);

  const blindTx2 = tx2;

  // console.log('*** Blind ***\n', tx2);
  const dectx2 = cfdjs.ElementsDecodeRawTransaction({hex: blindTx2.hex, network: 'liquidv1', mainchainNetwork: 'mainnet'});
  console.log('*** blind dectx2 ***\n', JSON.stringify(dectx2, null, '  '));

  // get authorization start ---------------------------------
  const authorizationHash = cfdjs.SerializeLedgerFormat({
    tx: blindTx2.hex,
    txouts: [
      {
        index: 0,
        asset: '5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225',
        amount: 9000000n,
      }, {
        index: 1,
        asset: '5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225',
        amount: 990000n,
      }, {
        index: 2,
        asset: '5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225',
        amount: 10000n,
      },
    ],
    skipWitness: true,
    isAuthorization: true,
  });

  const authorizationPrivkey = '47ab8b0e5f8ea508808f9e03b804d623a7cb81cbf1f39d3e976eb83f9284ecde';
  const authSig = cfdjs.CalculateEcSignature({
    sighash: authorizationHash.sha256,
    privkeyData: {
      privkey: authorizationPrivkey,
      wif: false,
      network: 'mainnet',
    },
    isGrindR: false,
  });
  const authDerSigData = cfdjs.EncodeSignatureByDer({
    signature: authSig.signature,
    sighashType: 'all'});
  const authDerSig = authDerSigData.signature.substring(
      0, authDerSigData.signature.length - 2);
  console.log('authDerSig => ', authDerSig);
  // get authorization end ---------------------------------

  const PATH4 = '44\'/0\'/0\'/0/2';
  const PATH3 = '44\'/0\'/0\'/0/1';
  // const amountValueList = [utxo.amount];
  const utxoList = [{
    txid: utxo.txid,
    vout: utxo.vout,
    amount: utxo.amount,
  }];
  const walletUtxoList = [{
    bip32Path: PATH4,
    txid: utxo.txid,
    vout: utxo.vout,
    amount: utxo.amount,
    redeemScript: redeemScript,
  }, {
    bip32Path: PATH3,
    txid: utxo.txid,
    vout: utxo.vout,
    amount: utxo.amount,
    redeemScript: redeemScript,
  }];
  const sigRet = await liquidLib.getSignature(blindTx2.hex,
      utxoList, walletUtxoList, authDerSig);

  // FIXME(k-matsuzawa): wait for blinding
  // const ret1 = await liquidGetValueBlindingFactor(transport, 0, true);
  // const ret2 = await liquidGetValueBlindingFactor(transport, 0, false);
  // const ret3 = await liquidGetTXBlindingKey(transport);
  // console.log('*** ret1 ***\n', ret1);
  // console.log('*** ret2 ***\n', ret2);
  // console.log('*** ret3 ***\n', ret3, '\n');

  let signedTx;
  if (!isScriptHash) {
    signedTx = cfdjs.AddPubkeyHashSign({
      tx: blindTx2.hex,
      isElements: true,
      txin: {
        txid: sigRet.signatureList[0].utxoData.txid,
        vout: sigRet.signatureList[0].utxoData.vout,
        signParam: {
          hex: sigRet.signatureList[0].signature,
          derEncode: false,
        },
        pubkey: pubkey4,
        hashType: hashType,
      },
    });
  } else {
    const jsonParam = {
      tx: blindTx2.hex,
      isElements: true,
      txin: {
        txid: sigRet.signatureList[0].utxoData.txid,
        vout: sigRet.signatureList[0].utxoData.vout,
        signParams: [
          {
            hex: sigRet.signatureList[0].signature,
            derEncode: false,
            relatedPubkey: pubkey4,
          },
          {
            hex: sigRet.signatureList[1].signature,
            derEncode: false,
            relatedPubkey: pubkey3,
          },
        ],
        redeemScript: scriptSigSegwit,
        witnessScript: redeemScript,
        hashType: hashType,
      },
    };
    console.log('jsonParam => ', JSON.stringify(jsonParam, null, '  '));
    signedTx = cfdjs.AddMultisigSign(jsonParam);
  }

  console.log('signedTx => ', signedTx);
};
example();
