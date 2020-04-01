/* eslint-disable require-jsdoc */
import * as cfdjs from 'cfd-js';
import {LedgerLiquidWrapper} from './src/ledger-liquid-lib';
import * as ledgerLibDefine from './src/ledger-liquid-lib-defines';

process.on('unhandledRejection', console.dir);

let hashType = 'p2sh-p2wpkh'; // 'p2sh-p2wsh';
const blindOpt = {blind1: true, blind2: true};
let networkType = ledgerLibDefine.NetworkType.LiquidV1;
// eslint-disable-next-line prefer-const
let tx2InputCount = 2;
// eslint-disable-next-line prefer-const
let addSignAddr4 = false;
let signedTest = false;
let signedAddTest = false;
let authorizationPrivkey = '47ab8b0e5f8ea508808f9e03b804d623a7cb81cbf1f39d3e976eb83f9284ecde';
let mnemonic = '';
// mnemonic = 'call node debug-console.js ledger hood festival pony outdoor always jeans page help symptom adapt obtain image bird duty damage find sense wasp box mail vapor plug general kingdom';

for (let i = 2; i < process.argv.length; i++) {
  if (process.argv[i]) {
    if (process.argv[i] === '-r') {
      networkType = ledgerLibDefine.NetworkType.Regtest;
    } else if (process.argv[i] === '-nb1') {
      blindOpt.blind1 = false;
    } else if (process.argv[i] === '-nb2') {
      blindOpt.blind2 = false;
    } else if (process.argv[i] === '-s2') {
      addSignAddr4 = true;
    } else if (process.argv[i] === '-t') {
      signedTest = true;
    } else if (process.argv[i] === '-ta') {
      signedAddTest = true;
    } else if (i+1 < process.argv.length) {
      if (process.argv[i] === '-h') {
        ++i;
        hashType = process.argv[i];
      } else if (process.argv[i] === '-a') {
        ++i;
        if (process.argv[i].length === 64) {
          authorizationPrivkey = process.argv[i];
        }
      } else if (process.argv[i] === '-n') {
        ++i;
        mnemonic = process.argv[i];
      }
    }
  }
}

async function example() {
  // const addrType = ledgerLibDefine.AddressType.Bech32;

  const pubkeyHashType = 'p2sh-p2wpkh';
  const asset1 = '5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225';

  // connect wait test
  const liquidLib = new LedgerLiquidWrapper(networkType);
  const connRet = await liquidLib.connect(60, '');
  if (!connRet.success) {
    console.log('connection failed. ', connRet);
    return;
  }

  const parentAddr = await liquidLib.getWalletPublicKey('44\'/0\'/0\'/0');
  console.log('parentAddr -> ', parentAddr);

  const PATH1 = '44\'/0\'/0\'/0/0';
  const PATH2 = '44\'/0\'/0\'/0/1';
  const PATH3 = '44\'/0\'/0\'/0/2';
  const PATH4 = '44\'/0\'/0\'/0/3';
  console.log('*** publickey test start ***');
  const addr1 = await liquidLib.getWalletPublicKey(PATH1);
  console.log('addr1 =', addr1);

  const extkey = cfdjs.CreateExtkeyFromParentKey({
    network: 'mainnet',
    parentKey: parentAddr.publicKey,
    parentDepth: 4,
    parentChainCode: parentAddr.chainCode,
    childNumber: 0,
  });
  console.log('extkey =', extkey);
  const keyInfo = cfdjs.GetExtkeyInfo(extkey);
  console.log('extkeyInfo =', keyInfo);

  const addr2 = await liquidLib.getWalletPublicKey(PATH2);
  console.log('addr2 =', addr2);
  const addr3 = await liquidLib.getWalletPublicKey(PATH3);
  console.log('addr3 =', addr3);
  const addr4 = await liquidLib.getWalletPublicKey(PATH4);
  console.log('addr3 =', addr4);

  const pubkey = await liquidLib.getWalletPublicKey('44\'/0\'/0\'/0');
  console.log('pubkey1 ->', pubkey);

  const pubkey1 = addr1.publicKey;
  const pubkey2 = addr2.publicKey;
  let pubkey3 = addr3.publicKey;
  const pubkey4 = addr4.publicKey;
  console.log('pubkey1 => ', pubkey1);
  console.log('pubkey2 => ', pubkey2);
  console.log('pubkey3 => ', pubkey3);
  console.log('pubkey4 => ', pubkey4);

  // const authPubkey = '04b85b0e5f5b41f1a95bbf9a83edd95c741223c6d9dc5fe607de18f015684ff56ec359705fcf9bbeb1620fb458e15e3d99f23c6f5df5e91e016686371a65b16f0c';
  // const setupRet = await liquidLib.setupHeadlessAuthorization(authPubkey);
  // console.log('--HEADLESS LIQUID SEND AUTHORIZATION PUBLIC KEY --\n', setupRet);

  // eslint-disable-next-line prefer-const

  const address1 = cfdjs.CreateAddress({
    'keyData': {
      'hex': pubkey1,
      'type': 'pubkey',
    },
    'network': networkType,
    'isElements': true,
    'hashType': pubkeyHashType,
  });
  console.log('address1 => ', address1);
  const address2 = cfdjs.CreateAddress({
    'keyData': {
      'hex': pubkey2,
      'type': 'pubkey',
    },
    'network': networkType,
    'isElements': true,
    'hashType': pubkeyHashType,
  });
  console.log('address2 => ', address2);
  let address4 = cfdjs.CreateAddress({
    'keyData': {
      'hex': pubkey4,
      'type': 'pubkey',
    },
    'network': networkType,
    'isElements': true,
    'hashType': pubkeyHashType,
  });
  console.log('address4 => ', address4);

  const testPubkey4 = '030fa835a11a2cb01c58e2358dbdcc6d85e35cb2a38ca3d3d660aadb4bda2ad7f9';
  const testPrivkey4 = '7df5b968dee8f54c4b3cacf0386a4cab0eb7f6a10fc15f3b647bda227f4111b7';

  let isScriptHash = false;
  let redeemScript;
  let scriptSigSegwit;
  let address;
  let descriptor = '';
  let descriptor4 = '';
  let privkey3Hex = '';
  if ((hashType === 'p2sh-p2wpkh') || (hashType === 'p2wpkh')) {
    const address3 = cfdjs.CreateAddress({
      'keyData': {
        'hex': pubkey3,
        'type': 'pubkey',
      },
      'network': networkType,
      'isElements': true,
      'hashType': hashType,
    });
    console.log('address3 => ', address3);
    // const confKeyRet = await liquidGetPublicBlindingKey(transport, address4.lockingScript);
    // console.log('--LIQUID GET PUBLIC BLINDING KEY 4--\n', confKeyRet);

    address = address3;
    descriptor = `wpkh(${pubkey3})`;
    descriptor4 = `wpkh(${pubkey4})`;
    if (hashType === 'p2sh-p2wpkh') {
      descriptor = `sh(${descriptor})`;
      descriptor4 = `sh(${descriptor4})`;
    }

    if (signedTest) {
      tx2InputCount = 2;
      // 44h/0h/0h/0/0
      // xprvA35Stvys6RBQD5YqqfWyiyZSVE6JCVwEea37zrG6MsxaZ7xbCUAvbQzPYNddJ2QGBxea7jHvZh6NyKMBC97wspmZRHQqnHnevkhwy78Cehg
      // privkey: L1YRuEojez8mj6AsEPVA74Kvv7oqCUyzaWLLKrM8NZ46qr4FhLx
      //   (hex): 80fabf46d8e9dd12fc59299f61a7638bac33d7d125677a37bcb4b3a0e32bb23f
      // pubkey: '021a8cffee67e4a5d8e9cfe0e6dbcc86484b425e93508522224c32bbba96fb6d82'
      pubkey3 = '021a8cffee67e4a5d8e9cfe0e6dbcc86484b425e93508522224c32bbba96fb6d82';
      privkey3Hex = '80fabf46d8e9dd12fc59299f61a7638bac33d7d125677a37bcb4b3a0e32bb23f';
      address = cfdjs.CreateAddress({
        'keyData': {
          'hex': pubkey3,
          'type': 'pubkey',
        },
        'network': networkType,
        'isElements': true,
        'hashType': hashType,
      });
      address4 = cfdjs.CreateAddress({
        'keyData': {
          'hex': testPubkey4,
          'type': 'pubkey',
        },
        'network': networkType,
        'isElements': true,
        'hashType': hashType,
      });

      descriptor = `wpkh(${pubkey3})`;
      descriptor4 = `wpkh(${testPubkey4})`;
      if (hashType === 'p2sh-p2wpkh') {
        descriptor = `sh(${descriptor})`;
        descriptor4 = `sh(${descriptor4})`;
      }
    }
  } else if ((hashType === 'p2sh-p2wsh') || (hashType === 'p2wsh')) {
    isScriptHash = true;
    const requireNum = 2;

    const multisigAddr = cfdjs.CreateMultisig({
      nrequired: requireNum,
      keys: [
        pubkey3,
        pubkey2,
      ],
      network: networkType,
      hashType: hashType,
      isElements: true,
    });

    redeemScript = multisigAddr.witnessScript;
    descriptor = `wsh(multi(${requireNum},${pubkey3},${pubkey2}))`;
    if (hashType === 'p2sh-p2wsh') {
      address = {
        address: multisigAddr.address,
      };
      scriptSigSegwit = multisigAddr.redeemScript;
      descriptor = `sh(${descriptor})`;
    } else if (hashType === 'p2wsh') {
      address = {
        address: multisigAddr.address,
      };
    }
    console.log('multisigAddr => ', address);
  }
  if (!address) {
    throw new Error('address undefined');
  }
  console.log('descriptor => ', descriptor);
  const blindingKey = '2769451f3a1738d236a9cf747a3f1d427088b7ad20d01eb76c89f6105ffe88f6';
  const confidentialKey = '036390faa240c5a82e3bad4c6f07836573dfffb9238d010a90eb4ceef0946d40ea';
  const ctAddr = cfdjs.GetConfidentialAddress({
    unblindedAddress: address.address,
    key: confidentialKey,
  });
  console.log('ctAddr => ', ctAddr);

  // const blindingKey1 = '0e8ef84e19065269a8ebd92232cab53f21b0f0d31c42d824a5a9aa9c528e9597';
  const confidentialKey1 = '03fd456b187343c9ff4e18ab9d88980b36c0b1a64e862433cfd811b22e855760a4';
  const ctAddr1 = cfdjs.GetConfidentialAddress({
    unblindedAddress: address1.address,
    key: confidentialKey1,
  });
  console.log('ctAddr1 => ', ctAddr1);

  // const blindingKey2 = 'ff95155b8f7d9b8b7ba35d9a5237fe75bb62ba82996c69d493a70105f7f74e0d';
  const confidentialKey2 = '0269d5b8d1c53d4d42ec80b9f787c39324a5d0572182724b4e61e34380ca23ce15';
  const ctAddr2 = cfdjs.GetConfidentialAddress({
    unblindedAddress: address2.address,
    key: confidentialKey2,
  });
  console.log('ctAddr2 => ', ctAddr2);

  const blindingKey4 = 'b91d9b51d4949b896e8dd911285f3d79a84d2ee1a5230014af3232bfef746721';
  const confidentialKey4 = '036e77ff8109027c246125babd5d0852809367ea3d68704f6d8c855986d8521661';
  const ctAddr4 = cfdjs.GetConfidentialAddress({
    unblindedAddress: address4.address,
    key: confidentialKey4,
  });
  console.log('ctAddr4 => ', ctAddr4);

  const inputAmount = 10050000n;
  const tx1Data = {
    version: 2,
    locktime: 0,
    txins: [{
      txid: '7461b02405414d79e79a5050684a333c922c1136f4bdff5fb94b551394edebbd', // dummy
      vout: 0,
      sequence: 4294967295,
    }],
    txouts: [{
      address: address.address,
      amount: 5000000n,
      asset: asset1,
    }, {
      address: address4.address,
      amount: 5000000n,
      asset: asset1,
    }],
    fee: {
      amount: 50000n,
      asset: asset1,
    },
  };
  let tx1 = cfdjs.ElementsCreateRawTransaction(tx1Data);
  if (blindOpt.blind1) {
    tx1 = cfdjs.BlindRawTransaction({
      tx: tx1.hex,
      txins: [{
        txid: tx1Data.txins[0].txid,
        vout: BigInt(tx1Data.txins[0].vout), // invalid type on cfd-js
        asset: asset1,
        blindFactor: '0000000000000000000000000000000000000000000000000000000000000000',
        assetBlindFactor: '0000000000000000000000000000000000000000000000000000000000000000',
        amount: inputAmount,
      }],
      txoutConfidentialAddresses: [
        ctAddr.confidentialAddress,
        ctAddr4.confidentialAddress,
      ],
    });
  }
  const mainchainNwType = (networkType === 'liquidv1') ? 'mainnet' : 'regtest';
  const dectx1 = cfdjs.ElementsDecodeRawTransaction({
    hex: tx1.hex, network: networkType,
    mainchainNetwork: mainchainNwType});
  console.log('*** blind dectx1 ***\n', JSON.stringify(dectx1, null, '  '));

  let valueCommitment = '';
  let valueCommitment2 = '';
  if (dectx1.vout) {
    valueCommitment = (!dectx1.vout[0].valuecommitment) ?
      '' : dectx1.vout[0].valuecommitment;
    valueCommitment2 = (!dectx1.vout[1].valuecommitment) ?
      '' : dectx1.vout[1].valuecommitment;
  }
  const utxo = {
    txid: dectx1.txid,
    vout: (!dectx1.vout) ? 0 : dectx1.vout[0].n,
    amount: tx1Data.txouts[0].amount,
    value: valueCommitment,
  };
  const utxo2 = {
    txid: dectx1.txid,
    vout: (!dectx1.vout) ? 0 : dectx1.vout[1].n,
    amount: tx1Data.txouts[1].amount,
    value: valueCommitment2,
  };

  const tx2Data = {
    version: 2,
    locktime: 0,
    txins: [{
      txid: utxo.txid,
      vout: utxo.vout,
      sequence: 4294967295,
    }],
    txouts: [{
      address: address1.address,
      amount: (tx2InputCount === 2) ? 9000000n : 4000000n,
      asset: '5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225',
    }, {
      address: address2.address,
      amount: 950000n,
      asset: '5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225',
    }],
    fee: {
      amount: 50000n,
      asset: '5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225',
    },
  };
  if (tx2InputCount === 2) {
    tx2Data.txins.push({
      txid: utxo2.txid,
      vout: utxo2.vout,
      sequence: 4294967295,
    });
  }
  const tx2 = cfdjs.ElementsCreateRawTransaction(tx2Data);
  console.log('*** tx2 ***\n', tx2);

  let blindTx2 = tx2;
  if (blindOpt.blind2) {
    const unblindTxOut = [{
      asset: tx1Data.txouts[0].asset,
      blindFactor: '0000000000000000000000000000000000000000000000000000000000000000',
      assetBlindFactor: '0000000000000000000000000000000000000000000000000000000000000000',
      amount: tx1Data.txouts[0].amount,
    }, {
      asset: tx1Data.txouts[1].asset,
      blindFactor: '0000000000000000000000000000000000000000000000000000000000000000',
      assetBlindFactor: '0000000000000000000000000000000000000000000000000000000000000000',
      amount: tx1Data.txouts[1].amount,
    }];
    if (blindOpt.blind1) {
      const unblindData = cfdjs.UnblindRawTransaction({
        tx: tx1.hex,
        txouts: [{
          index: 0,
          blindingKey: blindingKey,
        }, {
          index: 1,
          blindingKey: blindingKey4,
        }],
      });
      if (unblindData.outputs) {
        unblindTxOut[0] = unblindData.outputs[0];
        console.log('unblind1 =', unblindTxOut[0]);
        unblindTxOut[1] = unblindData.outputs[1];
        console.log('unblind2 =', unblindTxOut[1]);
      }
    }
    const blindReqData = {
      tx: tx2.hex,
      txins: [{
        txid: tx2Data.txins[0].txid,
        vout: BigInt(tx2Data.txins[0].vout), // invalid type on cfd-js
        asset: unblindTxOut[0].asset,
        blindFactor: unblindTxOut[0].blindFactor,
        assetBlindFactor: unblindTxOut[0].assetBlindFactor,
        amount: unblindTxOut[0].amount,
      }],
      txoutConfidentialAddresses: [
        ctAddr1.confidentialAddress,
        ctAddr2.confidentialAddress,
      ],
    };
    if (tx2InputCount === 2) {
      blindReqData.txins.push({
        txid: tx2Data.txins[1].txid,
        vout: BigInt(tx2Data.txins[1].vout), // invalid type on cfd-js
        asset: unblindTxOut[1].asset,
        blindFactor: unblindTxOut[1].blindFactor,
        assetBlindFactor: unblindTxOut[1].assetBlindFactor,
        amount: unblindTxOut[1].amount,
      });
    }
    blindTx2 = cfdjs.BlindRawTransaction(blindReqData);
  }

  // console.log('*** Blind ***\n', tx2);
  const dectx2 = cfdjs.ElementsDecodeRawTransaction({
    hex: blindTx2.hex, network: networkType,
    mainchainNetwork: mainchainNwType});
  console.log('*** blind dectx2 ***\n', JSON.stringify(dectx2, null, '  '));

  let sigRet;
  if (signedTest) {
    const signed = cfdjs.SignWithPrivkey({
      isElements: true,
      tx: blindTx2.hex,
      txin: {
        txid: utxo2.txid,
        vout: utxo2.vout,
        privkey: testPrivkey4,
        hashType: hashType,
        amount: utxo2.amount,
        confidentialValueCommitment: utxo2.value,
      },
    });
    blindTx2 = signed;
    if (signedAddTest) {
      blindTx2 = cfdjs.SignWithPrivkey({
        isElements: true,
        tx: blindTx2.hex,
        txin: {
          txid: utxo.txid,
          vout: utxo.vout,
          privkey: privkey3Hex,
          pubkey: pubkey3,
          hashType: hashType,
          amount: utxo.amount,
          confidentialValueCommitment: utxo.value,
        },
      });
    }
    console.log('\n===== VerifySign =====');
    const reqVerifyJson = {
      tx: blindTx2.hex,
      isElements: true,
      txins: [{
        txid: utxo2.txid,
        vout: utxo2.vout,
        address: address4.address,
        amount: utxo2.amount,
        descriptor: descriptor4,
        confidentialValueCommitment: utxo2.value,
      }],
    };
    if (signedAddTest) {
      reqVerifyJson.txins.push({
        txid: utxo.txid,
        vout: utxo.vout,
        address: address.address,
        amount: utxo.amount,
        descriptor: descriptor,
        confidentialValueCommitment: utxo.value,
      });
    }
    const verifyRet = cfdjs.VerifySign(reqVerifyJson);
    console.log('\n*** VerifySign ***\n', JSON.stringify(verifyRet, null, '  '));
    if (!verifyRet.success) {
      const decSignedTx = cfdjs.ElementsDecodeRawTransaction({
        hex: blindTx2.hex, network: networkType,
        mainchainNetwork: mainchainNwType});
      console.log('*** blind decSignedTx2 ***\n',
          JSON.stringify(decSignedTx, null, '  '));
      console.log('\n*** VerifySignRequest ***\n',
          reqVerifyJson.txins);
      console.log('\n*** VerifySign Failed. ***\n');
    } else if (signedAddTest) {
      console.log('\n*** Signed1 Tx ***\n', signed);
      console.log('\n*** Signed2 Tx ***\n', blindTx2);
    } else {
      console.log('\n*** Signed Tx ***\n', blindTx2);
    }
    return;
  } else {
    // get authorization start ---------------------------------
    console.log('*** calc authorization start ***');
    const authorizationHash = cfdjs.SerializeLedgerFormat({
      tx: blindTx2.hex,
      isAuthorization: true,
    });
    console.log('SerializeLedgerFormat =', authorizationHash);

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
    console.log(`*** calc authorization end. [${authDerSig}] ***`);
    // get authorization end ---------------------------------

    const utxoList = [{
      txid: utxo.txid,
      vout: utxo.vout,
      amount: utxo.amount,
      valueCommitment: utxo.value,
    }];
    if (tx2InputCount === 2) {
      utxoList.push({
        txid: utxo2.txid,
        vout: utxo2.vout,
        amount: utxo2.amount,
        valueCommitment: utxo2.value,
      });
    }
    let walletUtxoList = [{
      bip32Path: PATH3,
      txid: utxo.txid,
      vout: utxo.vout,
      amount: utxo.amount,
      valueCommitment: utxo.value,
      redeemScript: redeemScript,
    }];
    if (!isScriptHash && (tx2InputCount === 2) && addSignAddr4) {
      walletUtxoList.push({
        bip32Path: PATH4,
        txid: utxo2.txid,
        vout: utxo2.vout,
        amount: utxo2.amount,
        valueCommitment: utxo2.value,
        redeemScript: '',
      });
    }
    if (isScriptHash) {
      walletUtxoList = [{
        bip32Path: PATH3,
        txid: utxo.txid,
        vout: utxo.vout,
        amount: utxo.amount,
        valueCommitment: utxo.value,
        redeemScript: redeemScript,
      }, {
        bip32Path: PATH2,
        txid: utxo.txid,
        vout: utxo.vout,
        amount: utxo.amount,
        valueCommitment: utxo.value,
        redeemScript: redeemScript,
      }];
    }
    console.log('*** utxoList start. ***', utxoList);
    console.log('*** getSignature start. ***');
    sigRet = await liquidLib.getSignature(blindTx2.hex,
        utxoList, walletUtxoList, authDerSig);
    console.log(`*** getSignature end. ***`,
        JSON.stringify(sigRet, (key, value) =>
            typeof value === 'bigint' ? value.toString() : value, '  '));
  }

  // FIXME(k-matsuzawa): wait for blinding
  // const ret1 = await liquidGetValueBlindingFactor(transport, 0, true);
  // const ret2 = await liquidGetValueBlindingFactor(transport, 0, false);
  // const ret3 = await liquidGetTXBlindingKey(transport);
  // console.log('*** ret1 ***\n', ret1);
  // console.log('*** ret2 ***\n', ret2);
  // console.log('*** ret3 ***\n', ret3, '\n');

  let signedTx;
  if (!sigRet.success) {
    // error
  } else if (!isScriptHash) {
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
        pubkey: pubkey3,
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
            relatedPubkey: pubkey3,
          },
          {
            hex: sigRet.signatureList[1].signature,
            derEncode: false,
            relatedPubkey: pubkey2,
          },
        ],
        redeemScript: scriptSigSegwit,
        witnessScript: redeemScript,
        hashType: hashType,
      },
    };
    // console.log('jsonParam => ', JSON.stringify(jsonParam, null, '  '));
    signedTx = cfdjs.AddMultisigSign(jsonParam);
  }

  console.log('signedTx => ', signedTx);

  if (sigRet.success && signedTx !== undefined) {
    console.log('\n===== VerifySign =====');
    const reqVerifyJson = {
      tx: signedTx.hex,
      isElements: true,
      txins: [{
        txid: sigRet.signatureList[0].utxoData.txid,
        vout: sigRet.signatureList[0].utxoData.vout,
        address: address.address,
        amount: utxo.amount,
        descriptor: descriptor,
        confidentialValueCommitment: utxo.value,
      }],
    };
    if (!isScriptHash && (tx2InputCount === 2) && addSignAddr4) {
      reqVerifyJson.txins.push({
        txid: sigRet.signatureList[1].utxoData.txid,
        vout: sigRet.signatureList[1].utxoData.vout,
        address: address4.address,
        amount: utxo2.amount,
        descriptor: descriptor4,
        confidentialValueCommitment: utxo2.value,
      });
    }
    const verifyRet = cfdjs.VerifySign(reqVerifyJson);
    console.log('\n*** VerifySign ***\n', JSON.stringify(verifyRet, null, '  '));
    if (!verifyRet.success) {
      const decSignedTx = cfdjs.ElementsDecodeRawTransaction({
        hex: signedTx.hex, network: networkType,
        mainchainNetwork: mainchainNwType});
      console.log('*** blind decSignedTx2 ***\n',
          JSON.stringify(decSignedTx, null, '  '));
      console.log('\n*** VerifySignRequest ***\n',
          reqVerifyJson.txins);
      console.log('\n*** VerifySign Failed. ***\n');
    }

    try {
      let verifyHashType = hashType;
      if ((hashType === 'p2sh-p2wpkh') || (hashType === 'p2sh-p2wsh')) {
        verifyHashType = hashType.substring(5);
      }
      const rawSignatureRet = cfdjs.DecodeDerSignatureToRaw({
        signature: sigRet.signatureList[0].signature,
      });
      const verifySig = cfdjs.VerifySignature({
        tx: blindTx2.hex,
        isElements: true,
        txin: {
          txid: sigRet.signatureList[0].utxoData.txid,
          vout: sigRet.signatureList[0].utxoData.vout,
          signature: rawSignatureRet.signature,
          pubkey: pubkey3,
          redeemScript: redeemScript,
          hashType: verifyHashType,
          sighashType: 'all',
          amount: utxo.amount,
          confidentialValueCommitment: utxo.value,
        },
      });
      console.log('verifySigRet =', verifySig);
    } catch (e) {
      console.log('verifySignature fail.');
      console.warn(e);
    }
  }
};
example();
