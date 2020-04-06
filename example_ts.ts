/* eslint-disable require-jsdoc */
import * as cfdjs from 'cfd-js';
import {LedgerLiquidWrapper, WalletUtxoData, SignatureData} from './src/ledger-liquid-lib';
import * as ledgerLibDefine from './src/ledger-liquid-lib-defines';

process.on('unhandledRejection', console.dir);

let hashType = 'p2sh-p2wpkh'; // 'p2sh-p2wsh';
const blindOpt = {blind1: true, blind2: true};
let networkType = ledgerLibDefine.NetworkType.LiquidV1;
// eslint-disable-next-line prefer-const
let tx2InputCount = 2;
// eslint-disable-next-line prefer-const
let ignore1stCache = false;
let addSignAddr4 = true;
let signedTest = false;
let signedAddTest = false;
let setIssueTx = false;
let setReissueTx = false;
let authorizationPrivkey = '47ab8b0e5f8ea508808f9e03b804d623a7cb81cbf1f39d3e976eb83f9284ecde';
let setAuthorization = false;
let connectionTest = false;
let mnemonic = '';
// mnemonic = 'call node debug-console.js ledger hood festival pony outdoor always jeans page help symptom adapt obtain image bird duty damage find sense wasp box mail vapor plug general kingdom';
let txData = '';
let signTarget = '';
let fixedTest = false;

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
    } else if (process.argv[i] === '-tc') {
      connectionTest = true;
    } else if (process.argv[i] === '-a') {
      setAuthorization = true;
    } else if (process.argv[i] === '-i') {
      setIssueTx = true;
    } else if (process.argv[i] === '-r') {
      setReissueTx = true;
    } else if (process.argv[i] === '-f') {
      fixedTest = true;
    } else if (i+1 < process.argv.length) {
      if (process.argv[i] === '-h') {
        ++i;
        hashType = process.argv[i];
      } else if (process.argv[i] === '-ak') {
        ++i;
        if (process.argv[i].length === 64) {
          authorizationPrivkey = process.argv[i];
        }
      } else if (process.argv[i] === '-n') {
        ++i;
        mnemonic = process.argv[i];
      } else if (process.argv[i] === '-txc') {
        ++i;
        txData = process.argv[i];
      } else if (process.argv[i] === '-st') {
        ++i;
        signTarget = process.argv[i];
      }
    }
  }
}

const sleep = (msec: number) => new Promise(
    (resolve) => setTimeout(resolve, msec));

async function execSign(txHex: string,
    signUtxoList: WalletUtxoData[], mnemonicWords: string): Promise<string> {
  let sigRet;
  const liquidLib = new LedgerLiquidWrapper(networkType);
  let parentExtkey = '';
  const mainchainNwType = (networkType === 'liquidv1') ? 'mainnet' : 'regtest';
  if (!mnemonicWords) {
    // connect wait test
    const connRet = await liquidLib.connect(60, '');
    if (!connRet.success) {
      console.log('connection failed. ', connRet);
      return '';
    }

    // get authorization start ---------------------------------
    console.log('*** calc authorization start ***');
    const authorizationHash = cfdjs.SerializeLedgerFormat({
      tx: txHex,
      isAuthorization: true,
    });
    console.log('SerializeLedgerFormat =', authorizationHash);

    const authSig = cfdjs.CalculateEcSignature({
      sighash: authorizationHash.sha256,
      privkeyData: {
        privkey: authorizationPrivkey,
        wif: false,
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

    console.log('*** walletUtxoList ***', signUtxoList);
    console.log('*** getSignature start. ***');
    sigRet = await liquidLib.getSignature(txHex,
        signUtxoList, authDerSig);
    console.log(`*** getSignature end. ***`,
        JSON.stringify(sigRet, (key, value) =>
            typeof value === 'bigint' ? value.toString() : value, '  '));
  } else {
    const seed = cfdjs.ConvertMnemonicToSeed({
      mnemonic: mnemonicWords.split(' '),
      passphrase: '',
    });
    parentExtkey = cfdjs.CreateExtkeyFromSeed({
      seed: seed.seed,
      network: mainchainNwType,
      extkeyType: 'extPrivkey',
    }).extkey;

    console.log('*** walletUtxoList ***', signUtxoList);
    console.log('*** getSignature start. ***');
    const signatureList: SignatureData[] = [];
    for (const utxoData of signUtxoList) {
      const extkey = cfdjs.CreateExtkeyFromParentPath({
        extkey: parentExtkey,
        extkeyType: 'extPrivkey',
        network: mainchainNwType,
        path: utxoData.bip32Path,
      });
      const pubkey = cfdjs.GetPubkeyFromExtkey({
        extkey: extkey.extkey,
        network: mainchainNwType,
      });
      const privkey = cfdjs.GetPrivkeyFromExtkey({
        extkey: extkey.extkey,
        wif: false,
        isCompressed: false,
        network: mainchainNwType,
      });
      const descriptor = (utxoData.descriptor) ? utxoData.descriptor : '';
      const desc = cfdjs.ParseDescriptor({
        isElements: true,
        descriptor: descriptor,
        network: networkType,
      });
      let redeemScript = '';
      let signHashType = hashType;
      if ((desc.scripts) && (desc.scripts.length > 0)) {
        if ('redeemScript' in desc.scripts[desc.scripts.length - 1]) {
          const scriptRef = desc.scripts[desc.scripts.length - 1];
          redeemScript = (scriptRef.redeemScript) ? scriptRef.redeemScript : '';
        }
        signHashType = desc.scripts[0].hashType;
      }
      if (signHashType === 'p2sh-p2wpkh') {
        signHashType = 'p2wpkh';
      } else if (signHashType === 'p2sh-p2wsh') {
        signHashType = 'p2wsh';
      }
      const sighash = cfdjs.CreateElementsSignatureHash({
        tx: txHex,
        txin: {
          txid: utxoData.txid,
          vout: utxoData.vout,
          hashType: signHashType,
          keyData: {
            hex: (!redeemScript) ? pubkey.pubkey : redeemScript,
            type: (!redeemScript) ? 'pubkey' : 'redeem_script',
          },
          amount: utxoData.amount,
          confidentialValueCommitment: utxoData.valueCommitment,
        },
      });
      const signature = cfdjs.CalculateEcSignature({
        sighash: sighash.sighash,
        privkeyData: {
          privkey: privkey.privkey,
          wif: false,
        },
        isGrindR: true,
      });
      const derSig = cfdjs.EncodeSignatureByDer({
        signature: signature.signature,
        sighashType: 'all',
      });
      signatureList.push({
        utxoData: utxoData,
        signature: derSig.signature,
      });
    }
    sigRet = {
      signatureList: signatureList,
    };
    console.log(`*** getSignature end. ***`,
        JSON.stringify(sigRet, (key, value) =>
            typeof value === 'bigint' ? value.toString() : value, '  '));
  }

  const signatureList = [{
    txid: '',
    vout: 0,
    hashType: '',
    redeemScript: '',
    utxoData: signUtxoList[0],
    address: '',
    sigList: [{
      signature: '',
      pubkey: '',
    }],
  }];
  for (const signatureData of sigRet.signatureList) {
    const descriptor = (signatureData.utxoData.descriptor) ? signatureData.utxoData.descriptor : '';
    let desc;
    try {
      desc = cfdjs.ParseDescriptor({
        isElements: true,
        descriptor: descriptor,
        network: networkType,
      });
    } catch (e) {

    }
    let pubkeyData;
    if (!mnemonicWords) {
      const pubkeyRet = await await liquidLib.getWalletPublicKey(
          signatureData.utxoData.bip32Path);
      pubkeyData = pubkeyRet.publicKey;
    } else {
      const extkey = cfdjs.CreateExtkeyFromParentPath({
        extkey: parentExtkey,
        extkeyType: 'extPubkey',
        network: mainchainNwType,
        path: signatureData.utxoData.bip32Path,
      });
      const pubkey = cfdjs.GetPubkeyFromExtkey({
        extkey: extkey.extkey,
        network: mainchainNwType,
      });
      pubkeyData = pubkey.pubkey;
    }
    let redeemScript = '';
    let sigHashType = hashType;
    if ((desc) && (desc.scripts) && (desc.scripts.length > 0)) {
      if ('redeemScript' in desc.scripts[desc.scripts.length - 1]) {
        const scriptRef = desc.scripts[desc.scripts.length - 1];
        redeemScript = (scriptRef.redeemScript) ? scriptRef.redeemScript : '';
      }
      sigHashType = desc.scripts[0].hashType;
    } else {
      // const sighashByte = Buffer.from(signatureData.signature, 'hex');
      redeemScript = (signatureData.utxoData.redeemScript) ? signatureData.utxoData.redeemScript : '';
      sigHashType = (!redeemScript) ? 'p2wpkh' : 'p2wsh';
    }
    let verifyHashType = sigHashType;
    if (verifyHashType === 'p2sh-p2wpkh') {
      verifyHashType = 'p2wpkh';
    } else if (verifyHashType === 'p2sh-p2wsh') {
      verifyHashType = 'p2wsh';
    }
    try {
      const rawSignatureRet = cfdjs.DecodeDerSignatureToRaw({
        signature: signatureData.signature,
      });
      const verifySig = cfdjs.VerifySignature({
        tx: txHex,
        isElements: true,
        txin: {
          txid: signatureData.utxoData.txid,
          vout: signatureData.utxoData.vout,
          signature: rawSignatureRet.signature,
          pubkey: pubkeyData,
          redeemScript: redeemScript,
          hashType: verifyHashType,
          sighashType: 'all',
          amount: signatureData.utxoData.amount,
          confidentialValueCommitment: signatureData.utxoData.valueCommitment,
        },
      });
      console.log('verifySigRet =', verifySig);
    } catch (e) {
      console.log('verifySignature fail. =',
          JSON.stringify(signatureData, (key, value) =>
              typeof value === 'bigint' ? value.toString() : value, '  '));
      console.warn(e);
    }
    let isFind = false;
    for (const sigTarget of signatureList) {
      if ((sigTarget.txid === signatureData.utxoData.txid) &&
        (sigTarget.vout === signatureData.utxoData.vout)) {
        sigTarget.sigList.push({
          signature: signatureData.signature,
          pubkey: pubkeyData,
        });
        isFind = true;
        break;
      }
    }
    if (!isFind) {
      signatureList.push({
        txid: signatureData.utxoData.txid,
        vout: signatureData.utxoData.vout,
        hashType: sigHashType,
        redeemScript: redeemScript,
        utxoData: signatureData.utxoData,
        address: (desc && desc.address) ? desc.address : '',
        sigList: [{
          signature: signatureData.signature,
          pubkey: pubkeyData,
        }],
      });
    }
  }
  let tx = txHex;
  const signTxins = [];
  for (const sigData of signatureList) {
    if (!sigData.txid) continue;
    if (!sigData.address) continue;
    let signedTx;
    if (!sigData.redeemScript) {
      signedTx = cfdjs.AddPubkeyHashSign({
        tx: tx,
        isElements: true,
        txin: {
          txid: sigData.txid,
          vout: sigData.vout,
          signParam: {
            hex: sigData.sigList[0].signature,
            derEncode: false,
          },
          pubkey: sigData.sigList[0].pubkey,
          hashType: sigData.hashType,
        },
      });
    } else {
      const jsonParam = {
        tx: tx,
        isElements: true,
        txin: {
          txid: sigData.txid,
          vout: sigData.vout,
          signParams: [
            {
              hex: sigData.sigList[0].signature,
              derEncode: false,
              relatedPubkey: sigData.sigList[0].pubkey,
            },
          ],
          redeemScript: (hashType === 'p2sh') ? sigData.redeemScript : '',
          witnessScript: (hashType === 'p2sh') ? '' : sigData.redeemScript,
          hashType: hashType,
        },
      };
      for (let i = 1; i < sigData.sigList.length; ++i) {
        jsonParam.txin.signParams.push({
          hex: sigData.sigList[i].signature,
          derEncode: false,
          relatedPubkey: sigData.sigList[i].pubkey,
        });
      }
      // console.log('jsonParam => ', JSON.stringify(jsonParam, null, '  '));
      signedTx = cfdjs.AddMultisigSign(jsonParam);
    }
    signTxins.push({
      txid: sigData.txid,
      vout: sigData.vout,
      address: sigData.address,
      amount: sigData.utxoData.amount,
      descriptor: sigData.utxoData.descriptor,
      confidentialValueCommitment: sigData.utxoData.valueCommitment,
    });
    tx = signedTx.hex;
  }
  const reqVerifyJson = {
    tx: tx,
    isElements: true,
    txins: signTxins,
  };
  if (signTxins.length > 0) {
    const verifyRet = cfdjs.VerifySign(reqVerifyJson);
    console.log('\n*** VerifySign ***\n', JSON.stringify(verifyRet, null, '  '));
  }

  return tx;
}

async function signTest() {
  // parse signTarget -> WalletUtxoData
  const utxoList = signTarget.split(' ');
  const utxoDataList: WalletUtxoData[] = [];
  for (const utxoText of utxoList) {
    const infoList = utxoText.split(':');
    utxoDataList.push({
      bip32Path: infoList[0],
      txid: infoList[1],
      vout: parseInt(infoList[2]),
      amount: (infoList[3].length === 66) ? 0n : BigInt(infoList[3]),
      valueCommitment: (infoList[3].length === 66) ? infoList[3] : '',
      descriptor: infoList[4],
    });
  }

  const tx = await execSign(txData, utxoDataList, '');
  console.log('*** signed tx ***\n', tx);
  if (mnemonic) {
    const tx = await execSign(txData, utxoDataList, mnemonic);
    console.log('*** mnemonic signed tx ***\n', tx);
  }
}

async function example() {
  const addrType = ledgerLibDefine.AddressType.Bech32;

  const pubkeyHashType = 'p2sh-p2wpkh';
  const asset1 = '5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225';

  if (setReissueTx) {
    tx2InputCount = 2;
    blindOpt.blind1 = true;
    blindOpt.blind2 = true;
  }

  // connect wait test
  const liquidLib = new LedgerLiquidWrapper(networkType);
  if (connectionTest) {
    let connRet = await liquidLib.connect(60, '');
    if (!connRet.success) {
      console.log('connection fail.(1)', connRet);
      return;
    }
    for (let connTestCount = 0; connTestCount < 120; ++connTestCount) {
      const connCheckRet = await liquidLib.isConnected();
      if (connCheckRet.success) {
        console.log('10 sec wait start.');
        await sleep(10000);
        console.log('10 sec wait end.');
        connTestCount += 10;
      } else if (connCheckRet.errorMessage === 'connection fail.') {
        console.log('disconnect. start reconnection.');
        connRet = await liquidLib.connect(60, '');
        if (!connRet.success) {
          console.log('connection fail. ', connRet);
          break;
        }
        console.log('reconnect success.');
      } else {
        console.log('isConnected fail.(2)', connCheckRet);
        break;
      }
      await sleep(1000);
    }

    return;
  }

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
  const PATH11 = '44\'/0\'/0\'/0/11';
  const PATH12 = '44\'/0\'/0\'/0/12';
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
  console.log('addr4 =', addr4);
  const addr11 = await liquidLib.getAddress(PATH11, addrType);
  console.log('addr11 =', addr11);
  const addr12 = await liquidLib.getAddress(PATH12, addrType);
  console.log('addr12 =', addr12);

  const pubkey1 = addr1.publicKey;
  const pubkey2 = addr2.publicKey;
  let pubkey3 = addr3.publicKey;
  const pubkey4 = addr4.publicKey;
  console.log('pubkey1 => ', pubkey1);
  console.log('pubkey2 => ', pubkey2);
  console.log('pubkey3 => ', pubkey3);
  console.log('pubkey4 => ', pubkey4);

  if (setAuthorization) {
    const authKey = cfdjs.GetPubkeyFromPrivkey({
      privkey: authorizationPrivkey,
      isCompressed: false,
    });
    const setupRet = await liquidLib.setupHeadlessAuthorization(authKey.pubkey);
    console.log('--HEADLESS LIQUID SEND AUTHORIZATION PUBLIC KEY --\n', setupRet);
  }

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

  const mainchainNwType = (networkType === 'liquidv1') ? 'mainnet' : 'regtest';
  let isScriptHash = false;
  let redeemScript;
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
      if (mnemonic.length > 0) {
        const seed = cfdjs.ConvertMnemonicToSeed({
          mnemonic: mnemonic.split(' '),
          passphrase: '',
        });
        const parentExtKey = cfdjs.CreateExtkeyFromSeed({
          seed: seed.seed,
          network: mainchainNwType,
          extkeyType: 'extPrivkey',
        });
        const extkey = cfdjs.CreateExtkeyFromParentPath({
          extkey: parentExtKey.extkey,
          network: mainchainNwType,
          extkeyType: 'extPrivkey',
          path: '44h/0h/0h/0/0',
        });
        const privkeyRet = cfdjs.GetPrivkeyFromExtkey({
          extkey: extkey.extkey,
          network: mainchainNwType,
          wif: false,
          isCompressed: true,
        });
        const pubkeyRet = cfdjs.GetPubkeyFromExtkey({
          extkey: extkey.extkey,
          network: mainchainNwType,
        });
        pubkey3 = pubkeyRet.pubkey;
        privkey3Hex = privkeyRet.privkey;
      }

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
  const blindingKey11 = '2d3bca15285584902e747d5570321eabe6acac7dadbc3a9093f5f8846bffee80';
  const confidentialKey11 = '038986c47b9d7ca1958b787e7d7299fa138499b8f191c81c0f2fc7e20211ec9b10';
  const ctAddr11 = cfdjs.GetConfidentialAddress({
    unblindedAddress: addr11.address,
    key: confidentialKey11,
  });
  console.log('ctAddr11 => ', ctAddr11);
  const blindingKey12 = '2641efcad9b6de678b5106e2fd2a93b34fd769b787e0bdb0f8f8ec13f7cc65c7';
  const confidentialKey12 = '02bdc76f7362d990c61a5ff9a339d1be69e84154b4a604339b425e36c5df394069';
  const ctAddr12 = cfdjs.GetConfidentialAddress({
    unblindedAddress: addr12.address,
    key: confidentialKey12,
  });
  console.log('ctAddr12 => ', ctAddr12);

  const inputAmount = 5050000n;
  const inputAmount2 = 5000000n;
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
    }],
    fee: {
      amount: 50000n,
      asset: asset1,
    },
  };
  if (!setReissueTx) {
    tx1Data.txouts.push({
      address: address4.address,
      amount: inputAmount2,
      asset: asset1,
    });
  }
  let tx1 = cfdjs.ElementsCreateRawTransaction(tx1Data);
  let issueData: cfdjs.IssuanceDataResponse = {
    txid: '',
    vout: 0,
    asset: '',
    entropy: '',
    token: '',
  };
  let issueToken = '';
  if (setReissueTx) {
    const issueRet = cfdjs.SetRawIssueAsset({
      tx: tx1.hex,
      issuances: [{
        txid: tx1Data.txins[0].txid,
        vout: tx1Data.txins[0].vout,
        assetAmount: inputAmount2,
        assetAddress: ctAddr11.confidentialAddress,
        tokenAmount: inputAmount2,
        tokenAddress: ctAddr4.confidentialAddress,
        contractHash: '0000000000000000000000000000000000000000000000000000000000000000',
        isRemoveNonce: false,
        isBlind: true,
      }],
      isRandomSortTxOut: false,
    });
    issueData = issueRet.issuances[0];
    tx1 = issueRet;
    if (issueData.token) {
      issueToken = issueData.token;
    }
    // console.log('issueTx =', tx1.hex);
  }
  if (blindOpt.blind1) {
    if (signedTest) {
      console.log('*** before blind rawtx1 ***\n', tx1.hex);
    }
    const blind1Data: cfdjs.BlindRawTransactionRequest = {
      tx: tx1.hex,
      txins: [{
        txid: tx1Data.txins[0].txid,
        vout: tx1Data.txins[0].vout,
        asset: asset1,
        blindFactor: '0000000000000000000000000000000000000000000000000000000000000000',
        assetBlindFactor: '0000000000000000000000000000000000000000000000000000000000000000',
        amount: inputAmount,
      }],
      txoutConfidentialAddresses: [
        ctAddr.confidentialAddress,
        ctAddr4.confidentialAddress,
      ],
      issuances: [],
    };
    if (setReissueTx && blind1Data.issuances) {
      blind1Data.issuances.push({
        txid: tx1Data.txins[0].txid,
        vout: tx1Data.txins[0].vout,
        assetBlindingKey: blindingKey11,
        tokenBlindingKey: blindingKey4,
      });
    }
    tx1 = cfdjs.BlindRawTransaction(blind1Data);
  }
  if (signedTest) {
    console.log('*** rawtx1 (ignore sign) ***\n', tx1.hex);
  }
  const dectx1 = cfdjs.ElementsDecodeRawTransaction({
    hex: tx1.hex, network: networkType,
    mainchainNetwork: mainchainNwType});
  console.log('*** blind dectx1 ***\n', JSON.stringify(dectx1, null, '  '));

  let valueCommitment = '';
  let valueCommitment2 = '';
  let input2Vout = 1;
  if (dectx1.vout) {
    valueCommitment = (!dectx1.vout[0].valuecommitment) ?
      '' : dectx1.vout[0].valuecommitment;
    valueCommitment2 = (!dectx1.vout[1].valuecommitment) ?
      '' : dectx1.vout[1].valuecommitment;
    if (setReissueTx) {
      valueCommitment2 = (!dectx1.vout[3].valuecommitment) ?
      '' : dectx1.vout[3].valuecommitment;
      input2Vout = 3;
    }
  }
  const utxo = {
    txid: dectx1.txid,
    vout: (!dectx1.vout) ? 0 : dectx1.vout[0].n,
    amount: tx1Data.txouts[0].amount,
    value: valueCommitment,
    descriptor: descriptor,
  };
  const utxo2 = {
    txid: dectx1.txid,
    vout: (!dectx1.vout) ? 0 : dectx1.vout[input2Vout].n,
    amount: inputAmount2,
    value: valueCommitment2,
    descriptor: descriptor4,
  };

  let outAmount1 = 4000000n;
  let outAmount2 = 950000n;
  if (tx2InputCount === 2) {
    outAmount1 = 9000000n;
  }
  if (setReissueTx) {
    outAmount1 = inputAmount - 50000n;
    outAmount2 = inputAmount2;
  }
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
      amount: outAmount1,
      asset: asset1,
    }, {
      address: address2.address,
      amount: outAmount2,
      asset: (setReissueTx) ? issueToken : asset1,
    }],
    fee: {
      amount: 50000n,
      asset: asset1,
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

  let blindTx2 = tx2;
  if (setIssueTx) {
    const issueRet = cfdjs.SetRawIssueAsset({
      tx: tx2.hex,
      issuances: [{
        txid: tx2Data.txins[0].txid,
        vout: tx2Data.txins[0].vout,
        assetAmount: inputAmount2,
        assetAddress: ctAddr11.confidentialAddress,
        tokenAmount: inputAmount2,
        tokenAddress: ctAddr12.confidentialAddress,
        contractHash: '0000000000000000000000000000000000000000000000000000000000000000',
        isBlind: true,
      }],
      isRandomSortTxOut: false,
    });
    blindTx2 = issueRet;
  }
  console.log('*** tx2 ***\n', tx2);

  if (blindOpt.blind2) {
    const unblindTxOut = [{
      asset: tx1Data.txouts[0].asset,
      blindFactor: '0000000000000000000000000000000000000000000000000000000000000000',
      assetBlindFactor: '0000000000000000000000000000000000000000000000000000000000000000',
      amount: tx1Data.txouts[0].amount,
    }, {
      asset: (setReissueTx) ? issueToken : asset1,
      blindFactor: '0000000000000000000000000000000000000000000000000000000000000000',
      assetBlindFactor: '0000000000000000000000000000000000000000000000000000000000000000',
      amount: inputAmount2,
    }];
    if (blindOpt.blind1) {
      const unblindData = cfdjs.UnblindRawTransaction({
        tx: tx1.hex,
        txouts: [{
          index: 0,
          blindingKey: blindingKey,
        }, {
          index: (setReissueTx) ? 3 : 1,
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
    if (setReissueTx) {
      const reissueRet = cfdjs.SetRawReissueAsset({
        tx: blindTx2.hex,
        issuances: [{
          txid: tx2Data.txins[1].txid,
          vout: tx2Data.txins[1].vout,
          amount: inputAmount2,
          address: ctAddr11.confidentialAddress,
          assetBlindingNonce: unblindTxOut[1].assetBlindFactor,
          assetEntropy: issueData.entropy,
        }],
        isRandomSortTxOut: false,
      });
      blindTx2 = reissueRet;
    }
    console.log('*** before blind tx2 ***\n', blindTx2);

    const blindReqData: cfdjs.BlindRawTransactionRequest = {
      tx: blindTx2.hex,
      txins: [{
        txid: tx2Data.txins[0].txid,
        vout: tx2Data.txins[0].vout,
        asset: unblindTxOut[0].asset,
        blindFactor: unblindTxOut[0].blindFactor,
        assetBlindFactor: unblindTxOut[0].assetBlindFactor,
        amount: unblindTxOut[0].amount,
      }],
      txoutConfidentialAddresses: [
        ctAddr1.confidentialAddress,
        ctAddr2.confidentialAddress,
      ],
      issuances: [],
    };
    if ((tx2InputCount === 2) && (blindReqData.txins)) {
      blindReqData.txins.push({
        txid: tx2Data.txins[1].txid,
        vout: tx2Data.txins[1].vout,
        asset: unblindTxOut[1].asset,
        blindFactor: unblindTxOut[1].blindFactor,
        assetBlindFactor: unblindTxOut[1].assetBlindFactor,
        amount: unblindTxOut[1].amount,
      });
    }
    if (setIssueTx && blindReqData.issuances) {
      blindReqData.issuances.push({
        txid: tx2Data.txins[0].txid,
        vout: tx2Data.txins[0].vout,
        assetBlindingKey: blindingKey11,
        tokenBlindingKey: blindingKey12,
      });
    } else if (setReissueTx && blindReqData.issuances) {
      blindReqData.issuances.push({
        txid: tx2Data.txins[1].txid,
        vout: tx2Data.txins[1].vout,
        assetBlindingKey: blindingKey11,
        tokenBlindingKey: blindingKey11,
      });
    }
    blindTx2 = cfdjs.BlindRawTransaction(blindReqData);
  }

  // console.log('*** Blind ***\n', tx2);
  const dectx2 = cfdjs.ElementsDecodeRawTransaction({
    hex: blindTx2.hex, network: networkType,
    mainchainNetwork: mainchainNwType});
  console.log('*** blind dectx2 ***\n', JSON.stringify(dectx2, null, '  '));

  if (signedTest) {
    console.log('*** before sign rawtx ***\n', blindTx2.hex);
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
    let walletUtxoList = [{
      bip32Path: PATH3,
      txid: utxo.txid,
      vout: utxo.vout,
      amount: utxo.amount,
      valueCommitment: utxo.value,
      redeemScript: redeemScript,
      descriptor: utxo.descriptor,
    }];
    if (!isScriptHash && (tx2InputCount === 2) && addSignAddr4) {
      if (ignore1stCache) {
        walletUtxoList = [];
      }
      walletUtxoList.push({
        bip32Path: PATH4,
        txid: utxo2.txid,
        vout: utxo2.vout,
        amount: utxo2.amount,
        valueCommitment: utxo2.value,
        redeemScript: '',
        descriptor: utxo2.descriptor,
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
        descriptor: utxo.descriptor,
      }, {
        bip32Path: PATH2,
        txid: utxo.txid,
        vout: utxo.vout,
        amount: utxo.amount,
        valueCommitment: utxo.value,
        redeemScript: redeemScript,
        descriptor: utxo.descriptor,
      }];
    }
    const txHex = await execSign(blindTx2.hex, walletUtxoList, '');
    console.log('*** signed tx hex ***\n', txHex);
    if (mnemonic) {
      const tx = await execSign(blindTx2.hex, walletUtxoList, mnemonic);
      console.log('*** mnemonic signed tx ***\n', tx);
    }
  }
};

async function execFixedTest() {
  const txHex = '020000000002d026a265c15a249d6c7ae5fa7421904925438c6721b44339e25839479ec89a850000000000ffffffffd026a265c15a249d6c7ae5fa7421904925438c6721b44339e25839479ec89a850100000000ffffffff030125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100000000008954400017a91492617485a7b6816675a8f9d450a36f442692dd77870125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100000000000e7ef00017a914e5f656cd3ce7597eab209b4c9314e974eec2a86b870125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a01000000000000c350000000000000';

  let signedTx = cfdjs.SignWithPrivkey({
    tx: txHex,
    isElements: true,
    txin: {
      txid: '859ac89e473958e23943b421678c432549902174fae57a6c9d245ac165a226d0',
      vout: 0,
      privkey: '80fabf46d8e9dd12fc59299f61a7638bac33d7d125677a37bcb4b3a0e32bb23f',
      amount: 5000000n,
      hashType: 'p2wpkh',
    },
  });
  signedTx = cfdjs.SignWithPrivkey({
    tx: signedTx.hex,
    isElements: true,
    txin: {
      txid: '859ac89e473958e23943b421678c432549902174fae57a6c9d245ac165a226d0',
      vout: 1,
      privkey: '80fabf46d8e9dd12fc59299f61a7638bac33d7d125677a37bcb4b3a0e32bb23f',
      amount: 5000000n,
      hashType: 'p2wpkh',
    },
  });
  const decSignedTx = cfdjs.ElementsDecodeRawTransaction({
    hex: signedTx.hex, network: networkType,
    mainchainNetwork: (networkType === 'liquidv1') ? 'mainnet' : 'regtest'});
  console.log('signed hex =\n',
      JSON.stringify(decSignedTx, null, '  '));
}

if (fixedTest) {
  execFixedTest();
} else if ((!signTarget) && (!txData)) {
  example();
} else {
  signTest();
}
