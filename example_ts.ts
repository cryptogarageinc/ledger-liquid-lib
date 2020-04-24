/* eslint-disable require-jsdoc */
import * as cfdjs from 'cfd-js';
import {LedgerLiquidWrapper, WalletUtxoData, SignatureData, NetworkType, AddressType} from './src/ledger-liquid-lib';

process.on('unhandledRejection', console.dir);

let hashType = 'p2sh-p2wpkh'; // 'p2sh-p2wsh';
const blindOpt = {blind1: true, blind2: true};
let networkType = NetworkType.LiquidV1;
// eslint-disable-next-line prefer-const
let tx2InputCount = 2;
// eslint-disable-next-line prefer-const
let signTargetIndex = [0, 1];
let signedTest = false;
let setIssueTx = 0;
let setReissueTx = 0;
let authorizationPrivkey = '47ab8b0e5f8ea508808f9e03b804d623a7cb81cbf1f39d3e976eb83f9284ecde';
let setAuthorization = false;
let authPubKey = ''; // 04b85b0e5f5b41f1a95bbf9a83edd95c741223c6d9dc5fe607de18f015684ff56ec359705fcf9bbeb1620fb458e15e3d99f23c6f5df5e91e016686371a65b16f0c
let setIssuanceToTop = 0;
let setReissuanceToTop = 0;
let connectionTest = false;
let connectDevice = '';
let getLedgerPath = true;
let mnemonic = '';
let mnemonicCheck = true;
// mnemonic = 'call node debug-console.js ledger hood festival pony outdoor always jeans page help symptom adapt obtain image bird duty damage find sense wasp box mail vapor plug general kingdom';
let dumpTx = false;
let txData = '';
let signTarget = '';
let fixedTest = false;
let waitCancelCount = 0;
let currentWaitCancelCount = 0;
let dumpPubkeyMode = false;
let targetBip32Path = 'm/44h/0h/0h';
let asyncConnectCheck = false;

for (let i = 2; i < process.argv.length; i++) {
  if (process.argv[i]) {
    if (process.argv[i] === '-r') {
      networkType = NetworkType.Regtest;
    } else if (process.argv[i] === '-nb1') {
      blindOpt.blind1 = false;
    } else if (process.argv[i] === '-nb2') {
      blindOpt.blind2 = false;
    } else if (process.argv[i] === '-dl') {
      getLedgerPath = false;
    } else if (process.argv[i] === '-t') {
      signedTest = true;
    } else if (process.argv[i] === '-tc') {
      connectionTest = true;
    } else if (process.argv[i] === '-a') {
      setAuthorization = true;
    } else if (process.argv[i] === '-dp') {
      dumpPubkeyMode = true;
    } else if (process.argv[i] === '-f') {
      fixedTest = true;
    } else if (process.argv[i] === '-p') {
      dumpTx = true;
    } else if (process.argv[i] === '-tcwc') {
      waitCancelCount = 30;
    } else if (process.argv[i] === '-acc') {
      asyncConnectCheck = true;
    } else if (process.argv[i] === '-it') {
      setIssuanceToTop = 2;
      if (setReissuanceToTop) {
        setIssuanceToTop = 1;
      }
    } else if (process.argv[i] === '-rit') {
      setReissuanceToTop = 2;
      if (setIssuanceToTop) {
        setReissuanceToTop = 1;
      }
    } else if (process.argv[i] === '-ic') {
      mnemonicCheck = false;
      getLedgerPath = false;
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
        getLedgerPath = false;
      } else if (process.argv[i] === '-txc') {
        ++i;
        txData = process.argv[i];
      } else if (process.argv[i] === '-st') {
        ++i;
        signTarget = process.argv[i];
      } else if (process.argv[i] === '-uc') {
        ++i;
        tx2InputCount = parseInt(process.argv[i]);
      } else if (process.argv[i] === '-i') {
        ++i;
        setIssueTx = parseInt(process.argv[i]);
      } else if (process.argv[i] === '-ri') {
        ++i;
        setReissueTx = parseInt(process.argv[i]);
      } else if (process.argv[i] === '-si') {
        ++i;
        const numArr = [];
        const list = process.argv[i].split(',');
        for (const input of list) {
          numArr.push(parseInt(input));
        }
        signTargetIndex = numArr;
      } else if (process.argv[i] === '-cd') {
        ++i;
        connectDevice = process.argv[i];
      } else if (process.argv[i] === '-path') {
        ++i;
        targetBip32Path = process.argv[i];
      } else if (process.argv[i] === '-apk') {
        ++i;
        authPubKey = process.argv[i];
      }
    }
  }
}

const sleep = (msec: number) => new Promise(
    (resolve) => setTimeout(resolve, msec));

let mnemonicRootKey = '';
function getExtKeyFromParent(bip32Path: string): string {
  const mainchainNwType = (networkType === 'liquidv1') ? 'mainnet' : 'regtest';
  if (!mnemonicRootKey) {
    const seed = cfdjs.ConvertMnemonicToSeed({
      mnemonic: mnemonic.split(' '),
      passphrase: '',
    });
    mnemonicRootKey = cfdjs.CreateExtkeyFromSeed({
      seed: seed.seed,
      network: mainchainNwType,
      extkeyType: 'extPrivkey',
    }).extkey;
  }
  const extkey = cfdjs.CreateExtkeyFromParentPath({
    extkey: mnemonicRootKey,
    extkeyType: 'extPubkey',
    path: bip32Path,
    network: mainchainNwType,
  });
  return extkey.extkey;
}

function getPubkeyFromParent(bip32Path: string): string {
  const mainchainNwType = (networkType === 'liquidv1') ? 'mainnet' : 'regtest';
  if (!mnemonicRootKey) {
    const seed = cfdjs.ConvertMnemonicToSeed({
      mnemonic: mnemonic.split(' '),
      passphrase: '',
    });
    mnemonicRootKey = cfdjs.CreateExtkeyFromSeed({
      seed: seed.seed,
      network: mainchainNwType,
      extkeyType: 'extPrivkey',
    }).extkey;
  }
  const extkey = cfdjs.CreateExtkeyFromParentPath({
    extkey: mnemonicRootKey,
    extkeyType: 'extPubkey',
    path: bip32Path,
    network: mainchainNwType,
  });
  const pubkey = cfdjs.GetPubkeyFromExtkey({
    extkey: extkey.extkey,
    network: mainchainNwType,
  });
  return pubkey.pubkey;
}

interface KeyPair {
  pubkey: string;
  privkey: string;
}
function getKeyPairFromParent(bip32Path: string): KeyPair {
  const mainchainNwType = (networkType === 'liquidv1') ? 'mainnet' : 'regtest';
  if (!mnemonicRootKey) {
    const seed = cfdjs.ConvertMnemonicToSeed({
      mnemonic: mnemonic.split(' '),
      passphrase: '',
    });
    mnemonicRootKey = cfdjs.CreateExtkeyFromSeed({
      seed: seed.seed,
      network: mainchainNwType,
      extkeyType: 'extPrivkey',
    }).extkey;
  }
  const extkey = cfdjs.CreateExtkeyFromParentPath({
    extkey: mnemonicRootKey,
    extkeyType: 'extPrivkey',
    path: bip32Path,
    network: mainchainNwType,
  });
  const privkey = cfdjs.GetPrivkeyFromExtkey({
    extkey: extkey.extkey,
    network: mainchainNwType,
    wif: false,
  });
  const pubkey = cfdjs.GetPubkeyFromExtkey({
    extkey: extkey.extkey,
    network: mainchainNwType,
  });
  return {pubkey: pubkey.pubkey, privkey: privkey.privkey};
}

async function execSign(liquidLib: LedgerLiquidWrapper, txHex: string,
    signUtxoList: WalletUtxoData[], mnemonicWords: string): Promise<string> {
  let sigRet;
  let parentExtkey = '';
  const mainchainNwType = (networkType === 'liquidv1') ? 'mainnet' : 'regtest';
  if (!mnemonicWords) {
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
      const utxoAmount = (utxoData.amount) ? BigInt(utxoData.amount) : 0n;
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
          amount: utxoAmount,
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
    requireNum: 0,
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
    let requireNum = 2;
    if ((desc) && (desc.scripts) && (desc.scripts.length > 0)) {
      if ('redeemScript' in desc.scripts[desc.scripts.length - 1]) {
        const scriptRef = desc.scripts[desc.scripts.length - 1];
        redeemScript = (scriptRef.redeemScript) ? scriptRef.redeemScript : '';
        requireNum = (scriptRef.reqNum) ? scriptRef.reqNum : requireNum;
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
      const utxoAmount = (signatureData.utxoData.amount) ?
          BigInt(signatureData.utxoData.amount) : 0n;
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
          amount: utxoAmount,
          confidentialValueCommitment: signatureData.utxoData.valueCommitment,
        },
      });
      console.log('verifySigRet =', verifySig);
    } catch (e) {
      console.log('verifySignature fail. =',
          JSON.stringify(signatureData, (key, value) =>
              typeof value === 'bigint' ? value.toString() : value, '  '));
      console.log(e);
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
        requireNum: requireNum,
      });
    }
  }
  let tx = txHex;
  const signTxins = [];
  for (const sigData of signatureList) {
    if (!sigData.txid) continue;
    if (!sigData.address) continue;
    const utxoAmount = (sigData.utxoData.amount) ?
        BigInt(sigData.utxoData.amount) : 0n;
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
      for (let i = 1; i < sigData.requireNum; ++i) {
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
      amount: utxoAmount,
      descriptor: sigData.utxoData.descriptor,
      confidentialValueCommitment: sigData.utxoData.valueCommitment,
    });
    tx = signedTx.hex;
    if (signedTest) {
      console.log('*** sign tx ***\n', tx);
    }
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

  const liquidLib = new LedgerLiquidWrapper(networkType);
  const connRet = await liquidLib.connect(0, '');
  if (!connRet.success) {
    console.log('connection failed. ', connRet);
    return '';
  }
  const tx = await execSign(liquidLib, txData, utxoDataList, '');
  console.log('*** signed tx ***\n', tx);
  if (mnemonic) {
    const tx = await execSign(liquidLib, txData, utxoDataList, mnemonic);
    console.log('*** mnemonic signed tx ***\n', tx);
  }
  await liquidLib.disconnect();
}

let isConnectCheck = false;
async function checkConnecting(lib: LedgerLiquidWrapper) {
  if (isConnectCheck) {
    const connCheckRet = await lib.isConnected();
    if (connCheckRet.success) {
      console.log('isConnected : connect');
    } else if (connCheckRet.disconnect) {
      console.log('isConnected : disconnect');
    } else {
      console.log('isConnected fail: ', connCheckRet);
    }
    setTimeout(async () => {
      await checkConnecting(lib);
    }, 1000);
  }
}

async function cancelWaiting(lib: LedgerLiquidWrapper) {
  if (currentWaitCancelCount) {
    --currentWaitCancelCount;
    if (currentWaitCancelCount) {
      setTimeout(async () => {
        await cancelWaiting(lib);
      }, 1000);
    } else {
      lib.cancelConnect();
      console.log('cancel waiting.');
    }
  }
}

async function execConnectionTest() {
  // connect wait test
  const liquidLib = new LedgerLiquidWrapper(networkType);
  if (waitCancelCount) {
    currentWaitCancelCount = waitCancelCount;
    setTimeout(async () => {
      await cancelWaiting(liquidLib);
    }, 1000);
  }
  const devListResult = await liquidLib.getDeviceList();
  if (devListResult.success) {
    for (const desc of devListResult.deviceList) {
      console.log('connect device :', desc);
    }
  } else {
    console.log('getDeviceList error. ', devListResult);
  }

  let connRet = await liquidLib.connect(60, connectDevice);
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
      connRet = await liquidLib.connect(60, connectDevice);
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
  await liquidLib.disconnect();
}

async function example() {
  const addrType = AddressType.Bech32;

  const asset1 = '5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225';

  if (tx2InputCount < 2) {
    tx2InputCount = 2;
  }
  if (!getLedgerPath && !mnemonic) {
    getLedgerPath = true;
  }

  // connect wait test
  const liquidLib = new LedgerLiquidWrapper(networkType);
  const connRet = await liquidLib.connect(0, '');
  if (!connRet.success) {
    console.log('connection failed. ', connRet);
    return;
  }

  const mainchainNwType = (networkType === 'liquidv1') ? 'mainnet' : 'regtest';
  const parentPath = '44\'/0\'/0\'/0';
  const childNumber = 0;
  const childPath = parentPath + '/' + childNumber;
  const parentPubkey = await liquidLib.getWalletPublicKey(parentPath);
  console.log('parentPubkey -> ', parentPubkey);

  const extkey = cfdjs.CreateExtkeyFromParentKey({
    network: mainchainNwType,
    parentKey: parentPubkey.publicKey,
    parentDepth: 4,
    parentChainCode: parentPubkey.chainCode,
    childNumber: childNumber,
  });
  console.log('childExtkey =', extkey);
  const keyInfo = cfdjs.GetExtkeyInfo(extkey);
  console.log('childExtkeyInfo =', keyInfo);

  const xpub = await liquidLib.getXpubKey('44\'/0\'/0\'');
  console.log('getXpubKey =', xpub);

  const xpub2 = await liquidLib.getXpubKey('m/44\'/0\'/0\'');
  console.log('getXpubKey2 =', xpub2);

  const legacyLockingScript = liquidLib.getPublicKeyRedeemScript(
      parentPubkey.publicKey);
  console.log('legacyLockingScript =', legacyLockingScript);

  const addrData = await liquidLib.getAddress('m/44\'/0\'/0\'', addrType);
  console.log('getAddress =', addrData);

  let directMnemonic = false;
  if (mnemonic) {
    const mnemonicExtPubkey = getExtKeyFromParent(childPath);
    if (extkey.extkey !== mnemonicExtPubkey) {
      if (mnemonicCheck) {
        console.log('unmatch mnemonic. extPubkey =', mnemonicExtPubkey);
        return;
      }
      directMnemonic = true;
    }
  }

  interface PubkeySet {
    bip32Path: string;
    pubkey: string;
  }
  interface PathData {
    bip32Path: string;
    pubkey: string;
    pubkeyList: PubkeySet[];
    address: string;
    descriptor: string;
    confidentialAddress: string;
    blindingKeyPair: KeyPair;
    issuanceData: cfdjs.IssuanceDataResponse[];
    vout: number;
    amount: bigint;
    valueCommitment: string;
    abf: string;
    vbf: string;
  };
  const pathList: PathData[] = [];
  const dummyPathList: PathData[] = [];
  const reissuePathList: PathData[] = [];
  const reissueTokenPathList: PathData[] = [];
  const issuePathList: PathData[] = [];
  const issueTokenPathList: PathData[] = [];
  if (tx2InputCount < setIssueTx) {
    tx2InputCount = setIssueTx;
  }
  const maxPathCnt = tx2InputCount + setReissueTx * 3 + setIssueTx * 2;
  for (let i = 0; i < maxPathCnt; ++i) {
    const childPath = parentPath + '/' + i;
    const blindingKeyPair = getKeyPairFromParent(childPath + '/0/0');
    const pathData = {
      bip32Path: childPath,
      pubkey: '',
      pubkeyList: [],
      address: '',
      confidentialAddress: '',
      descriptor: '',
      blindingKeyPair: blindingKeyPair,
      issuanceData: [],
      vout: -1,
      amount: 0n,
      valueCommitment: '',
      abf: '',
      vbf: '',
    };
    if (i < tx2InputCount) {
      pathList.push(pathData);
    } else if ((setReissueTx > 0) && i < tx2InputCount + setReissueTx) {
      dummyPathList.push(pathData);
    } else if ((setReissueTx > 0) && i < tx2InputCount + (setReissueTx * 2)) {
      reissuePathList.push(pathData);
    } else if ((setReissueTx > 0) && i < tx2InputCount + (setReissueTx * 3)) {
      reissueTokenPathList.push(pathData);
    } else {
      if (issuePathList.length < setIssueTx) {
        issuePathList.push(pathData);
      } else {
        issueTokenPathList.push(pathData);
      }
    }
  }

  const allList = [pathList, dummyPathList, reissuePathList,
    reissueTokenPathList, issuePathList, issueTokenPathList];
  for (const list of allList) {
    for (const data of list) {
      if (getLedgerPath) {
        const pubkey = await liquidLib.getWalletPublicKey(data.bip32Path);
        data.pubkey = pubkey.publicKey;
        if (hashType.indexOf('p2wsh') >= 0) {
          const pubkey1 = await liquidLib.getWalletPublicKey(data.bip32Path + '/0');
          const pubkey2 = await liquidLib.getWalletPublicKey(data.bip32Path + '/1');
          const pubkey3 = await liquidLib.getWalletPublicKey(data.bip32Path + '/2');
          data.pubkeyList.push({
            bip32Path: data.bip32Path + '/0',
            pubkey: pubkey1.publicKey,
          });
          data.pubkeyList.push({
            bip32Path: data.bip32Path + '/1',
            pubkey: pubkey2.publicKey,
          });
          data.pubkeyList.push({
            bip32Path: data.bip32Path + '/2',
            pubkey: pubkey3.publicKey,
          });
        }
      } else {
        data.pubkey = getPubkeyFromParent(data.bip32Path);
        if (hashType.indexOf('p2wsh') >= 0) {
          data.pubkeyList.push({
            bip32Path: data.bip32Path + '/0',
            pubkey: getPubkeyFromParent(data.bip32Path + '/0'),
          });
          data.pubkeyList.push({
            bip32Path: data.bip32Path + '/1',
            pubkey: getPubkeyFromParent(data.bip32Path + '/1'),
          });
          data.pubkeyList.push({
            bip32Path: data.bip32Path + '/2',
            pubkey: getPubkeyFromParent(data.bip32Path + '/2'),
          });
        }
      }
      if (hashType.indexOf('p2wsh') >= 0) {
        const addr = cfdjs.CreateMultisig({
          isElements: true,
          hashType: hashType,
          network: networkType,
          nrequired: 2,
          keys: [
            data.pubkeyList[0].pubkey,
            data.pubkeyList[1].pubkey,
            data.pubkeyList[2].pubkey,
          ],
        });
        data.address = addr.address;
        data.descriptor = 'wsh(multi(2,' + data.pubkeyList[0].pubkey +
            ',' + data.pubkeyList[1].pubkey + ',' +
            data.pubkeyList[2].pubkey + '))';
        if (hashType === 'p2sh-p2wsh') {
          data.descriptor = `sh(${data.descriptor})`;
        }
      } else {
        const addr = cfdjs.CreateAddress({
          isElements: true,
          hashType: hashType,
          network: networkType,
          keyData: {
            hex: data.pubkey,
            type: 'pubkey',
          },
        });
        data.address = addr.address;
        data.descriptor = `wpkh(${data.pubkey})`;
        if (hashType === 'p2sh-p2wpkh') {
          data.descriptor = `sh(${data.descriptor})`;
        }
      }
      const ctAddr = cfdjs.GetConfidentialAddress({
        unblindedAddress: data.address,
        key: data.blindingKeyPair.pubkey,
      });
      data.confidentialAddress = ctAddr.confidentialAddress;
      console.log(`addr(${data.bip32Path}) =`, data.address);
    }
  }

  const tx1InputCount = 1 + setReissueTx;
  const dummyTxid1 = '7461b02405414d79e79a5050684a333c922c1136f4bdff5fb94b551394edebbd';
  const empty256 = '0000000000000000000000000000000000000000000000000000000000000000';
  const inputAmount = 5000000n;
  const inputAmount2 = 5000000n;
  const tx1Data = {
    version: 2,
    locktime: 0,
    txins: [{
      txid: dummyTxid1,
      vout: 0,
      sequence: 4294967295,
    }],
    txouts: [{
      address: pathList[0].address,
      amount: inputAmount,
      asset: asset1,
    }],
    fee: {
      amount: 50000n,
      asset: asset1,
    },
  };
  if (tx1InputCount > 1) {
    for (let i = 1; i < tx1InputCount; ++i) {
      tx1Data.txins.push({
        txid: dummyTxid1,
        vout: i,
        sequence: 4294967295,
      });
    }
  }
  if (pathList.length > 1) {
    for (let i = 1; i < pathList.length; ++i) {
      const pathData = pathList[i];
      tx1Data.txouts.push({
        address: pathData.address,
        amount: inputAmount2,
        asset: asset1,
      });
    }
    if (dummyPathList.length > 0) {
      for (let i = 1; i < dummyPathList.length; ++i) {
        const pathData = dummyPathList[i];
        tx1Data.txouts.push({
          address: pathData.address,
          amount: inputAmount2,
          asset: asset1,
        });
      }
    }
  }
  let tx1;
  try {
    tx1 = cfdjs.ElementsCreateRawTransaction(tx1Data);
  } catch (e) {
    console.log(tx1Data);
    throw e;
  }

  if (setReissueTx > 0) {
    for (let i = 0; i < reissuePathList.length; ++i) {
      const pathData = reissuePathList[i];
      const tokenPathData = reissueTokenPathList[i];
      const issueRet = cfdjs.SetRawIssueAsset({
        tx: tx1.hex,
        issuances: [{
          txid: tx1Data.txins[i + 1].txid,
          vout: tx1Data.txins[i + 1].vout,
          assetAmount: inputAmount2,
          assetAddress: pathData.confidentialAddress,
          tokenAmount: inputAmount2,
          tokenAddress: tokenPathData.confidentialAddress,
          contractHash: empty256,
          isRemoveNonce: false,
          isBlind: true,
        }],
        isRandomSortTxOut: false,
      });
      tokenPathData.issuanceData.push({
        txid: issueRet.issuances[0].txid,
        vout: issueRet.issuances[0].vout,
        asset: issueRet.issuances[0].asset,
        entropy: issueRet.issuances[0].entropy,
        token: issueRet.issuances[0].token,
      });
      tx1.hex = issueRet.hex;
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
        blindFactor: empty256,
        assetBlindFactor: empty256,
        amount: inputAmount,
      }],
      txoutConfidentialAddresses: [],
      issuances: [],
    };
    if (setReissueTx > 0 && blind1Data.txins && blind1Data.issuances) {
      for (let i = 0; i < reissuePathList.length; ++i) {
        const pathData = reissuePathList[i];
        const tokenPathData = reissueTokenPathList[i];
        blind1Data.txins.push({
          txid: dummyTxid1,
          vout: i + 1,
          asset: asset1,
          blindFactor: empty256,
          assetBlindFactor: empty256,
          amount: inputAmount,
        });
        blind1Data.issuances.push({
          txid: dummyTxid1,
          vout: i + 1,
          assetBlindingKey: pathData.blindingKeyPair.privkey,
          tokenBlindingKey: tokenPathData.blindingKeyPair.privkey,
        });
      }
    }
    if (blind1Data.txoutConfidentialAddresses) {
      for (let i = 0; i < pathList.length; ++i) {
        const pathData = pathList[i];
        blind1Data.txoutConfidentialAddresses.push(
            pathData.confidentialAddress);
      }
      for (let i = 0; i < dummyPathList.length; ++i) {
        const pathData = dummyPathList[i];
        blind1Data.txoutConfidentialAddresses.push(
            pathData.confidentialAddress);
      }
      for (let i = 0; i < reissuePathList.length; ++i) {
        const issuePathData = reissuePathList[i];
        blind1Data.txoutConfidentialAddresses.push(
            issuePathData.confidentialAddress);
      }
      for (let i = 0; i < reissueTokenPathList.length; ++i) {
        const tokenPathData = reissueTokenPathList[i];
        blind1Data.txoutConfidentialAddresses.push(
            tokenPathData.confidentialAddress);
      }
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

  // set utxo data
  if (dectx1.vout) {
    const unblindTxoutList: cfdjs.UnblindTxOut[] = [];
    const utxoPathList = [pathList, reissueTokenPathList];
    for (const txout of dectx1.vout) {
      const addr = (txout.scriptPubKey && txout.scriptPubKey.addresses) ?
          txout.scriptPubKey.addresses[0] : '';
      if (!addr) continue;
      for (const list of utxoPathList) {
        let isFind = false;
        for (const pathData of list) {
          if (pathData.address === addr) {
            pathData.vout = txout.n;
            if (txout.valuecommitment) {
              pathData.valueCommitment = txout.valuecommitment;
            }
            pathData.amount = inputAmount;
            unblindTxoutList.push({
              index: txout.n,
              blindingKey: pathData.blindingKeyPair.privkey,
            });
            isFind = true;
            break;
          }
        }
        if (isFind) break;
      }
    }
    const unblindData = cfdjs.UnblindRawTransaction({
      tx: tx1.hex,
      txouts: unblindTxoutList,
    });
    if (unblindData.outputs) {
      for (const data of unblindData.outputs) {
        for (const list of utxoPathList) {
          let isFind = false;
          for (const pathData of list) {
            if (pathData.vout === data.index) {
              pathData.abf = data.assetBlindFactor;
              pathData.vbf = data.blindFactor;
              isFind = true;
              break;
            }
          }
          if (isFind) break;
        }
      }
    }
  }

  const tx2Data = {
    version: 2,
    locktime: 0,
    txins: [{
      txid: dectx1.txid,
      vout: pathList[0].vout,
      sequence: 0xffffffff,
    }],
    txouts: [{
      address: pathList[0].address,
      amount: pathList[0].amount,
      asset: asset1,
    }],
    fee: {
      amount: 50000n,
      asset: asset1,
    },
  };
  const blindReqData: cfdjs.BlindRawTransactionRequest = {
    tx: '',
    txins: [{
      txid: dectx1.txid,
      vout: pathList[0].vout,
      amount: pathList[0].amount,
      asset: asset1,
      assetBlindFactor: pathList[0].abf,
      blindFactor: pathList[0].vbf,
    }],
    txoutConfidentialAddresses: [pathList[0].confidentialAddress],
    issuances: [],
  };
  let totalAsset = 0n;
  let startOffset = 1;
  if ((setReissuanceToTop > setIssuanceToTop) &&
      (reissuePathList.length > 0)) {
    startOffset = 0;
    tx2Data.txins = [];
    blindReqData.txins = [];
    for (let i = 0; i < reissueTokenPathList.length; ++i) {
      const pathData = reissueTokenPathList[i];
      tx2Data.txins.push({
        txid: dectx1.txid,
        vout: pathData.vout,
        sequence: 0xffffffff,
      });
      totalAsset += pathData.amount;
      if (blindReqData.txins) {
        const asset =
          (pathData.issuanceData && pathData.issuanceData[0]) ?
            pathData.issuanceData[0].token : asset1;
        blindReqData.txins.push({
          txid: dectx1.txid,
          vout: pathData.vout,
          amount: pathData.amount,
          asset: (asset) ? asset : asset1,
          assetBlindFactor: pathData.abf,
          blindFactor: pathData.vbf,
        });
        if (blindReqData.issuances) {
          blindReqData.issuances.push({
            txid: dectx1.txid,
            vout: pathData.vout,
            assetBlindingKey: pathData.blindingKeyPair.privkey,
            tokenBlindingKey: pathData.blindingKeyPair.privkey,
          });
        }
      }
    }
  }
  if (pathList.length > 0 && tx2Data.txins) {
    for (let i = startOffset; i < pathList.length; ++i) {
      const pathData = pathList[i];
      tx2Data.txins.push({
        txid: dectx1.txid,
        vout: pathData.vout,
        sequence: 0xffffffff,
      });
      totalAsset += pathData.amount;
      if (blindReqData.txins) {
        const asset =
          (pathData.issuanceData && pathData.issuanceData[0]) ?
            pathData.issuanceData[0].token : asset1;
        blindReqData.txins.push({
          txid: dectx1.txid,
          vout: pathData.vout,
          amount: pathData.amount,
          asset: (asset) ? asset : asset1,
          assetBlindFactor: pathData.abf,
          blindFactor: pathData.vbf,
        });
      }
    }
    if ((setReissuanceToTop <= setIssuanceToTop)) {
      for (let i = 0; i < reissueTokenPathList.length; ++i) {
        const pathData = reissueTokenPathList[i];
        tx2Data.txins.push({
          txid: dectx1.txid,
          vout: pathData.vout,
          sequence: 0xffffffff,
        });
        totalAsset += pathData.amount;
        if (blindReqData.txins) {
          const asset =
            (pathData.issuanceData && pathData.issuanceData[0]) ?
              pathData.issuanceData[0].token : asset1;
          blindReqData.txins.push({
            txid: dectx1.txid,
            vout: pathData.vout,
            amount: pathData.amount,
            asset: (asset) ? asset : asset1,
            assetBlindFactor: pathData.abf,
            blindFactor: pathData.vbf,
          });
          if (blindReqData.issuances) {
            blindReqData.issuances.push({
              txid: dectx1.txid,
              vout: pathData.vout,
              assetBlindingKey: pathData.blindingKeyPair.privkey,
              tokenBlindingKey: pathData.blindingKeyPair.privkey,
            });
          }
        }
      }
    }
  }
  if (pathList.length > 0 && tx2Data.txouts) {
    tx2Data.txouts.push({
      address: pathList[1].address,
      amount: totalAsset - tx2Data.fee.amount,
      asset: asset1,
    });
    if (blindReqData.txoutConfidentialAddresses) {
      blindReqData.txoutConfidentialAddresses.push(
          pathList[1].confidentialAddress);
    }
  }
  if (reissueTokenPathList.length > 0 && tx2Data.txouts) {
    for (let i = 0; i < reissueTokenPathList.length; ++i) {
      if (reissueTokenPathList[i].issuanceData.length > 0 &&
        reissueTokenPathList[i].issuanceData[0]) {
        const token = reissueTokenPathList[i].issuanceData[0].token;
        tx2Data.txouts.push({
          address: reissueTokenPathList[i].address,
          amount: reissueTokenPathList[i].amount,
          asset: (token) ? token : '',
        });
        if (blindReqData.txoutConfidentialAddresses) {
          blindReqData.txoutConfidentialAddresses.push(
              reissueTokenPathList[i].confidentialAddress);
        }
      }
    }
  }
  const tx2 = cfdjs.ElementsCreateRawTransaction(tx2Data);

  let blindTx2 = tx2;
  const issueList = [];
  if (setIssueTx) {
    let cnt = 0;
    const startIdx = (!setIssuanceToTop) ?
        pathList.length - issuePathList.length : 0;
    const maxIndex = (!setIssuanceToTop) ?
        pathList.length : issuePathList.length;
    for (let i = startIdx; i < maxIndex; ++i) {
      const pathData = issuePathList[cnt];
      const tokenData = issueTokenPathList[cnt];
      issueList.push({
        txid: dectx1.txid,
        vout: pathList[i].vout,
        assetAmount: inputAmount2,
        assetAddress: pathData.confidentialAddress,
        tokenAmount: inputAmount2,
        tokenAddress: tokenData.confidentialAddress,
        contractHash: empty256,
        isBlind: true,
      });
      pathData.issuanceData.push({
        txid: dectx1.txid,
        vout: pathList[i].vout,
        asset: '',
        entropy: '',
        token: '',
      });
      if (blindReqData.issuances) {
        blindReqData.issuances.push({
          txid: dectx1.txid,
          vout: pathList[i].vout,
          assetBlindingKey: pathData.blindingKeyPair.privkey,
          tokenBlindingKey: tokenData.blindingKeyPair.privkey,
        });
      }
      if (blindReqData.txoutConfidentialAddresses) {
        blindReqData.txoutConfidentialAddresses.push(
            pathData.confidentialAddress);
        blindReqData.txoutConfidentialAddresses.push(
            tokenData.confidentialAddress);
      }
      ++cnt;
    }
    try {
      const issueRet = cfdjs.SetRawIssueAsset({
        tx: blindTx2.hex,
        issuances: issueList,
        isRandomSortTxOut: false,
      });
      blindTx2 = issueRet;
      if (issueRet.issuances) {
        for (const issueData of issueRet.issuances) {
          for (const pathData of issuePathList) {
            if (pathData.issuanceData &&
              (pathData.issuanceData[0].txid === issueData.txid) &&
              (pathData.issuanceData[0].vout === issueData.vout)) {
              pathData.issuanceData[0].asset = issueData.asset;
              pathData.issuanceData[0].token = issueData.token;
              pathData.issuanceData[0].entropy = issueData.entropy;
            }
          }
        }
      }
    } catch (e) {
      console.log(issueList);
      throw e;
    }
  }
  console.log('*** tx2 ***\n', tx2);

  if (blindOpt.blind2) {
    if (reissueTokenPathList.length > 0 && tx2Data.txouts) {
      const issuanceList: cfdjs.ReissuanceDataRequest[] = [];
      for (let i = 0; i < reissueTokenPathList.length; ++i) {
        if (reissueTokenPathList[i].issuanceData.length > 0 &&
          reissueTokenPathList[i].issuanceData[0]) {
          issuanceList.push({
            txid: dectx1.txid,
            vout: reissueTokenPathList[i].vout,
            amount: inputAmount2,
            address: reissuePathList[i].confidentialAddress,
            assetBlindingNonce: reissueTokenPathList[i].abf,
            assetEntropy: reissueTokenPathList[i].issuanceData[0].entropy,
          });
        }
      }
      try {
        const reissueRet = cfdjs.SetRawReissueAsset({
          tx: blindTx2.hex,
          issuances: issuanceList,
          isRandomSortTxOut: false,
        });
        blindTx2 = reissueRet;
      } catch (e) {
        console.log(issuanceList);
        throw e;
      }
    }
    console.log('*** before blind tx2 ***\n', blindTx2);
    console.log('*** blindInfo ***\n',
        JSON.stringify(blindReqData, (key, value) =>
            typeof value === 'bigint' ? value.toString() : value, '  '));
    blindReqData.tx = blindTx2.hex;
    blindTx2 = cfdjs.BlindRawTransaction(blindReqData);
  }
  if (signedTest) {
    console.log('*** blind rawtx2 ***\n', blindTx2.hex);
  }

  // console.log('*** Blind ***\n', tx2);
  const dectx2 = cfdjs.ElementsDecodeRawTransaction({
    hex: blindTx2.hex, network: networkType,
    mainchainNetwork: mainchainNwType});
  console.log('*** blind dectx2 ***\n', JSON.stringify(dectx2, null, '  '));

  if (!dectx2.vin) {
    return;
  }
  const walletUtxoList: WalletUtxoData[] = [];
  for (const num of signTargetIndex) {
    if (num >= dectx2.vin.length) {
      continue;
    }
    const i = num;
    const txin = dectx2.vin[i];
    let isFind = false;
    const txid = dectx1.txid;
    const utxoList = [pathList, reissueTokenPathList];
    for (const list of utxoList) {
      for (const data of list) {
        if (data.vout == txin.vout) {
          if (data.pubkeyList.length > 0) {
            for (const pubkeyData of data.pubkeyList) {
              walletUtxoList.push({
                bip32Path: pubkeyData.bip32Path,
                txid: txid,
                vout: txin.vout,
                amount: data.amount,
                valueCommitment: data.valueCommitment,
                redeemScript: '',
                descriptor: data.descriptor,
              });
            }
          } else {
            walletUtxoList.push({
              bip32Path: data.bip32Path,
              txid: txid,
              vout: txin.vout,
              amount: data.amount,
              valueCommitment: data.valueCommitment,
              redeemScript: '',
              descriptor: data.descriptor,
            });
          }
          isFind = true;
          break;
        }
      }
      if (isFind) continue;
    }
  }

  if (!walletUtxoList) {
    console.log('*** Sign target not found. ***\n', signTargetIndex);
    return;
  }
  if (!directMnemonic) {
    if (asyncConnectCheck) {
      isConnectCheck = true;
      setTimeout(async () => {
        await checkConnecting(liquidLib);
      }, 1000);
    }
    const txHex = await execSign(liquidLib, blindTx2.hex, walletUtxoList, '');
    console.log('*** signed tx hex ***\n', txHex);
    if (dumpTx) {
      const decSignedTx = cfdjs.ElementsDecodeRawTransaction({
        hex: txHex, network: networkType,
        mainchainNetwork: mainchainNwType});
      console.log('*** Signed Tx ***\n', JSON.stringify(decSignedTx, null, '  '));
    }
    isConnectCheck = false;
  }
  if (mnemonic) {
    const tx = await execSign(
        liquidLib, blindTx2.hex, walletUtxoList, mnemonic);
    console.log('*** mnemonic signed tx ***\n', tx);
    if (dumpTx) {
      const decSignedTx = cfdjs.ElementsDecodeRawTransaction({
        hex: tx, network: networkType,
        mainchainNetwork: mainchainNwType});
      console.log('*** Signed Tx ***\n', JSON.stringify(decSignedTx, null, '  '));
    }
  }
  await liquidLib.disconnect();
};

async function execBip32PathTest() {
  // connect wait test
  const liquidLib = new LedgerLiquidWrapper(networkType);
  const connRet = await liquidLib.connect(0, '');
  if (!connRet.success) {
    console.log('connection failed. ', connRet);
    return;
  }

  const pubkey = await liquidLib.getWalletPublicKey(targetBip32Path);
  console.log('getWalletPublicKey =', pubkey);
  const xpub = await liquidLib.getXpubKey(targetBip32Path);
  console.log('getXpubKey =', xpub);
  await liquidLib.disconnect();
}

async function setAuthKeyTest() {
  if (!authPubKey) {
    console.log(' Please input authorization pubkey!');
    console.log(' usage:');
    console.log('     npm run setauthkey -- -apk <authrizationPubkey>');
    console.log(' example(develop key):');
    console.log('     npm run setauthkey -- -apk 04b85b0e5f5b41f1a95bbf9a83edd95c741223c6d9dc5fe607de18f015684ff56ec359705fcf9bbeb1620fb458e15e3d99f23c6f5df5e91e016686371a65b16f0c');
    return;
  }
  if (authPubKey.length !== 130) {
    console.log(' Authorization pubkey can only be used with uncompressed pubkey!');
    return;
  }
  const liquidLib = new LedgerLiquidWrapper(networkType);
  const connRet = await liquidLib.connect(0, '');
  if (!connRet.success) {
    console.log('connection failed. ', connRet);
    return;
  }
  console.log('authrizationPubkey:', authPubKey);
  const setupRet = await liquidLib.setupHeadlessAuthorization(authPubKey);
  console.log('--HEADLESS LIQUID SEND AUTHORIZATION PUBLIC KEY --\n', setupRet);
  await liquidLib.disconnect();
}

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

if (setAuthorization) {
  setAuthKeyTest();
} else if (fixedTest) {
  execFixedTest();
} else if (dumpPubkeyMode) {
  execBip32PathTest();
} else if (connectionTest) {
  execConnectionTest();
} else if ((!signTarget) && (!txData)) {
  example();
} else {
  signTest();
}
