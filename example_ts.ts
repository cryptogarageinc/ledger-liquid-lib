/* eslint-disable require-jsdoc */
import * as cfdjs from 'cfd-js';
import {exit} from 'process';
import {LedgerLiquidWrapper, WalletUtxoData, SignatureData, NetworkType, AddressType, GetSignatureState, ProgressInfo, UsbDetectionType, Device} from './src/ledger-liquid-lib';

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
let connectionMonitoringTest = false;
let connectDevice = '';
let getLedgerPath = true;
let mnemonic = '';
let mnemonicCheck = true;
// mnemonic = 'call node debug-console.js ledger hood festival pony outdoor always jeans page help symptom adapt obtain image bird duty damage find sense wasp box mail vapor plug general kingdom';
let dumpTx = false;
let txData = '';
let signTarget = '';
let fixedTest = false;
let peggedTxTest = false;
let peggedTxOkTest = false;
let peggedTxMaxTest = false;
let peggedTxMaxTest2 = false;
let peggedTxMaxTest3 = false;
let peginTxMaxTest = false;
let waitCancelCount = 0;
let currentWaitCancelCount = 0;
let dumpPubkeyMode = false;
let debugMode = false;
let targetBip32Path = 'm/44h/0h/0h';
let asyncConnectCheck = false;
let asyncCommandCheck = false;
let reconnectTest = false;
let testContractHash = '0000000000000000000000000000000000000000000000000000000000000000';
let continousCount = 0;
let continousSleep = 1;

for (let i = 2; i < process.argv.length; i++) {
  if (process.argv[i]) {
    if (process.argv[i] === '-r') {
      networkType = NetworkType.Regtest;
    } else if (process.argv[i] === '-d') {
      debugMode = true;
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
    } else if (process.argv[i] === '-mc') {
      connectionMonitoringTest = true;
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
    } else if (process.argv[i] === '-peg') {
      peggedTxTest = true;
    } else if (process.argv[i] === '-okpeg') {
      peggedTxOkTest = true;
    } else if (process.argv[i] === '-maxpeg') {
      peggedTxMaxTest = true;
    } else if (process.argv[i] === '-maxpeg2') {
      peggedTxMaxTest2 = true;
    } else if (process.argv[i] === '-maxpeg3') {
      peggedTxMaxTest3 = true;
    } else if (process.argv[i] === '-pegin') {
      peginTxMaxTest = true;
    } else if (process.argv[i] === '-acc') {
      asyncConnectCheck = true;
      asyncCommandCheck = true;
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
    } else if (process.argv[i] === '-rct') {
      reconnectTest = true;
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
      } else if (process.argv[i] === '-ch') {
        ++i;
        testContractHash = process.argv[i];
      } else if (process.argv[i] === '-continous_test') {
        ++i;
        continousCount = parseInt(process.argv[i]);
      } else if (process.argv[i] === '-continous_sleep') {
        ++i;
        continousSleep = parseInt(process.argv[i]);
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
    signUtxoList: WalletUtxoData[], mnemonicWords: string,
    ignoreVerify?: boolean): Promise<string> {
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
    const startTime = Date.now();
    sigRet = await liquidLib.getSignature(txHex,
        signUtxoList, authDerSig);
    const endTime = Date.now();
    console.log(`*** getSignature end. ***`,
        JSON.stringify(sigRet, (key, value) =>
            typeof value === 'bigint' ? value.toString() : value, '  '));
    console.log(`getSignature: ${(endTime - startTime)} msec`);
    if (!sigRet.success && continousCount) {
      throw new Error('getSignature fail.');
    }
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
  if (ignoreVerify) {
    return '';
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
      const pubkeyRet = await liquidLib.getWalletPublicKey(
          signatureData.utxoData.bip32Path);
      if (!pubkeyRet.success && continousCount) {
        console.warn(pubkeyRet);
        throw new Error('getWalletPublicKey fail.');
      }
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
          redeemScript: (sigData.hashType === 'p2sh') ? sigData.redeemScript : '',
          witnessScript: (sigData.hashType === 'p2sh') ? '' : sigData.redeemScript,
          hashType: sigData.hashType,
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
    const accessing = lib.isAccessing();
    if (connCheckRet.success) {
      console.log(`isConnected : connect, accessing=${accessing}`);
    } else if (connCheckRet.disconnect) {
      console.log(`isConnected : disconnect, accessing=${accessing}`);
    } else {
      console.log('isConnected fail: ', connCheckRet);
    }
    setTimeout(async () => {
      await checkConnecting(lib);
    }, 1000);
  }
}

async function checkConnectingQuick(lib: LedgerLiquidWrapper) {
  if (isConnectCheck) {
    const connCheckRet = await lib.isConnected();
    const accessing = lib.isAccessing();
    if (connCheckRet.success) {
      console.log(`isConnected : connect, accessing=${accessing}`);
    } else if (connCheckRet.disconnect) {
      console.log(`isConnected : disconnect, accessing=${accessing}`);
    } else {
      console.log('isConnected fail: ', connCheckRet);
    }
    setTimeout(async () => {
      await checkConnectingQuick(lib);
    }, 200);
  }
}

let isDumpSignature = false;
let lastState = '';
let pastAccessTime = 0;
async function dumpSignatureProgress(lib: LedgerLiquidWrapper) {
  const result = lib.getSignatureState();
  const cur = new Date();
  const hour = (cur.getHours() > 9) ? cur.getHours() : ('0' + cur.getHours());
  const min = (cur.getMinutes() > 9) ? cur.getMinutes() : ('0' + cur.getMinutes());
  const sec = (cur.getSeconds() > 9) ? cur.getSeconds() : ('0' + cur.getSeconds());
  const msec = (cur.getMilliseconds() > 99) ? cur.getMilliseconds() :
      (cur.getMilliseconds() > 9) ? ('0' + cur.getMilliseconds()) :
          ('00' + cur.getMilliseconds());
  const timeStr = `[${hour}:${min}:${sec}.${msec}]`;
  if (result.success) {
    let prog: ProgressInfo = {current: 0, total: 0};
    switch (result.currentState) {
      case GetSignatureState.AnalyzeUtxo:
        prog = result.analyzeUtxo;
        break;
      case GetSignatureState.InputTx:
        prog = result.inputTx;
        break;
      case GetSignatureState.GetSignature:
        prog = result.getSignature;
        break;
      default:
        break;
    }
    if (result.errorMessage === 'not execute.') {
      if (lastState !== result.errorMessage) {
        console.log(`${timeStr} getSignatureState:`, result);
        lastState = result.errorMessage;
      }
    } else {
      const state = `${result.currentState}: ${prog.current}/${prog.total}`;
      if (lastState !== state) {
        console.log(`${timeStr} getSignatureState(${state})`);
      } else if (pastAccessTime !== result.lastAccessTime) {
        console.log(`${timeStr} getSignatureState(${state}): time[${result.lastAccessTime}]`);
      }
      lastState = state;
      pastAccessTime = result.lastAccessTime;
    }
  } else if (!isDumpSignature) {
    console.log(`${timeStr} getSignatureState:`, result);
  } else if (lastState !== result.errorMessage) {
    console.log(`${timeStr} getSignatureState:`, result);
    lastState = result.errorMessage;
  }
  if (isDumpSignature) {
    setTimeout(async () => {
      await dumpSignatureProgress(lib);
    }, 500);
  }
}

let multiAccessTestCount = 0;
async function multiAccessTest(lib: LedgerLiquidWrapper) {
  if (multiAccessTestCount === 0) {
    const pubkeyRet = await lib.getWalletPublicKey('44h/0h/0h');
    console.log('async getWalletPublicKey:', pubkeyRet);
    setTimeout(async () => {
      await multiAccessTest(lib);
    }, 5000);
  } else if (multiAccessTestCount === 1) {
    const xpubkeyRet = await lib.getXpubKey('44h/0h/0h');
    console.log('async getXpubKey:', xpubkeyRet);
  }
  multiAccessTestCount++;
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

async function testNotifyFunction(state: UsbDetectionType,
    device: Device) {
  console.log('notify: ', state, ' device:', device);
  await sleep(100);
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
  const devListResult = await LedgerLiquidWrapper.getDeviceList();
  if (devListResult.success) {
    for (const desc of devListResult.deviceList) {
      console.log('connect device :', desc);
    }
  } else {
    console.log('getDeviceList error. ', devListResult);
  }

  LedgerLiquidWrapper.startUsbDetectMonitoring();
  LedgerLiquidWrapper.registerUsbDetectListener(
      testNotifyFunction);
  let connRet = await liquidLib.connect(60, connectDevice);
  if (!connRet.success) {
    console.log('connection fail.(1)', connRet);
    LedgerLiquidWrapper.finishUsbDetectMonitoring();
    return;
  }
  if (asyncConnectCheck) {
    isConnectCheck = true;
    setTimeout(async () => {
      await checkConnectingQuick(liquidLib);
    }, 200);
    setTimeout(async () => {
      await checkConnectingQuick(liquidLib);
    }, 200);
    setTimeout(async () => {
      await checkConnectingQuick(liquidLib);
    }, 200);
    setTimeout(async () => {
      await checkConnectingQuick(liquidLib);
    }, 200);
    setTimeout(async () => {
      await checkConnectingQuick(liquidLib);
    }, 200);
  }
  console.log('current application:', liquidLib.getCurrentApplication());
  console.log('last connect info  :', liquidLib.getLastConnectionInfo());
  for (let connTestCount = 0; connTestCount < 120; ++connTestCount) {
    const connCheckRet = await liquidLib.isConnected();
    if (connCheckRet.success) {
      console.log('10 sec wait start.');
      await sleep(10000);
      console.log('10 sec wait end.');
      connTestCount += 10;
      if (reconnectTest) {
        console.log('exec connect.');
        connRet = await liquidLib.connect(0, connectDevice);
        console.log('connect result:', connRet);
      }
    } else if (connCheckRet.errorMessage === 'connection fail.') {
      console.log('disconnect. start reconnection.');
      connRet = await liquidLib.connect(60, connectDevice);
      if (!connRet.success) {
        console.log('connection fail. ', connRet);
        break;
      }
      console.log('reconnect success.');
      await sleep(1);
      console.log('current application:', liquidLib.getCurrentApplication());
      console.log('last connect info  :', liquidLib.getLastConnectionInfo());
    } else {
      console.log('isConnected fail.(2)', connCheckRet);
      break;
    }
    await sleep(1000);
  }
  await liquidLib.disconnect();
  LedgerLiquidWrapper.finishUsbDetectMonitoring();
}

async function execMonitoringConnectionTest() {
  const liquidLib = new LedgerLiquidWrapper(networkType);
  let isError = false;
  const checkAndConnect = async function() {
    console.log('reconnect checking.');
    if (liquidLib.isAccessing()) {
      setTimeout(async () => {
        checkAndConnect();
      }, 200);
      return;
    }
    console.log('reconnect start.');
    const connRet = await liquidLib.connect(0, connectDevice);
    if (!connRet.success) {
      console.log('connection fail.', connRet);
      if (connRet.disconnect) {
        console.log('wait connecting...');
      } else {
        isError = true;
      }
    } else {
      console.log('reconnect success.');
      await sleep(1);
      console.log('current application:', liquidLib.getCurrentApplication());
      console.log('last connect info  :', liquidLib.getLastConnectionInfo());
    }
  };
  const checkConnect = async function() {
    const connCheckRet = await liquidLib.isConnected();
    if (connCheckRet.success) {
      // do nothing
    } else if (connCheckRet.errorMessage === 'connection fail.') {
      console.log('disconnect. wait connecting...');
    } else {
      console.log('isConnected fail.(3)', connCheckRet);
      // throw new Error('connection fail.');
      isError = true;
    }
  };
  const testMonitoringNotify = async function(
      state: UsbDetectionType, device: Device) {
    console.log('notify: ', state, ' device:', device);
    if (state == UsbDetectionType.Add) {
      setTimeout(async () => {
        checkAndConnect();
      }, 200);
    } else if (state == UsbDetectionType.Remove) {
      setTimeout(async () => {
        checkConnect();
      }, 200);
    }
  };

  const devListResult = await LedgerLiquidWrapper.getDeviceList();
  if (devListResult.success) {
    for (const desc of devListResult.deviceList) {
      console.log('connect device :', desc);
    }
  } else {
    console.log('getDeviceList error. ', devListResult);
  }

  LedgerLiquidWrapper.startUsbDetectMonitoring();
  console.log('call startUsbDetectMonitoring.');
  LedgerLiquidWrapper.registerUsbDetectListener(testMonitoringNotify);
  try {
    const connRet = await liquidLib.connect(60, connectDevice);
    if (!connRet.success) {
      console.log('connection fail.(1)', connRet);
      return;
    }
    await sleep(1);
    console.log('current application:', liquidLib.getCurrentApplication());
    console.log('last connect info  :', liquidLib.getLastConnectionInfo());
    for (let connTestCount = 0; connTestCount < 60; ++connTestCount) {
      if (isError) break;
      await sleep(1000);
    }
    if (isError) {
      console.log('connection fail on error.');
    }
  } catch (e) {
    console.log(e);
  } finally {
    await liquidLib.disconnect();
    LedgerLiquidWrapper.finishUsbDetectMonitoring();
    console.log('call finishUsbDetectMonitoring.');
    await sleep(1000);
    exit(0);
  }
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
    if (continousCount) {
      throw new Error('connect fail.');
    }
    return;
  }
  console.log('current application:', liquidLib.getCurrentApplication());
  const fwVer = await liquidLib.getApplicationInfo();
  console.log('firmware version:', fwVer);
  if (!fwVer.success && continousCount) {
    throw new Error('getApplicationInfo fail.');
  }
  console.log('last connect info  :', liquidLib.getLastConnectionInfo());

  const mainchainNwType = (networkType === 'liquidv1') ? 'mainnet' : 'regtest';
  const parentPath = '44\'/0\'/0\'/0';
  const childNumber = 0;
  const childPath = parentPath + '/' + childNumber;
  const parentPubkey = await liquidLib.getWalletPublicKey(parentPath);
  console.log('parentPubkey -> ', parentPubkey);
  if (!parentPubkey.success && continousCount) {
    throw new Error('getWalletPublicKey fail.');
  }

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
  if (!xpub.success && continousCount) {
    throw new Error('getXpubKey fail.');
  }

  const xpub2 = await liquidLib.getXpubKey('m/44\'/0\'/0\'');
  console.log('getXpubKey2 =', xpub2);
  if (!xpub2.success && continousCount) {
    throw new Error('getXpubKey fail.');
  }

  const legacyLockingScript = liquidLib.getPublicKeyRedeemScript(
      parentPubkey.publicKey);
  console.log('legacyLockingScript =', legacyLockingScript);

  const addrData = await liquidLib.getAddress('m/44\'/0\'/0\'', addrType);
  console.log('getAddress =', addrData);
  if (!addrData.success && continousCount) {
    throw new Error('getAddress fail.');
  }

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
  }
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
  let firstInputAmount = inputAmount;
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
      amount: inputAmount - 50000n,
      asset: asset1,
    }],
    fee: {
      amount: 50000n,
      asset: asset1,
    },
  };
  if (pathList.length > 1) {
    for (let i = 1; i < pathList.length; ++i) {
      const pathData = pathList[i];
      tx1Data.txouts.push({
        address: pathData.address,
        amount: inputAmount2,
        asset: asset1,
      });
      firstInputAmount += inputAmount2;
    }
    if (dummyPathList.length > 0) {
      for (let i = 1; i < dummyPathList.length; ++i) {
        const pathData = dummyPathList[i];
        tx1Data.txouts.push({
          address: pathData.address,
          amount: inputAmount2,
          asset: asset1,
        });
        firstInputAmount += inputAmount2;
      }
    }
  }
  if (tx1InputCount > 1) {
    for (let i = 1; i < tx1InputCount; ++i) {
      tx1Data.txins.push({
        txid: dummyTxid1,
        vout: i,
        sequence: 4294967295,
      });
      firstInputAmount -= inputAmount2;
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
          contractHash: testContractHash,
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
        amount: firstInputAmount,
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
              pathData.amount = data.amount;
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
  let startOffset = 1;
  const assetMap: {[key: string]: bigint} = {};
  const tokenAssetMap: {[key: string]: bigint} = {};
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
      const asset =
        (pathData.issuanceData && pathData.issuanceData[0]) ?
          pathData.issuanceData[0].token || '' : asset1;
      if (asset in tokenAssetMap) {
        tokenAssetMap[asset] = tokenAssetMap[asset] + BigInt(pathData.amount);
      } else {
        tokenAssetMap[asset] = BigInt(pathData.amount);
      }
      if (blindReqData.txins) {
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
      const asset =
        (pathData.issuanceData && pathData.issuanceData[0]) ?
          pathData.issuanceData[0].token || '' : asset1;
      if (i == 0) {
        // already txout set.
      } else if (asset in assetMap) {
        assetMap[asset] = assetMap[asset] + BigInt(pathData.amount);
      } else {
        assetMap[asset] = BigInt(pathData.amount);
      }
      if (blindReqData.txins) {
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
        const asset =
          (pathData.issuanceData && pathData.issuanceData[0]) ?
            pathData.issuanceData[0].token || '' : asset1;
        if (asset in tokenAssetMap) {
          tokenAssetMap[asset] = tokenAssetMap[asset] + BigInt(pathData.amount);
        } else {
          tokenAssetMap[asset] = BigInt(pathData.amount);
        }
        if (blindReqData.txins) {
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
    const addrCounter = 1;
    for (const asset in assetMap) {
      if (asset1 in assetMap) {
        const totalAsset = assetMap[asset1];
        const amount = (asset == asset1) ?
            totalAsset - BigInt(tx2Data.fee.amount) : totalAsset;
        tx2Data.txouts.push({
          address: pathList[addrCounter].address,
          amount,
          asset,
        });
        if (blindReqData.txoutConfidentialAddresses) {
          blindReqData.txoutConfidentialAddresses.push(
              pathList[addrCounter].confidentialAddress);
        }
      }
    }
  }
  if (reissueTokenPathList.length > 0 && tx2Data.txouts) {
    let addrCounter = 0;
    for (const asset in tokenAssetMap) {
      if (asset) {
        tx2Data.txouts.push({
          address: reissueTokenPathList[addrCounter].address,
          amount: tokenAssetMap[asset],
          asset,
        });
        if (blindReqData.txoutConfidentialAddresses) {
          blindReqData.txoutConfidentialAddresses.push(
              reissueTokenPathList[addrCounter].confidentialAddress);
        }
        addrCounter += 1;
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
        contractHash: testContractHash,
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
    if (debugMode) {
      isDumpSignature = true;
      setTimeout(async () => {
        await dumpSignatureProgress(liquidLib);
      }, 500);
    }
    if (asyncConnectCheck) {
      isConnectCheck = true;
      setTimeout(async () => {
        await checkConnecting(liquidLib);
      }, 1000);
    }
    if (asyncCommandCheck) {
      setTimeout(async () => {
        await multiAccessTest(liquidLib);
      }, 5000);
    }
    const calcInfo = liquidLib.calcSignatureProgress(
        blindTx2.hex, walletUtxoList);
    if (calcInfo.success) {
      console.log(`sign utxo count = ${calcInfo.analyzeUtxo.total}`);
      console.log(`tx in/out/issuance count = ${calcInfo.inputTx.total}`);
    } else {
      console.log('calcSignatureProgress:', calcInfo);
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
    isDumpSignature = false;
    if (asyncConnectCheck) {
      const accessing = liquidLib.isAccessing();
      console.log(`accessing: ${accessing}`);
    }
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
}

async function execBip32PathTest() {
  // connect wait test
  const liquidLib = new LedgerLiquidWrapper(networkType);
  const connRet = await liquidLib.connect(0, '');
  if (!connRet.success) {
    if (debugMode || (connRet.disconnect === false)) {
      console.log('connection failed. ', connRet);
    } else {
      console.log(connRet.errorMessage);
    }
    return;
  }

  const pubkey = await liquidLib.getWalletPublicKey(targetBip32Path);
  if (debugMode || (pubkey.success === false)) {
    console.log('getWalletPublicKey =', pubkey);
  }
  if (pubkey.success) {
    const xpub = await liquidLib.getXpubKey(targetBip32Path);
    if (debugMode || (xpub.success === false)) {
      console.log('getXpubKey =', xpub);
    } else {
      console.log(`xpub(${targetBip32Path}) = ${xpub.xpubKey}`);
      console.log('PublicKey =', pubkey.publicKey);
    }
  }
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
    if (debugMode || (connRet.disconnect === false)) {
      console.log('connection failed. ', connRet);
    } else {
      console.log(connRet.errorMessage);
    }
    return;
  }
  console.log('authrizationPubkey:', authPubKey);
  const setupRet = await liquidLib.setupHeadlessAuthorization(authPubKey);
  console.log('--HEADLESS LIQUID SEND AUTHORIZATION PUBLIC KEY --');
  if (debugMode) {
    console.log(setupRet);
  } else if (setupRet.success) {
    console.log('Authorization pubkey register success.');
  } else if (setupRet.errorCode === 0x6985) {
    console.log('Authorization pubkey already registed.');
  } else {
    console.log(`Error!! error code = 0x${setupRet.errorCodeHex}`);
  }
  await liquidLib.disconnect();
}

async function execFixedTest() {
  const txHex = '020000000103b716647dcad588b5957dd8e560c15c57074a5fffad4fa00101ecad9ed46fedb60200000000ffffffff3a961119251ab3faa675ab8161cfba1206f0b2d440d95f7bc3397cbc679ff10b0100000000fffffffff5d8b58d27407fd84c7b4bbde71140506b20e3a97ceb17896c63cb7aadaad6cf0100000000ffffffff070b6e0037526679be1a229fbb92bc2075865b2b70a0820d6f4163f5ed0378a1f260081a56a7c3a9a43ff1e9ed97570fc7e96c7b08d777e0d0fae1832cc8ed1e0b14df03a03b9e150d8c8dc59a3a9bba5b31a970595076fc74b72c7bb1675b65efa872bc2200203a5ddaf62186dfd0e7602cebaa2c696e5562395c6004b3b9f727c2a3e3869ae00a09b4e18f1ad1b32ed71dd8f61ba98ad154e3fefb37d5beea3b31835b7acfa14a0918e6f8fb5be833fac305fecdf1f3001655cc4e35bd120e2d7222487035af8731038df5acfaace27c11c4a2261f64b9cb8270124973ebf051c512f089034ace51f4160014819b2e81a007ccf5a145a3acc0d218e39cb98b7f0a4157ad0e83600c456774b8f9689462d9a49bd62eef9f2a8aba25984058a53c53082300d9eb00ef92d2f9efcb202e94e4e67f11d1040e5637d9a18180d1e488d37503ba436e2b56f25a361f5108ea779205f63231ab61b3aa6bfa8b2326e0619f22f916001477a5d35340c64a99938bd8ea49542278344a160d0baae4c0fd5376ea3206ca5d0b24677eaae0e898a38552a36a7d619f0803c22ede08ffab51cf56a0d22692fb3b7dc438e90183656b6b6a78ceb3b75ef8385af1ecb203c52d8ec7a0d71be4a163c8706c13c4f427ad52029322341363fb2fc360c35a1322002006d9511d1d863dcac3bf5b31d5c4ee50c39f8269281431d1fc2ae9fc4a5e8f260a5556bc2895e06a82562926c2eb799119bd0ad784569ce57e20f6d5d63be8418908dfea4354921185a4311f424888912fa5a28b48a4ef476468e404e2823faf9c020391db6b3b966e34e4acdf7ae92021c8365fbca6126140620616971a712d4dea6f1976a914c429439eccc87e5bc0b666a9e245fca0d06f4a2388ac0bd74d0d859999447393385d5154e65c21777bcfd32f0716e7ed33b3f6bd405be009d818b3be49a3bd87c532d127bd8820dcce8b161114d10a3c357b35707eea1e5103009e94cc4ff5c9a3b13cfa29556fa0a0a01bc0bdfcaeb23e800e2b0e654abf0a1976a914a806744d8502be1cc456d9038f77b7713810be7b88ac0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000000001bb0000000000000000000000000000000000000830300079dfed75435a350375bb013c6d6247d934bb0b592d7bf8598680e26984cb679dee7b0b923eee3847382a7e71179292b5f9022fdf61538178bb4d35fd4123c12926c9038816aa4a08fb18ac1b05a1b1a7f9c0ec2d7746c6b8fb0e27b4cea638439f92b1d3ee0897825b9b89e51d93a6504a12b1c129ccf4e14ca87598e5c508a79fd4d0b602300000000000000013efb016c295a06bf4e95caf8b771c1e5fdf8fb73fb3ca874c76e31ff8e81a4617c26f961ec52510d3fa22ffecbb1ac8f6993dbba7bd1d7a10bc4f8480710cbbb1f385ecaf0980a9506064476e6e4ab43f45025628f6b35e90255884cf59c76681ea674bc8ea08485768f77a717dbe69c8ff99dd7e3767cf9593f53ac11f32596db5181a4a4891db5f8abb5a06e4e0eb78ab758bc16e4e2f46467333e3538ffa3348046e80a7fd2dca928ab07d449e57117c03b1d38a7b5316ffe9de05a7499825c05ec0696f76ace137dd5966a20295e6e3f9d1ee28a3756ee706874be416ebeebde4e3843066461181928a3173b08e35ca47d00d409b98fbb5f96338c73945e31196b5587e05691af8d0c1e7742cb13d0166c9b6e994d3e4a09985b8395d09ee80b5015f3da36fc336631474eaadf345203aee4d3e78782d67aae7324691118bbedda7b17b23b2badff1d58de00edbffbc68d1cbcd9a36ee83542acedf5b2a0125f84b5fcc8109bc7a094dceff49b63eb5da6265e0f915b49ea60f6f5e29e4e06a0fe2ad629da2d76a423722e4c2e3810812d325a68a42658037a94bd567f7a02696c002e62d1973420685a6bf6c4c3975ffee88d3e158248b4ba7d6113dd567d6160a7e27c8e32db2094a10dfe9b0b99766e1a2df1ec9e0036ff1a2609160a5835ac7b15b505504827bc1c3bac44f0ec70ba2e726ea328522a8ada94fc9bb13414c7627fc236d42e01c58c4afd05f985d927da1a83362e16186e872de3912bcecc5f3c42e0b80b98bbc980cc51fc12b1577dedbd3186af5a7cb7678a8a457b3e82a041408ed6ceed3b7aa0df29362915abcade821ee5c2c204aa2fb858cd3c0e2e54e9036178d0c656d35eeee1a91684fddd636500fcbb81e7b4786d6b8cd06d65225bea3040e7eac1209cd4980e871788fa3e399f01193bf4ed658b98b405f11c2588386934075f6dcbdebba0886e44c3135d350fef558a04bd4b6eb0e9bb50038ee6100c77fe60ca58b8222b4f999211b12d0fdcedb9212f77a9a13ddb702e6befcdecb8beb474f5c504b62072b97537df2f998a5b45834e4c62f4f9e4d2c805ab6aa54c303c7a9172d0abfb035d3caf6929b72bf4353adf0297d5b2f3f334a6d29726e1f8f8c61628714478c843099925056c74a14439432b25a8a226056aa5a9664ca43464e30ad157f5d4db909dbb600e3643503620f1888254f777d071ca7e61a16c0332b4e0c58ed18738c0a80159a749197b0a5699baae462b83053f61cd3ac0f768b34a799c99dc7bd83ca65f36e9aa5d95fb1bc474d59df6fc5fc50c07ef0cf644116d7530e55a9505f6a667d02f509037bdadbecbede18db751aacc8a7a3d02f866069bc9b6fa6cbff1c99924bbe4cbac207e023cfc5bfd4bab8bf485221de7624c0440a4eff6c08983f5428055212c3ff4d5afe6e8c59e0f4e37ef56416b9641d226173f8a05e6f41e41b05962793648ede411a58c26c78810cbfaf3df50339d47647bc1598bdec14915332b54b539d742c29e2f516b5a2f7b3397991590b4ed1a76a70d9ca49562c805678a8a7eb84f75662a900e440b9752e0090a1448b07605ce7102d64b9148f91c202d408719f331bc454ae604e1f505f3467c3e8352975323b76773b61ee57fc68b5c5a4576ad414a758738fe44abf826753559dec16978842d205a122f1b568cec9529b0bb8f81b1274e27cd5eb66c71ef5c3a16b5e501e978a42cd2fab34947cc6dce08c4c4096a78428c844c914835f563dc4a92683cde28538ec13def435061030ed34f8020cab12402c4611a7c526c6f8467f360b9f9cef37fa7aa20fed9d2bee8c00b337fa73f093db0426d157cca82e6d8bb54821009d3b5d500f941954fadf746798124cf9a3cf48662fb3f8e8a4067b50437084b7a52104e51349e93ada61d464f78cd984b2089bcdfc1645a3eac4dedd7cf2c66782777529a1d6889ef82239a2c4ec190586cab1ed8c1983fc5884de24bb06faaff92021fb95fd9312ba55e0a1e3e4805ff38b390fe1aeb65e7ab936fc3d58bc905a970e8746efd59d1608e07955411b1865587df1bd04a9a3f2253216907af43efb1a4d27eada34812943c1eb98a411c270c0aad11a89c2e838f4465548833f1f93f9deaf922686711784a5f414c759de63a052327d3a7f8c381633935e2977ca452ca8c3c4589e5d4d0d5d17057a574985fd7ce1d6287092418b5719bbaf0edf3d6bb074913c0d74cda8a0d5b148d44387e412b416a1329eefd20cf48f227895e2fe07b770c8160a1d83529792435f18c18077ce030b67e39c20e67ad5938e1ae22f6713c69307afb9b98249ddbfbdddd251c818eb1e8240425c6289770e8805637c6e908b821257577faecdfec04924e163da6e8066c7a3e4ded8b9867c221f4e35c4e0a7a5e50b3775855d27b1527fbae32ca22d1e9a82c5c050c0d37992c17cb0ba867572146eb729580f3b2e564c91da0985a4da835e7f87cbc904cb244fba70a91b79087782bcb15b25279765af4a87351f459895c67d92c159aa8fa1cbb93aa89050f981f06179ddeffccfd62cd06d50d391417b6c0e40dec620e596c67de415492271d17133a42754b6147beaab3da78fa5b38355b02434b575169bbe21a1551d5ab4764b2e0d48c497c22a1e58ae7097c5fed4ba82647a361d11dca00db3092dc41386aa73db24af3c659f763504c3ccc3d3532b6727ac86158d08cbc7f047e4e85f3b9ba72c557ca93e6b70c2e5c4c76eebf5808be0abc35e9271d5018a46e7e86aa98e2f7a9f4be83e061d091f64b59478628a413b8baf89f39653ef305f756aa5f4f17befb2f8022c391abc63f40e20df11c7ede6d98f466bdd5f5fa2edc2a9d8f668deb8148460200fee45204a4204c1782d3be19059bee095a8a80dfb61d7adedda55f1be82edf63e2b8b1a5527a7c1a049ff45494a17b2ff11bf8c47cabb2c0f44edae53c1f2f8ebbc4e509f6f0de6fc07ecd78b2cdf3ee099d9caed26f7d1e9797526d508b4a8950b4c1ca3c1d387392644c70c90dd13e94a6ea775087b5f9384d7e9cf92f5e6460107f72a4dd0d6694e1c876fcf815903bf171f6f048cd7f86b55fb226f015eae674aa0246bf2f1a501c65179a2088a1498ceadcba739c7b74e9a8512017e2eae592bd60053d07259cc71abf7ebf7aab3b33a336158159a4496ad57478e2f653de5e50e0e9dc744df5516646e9da27543a5fa6b5dce8cbb97757252d6b4c30d3cbcfd01615cc771d0721d7e56e1cfda241536479def4338ceebdf79b6071e332b3234dc096d2c2a03f008a7f489427562b3eaee25417db988e649bae3e6a84233f3732e965d2e890a1b4cc52964a965bf89967861acd1b9ecaf94748436eb8c34ab916cc6ced65cfd26014ee9281bda6a5f7dcda2192b141e06888dfdb5e608030b95ed1353cc3d3621afd663da1f62c3d34d3b5ac440f899a149d521247c1e40c5339d154b4bc1bb504b2f3d5e292b2b37773b448bc4b954f2ae8be666272b4c1fa659183ee75721f08caa19837ffb1c58899c97b7549bfa3b4c8aa4d8dcfa31dbccf19659d83180a0c6f56ebd409463491e6633e055f658b312d9b1aedaa4f6a0f209d2672fb1f3beafa5d21fffe19901a65ea1123282461981ebac37bb1950c7564a939582ed9b9e3a97b9cbb3404c099eb96a7191c1c3f7e7beb21965a63bb4981dbdc26648cbf258ea894638d2995f0c42ce9481247c7fc767517acfe77449413edb119fb06d5bc9d98e3c2c6e8d3d9685c68de265a2ec270e2da963bb4cd29cf11315703baa656fce151faa9000f9b64db6f7746cce2455f32f9648325740fe3562114e459055a814bd9f83daae2cd5edd1a1eecb0033a6b2f3a11e804089e443c292f1adb53eb4e16ee8e3b3437592ff5e280351d5d40d8a3c7b64e814c6d8f4acd84a6aef1949ae5061f2bd3a8701001c94f0c84874f7745436e91b94591b3f589fb8f54dc4843006e06d4cdd2f5ce28738a799915521caa7b399ba4af28e44ffc63254cb3ba690a24774f6ab2fc027682e975d99f4fadc4bdfc96dc4a1e14694f7d94c7fbbba783030007dcf0691a1123bde76b1008e07a3524ce9c8032118048ff2c5e668ff65b1722eb31871e5502226652259ccf6f2876735ffc223590cc50400a2aec151efb75eea192ad685d87b867091ed9d26840aa615eae6c99a6a2e676e2d8d111a9ccbe7b7fc1a0ffb2d91954d9f273d0336fd603130f2d3a8f20c3316a3355326c3496afe3fd4d0b6023000000000000000135cb01778f0005c5d8e1922733a6af6ae74318ca8e428a4cb27bb4ac6c3e4c5e13e5fc40596834b682e24841432ef113e68e8fd93f9983eb8b548110f82d3bfb22056f04d29db41c902c617933cefb39d93e0cc9723fe3ffe31419ddea91022aa25b82f946b2e82d6745277c72c875fca4350b4c213c42691b003f4538092e31f51867a8a61c25ab87671a18da522b8da2bd7eaa38a298dfa5dc874170ade11ff0ef0b17079130425d4562d6e82389497fb99c3ba5af9706084b50fb6ef10b1c1c2bea805107ff747f7c160c95ae0298b710dddfe1a9ae570b492aa7db0337184c87f3d7d50a9997c4a429690abdbb2ba0c952caeb18bae3cd47e4d8ae2137846d1670ec99ef420d7eaec09d2948a25df4605cc8f1bf3c21e83a67aa83a7ed77bc458a7ee8b74996e59239fa63ceb4e56969606261b5a09377a14e1b28385cafeee03777cec2d0ce8aff47b4efec6b726ea13a984a17d5930b5c15f6b52a6cc44cf1f663104db31c6536a9e999584d0af187a37da995877db4cb734ec1fbd5cc68ec94a6b071abca6812500a27cf9293755e6d91916b929ac37e4befb496dc3abf72eff3f39afcda1cd805fab2658b94c3dca55554ed22d104ff5926d386c65e75f20e41254440a64163047344b4beef986d2eb07ef2f49e6d79ce097131703cf70528433514f4c3506af45ecbaa6ed0ddf1047c670ff98c16cda717bb3220f61289d5f409a27fb5b054c2aa9790390dfec0c5a333c32915298cd432e505fe49360c257474b0da174e71547653c08335eb8d8c8cab63262178cb3cb719b7a9b0e94029995c0c2ec9c2edbf6f21d6e44805d0586ba19276c0a06e93bbaaee2dc73a7c3e79bcefdf8a646863589060f48d1576527c1e4cb2150abc5dd1dae84a364073af9dc18dff3fc17fe8dd32fdf31696cc0f66fe63a102d65c116a4df33495c1a791646813adc7698089525045640088579add1d41aded6f86678fad41a674061a15cbc6ad1adea6b9026b19376d8ade0ab9e04dc9b41ad06ddd6e57819ea15393fb105ac5f3e32b26baf49b84f0117691e2489979186a7d68cf6bc7d4988d2a9e7e030a06b4150c1893603f69a75eb561d7b5915142de480306d17b5ac10bfc7717659118fb2f17b5128357713a214bfd08a1f9d7345e8c81925d884447d5c316d6f29e76159e0738b2951c20e9c871868219e75297b27aaa74ebfdf7a88aa07a0c49eb6d7dc63aa5414349ee793b0937579ca2236e97416eebce7a6b2c210fe14d08153639ab24248bcc99eb695ecb64fc556edb2c353d75aaac8e7e8a8f2a4b37a14b43c3c1667a1ed5bcf730442e7a301868dd60acd3355309f96034e95222803eedb975329790a6f8a69c21ef404659f7b41cb263be57eb77e12086240f2e9948236b1bb73f3c523c897ff39d879c02ca65fb433c87a33dcac0107ea46c11d5f5ba4223a171ebcf481db2c233f05544153e868c7432b4f722ad035fbb8cb4b18d97a4c41dd4ffa0188dba9359a16010986f7531a89e26ebd49a23fb126752d20324db296fcbb74c96121e0ba5d18483bb4252971aee2fa7276e54ff5e81c46d8365cb175341c69654afd5861d565e815f098b91b9381f0f28004669193158bb34b12ab61519978c1970532eb2c05c5f5fff99b6094e6d5ec72f8d1b66261cf80de1bae5971d5b97cd20ffb673bdc74f2fc36f726b26bfabf31a2f05eb08d91bdba329a4c64c60556800e1857a23cfeb2506710b5ab7fcfc24bb293a2cef055c373c2073c233ecc7ff60127102365399f5b7219175f69a04e85a9b9a6bfc81937a5a4ede8bc6eb7685966f8f84ba324c78bd59df428532d02408f81b75998b201e59480d164dd624deb887b395424e45ca306bb9b15e4619d810c7e6f06d6e98e5a7258b8783e40096dabbbdaeeb09d0b17d94f0f56b4a177cf24aa7a6e7370831da48ce38330bbc60df90fda37c42474d1c1e3045576c7abb69ad27b97b09b60146d59f2840ad24ae06823e3c81aa63c4417359bca558001a41d90696c6266f0d6316950812fce41c3ebba5b5c8f3ba54ef6007659ecba2c7f748f8c26464374cd688636dea3701307d95190b89525dfc82f770190d2942f60977e8bc2aca4c1afc1c544f12206434059e5fd2a929919534695fddfefac397792b8ef62143e4f85c5054f7860e23e2ec56207afb6e6dfd8370ea3e2988c96b2190a9f5d38507bbf0748d511d1c360892ea6dd8918a5843791f9158e2b29bd169484a083925812364c0f44dac55bf49ab3095d311f5fd764b30e6c58d2ad6b6bf53ed0c86a5e899dbd37b11e188c7f377e96b524b8037185b54d0fab109ab5f619f398ccedba48a3042a27cd97e2ea4b2f06e7e027e21ea2a09ae23b60de10330e99a742ce2416d6b179a71ced411c4ea76d3abe3e684399ef6300fe9eb4e75e756de82d0162126988bd97f8d0fc7fd0faac83860049d839a0574e054edf4194852e24be5a97462524413e2b51151949d732f1414ac97ab4ec03b5e9ba0e925e24c88f3ae897324fe1cbd2d69a53b026fb51f8d7e0733c0880f95c19a30e4123b98ec3e76de30f4ac8a6cfbb5666ff99ea4a43878291e63902231b0d6a38e5c9b8421c5cc59ea4a0e75f502ec06e5cabcba91a18cece72c27e9df906d8407c10a3de3b06d6c4f8426b638a01bf0bdb6e7d1928f912dd6d44df19442d7509c4c13c706dbbcd7adb9f13e3d63eefaabd3304ab29abbb30f990975b5a380fc19da3209b00def5c4d17db4e4ecc9a03ca0df9cac0619d431ad627b53d48d413fecc5784e70625aaf352d6fb97dcb100e189af85fd0bc085afef28232ce7fb05fb510c61c099b14724f0bc788aedfe0ecbf2d94e98f8541b565da0bc3ad68ddc4ee4816ab2ec457b45d373102d78818318c2fb4f5112099c2aa2f494a033b08d95f8d22933682bf060985ca5cb3a1c00e11cf3d478da87d24492bcd78119d86957b11d39534911aaf6fea6b6efbee9a4d30aa1c56cfa8379ab1747163c70d9512b07d1bb1c1e296718266d355db01253d7adea89544ea97c5454ee7be9c96260c0de6b433de3c280db204f0d8d7619554d19e5df8a65b81f9a51279ca5c60a48801c5e6aa6cb52b3f8e01d7d52f764b8bfaf73cafc60b1801daebc2f1c42a88b959fca5ff40af283c024624252416fd1664aac2f1cfe7feda96454504390c6cec22c606fe43b5c5d381df429370ea5a65131c7cbdfa3d062427a66e3bddab4c6759d737b3414ca9f888b8653f05e4129eb6852908cbefdd3008d48793d12cac411482da2d3e589f120cf7a026be7c4e92b7ea52dc46f218d3356d5368ca66910f161e883db9b89d190dada664c49066ef944f0942f0f1da00a2b402fc827e732f7a07a83781e10195cff1ac83d17b4a72fad3220555385308296b60ab98c75df635328fc1eab0cbac1fef62aba556faf59a167edddb1098e8b62a9990051c8f48d251d4f391fd10fbcdc886cd04d4251238bc21998c199415a7f7e529b6feae2daa700d65a03222b4feced9fc6c4c2902e06d62d8459c687a07a282a5f696c01735f39bbeabaceb804085907283fed76abca8a41c36fda97b5b67c12e336060ef0089bfc3137c2592fae01901447a2fac72df3dbfd35ab7db3ee22c4be4744ff88b62ede55e6391a59c2bd3840581d948de4d6fa032da550a5e9492da904f0d9016f8e4859cd6c3f7c213ab0039460fd2b95c1c7d5a13d671c1d3dd31665a18eba3d3e5b16f88a01ec9f2ba4f0a402b89351679a73758b2b6b946cdd28e668bd1f29d66749f470c6708c058fe9a8c5a4a0e1477f897a362148854157ab86662a2f079d067c2e3ff3d42d29bce95d183bfd682fb87d22a3364d2dea6a5b6b1abf9ea24ef3e8e816a657a37a637b404f6c7e915bd25ad9912a8f0bfaf64fe943d9789d8bfe8b0414825c3bbe0fa3d961eface6d30861cb80721ab21474c8e9843d5b85208594ae094739758dd5ce7dbe28b2cf739b7c941008b1e30b0f845ca00796aa5e74e6e8a61c3a5e7f21177a74d46ffa40f005269f6652f41887d30891a621d2640ff61051ce4b830300074c23684fff1b4306a7f9eb406fa63ed28995d4e4aa420bc41400314bc21789380a8b92a9a67bc551ebfaa0800c74bf56b89660d05010b66a3af2688977a633080c89f54f89223dcf99be380f34a74684b05297c5ff6fa7bc40b96deb7ce0e1d1c68b6ed33fc76656208842a07f9204a0cdf963e4c305206a56a01c62f383dd41fd4d0b6023000000000000000169fe00ef36cf7d9db1c3a81a01e8c2eddfe8bb785f25e5f11f6ab7061cb2bac8e584884dc8717b87bdd91ad444ac5e39f40dfa8f7e4b12425c5c901808d820754fcf000171521688802df2f5548fe8343472bad0ec0b164a2b0aa5a1122cc54dd0eafc31a75002b76b16a6c618983d4c8a96b2cb561b2594aabae1bde7586ca01707cb8255190565edf1a5931286873374d961200b63050b9229dcd3fabf84b0118b409f6d01f096a6052185759b74dc2fff56cc37747ddbc184f6bbd23d91a75bb6b02323f0bbc56a24f2a8b6ac9d036f212158b4e240bc7d9f57faac04118ca9b9e97e45b37e7bd133b71d6a4537ae1ee11e5bf9262cd62877daaeecbb04bb22d093a8a8e6ce523914e02f734993f79f66d3daeed4f3d47c00f81caedb638f4b3c40a336bb104d0567510ea6b32a68371f7d81229680cfc4d523a553bf18ce3770b5fa879d4abbd7644d54f83d359404bf8718c0e851968f26d483d11dc793302e492337571aa66b06be3dd169085289c809adef57189b200f7821ccf250e9e66a7996c7c49502204aa705d9bb1f939f409fe2415ac98cd98ed6145d396890e6fc35d3222b15c72923c93ab060ee190d975458b9c9fc2d67e33d679e3e10ef97844a204267b1f55f60046139b837aefa75119b38f3229daab86f841b9a57a185b29d56358394d9ee56c321b874dcb33e0ea39d3d5b23537cb87d1b5d3cd264113ae8fe3f2b5c1171eb2a1e347064015c238769350ee2a1199583a13faa0480aee68d8d2cf02fd7a2921074565aa71eb341f7e5c374270f6781b2dd5fdcd2aa362fcd742d092ef50f12704136d308d3b2300e925a33c83fc8237b20c255e365eda31cac810467de3756a275962af7b19553562a53c357314ca7c876bdfeda8480879b577d323127d706b3e61752eb7e1bf3fc00b7f78d14bb6ddccd838da46af19432d1f359002c514c956069a35122741be65f19cd04d834c5824e312e93554f1aefe331ed9ff85b17d24eefae8a3e40db935e72336b5ab80dbd2687c481d7d4f6ec6a9b668be06e2996ec0714b787238d5bb95b298883cd1d9254527ba7fd6731398b4a7c39f4efdf47d955edcb351c19df0c190b9de30ca4c2b92c3cae06c0ed796130a1b1d9273b0b20d6ad93e9e05641575c09211c68c77ec53a1f3e03dc2e26af6254926e9d2d61554ce7cee8330da6abfa32b31ee0ba9b804dc38e7a97a51b2df1cde47e90bdc55bd489707becc0f7b98099b6972c0d08323ad2ec931a5d3e2140abd675b189300b6893b68eafa63c158e699dbbc9ea9d13a5e6afda8d715662475cb901c641e8338b97e5600ead66a48e525ebb4418b2af62fae214a2c21374e0f77e78168b0b981814648bb6242f008b5ebd3b111694334572ffee691061bcbd506995a9eb4662f6419c3bc0c2adc8d9610f0130642f6d0933f7740ab192fc6afbf43268db7a07148cfbbd4ecdd1e8a8557a90f3bf6fda6fc2cb59f2a3f0d2ca2179673ed855d4e99aef673082b0c92e5ba98eaacdcffe1b54682afb569abf126bd2dc3464c60e7b8b8249fca93889ec34d6536b43251b7ffb071f17787c5e21327e6f317a35cb004935d67f40c1e1cd8efd0669418b88cb43f347c8bed157db6d114432fb67ef600c480d2409aadfd94a2a8aaa063b5fc21833c17320e04fcee5aebd2fb56e4e98bc08347e6a59458232e752b4072849ce73095bc093122e43cb0e0b21dc888628206ae58c96df382d669f8a83652b306c85984be91bdd1a3729307f50fa8c40c0c4adcf0db63a101f19b03084eeb1b468eef5e151262380eb7ed8a16209b1f6efca2a98c486c45aa8c1813606652d13f744d9f85a26e125686ad47476616f3bc0e40547a4e5c697833479e1e6afa4ff3f1079a29f402afff8c15b8e8dbc59b30e0fefea577730376a8d2a085de36ee7fc88191be8702bb47e501b838f6745d34e9e691a2d069b995ee953804300a46d430c56c75911030ec227f10e9bd08e968faa11abac02c0e844bb662bed85c1515ad68f9daf25e1c9b2f4376feaf35b15e5d33a98f3cef654952b3a32a34def5e90db6d5a4b6e9d4b3e7b75faaebcc78bdf723fa080df5611da74a62bd231e3195bd71d0e18acd866569bad987a87315f59368d530f16a0688f1a94012db048d0749bd494c7b005159f75760e6b1ad1b3560853d336dcc944b6ba42f965bbba389414fe8c777d626c562264321d5d06247bc5d5cad9823f969545975293d18f251248efe32cd77e43a5513eb5719b9b5c11b3cf24e7343ca1ab0690119769ce560120f64aaa8c863abbd57b961023d10d2e873eec935d94c54fda3c75c8e46e1f8329e629d9066d86d63d92c26600b4bd6ef0d8016395e7a8c0419dc6f4b48975733b170ceda9781bc34c9deac753fcdfd84f2e34138262ca5a872f89e0be945ed69596a3e644f75a7c948ba7a9db58a699cd6b57b4b78f40d253bcb27c173a51e623f8564f6b31199e08f273cf25b8e6fe6d0f9a754ccad456508778bb22652ded0fe4b7a647bd08daa714df9a3ea8fd9e3eacd70dcf886f8fabcec016d63ca161d87e60d0676a3a4f364641d3cf27ecef87526c065667a0268d42afe946bbd3f763dd8574e1b3430472d5821e86658a4f56f109d7eba2e0f3c56fb05a627b852219b80ed29af6d146c9e90548335866b5969abd19815d06c9fc29d478f90eb83699e69c85c41715e4e02e9bb5dd4d9d8283356cf3f2d3f1a6179cfcc77da51ed62712e9f4b151c03854a4e740651aa0c428ce19e38593f5352c3bbdc09fb047557b30e7a330e933738e7f1ed5487b2d20308e15e58cb20232f434b058467f6217e66bf00968de266ff1afa094784e1f589482d128813dc7541f15c503f3187590c5b0e14daef310bee93e98619fc3acd55df9e3e3fa87c0565c97817ca6ead9c22702afadea47c4bdac8f17f2a521bcbeac5200ba4036b6d39e9175018bf51894cf4f908705b8de86c1e40eaf5fb8d6569cc562a675ff5f3a095df31721931b84badeb1879871fd90317cd63d2b66345f59060287edb14229a7e72cee6904a56c36ea5a47e372798cd75d49ea790b71a03dd0466d4cab333868995aa16d7528e98f10541fa2f65221b58f27d82debea1eea68270166c6a6bbdef9eea0d3dd83ed702ee831ce8c5f171fc2993e4e2c209cdd344a4b740656fd0d307fe97f223f69104758e8573ab1a0d298a2956eac92c5a427e022b226005c90ec89a023dd91b376552688b9cae4b32ca0230e43a5a475889ece074bdb6aca03deb0353493326b817fb26d675dcf6b3898fcc7193c7db496e89f2b4b6ac4606ce4fdbcaa6b2a0e6234c1290512e8d8841781b5ebebe617e0c8346ff43ad7b9ef2c385090f0faeeca7a893f3deef234c8990dd114cc0840f33a1627de39aa15516ae5f502e99e08791b11b077639be53585adf05ab93c61453c8a4d5bb7ca81f0da1eea2844c12f3f85939f7b3c07e047b30ad17963b65f8419d7e299873430dc83d268db3da1f66132a7c5b3a3371ff1c04e83341647e1ab6d867bd452a979e6de1a121f87a0b588387d933a8fee57983d96b0a142a1dcf4d43c4bd5fcb735f03637c4a70280ce814273bd799ee60bbedd637e227618e6f6f0046eaea377c4633a9523704804f3ecc36e72bf654616f9865ffcb2e919d4cd68e30240be77e46fde095e9750e22404810efa2e7054e04664576ece5b68f4aa53e10590b6009595fec196d471d844db0d9c62ce48e669de49f6d94a19e7d26bbd3e1bf953632070ad934bd2ccfc9fa0d01ddd2839cdc3a4d0f5314af4d5c9f73ec269435c80faa497108b872b90558d76ecf8eefb823f91e0f0e103b7e0baada6bd50300c818de54b3ade0cf6a246077cd35050e45efad74f55e8a11da641ec41b1c6c07f840ddfbc2efcc09b21e1590ab7c1ee320522615a819335311c25f5943e296c2b9c08d7db1fb6af983c249b9fa8c7f1628e65b62b2624eda592dc5897b29ec9b2090c90a557b63141b4162e5ea06137caeb6f29cffd673a3a5c6720ff553e7bca7d735abe0a1a1acaee4503507d143be0830300074fcffcfbedaa3f3da980d9d23a2b163ffac44c9f5817675742a53c19b67c489e401d715ad61fa1cc599b24bf2f3c22e081935af6a1a222923ad7753a1e9c31d44e0b35f9159699f04616bb40855eac04859bd85cab464f30af3b7ef0257971d105d540409bc8a4732a68cc792a81ccd9aba58a0ebfda05d373b6d2ef600176cafd4d0b6023000000000000000147c301623b7318b4b0004f6022a932943f28661cd4ceb5b10e685c4874649123f7a05e52c20f175e82c9d2e44b353ae7f3ee89e619399919c6e526ade400b1af298f3eadb083463e583c0965aa22bdce0d6c8465b00bf2881311b51d9a63ae6a9141ccea5bf41cdb2bfc860a59df49440407ce83577d5def19911e7ddd4c1f90eef15550be555ae16907b0b162126c1bc603902baf7602571e6fc5f10088ff1c7877e2119b58a334abcedba34ba995fe3f2dc41a1d289d4d50bcd2f5555e4658be1fe10ec494c981b3091eb8ce0af4e42eeae8ad00dfd2a40c303eee915e3d13620d0d177515cf014833d75de352d991979456f8360c1d0a9d74428b2ad3f843eb76e7d75eaacf101ab7912fed69ef300eb008c8f1c533cc523d06f01fd23c5e550fe2dd5aa29f46d944b7da367ddbae9b8f80f0f6b83bed848048b3135d93ffcf92c8e80d3424c3db8fbf7d1bd3cf47667b08bfdddd662a1df017730a0e3273e8170cf71924ae07286f74c9160b427e23d4e25bacca54972b5d98f1ec788809da9082db89d157c84e33619332586a85fc75b66d9f58493dd679b10d6f35e26bca02db951ba08984ea094e0e048ac867301aae7949a2b8a74351dcd8fb60ba96a057fd219403e34de505a1f82be0a5044d467e7b092437f31d082bfe9ed5b4b72d549cd239a3ee32b4c939066067cc8991cf6a0138430bd413b29b36f2288a36777dc4c5aed3e8dd4782a3d7e8177324456277d5d356338ed48dc8511eab79818bb1bd74ed49d5f90bd7375d62ec4b62b7f0ec6433402986ef6def4019f31ee21f6b7dad767a616d4e26b33403040d3f3a847dbd2818a5e7fc92629d4be3aeddbd3291a13c6f2c8ccab09fe96402ac98726b6bd7353aabc6795078717c7e6fe41cdf5c490b831894272eac43582b3586773a35e28277492ebbff1782ad40732d1a29c73a9f71b8510ea16d7c6f8f8e8857fa64ea4a5832f2103865ed4bd7bae18ba2473037cf91d7b52e152253eddf06a54ab0578246a6856d012d621b2c4348ed9dc6479653d431ecfb71f7fa55faba43a841d18eb1f9ecabc45686a8f173daa31752e0862692c3b08ce6fa45002efc6b6ed45ac252c8bf67d72f73cf8d93d503a7738d4abf73c7354e8999e465497ab23c4237344f3e9059201162e8e4b659cd1e8b7ada1f1b20791f1ae47d7f84efbe03c21660d950676a63b0bb8f59cc155861ffef8572369630e8d33ce7597cebcba716c206869c3eee1c1e68dae10c33bdf0b4217f8bb332a8d138c343374807ddfd7b4e881e950fc27aedeb842c55ba6d7d261e0bee21581ec96dd245822fa6549f0ac5abf539afbad645c166c2edf4b18045c3e9b9fc893412ac3d9134cd46037a8210ed6bee8ed6f771aab47a02280bd89d8172025be6fc2a30413c292db979a63bf72f59e01b36698fe49628e7ee1bd49c50760ae0bc333a25bd5ef0062b4d22671e512b667a62429517b02a420c60f5ca3fea20cfee28f19264db3ac4217731a3063b77a1e20416eefe6c864e837df2c520b02f9011b3ad62dcef879a74366acbcb4bb48fc55298f6fd7dc844a7f1e328a10674d4e32df8b15b613d20753ba645efe80489afe4f67f23297a44265b5e62b8676522fe5712ae983c3a38be9c4eeea8793239e0438ae7717ae489b1baa2f4cbf7aede4cfef9cadcc8ef83185002cf142aac538727db19e2a6bfec2bc2e1dae2ba020e681653f1c0ce7f640af80e291efe697c8ac22716e521c8fee6619875624d67ac218118317624b918dfcc9fc5ed4d4a9f8ea6c59c8e2ac77f70332a8137bf207d8d89dd9b4901eb54458ce60b3179947317d2915b9aad6646e611d358067b70b1ea43fbe13db649292cfd2ac985cd3b0b0656714739c685afa726d0e55566580f78bb572114ed8e6e00208c1fc37c88a17334a6362ced4b5f04f1df2798945ee2bb286124b7c0cc77665f4c7dfcdcf2537301707908a354fbcd78d4dfd2afacaa62ebeec014302ef318a1f9db315a055b6aba0823aa0e3e385bcba82374044b1d62bf1d94ea3325599c46a90ee6607c66283f8b00bc091cc63c7bafb18bc0c1d9ae877a6000b7d68650f8747ba33f32b12334c000499847609fec2c25b83a5bbfc8e6825d080f652192c08270fa842336c888c8c1e72d6b4c4a7db158474137d29ec883150bc9c27bc6d25c8f82c07beb61be0781e06c71525aa5b157ebef95accf0c55cfa02a4aeba66a612a849ea6a7afd99cabd221fe8f87bcb20849746d22830ce8d5d91294d7aa0f7dcbd15e199b7c9b619cc41411f44437b3c765a8eb7d2c35dc1a2b05b1055d12cdbcae324ef41a7c1608049b43fd28c6d043ff761e6066d695fa8599635adbb81a801b25d0ede16fe6d6a35beba79588e292c50a1d3a9cd7d7b366bf90e8b6b3c195f1786183c854c87d3261b39d666e2067b2d1b9aa1979b88070b6db2a599e8194f6bce938deb327d65609c738ad386d21c377bd72d20964ca8d4db671714277ce6a20666f647a1ed4125baecce21025ed0adc808824287af49b76eaac2bbd310970bf530ccfec081ad5dc3c4c9849eecefdbb4e8c1742e60ecb6849e3c64895264ecb0a8af4307d5f431df33b55b546bbe739e61587d11bd0cee3c059485374d95fd5e606a745e20f4efbb46fe77296ce4e4b08434e789e9a503bcb718f856798e70e216b9f63cb9d297fcabe669e00ef974a268d7f1b139b631169af5198a0fe350dd3fceca6404cd865b9d17abce0d2fd5ad4e35eb9313f9e66931508680607b5e73fad96f6c5856061db8044e2cede0c38dfc4306c1b029974b5294a0beb0869a06aaf6e52531f1326f96f0eb0bea454155000500e28a2c1f291f1874dfd2bc9fcf0321dd57985b5ed1284f7939f067110b601d1bb356a13fcf06c2cf4c33addaf62a8a94b9d80c8879ffb16e74f035ab5a86fb5f9306cd154c8f76120a3279f39f6e72f672124d1ea7d30e82be441ff863dfd65c5ea1a1037c7dc1b6518e9ac89f48517ee1d7eb9023a4712f74f74e1ddce3a4f2fa259b8ecedbbf21394a30b89bf800145fe31cc4d997bc6e6915a6b0a83756e4a814d68c768178e6f91de34fb5e86f07825561ffcd204c3c6ebcd25c9cf86429729ab5c5aadb59941e5689e192ca9ae1a9cf9b8832c1324e389285a2137de258f3504230f763a0360bc2839991c530cee80bf85d837eb34d2f7ac5040fc4b209793e3ab302841dd930bee48493fd61e9071d9c224eb32698cfad33d8fca58b6d60e280d24546daf7015125113b03cfbfe763aef7e3ca257b6e803c2d1d697cf3cd5a3c4d4821b3e75651102501029dc4b1df0f75441cdb7bf9c191bde1175376548743f33d94b9db941a724666869ade57daf73bc617f18e6c9db44638b6ac86544b8acdfccc8fefdedcd9116c4672e9589cddf6bddfa4fa6e20689299c1ebbe58ab898ebbf0bd659eb79afa0fee869e265d0b766e46b4d9905f99f8eeeed944334606808d860de05de3b071cdb80a5ee00d416f45b803fc4fd5fc9f0c25e9c1c3948cc6c4cea665b2a1cb6692ce224ba172c0eb7dbbebb35f337868e6a5f908afa44de99399d6b6ccd3acf3be3a9fcdb73827ca2dd671bc1cbb7aac993e687fc6746191c50da3d0db66ddadf9071c1773a0911bc126eef40e4c1038a14277c76202fbdef1845ededd8b827ffda726e1911a77cbe70436365aed5e8c5cb08e0b66e569de0e9a7ccb7d99ab2d9fddba2e9ab78f8c50005d900d801537fa8a7fb3d79d83d2b105e9404c3cd2b7ff2c7913fe983baf04e4b9288cd58f524d2c8009d9f0dc79dbd4c30f1253c5734e55aa3fb987b0ec889e0567b5df39145ec5b867a122a3de1122636c0ed54ea1ef4c5e8db7df536bb9ca4e23ba8a43a3df94c0a0aabf9dc96c529c651ff68cdb79d8f7b8021aa0899edec82b46155fd13a79d9b30cb14686a0e830d236f97004934d648f5acf3f992efbbe950dc056147e9f873a01c5ddb0e67ca944a8b6f000236d29a48331198abe60482319a7a6b56103eae14684004712007e42534a925600d05b59b445efa38cb33dcd00875830300076108887a8f9c8d8fb1e1d204e9d48dbb55a28cdedbcf6258ba775108326ac8105ae20db39088fb25ac9b6e685d9d74de5316214307c5087b17aed5eca113e98d2b4fa108f857fb305020a6f6fb56c807d0685385927ebef7b53db61c9448f8405d9e4a5116cf3e6100126b5c21bd2eeef78b7294a2a0ac356f3dcdd51b1e8a7efd4d0b60230000000000000001dbb100c24bae77452ed1830c85fe17f579a31a90c1e87bdd76900168775e9f1601594864a4ad699ffaa30b4e0e301552e9ab77534dfdf9386aa42e6ec4b3761d8329dae05e7b67796f5d110606aba7989136958e9cf622167a69ce222404a787b72db5ce1740174e4da7b164527eb297dba396988562d59acdc61f52e96800fc033104f3dd6398a8ade84cb704ee52914fe3da2eda4b3901c9f6104365517d4bf4021d5339119560a4d8ef78297b7b201abcfc0955739c26a9c9a8f887776a9fedbf656f7ae3d644c6f2ab9f6f90d3f9b9f0528b2682603cd5199fdce7abf5440a840d986e99e8a0f76424c4e9cb233466b3b97247e77403b1cf1f8fb8ad8085603cbca5c671b0de0d53539546bd1b7926d402e40974894e4bf4a6022dbd950ec95a4202da634ca71d9c48942e282493baa8eb5cace782a18b57b3f796436f7c3e0411be4b62a2509c00f176a9ca97380c79fd85d0d879f77620f0c079684286b2aa512fba170e564af5cbafe0e0d1a3bf4fe9024b86ae97517705dae403d034583ca5ae13f77e9cdebc61cfd547495d71f8f2772f32eb061a89c2a23ecd7ede8b779bd87e2a37b9538e53341e7fd26f65a63012924ddbb26d64599e52bcb7c7ecc35c383ec5eef862c31091f909701f333028b18fafa359857009a26fadf255b776262f2536d6e4c387119a2c120098135f1a7b2d81ddda263442605e1ff03a17b74125bb673f7d35560e9c72883104f2229c4715167a990af1600ee333e1ebc29d0a54a2fe67ee8d7185a81e3be5072cd0994ee01a80df7f1d5a28420f5afe1516b27beae3774cde034c165d095c589fb81a3fa7e99b5a1d3a7cb3a6bf19ea4e65473a0af859e2e260f41bd78a055115b8708c523dbdc457ae5d833756af17dc3c45a76fc546a636bb5d652d14e951b9a051bf7965da0df74f751aefb585ceca7391ec5d628b8d9e548a8f7c216e05d6cc41a4bd4077c826673190f62f25337bfd11ade44a2e25f0fd015eebcac57f31dc05d79cc0a5aebceb868dbb5ab85c30ddc05bdd66b2193b07eae40815389b0201cb871c184754e3dfd6cd005bf67b97c9ff55e73b807645a200e8c93c49ad9e54e7bffdae15757179d82593e6aadd997970023db7ba425ebc6122d5f3c2b91255cdbb625a9b799154b779bbfe3db3d86d923cd705d9f64eddfc7ea89c0fb98208aacec00e2121a2062ad0d00fd95c46b586971b735aeed47aaf1b82ea8ec04eea0fe6a4e9885ed2a69fdfa8ae22983537e4aad5ceb6c0db59f69f9aaa84768755398063b08444e9523a9b28c4b128f9b48cfa237bf1b740645b1672fc407731cf03dd6f2ac6558e769066457471270dbb0dc0abf25490b89459bbd7fa67aa79aaba2a0aa775d901dcebca9f948d255425ab32ff143d8bbc51d1016e972041b3d552fb941b99525c7efad512d8ffe30e3bde9cac81e0ce1a3e96e0b8f02ea399c085fb85787091c3496d26da71596f9e3d9764bc0d1455abb68c65dc9e492a0c892baf609849988250b4745875b3189919c23f559ece496dd22797c41c8acffa8d0ec161c949b388681066004616bc65e87e83779f83bcb4526037c1ffc141fb0c320d6ea6062c80e54f5b88c9dc50a7cc6b131f11198f875b29bc7dbdec4354a08fced9490cd7cf6710f983f3813ca915ddf74a471848d61ea512edaa590dadce3de4e47f162c59faa2d72f3bcb40bf1ee6ec9f45128ae2254ac0bc8497cf6ae53945729bbe77e3e54e4196ba6498ec66a1472efc9e84677c16b4592b901685a4beb48d0e6078fbcf21e9a365120b897e2321dc4115cfd10288048761fb000f4ebf7287bd3061cf13d413de59ef65c6ee9aa56722a3d55daafb92245f929c6d61c3538fb1e853cdce906e5a0af5510a3cb75050b247a1216100506ff4204622b6b8b44fce600640c2ee58a8df9f85098c6fb2178115dd27c97eea7d14a2546f84663c7d1e89888ed2f6c6c17a904c89c5a2d36ee11532a9328fc0f5ad9d5bcb30b177bc90986b0e130a42518f817cfb1062da321db8c9b0da75ed21a197c05b4678e2acc55440878f4c7ebe6c0d081668d7510441f6d54766c7b342674ffc03fcd8a8d5f130e39aaeaf05407ce6712e2c6554467cb45c21656491188b5b29521984194ec1c5dba0219b2a0e719bb9a68ed6799a54b4593e069526897d00f5c171e96cc62682b014904832206e605e92e0d707ce5e2972e2b74abe39d0bdc29157c8dc9782febfbd15b68f8d45629346c1087b16f6531a693da31f0b94e6f01dc64df3f9e11cc344cbcdc465c97d79bc03dba48d85f7b743669b88567f0df5c85c69703e4eae4cd2384a21a6a326b50f2d3ff541c901c0c4e666d950969330329a14b821ad80a6694b20508bc5af4d872dbf8897cb9aa50180f31f45975d02627eef5e8c39dc019b57055c8eef6ca2879e9a02830d8bec592f964b2ef0a1c32e8dec2b862886d9204b490606c56ab498b9ff8b481fb491d4be6d89bbf378d5d7938ab983f3337d9869983e1f2153e1e16cb71e441ee0e1ab0558790fd037d30c17ef8536c310645e1d4a24d681428c275dcdef61ba0fd59dee8887cd7f54f2e95dc20727680f39794dcd726b5a0fff83d80da80297fb6db5b0b676d1b28b29955704913b1d9eb1442f8bab65fc93f1fcacc658089418c340c52757ff0d69561e2e7edfaf6551bc5ba39a8a93c6744d019e6c624741e9cdb95bd824280074a1dcf4a82093cb33ac5655f634c8696b9378921e8107063d6720fb0ce89743e577872246ee1f2b618810c6539e614d0384a2eec4c42d0fe8108b02f51866f2b90838df65d9097403b9c5f7105d5f75ce1dce13c7a830fd50c81b608df0b3cf955a89455b09efb026beec5e95e6c106dc3f88a2b31ffb1ab60690edf505a6d881053a2ad6e4d2f7b53471f2f5695aa8f3deab7b16fd6b732abf28a08e6850dea5b72e0e852241d88b367bf508f57c326070a516779016e2595af7a623bde538870579f4d40d88cecb5c0e7cb92ee596766bf8f20986e29340756b262ee01ddd8e0e5e225cdfd8dd170785c7089daae6331356e88f8a363d614e11735f08e6301cbfb889ff4ef75fd5582d4f735fab006b344452fef87145f47a3b1e6ea9030a8893f49f6db8cf01b03284831bbf340a46d6b59f1acd8b4ea06eabdd80093711471959525fa5609321b27ebb68be4c6951f331d1e273a9f65dbc1885c1557648cba5e5fca6776524552c0f548f9faf2843d50325b570fb14e55c9bcfd43873cb3f22ef3ab52f969ad4b8dc881e2b4ab503f4512ec0d4247a48051359092417383a57184dac6208ca80a7b405deb3668a63d49697973c93a04c4b0a2ce47332f0bfb457c5a8338ebdde89d5256bc363db82ca635b768c9f50f92d8e18b1fbb40c5b5a982b2ce9350612cd39f7ea703e6a935e5502e02063361b341d4ab113dcddabc789e4a2725c4ce03620b8244124145cf4e4dc2b76e7014ea2e5045e4ee4e309e857de645a7f5e96a9ff4937a3d93be633259d2c32075f2b78eefea25294025c078c7b90d266922a887608f90611303a433dbb3b7e22852f69a273613f60a4529c592cbeaccac2a63c6555222fa6cbf254dce9aaa176f68309348d4c41669c3a8e9e3f66179c63a9f52a5f1aed96d99af0a9fa358a130030d16ce967e4e62172df23c3b415ec735e5a95a0ce97a7ee7ae97797d3311d04c32005c6b20cedcfd7daaac2e9a81e7d1b47f06125d0373e06b62f7d82fdc0b1afccef9f71b1512b2064cd648b79b33a4901445f2e8eacdcc123d34af0aea49335fb7a5c4caa8a6e8862c0e529ea905a2a4f44fd96d2b64d7bf882ad89036a5c5609fde535c3bdc0bbb8f38cc293b6591ba1b634554577539cee30f6e51a55028c2fd9424b88b520f60844987930ed049bd9ca57f1da23a608689b76138c49d652328a37caf29ea935a021602aa4bf281d534fc65b6d791b42cd201e5810169169b45277d21f0ea3815aa9872a0ee97ed13beb0f16547213b722ad6fea7feac7b96c457b8fa1fb070aa55c05e9236abfe4381f1d5d5b0bd72136126cd88303000710926c67d1d676dd76e4d4dd6ed60693b45a0dd4eacd1fbcd4d7db6cde097e121743d6aa8d90100600777c67b00bc65521d7d9515f1e8c31bafc5d31815744cc8d49e560faac0b9633cd64c6226942c5bec46382426ee54eec6d12b03ad507c4370d31802f74b3b3384f11bb791d95d82f9dd9a6da69da4b826ba719039cf282fd4d0b60230000000000000001dfb701da82db09faaebf21b5ba1d0e7cdabf2589b385150c5b92de7775bab1de5a4bc2e3cd34dc24fb2f9a1c7963b81d11e43ad253b7a35e167cc86270d8d81fcfb3b4f77a6384f794e9710105b75f1aac82581328579fabf33e535d8fc63151c8b50d206c317c6089417cb403c9df8c77fdf642b372cec878a33d4ca874f19c9284ec88f3834d8c2aad43b2bbc09bc8adbdb78014b9ce941d36ccd6236f69397c4c315d9b7e249b8410f3641005bf29b0ed4500978b44c3f49ca24968dee8fb9a2092d1958ce4fcfdd2f27ae1f17659ac29905daf3e2bef713dbaae4418d5aa1c8570d6b94d942b279f2300b59c9e1f188621bad942d228a2ce1e67e7e2936cc993eb6f6c2f1aa0857eb2c5cae4bce770758b2f9ba7ac33143a7e13f0b2c30853b11ab3e46a81d192d8031ec09a29b2a091be40bd3e1cf6aa8ca95f020121c4c1a0230e172f13f7443b2c128c5d1f613c8edf9438f50dd5f2e1372c399138090b4aff5299ee8433281557891f1d7d14d805254b30fc507952b133df476d240ec2506f7e50d07d48fab8e03581580b0c969e365bfdde78701dbeb35533171d82346f4bf7c1619f95b93ec10c26e4458b0b2cf117ef3fe0fe42c69ca7216db176a2f886814aa740b37fc53c1cd52b9efffd66905fe06ac7174505c5cc80eb4dd68f228ea53d96b3fddbaaf3ba283cad002d3e52e210f65114eefc7a69de620c074b5356c28738be90b269cc10d9b382fba8a184b1ac2938b177b74419c744e81aa41b5b94360f34644c8314d07038e723f3b12010d353663555c86ba9c29194c6fc7403afa3773a69883f52d3ab56dc09753e1a2e40cae2eb69a6cbfb487f971f706cab04884798a092daacb5eba17db7b7073d8e45f9b781005414c608942a8fa79ed1cbc586e5295934d4f17d14f7cc7a46c30df7a779c28f1236d6ca5f5dc185ff815e88e1b69504e4f6fcbbe314dfac575aa40cfb89ad65c4448d6221973430b8daa33b91fb9c6a6c5103e43a0a2010ce229910e9532927dd54de8658db86319d6eee142ffff2b0787c2d25d736d2da49ac395c1c2648851ebf1fbf60a860cb39e7c2f99a65088235fb9d42536d58d10e55a170953ec86bd38e3d9764a604aac70dc1d12de3738a9df6e40263b68ea314cd192b57b4892676428fc7cdceacd627a1c4324d8848b04db2ec038be318154772bcc8c5cc3b21ab2e2f6c01a8e7b10923fd0c457e98ba704952ca8adad89cd0172d5ebaced644bec4d87278e9a6ffdecefacaa1e729d722fcd4e1669ed4a62808eeeb4cd22e6e0db06737c6ebd287de12eae37622b7a95f421c43245b7c3b982e3baa39b2a70dcc3eaf59883d15e4d666db50e479c431de2d698fe3e1d92725cd6f948fd9e666499133bd9edc14d7255d19bcbd45a8b549c10ee9370154c0d120b93799a6ba2e0d854d1874b9817fb01f470463ea9026b0715e5fabb88df729e87de62cbf9a77ce746f38ae44911f3cb71c456711edca5ae9205abf2c629734e51fe993bf8cba0074ecd92fab62cfda8e53c9cca56e58a950d27826644b980af95562f0c3c1880245b0cc08249c2ee49e5d7b758cc5bc865daa5ac571692dc6845e6456a1145a148d752f79715072537e4465fc6396f2f1835885947038c2f113742c3ee55481a1e5def959fc90dad7441aa943e01e8c89dda1da6b6669d076a80355510466379b56f3608529acb3f13683977e382923916407ae2b22374cdffe3f2aec7ab132cf134345656aceea5b6b590345da4018b2428fb09d5492b55226939e8174d17ae421ffbccbd1e860540e8c7221cec6a2b01034dcef6fd8da68fac4f9dce69ad86ff5f075090ef528c0cca66a1da366337a1c668e2abbe84af21153293e058b83e930969bd8a21df8ecb4e1e2b8d6d0773d341c3ad62078817386397161c4769b3636141ff19f03ecb6298310ab42aa531e696e51780d58b014bd0a3f8a203287f23888dc27a6938c018b01aacb1417dcd7f2960a14bde8ec83c7c43d192ce7be7c1fe1ab8c6d0ac0a9a91b448ee5a07815588f97deaac7fe1bc95939733c99f418167f5036faf869202023fffd15910628f0daca2decef32194f28f4a9db4286487b3ce8d07c6647acbf6e6ffa2ce5c33794ef40494a20dec84642aa96e5a391fb7888b2356b0671872f6d2d777d759058a82b1a2697122341421ebc4971d2b32457774a38638a0827d93c921ccc4099ada65b3f5877d35b7c637ada3dad8f9cf9e556ec8a47cdaf5e3a685846b10c99f4dec1129b90e9fd8d8e1e0d16d61bd03e662f51c3d4a1bc336e3ae2e3d5ec97344c8cf32f786043be94320aaa0dcea0dd49439156e6b0393864434f4147ba40d1e56535aab420424f4062ef1ffbb6fff6fef5152f2d0f66ea8d2602d74e4dbebe888cfd17a9b2e6569de78345c7d5840d8151b352e97901b3ba57dbb76881f1c460c9c79d2e7e36f59f65e7d0691571f5595a3e2d7b0a88d4f1d40f84c260604392821ced619889a673192901a495310a3db2aa65e1d88c0595c26b2bf21ea89a7789f581bfd72d1939ac5f8e139519389235d2663b54ffefb4e379b4ba27c8d94f12466dfba967f6372fde44d9122a34499d291d39810f704a34bafbe0107050283462fa30936f3a254ecec5d50fc955fd00044f4b8b058b18e9b6c204ec957fd8355efdac979a981c724f467a80f76bb92d1fbb60bb0b34131bb778264ac15292994f1d141d36df09799b54485ef3cdc74ae970d7de6149812b7abf4da5226f6db4396411b11c1b3d81036efc85983fd1b3ff28c46939a85c4d8e7d18a8d9a1d8f4cddeb18ae681730a084cf8b6ce4e571da10b79cc245f21f083f55cad82d2fa4cf83a10e5680279393f2d6096d78efcfde6db3135cb7d40fd9b46a248aa86c9b5f6c0ea685a186ddca2a5b0760556e66460348affa5561ea685d00a22b2b2419fd78e8c2ea08399d6b4bfd3fcb5ec23c089338be6c6256e5162c0c84e3d7bc573425a917dc4b85237573cb41bb2923718ff0a9a5b15a14ecb79b2e599674d30470103cd8a66e5aa9734dc68fe647b705ef9024886565343779d01b9ade5c531cf19c0940c961b09c10ed8de842b66e8ef42009c8cbd67e3e0dd5c787a4521405ae7ac774459a5b76cb89e0d78d6e922082d868ae35c89bb4e7fd46a48d858499519eafbe5b0d8b50aedde9b5ae43db83c3acd39406b2d6ce4519e7694e39c39d1834999a5facda3d31df3e5e7b4549b16d8ff4c95226e2710a586d3886740943767e00de834233d2112b1829a5d66903587adb91487dd86e5a85119627738d0241fb0a8796770d61a1f08b2b0bc451a813cc9e35bbfa66a70e8e599b59b05f54c1cf644e652fc42cb8ac924b6bdce781d2dc0be8a7efaf60938f1413a3475f34d44674b54e6eb05848816c65b09d0580db6ead93de7f3f54d5b64d87915bfb9d020aabcf6977ff87f06ea55e54fa5788ac4ab9d2768e78f0a4f57b63b5ffb3c1a26e61c37a93cf86b8854ddb309f28a36183c6aa78f1fb4561d4a8c032c44920de55a3960685121f6641e7ecb97c79814cec3317e3551b9266b31aeb6ed040c42d99e373c3128aa06057f104ed4ca95b2df2fdef903f761c4ff9a31790dc018f08021455af5f2ef20ff2775ea3ed2b78fe9677faa56d2b831e0e24f0738d3ab46fdfcd743a8898323e41ef035021f23faf93e7f1d67fcaf5f2b66d6fa42ea2fbf04617fca89370f5f7535d787f77737ad537a949f3d83288a656e723f31340a17c9ccef29e82097ecb9e208ba5a8ffcfa80922e8252d3c35847f4be1715a7d09867c1d9c4e895acd311066f36dcdbf9792154714df5c85fa0628b60f2a0e8a4cf1b14f14c16dc70669c406b2cf1a9096a711bffdb8546e616108234e91adbe086decab094c3b56516d99c12250fd7840dae02029c5e91e752524def84b8b38924a96bbb7c0bf39f9c72060a591de2d85e1ec9a970fc31c922bdeee6a42ed272430eeb9881bfc1eb7196d8e7fc9e60181dff308717bf50d69ef9d3e74142b7fabe91802b84f5b99239e9a29d88b00bada2f0f1a06c18bb930000';
  const txHex0 = '020000000104b716647dcad588b5957dd8e560c15c57074a5fffad4fa00101ecad9ed46fedb60300000000ffffffff3a961119251ab3faa675ab8161cfba1206f0b2d440d95f7bc3397cbc679ff10b0400000000ffffffff3a961119251ab3faa675ab8161cfba1206f0b2d440d95f7bc3397cbc679ff10b0200000000ffffffff425f70b688749726dcc251a8bdcb905efe150d281a365b013525e0ee012d921d0000000000ffffffff080ba7acb13b554a07d97afbc57e2a0d8ee3d28b8f40735d1a40f68b7e159949c13808185f95ae7c5b080c9cc4b484d3947165f43e12897aecbbe90e91d89ef6e81bc902258dc6303f09e65627d5632cbc879447e7381cf2f100b25893f07c42698e6ab316001445260ac2cf5ee003fc6babbae62772edfb4ee6340b3d15b06011d87c13a817a09ec2e70e135b0c57fefb165fb5a5be4d79525205000842ef87fc2f49bfd008273966a1e1080e5ec2bf6d160fd0c1fff8ce4bafa652e802d636814c023633544a10ee09dbcf021b831ed5fc3f8d12d2026ab3a558ce5fe1220020fdb59feaca9cb25fd3c3dda18e1bbfd1d8cf734d3a3c23b7fd59995610241d0b0beb629b3a0c73ff62eaf0f831a7eac6e6276078be0bc163ecf17061ed9c2899ec0909c2c58a57d1a7f3122df3a6a294401c5e9c45060ce43208403a6cac61ec0ce402ac597abdae972eec381d5c706bc1e669899271adeb0fe94537ae50a9e3144b96160014c8c8e330142baa76acb66324f8ebb7a7f1c684f80a772eb4223c43da1490e0250d9411c860641c9851fa9f3c84066323c437b8c882099ae87a37ba4a5848b3ab20af64cad62cec3dc18c033969f535508d85482ecbc0036b4ba72ae6d16755de9e543c5f2dd4ddf2be49532d651eee0df67be534d2bd00220020099e7a0de62c55bfb7ccfe8522e938049d0175c0901ede4bc4758a29df5f64870a0c24e1ce3b372bad96ef583da3d958c79861e89cf38e52ef9c25eed0b5f20bbd080362436b02e78c6ca5ad6098c1dcbd1efa39440b43b66fbc30a4d3169574109803ad3f6a1d1076b3d8af0936918d63e0e78987c6df8893d92435c70072f2744afd160014f72d2aee467dcee1825b026a916791b7526eefae0a4ff1683481c1f79d5364bf4a39a98cd928110acbc36e47fb0e3311b349deb65509250754a7b0f337a9ff24d6988fe70703bc73700da65b33869d3c9fecbd1e4fe4021d26a18c949064610854b8ebe3a31f02b51f11f8c45b68e90120a19b1aa43db01976a914669951ec1e19537d5c8046b8762b038ae096de7288ac0b96338eb2168f6d086f683aefc427581231b6014fd6a7b790d60e03b082993b8e0816004f755e006314f7cfe4cd0e35467b6c1c5ea3db8d4c5a768786da001c458403100607becd5c82d9513b796f1d7d646101b1705d79c3f93047cac470b7fa005c1976a9146eb7965a850f7a094442e756d0505cd433a88efd88ac0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a01000000000000209c0000000000000000000000000000000000000000000083040007d3cf057e80feacf15aab85666a69382a0ab0faf75a0ae01f0ec8f13aae97da858bed098e9a4a1464dbdd6d8b12c1a132325b40d5af6a6486809ff13114a6a33853f38019af5b7613d986477135881af63ca8fe595a76f2fee981932d276ca9d09bdd690151dba542c3b0badc02eefc5d4d1707de2d6d151e21c8a0cd243f90fcfd4d0b602300000000000000017a4e01409a1822a2dc35aae3e63dd5d5ad99d8c0bc01343ebe4c1623e63261d5ada9d5a1b101f4d3fc308b1369bdbc99cec275c70b5c3c43c766c7b82cce32d6aee59226b3251177d34e5c52f4f84771013597e7e70c5b9e53367e3923cf6d3eabd085b5ee6c1e8cb2ff1eff65d220b7012be5288d998af4721dd4b19d08d6a34a3aac89806aab01aecba3cf82b2a58a4fd1f8010588bea5918f783644fe8e94dd1fe1cac50b6cc4897fb61c6b12c4498f7e41185f8165319f0f2659b061700fdda9ba9688df3dde4744ce24e3f5460130a1aeb6fcb3f2b43b47b0e6efaaadeb3836c2ec7439571f18988eaa44a4368e920dceceb7507eecffc0efa8f231c3c51076556920155b19b88e493ae5c4be2e1f778becee922f10d262e2c3f033a36aa4bde91ca10e05a0fa48d78e438d8b732836fc9a414c14a5931d317fa868f23680d7a995b80a2b831366d04e18791ad18dc4413138ba060a44c88bab7d843f27e3b83b55a87d6213a872f0b523fef7311d3d56233fa737533fd605e260fb1cc58de4ecaed2cf700940b2bcf444669deeea4e4e150dbdcdb9f7aae0ed170ef51c377451a2ea27618b7d4240ecfe8c28fe3bef8b14fe2662291166be06a4658e6045ea7e82f83798ff9af75003fed7fa792e95ab4b566db09b5ccac180708da1cb0e77246f44c47a3aa74c5a51eae81accfb3338917d63aa0cde94a11b7a110b06b77d387c4b03b89be99fa240419f4b03714f9654dd6ed48dd79011199b00f97abf5f2a374112dfef04530a7a3323ed2b2f5a5ba77b2d9479a8908c272db1cfa5e7c4d148c6c4eb73d62501e231736d3c06f3c40a9e9b7b8360b1fea7b732d10381c743f983305cf1d10eb7d25d00aa5153f89ce619c0e4ca4874d75b4b7a1685281b0337828cc33df7613e599f00238c56af98f28178553b02a97d20fca7968cd8bc627b5bc0e1f27d7a5db6d29e5e4a416e47bce5b57439fb7b56634d9882498431dd249eed7f35ba83506934640d0676b53099e0c03dae3ad6035be6e3008a46c0fac6ffdce82c5524fb32ec8f3a86b676c90c03830f23adf85482be4327575603c7be457a599bcd0a9e360300326316123b611334fe9b7bfe1d151e4d191fcc67c80b988ca2ec0d75b944be0c88f31e78a3b516e6f1b5ce95b1458a2d2fb17407494e97c40edd8e1e5d414718212173f54f4a85789303cb668f77feafd1b46070b1d1955c83d585e8b233c3e95b2ea2f58dd802daa8de5f599ad73a7e5b8f5b10f4e15bb800670e500bedb4277f671bda9cf67c5fdda0c5ae7606000419139999734466cad295c1096ab87c1b40d84273109af270348dfe0805029341e4846bf078f41419bf22eb890ffc27322345442af7c7440fbdc9a52b2e47e47cd92a902d4488c71898daea345631786f1c853d6a672ed58f1f5b4e2de1150cdbd3111bf2fb460d82d2edcef9173daec12d1308247e6abdcd7f3fe99fb471b22c11df0e038917a77212b63fc108f94b062ca6198cbf80b5c10f72617c1f71fd12866b66e643fa18c8e7aad8b406b362a493be745f3d60a97cf13f64b3d83eff6b744e16f825f4f01ca036ee52045da21ad874c09d52860ab138e1e84aab6f06744205b14f799679bcacda7fd3452b74bcadcaa481acedcc83570dddc2e2594042b198a2c9d996f4d31e23759b001459e0211be608389f1e57c243afa6bbe80cbf517d3c841c16548a579c258f0151b3c99ec3c326de49525c4ed33cdc5a670facb135e404e0f2decd9807760218cc2997f9cebd46f3e4d80cc392540ec405d916b9ef8371221bda2c8e0063266ee6e51478701e67a1e29147cda05b608ff31259c37f4cc4048a92cb880300ed9a0d48a065a0cd7b1497eacf78baace706d19b1a7946d7c247366811e74b1362c87937241cee4bb683188e652b0e13643d477f0aabfef465cec72f95d52fd235557147360dd926b93f0715e86d17217c9b4a8db7d16b895d1a70b6e69e381b19a65fabe76839592bcd4d609cc2bb053650b25a60e5a2c06455d83fdd3bb9bd224f36e7b53466289034be81e5441e380ecbdb6e62239b847a4309c5213471318f18ab96ad17b6f63a05999f291d1e607d27d08c96ea4e13daf482a85aa2f718b824b5f24424cf2950fa5a0a001d1051aa4b30ea3c36387a01a9e1f7425de95836b623a3997e39ef2b00f9229a77c75387db35a23f36dac421b3fd2e47fc92d1e982bc3a30be78e13d75758a55d81c246e560ca53b9e7e172c3b398b80777716a88bbd70e2df4e060752979e81d3b7814b2bf8f02f1b2f2607a21d77a25847259549988274d0278791ca48541c0022094c375cf82ed138150f1c9165063b691087c0a4585db07b0784381841f6077555f566dc9baf25244481ca99687da4381984c7a3e124007a713a1d349494ce044cedc5d9c63ff405c011dc2df28afdac46d1c0969fe67f870ec0c7efd5760c87013cbffb3e7255df5de40ceaca5b53428e84820def3b0d12592ca6aaedddc14afca20f9089bccde246061c443d5c8837d292b943709f85e2a1ecde3c48b15cd9a6c4f82b60b13359a12c6c9b6cfc0b6121690401f47820f36142493996aaf53bb487d9c097f8cc5e1fff19b6f73df9bf3f33b31c82530cf7032b3ebd38bba8e4a97c9798b5521236f615d7f920d3f01b4d3bae058339c01d9f7967d941876f2fa86d803dcb65a10f4699f623b792011e341be368f3b3bb17202ce0bf777cf4a9b0bbce844c1c3144ee4f4b74458a39856d1ef381d674996e5843a1d796fa2b3a6c7cd4f4957b04561e9bda2659174388e195a7e1ea01bf4f16bd2779c2526a1141206b988b39487377275b1530617e7d70c6c62ced444243c70673b1036a1b164b6ce6469e5c328fb14e66941973e0003a868353d2192c2d59a04ed05b5ec175ebfd693f67bbf1961bda1c2abdc37d35d616460471337297ef1ce7ba87b01d65da9395055430e391de5ae6a838a3f355f957be228bdb7bc70165db416208b49d712763e16875fbfd92969d00b9b84b14bca4783138ac62707802165d29da48892326e06e03478aeac7a986a8fac91e650ec1c9e410b59e24e3a20faa788791c752c41b6a33e16fe2707d0d4552b2604f568a9410b8d18e00a6723ed58f2060295881e42ab546ae781ec0a6cb8b43601443f4d34707261fce29d99f70e3664afad106355213d8453cfe8863afb68c359395755c692d71954db359337d587684f28744cac109c75f39fa0fe7a43e213a06c445c0bdf49a0ebf879183f94ff5767f22b24ccf9a8d339561b1462b05fe05b7c9d97f1c85ef9bbec56957d6eaa1a199e286d289227e0efb1108561cfef13bade4a7d659f20b179bd178b6aa03dfea9516d4d6ae4410cb0651f821c9ec728d801b60dc9c36574eedb978ee34b87c6a27d1d8ffa12fb3f9cf2350bb07dc23ff24be5a0a9d075772a1e7b4a50ae7556043936d8c388d09114310d77f67127ff6b4b6d464c40b678d8a8cb8aa656fb5ff82bf4375bfddb68465bf44ce8d2474075ba8e92e9465a9274ff60927b4085382e527e0aa3c8230c860da510dd537e4b2726affe5472549a803c0cea7cfd2e76a948cb31d4b436c0aa4750275e4aafd322dd054c4eb26e67ab3157ac0c5183b2122b9658a898917940decc402a2d839331d00f38dcb66164b6e82346805b2796fde4c878953d674138ae8bbcbe614fe81dbc9220db5e7fce88cd65591c7e49faf2ef60eda7eea2ebcdb54f98ab74a4f4fac2e7deb274c3e07ec0fbd7b1e045653b8bb4e5a6c3c169b2bdaafe698578aa062c4cbbdd6d5bcfc32403dcced0bfe7d1f786c3ea81d03c43c03cbd07b43ec0f33f6208469df65b5837d049e050dddcd07eee0012b07d0f043f17766f8779e70dea9c8022255b842642b98977e521df1b2cb8a93c2537da7fe8367a2ad1028520b4416a40ae2f9050d90437d7bd8ab0b6795dcddc542bcc7d573dd2a8431821c2fd8f87d96b0163aebff96ea8954d67008b7118b5657eb0a1af12f65fca7c8afd7dc0161fd1634acfacc84d59d03f41bcfb2fe2bbf64256cc1f6ad8583040007142df6fd0a214edd8ab06a03f075a1f26587a72cc9fa7e8edddb247896a21707daf52083abead224a04471adb20fcae817fad6bd280bc6d5a1a7a0bfddf953e1ff2adcad12631909125515d54b1340f12c1f0144139d60a790ec9d0b53d933eb39c3e6d2295da1ae186e54af3bbd3904da67476deeb1a8d33344567dab55d89efd4d0b60230000000000000001e3b900324dcd6c046d691df057a8f65fadc6539cb883ba4fe5740dbb2f8a8849937998fd90db6fb2bb6e53f3422dbc3e3af6f6ef28b3aff40b1393de58ce5dc067662c52b52cd81a2222dda967e607f79e3e34d266b3585766e89586a9b9d688632063d319c4c49a33549e4d132e1ff93f1a0de7fe0d2dfe33b4cd50ad06de763f7a7467682cb9f1a3b0cbe8edac07be2c4dedb0a18046d283d36d73d11b4a65696905618aa5926e7b7a95243b5884b0c4b2af40a5e667dd6884c379ad508e5dbe945d77d458f7a5a643594126806bfdb93c0df97ac49d7d8e008f4614ed5efb8a66b562d02c1a7c1aa3d244fb53c10f2f4f25f72a3bd7dd47259317592cbecb2c9b323b9d409f59ff2c60ceebaff9ceaf5b9ef84a14e83d111c904ece8805f7b701ac80ccb4ad09cf261b3a14e6e23aa5e020101dbba3c13baf1dd899ff3cce461810769697636f3b64a07e38c4e3a98772253d8a9455668be31248f5ec0b10fea68114e824175e0f638f6259972e97bead1bf932749f67d0654d8d621b45fd4e3f8a58e49ab4d693a454bdb4724d336cb5423377006b8be52d59a4790ebd3a0c30b43e1627ad8bda3192c0dc5410fc3727695a5f85a588752813e6b0a7db9aa2c99c1da8f276b9c558d095971ad44e0c9fc1759a220f4039af3477f9b76de7f88c176d9cbeaf166c5e75754f2989de041740f9a97ee0a11d04af874626efcafe782c2d2624d67eb55079606e0c31772da2981a784f09f00a1e51296d300662ac538b1a431e189040c3b30af4ccd959383fe1e18c11cd940d970d2b30afe79f1ad30a617e9302d77ed0878a9cd9d58c8a8b0552ca81b1c73a0487c8ca65ee4b58ff189c44bd6568587bc5035484c648ce472d95de8f5ebe9112bd55e44ff6df843a1f3b6c41ca474561e318236db69ca89c869e0c0055c808ef090457cd30f831fdaec7c67a581a778aa99499c4c14bba0198a13079c9b3f95ce48721ca2a6285da79d1383ed8f8c10fe11b478d6925072899ad3aa7fc846e9b8d50c1ab86622a3f49a49407adf4393e9b82903bca9c10b7dcd9939086fbe16417faa86ee375f792cdc38b61b7705720f33a0658ef7031f92c45a60b00ea37a91d70655041098fbd23ab2794f0400702342842145e6eb4061ed8ccc47142afa9bd0984345c125c402001d8f22add32bfdb4302cea4b8a2264fdfa7271130e9d52eaf9977b8cd20bd067131521858e43fba605a9596fb735eb0a0f9c9bf6c0db28f37e50b4ae12d4d33d26bd148004e2b5c74f0221d742b3336e6d142ae78a995d7595549bf5bf982b2f4d71923ea892f83aaa8f34db2138e4d950618989c50d372c6855e87ef587088e7ab23b01f5101fee6fbd4e583a5300c8a1593b217bd38339d7fbd2102c94574fbdc910847309ab220734268b3b4fa9b8b5e75f13219a5655454bc8fb4a7b82ff3dc42770b6cb6d3cf57a3b6536366dc7d274e32acd5b1c0d2323abc9af0e54d57e332e834ceffcd5f77a7584c6d966bcac98bb771b4b9e9e8cb02ee77555ff038a9495ffc5a91ec42ad62d13598e2c61ef9f4ee2b904f2cedd85de05b4ea78e174483f6b54b1e352a5aa6b2755a739b6082384585dd1d7169e237ef5bd5afef957b162fdd5aa87bf622340046d5544ccb7ed768fa1954d1f1de10693ba2cbb595c7fff92192306aff1841e5a9be559f1e38eee12601f98ccfaa662b31ccbf051a7c959f5b08054d78dec7d3a9da028e29de4c2b0deb1098d8f15beab032ee0098f23fca8d5ac6515fa2bf8893f98b5692c8f352747d9fbba1b3ef3f9ab2b16ac21d5d90687f8428ea7e7999a97cdefa59e4ae4999778d1c824d295e04cb9ce99a0e12a9c77f8e844f8e89e2cf29652df730f02bbee422cb232e7c78bddac42f28b7d2db14d2bf668d2bf22359e4e1b260af7476542d8d7223b4cc732e3f5b039455609c442f017e4312600e31e1f83167db0820f6954346105563a7ee61b6da274422c8b518daa79c2c0a6dd046e40dceb69d46b74cbc246b707606024f7c39978b64dc5db7f0cb4eafe6c7c91c3f24c6810a709dc5af07d158eba3072ff0e9015bcad38fcb6d2ae37cd4e7959a8b1d21d8d6a76815a9bbabbc65f2e093a38d529b5228a05c53e8c04cb5af5d91bbf7493d3d5e4e1f4219f228c6d78ccfd30e40c6ad5a08fff6be972cb6dfd5a0b4038ccab6736acbbb5fadeea4f558130b35e63d314177dc5e8d62391465496b2a1781d268ce23b0fd630125e222e1e5c343ccac192dd2c0feca74661b67cbd8568bfc8e4291d05f3ee61f92d104fd0c114f0ebed58566e5893180e1feca0f2c1080265d7eb5508cedfb4e73001ec09c40d67a36eee876acb2083c148415f74a3b4145e9c9a4ad0de6402e47a347ea3934e6832e7d2d90eddc8399de35b8e50d78b8fa26689d2bb326ec7c037338ac69664d4ca98037ae14877c5e3a8998a9d4e80d0cf71447a13114399427fb61bcee9dc8b6dcbb7b4945414089861db52d6352094fd38f3580e8aabe5a1f5cb384d2533d93690f51fab7519317622d90475c282dbd8f384518028b71c6e313838c4b85226220c70e46073024ed4eb8dc651e88b3c42219f54f9b1773bbcd98342f113d9245a3c36eebea1ebbd3729f712f7bfd2d5c6ed4b917efe676810070d8046a90df8609685749005ab1da1db654af423eb8ba136763331c1a698118f7ee3f6f7e4a09d4bbc1a901db92a138a72a207a7aaf4d6cbc2902bfabed3c9d859797b69b35c12637a347a3e1720db0fb406a89f6ad2deecbb90184233fb530ca4db988ff287045c2b0f9c9081cb3a8f5bc996599d9978090f31124a4c18c9effbe919e69af1303a8358a68fd9b722b3b60f946266e98a37570f2de5d1c8ca15d238c8ae2c8254e360ed8b0fa5373cac1fd014a7633075c5926ed58427500bb35371c75a6740aba4faf84bf653f00652b656af7df30008994a0a7a0724d9c783e2f7f7c653ad0f5f016620b7d5d7221eb15f5588d7fa353f90dc01da9db4b133883d07c19d6be3116f9dde14ebf844819f838f979673dfcd364ce3b9c39c27201e5459429ea3c5e6f24fe309989b1bd56f5f1bf7f0aa7aa65cffa70801449d627e640f29004d05fc0d3a5c5298c0b7d12e7f2b23d2199cabaa6b98edd96597c2c68f34b95ac9900f8fcacf4d87ad98c0dae079567b13645903986af44f2e172da90165aadc8a90bac1d714a8891e64174da16fa0e0fa558e09706956b8b20dd8bd387776a25aa607c59713e60f4184492835bd8229feea43c9c5d99c0a68075b8e8c47175955c2ee628697cb3874cf10275019fd8af8387ff4ca223f2eff9feb15c902358e8170ebcf61324daa07271ef679fc2b23e1aeabbb616d437af9f408cee5106b5a792b9d9c4d56058ed89e9bbd23077d0a93a87d45838526fd9d88ce4828ec43de0a2ed5d174ba6d8917af1cefcf8b922ec91265f8cc9b2a16d1d7f8fefff74c397292a4b52c879c3ad2252ca4d687bbc533d2105179b461b9964035a48d8917e735fbf3aa03ddab63f586df424ac3470668c9ea6e50b8aa2c3cd98cb14cb356cdce5a08cefde15a16e414f5210e699939bd1f411ce5607878bc0fa5e2b66694133f2abbdf6b0b3a223a2a1d8b1980834b90bf65fbdd01061ceaa1e5cd9779352c950a528348511dd0019eed2a230c14b484a35c1a5524c456fb51258c37d18a5b5fdf21fb57819f9b76ec7d6917fdf5015cfa6af475f07f01346b66096428671c70fe83e1502c55c443daace4686757aece08f831368547890e0037e035005ef331ad13c805c6e46274ffe5321ab895f3f3f7356c1c1a11e7a67d953f1f0ac49b2ead46b5ab505f4044c847fa6ca0b5ccaac7fefda636b1eecd8d072cb1bbf54b0707eabe8570f1939a4e56eb6e3e3b7a52e52b65819c51bb512d1d0e4ee57b502bcb80c2d435a23d6d3d9c313fc5069925d7073e93fd1bcc0d34df7f165b80369807e22bd83abfa18bb0b8854a14ad70de5756278cce6b46b64eda2bfc1620b99aa666758193420fa673c7f40b897c2c9c97e641eb9640f022a5a1230ce35605a8304000b7c727eb57dee171bb6b7a34ea4acdb462dde508e0c9694aa5dc3b6db43ffd15808490a7bfa1b6f25641ac56925698bb46bde643a9ce33dd26f200c5e10a774f742a776b3f25ad7ebc1337580694bfdf24cab914255a072bd3a83aec03ac90563d9f0f6e6d59b467f39e82080f48d89ff38c56d6cb899202aed5632d22165b99ffd4d0b602300000000000000013e4001569223f8a2c801505ec0e10991e59f24170019bff90a479ee97e2ff7c3a64f85af1cc8faaea3e7c74f4b866d593dd592b61fd7d2abf7db07569425bcc80e12b0bf9f972d2ce0f59a32046223d0898a5f52a0a4b5bd6714253a3d07d573b029f448a549ca1deec51384d3a97bb286524c8170ec99555e373cda96ba80a199c0cef7e3ffc12d664bdc3f95d339cd49b7f0516a1accd066426a9c99b774878fc3360940132508f70080ac6ba7404a90ecd758514193af25fdc92ddbaba448decc4482f102a4c7f24de4b7603eab725dd7d6495c3b71c144e7abefa4e3f198d85199f40abb809afba72a09f20d10a1fa0b955c7ff9f8b39bcb732237967da6cdd0667e2c48e3096f1d85f4bc752452674d83c516d158a668441daa1e82e423c1e955807c5388645adb03726191faa5874072b3a9bb863fdcf9575813b6a460a4cea0663491ea15eb5e2e6f34d8e09d24755fc46db48d5556c99a5c1dae016b7a5492a488991c4b6c6b39311d408c10720abaa3666c38bbe7c23d2a141473d14fd8f8c53deb7503a62fe03296f0df805b33505525d719e276866cdef04b866ccfc1bdc8d8988dbf8ba1c679b0a4a27d043593c08c0029ef7aa989003e9a0fcf00b1e314963ae80d794c7ddf6ad68de321653ee062b51132078c95aaa97dc2e7937b5fb62058f7c376989281fa77007fd4639764adfafdf056dfd7ea45a62997195effb74ba31a715d4beb9f5dae13b984bd1b50eaca2764a2e93626a1a86a9d8c853628f743c50e62c8bcdc71abf5d79661c7c0beff8722812e6ba37eaa0e2a631cea876bf4b00c9ae1d41bbdee38597bdbde12c120734c89cced0166de02b1287737b7ac427eeb7034836dcffc9af69ce5e7ef9f99a50ffe831ff4a989420aa06a5034f28984d795b4bc643cf418cb60abb6ed3a9806dc3b8be19922a375a55e5b7a707788c063a41070dd9485591dfd21df48cf6b8c58b3ea9bbf8fda0e628ed60863d402acacc5a8939364b93c917017060bafd1e1a6ede6c5af2f5f2ba235426beb4f359e31b586443524c839a57a28666347018de9796562aa2da3d95517226db539afb389eee8ade40750ef1e1264451db3ed56e21ba9531d5885509bba16387e26e3bf226ec4dec4287c77066f71e83bb4e998feda60c269f20ad4f78492adbc1337ace2c4083a7bc50d0b60f4660cab3a315b185679ecdebadca404f193229cbcb2582be40c260f1d2ab0bde454297b9d0bd9532272b3acd2eef0c44fe9ee0caae0c8ebe88d4dbe319fed6a82416c94b74b889a67850961f9a1addd3236abf661988321f2e00dcb9253d67bb66e54e8f0f6f3f95a06960ca98c7b4bac2c7482e0c85f3936cd3d7f16cb94472433226d932ff1afe9604add4d4c1fc8876434abddbc54537e7f2d6e8f80d17c3be7a40cfedefc6e02c0ccfba4d19f6029671d8e4ae6f94e8e7108f6b07221b50e04316b6bc998e309a781346b46c1b5396e199d9c8867ee4bc9be0679ea19b6c7eef3a30bdf7083f2a9a1c4ffad3d861bfbde872f43c5524c9d32e7d7b3639ae60b1a552e6ae6ce1652a1f3b39da75c307be01ff10b4ff6fbbff9ee4cbf48f02809ddcb100ecbba23833174380dcfd7cd6dc5f46e74ec5836f7021cfaca5ff29d9b150e35e7f8d24a81b2687ebdabbde02a6f6b3f8fa46e81d03fab427d0930748857807ef79119bafefb6e67cdb743692c9bd61500d8e7a8848d6ee3ff001e26ddbd50a576c42fd88647a41aa4935a5eb1c5ae6c6c2cb9095966781fac3b363008d0381d035e3affc9b9de38d2d8eac45f94443723fa804be959e2fa93b775e5394678e130510f57d3dfb877729fef07b6d82b620d52a8b957895bcf30de1aa929d5a56fce6c79ba22ec31e869c62d11a77dd9b44fa9fd3be445e94a9624d3dc2fc6be96f1796181bf212f4afa80c8a36129e35a66e548acf4fe7f93d6bc1446de10870c571fbc467f433b985faaf605fa6b79763bed5cc6d7837cd2d231e3ebdcb1b477ca122f17a33f541695840297a6964341b6a58753ef181052c44fe12cdde2107e88a14b1b2e33cc089b601e5d664c98549f3a4911c10080672555b8322740f69e7c88ff2fdb7299d5ecac166a6276048ec287a84c8846653cde6d63e123cd54d366976bca1accd120af24ebb496e0e01f34d462a7891378661bf68c4a5bcd00099f91e9ec7612e30467b3828820413460cb94e3ccf8711861c5a6a7391ea13d73840ea36c084ea2a1ad6112de0f2b638e91450b46d9c02115bc1ac72fcc0ffcface863849c01d1618b01433b0ba1c9be2d386b68b27a92dc2c0cb13689fa63f58a16eae9c63f0d818ad35b7f914a1620af5357c60de0a7e1b2f0b99b3a779b687a1a277a2d9c856818ed33854d16bed3a02a5a51bf7c01a66a762b7bb11e4cce5db6d3bf3c38959c2d3d32e4354483c19c216f2f9fbe3deed66a028349cefa421c9f6d6e35c51349c4106c97cda51b9e4459c208445c51d912d1106b3f08503d7641f5f8180b8d6723cfddb27199397ebf009533d1a4c4e85df396cc007db365a86667a1390c89a101ba7165cc5b6bd32e32d83f0329518a1a2cf9e175319a0efafb910d05a303ca68963034d15766e56e3951570acfa493fe1d6c6525b3d127adf2d15b3304bfe9930047ada3d76d8ded04df362a1b470c4286b6044a53f4c17046f57b2210e11fe1589fcfe7f5787af09294bd0e96967333a57d1a2bb416d5a275507ebec8ab06a0a2b105a66707a55753786c0abfa3b9a02a39bea846f4822e0f0dfcefc92c8a33a368a2e9c06b36f419a4326a34b34be23cdd953282af828f9ea2891ce5f773a621727317135515c672159433fd4fc27013b296ab32cfa2233a10f38ca4770a5b975db29cd2f5bbb10be3caa7075c80ba60c7ef13c40fc9e99afb13338678c1793f5c8b68a76cd22792e1e3943f93d157f726804f9a86c198c26447d1755cf3be3474946b21566b7011d69da517ae14dd503a7447f83fbb13ed5d2be727e53969b19e50ab635314f478265e6c8be00880f72d486da7c125b0f2aa99e2ba1db6cb591db887734b96e5342b0c3c7e10932fd9035d4ab3ddecb9722e27a8985f4190f886e52947c61b64420b6e60411188ab23ca33b9815483b4d33487ebde0b9979e327823eed6b9bfdd2dc3c622060a8ad1f54548cdf53cb43e2780a0ab4b89f8a0d45836412f16dd8374c26b8b85c0c546946f4b100d7663e0e6d472253308cd5b54eba1b82c45da9e4407577a4a27a49383c8efe8a5aa3fc65d5506cbec17c43b97cd3f5adc67c380396808545c912b4e24f58e436e6ce27a4fa74c3c32eb57362d1ab075f96f874d4f0ae234a1fb645fefe3d939efa78186e18f12f7e05fdd4109daaa814303f3ef1d4ec239a0b04c5199b08b364734e577a38dc14d5eb4a6b3743a333108400e752378ecfb7e94bc8d7f28cd0699f1b4046e00f3fb84ea9df61479211bc650a53c6847c1aa73a376ef029399ad8985068e16f2dee0b3e155da5d7f629de7448803d8abc442e180f51956cb82de63e8aa4f1f699650930bf066cbcab073b3ef7da06cef4e2d2315667404fa9e465c8c09e57b97cf3cc2b9893a7f9d6c4b22a9f84a3a4d5ab93c5fcb1ee041312460bdc15d9b1c878ad5bb2619ed4a5e63491b27ac2d756cb9e42c4bd31e0423b680e6c190c2e6688b4b95557c0e53648b51f153ed07784efef9cc4d7c2581fc85439498f1cee29830e8cb821e30852374981e35f0ac3434cde26cb9b1819f42e76c702086e9251ab091a476092a6d8d42a09f131a70ec568c64a1817e4ec63326503f31197abc65f8b405b1f89aa011e86752abe821721cf29c45c440dd692e9ac46437dfb93f89fc0c644d4a9aa64a5e1ff80941346b3183130257c51c39a79041ffff86a893d0193474094438444ed7bc6ad2d864e7602381e902a491341a7bf3fc7c8528936a7a0fe01a19dbea2551b7c8624ca7531a59118d5a3b299e41d000296847a2939219af9d8b5a20eb041baaf24809dcde22f2a4064cbae2aff887afd5a053ff5ea4cb943ab4e270066ec3ee8304000dd9aa1e2afe7bf149610ed6763494d822087426079376a6d92a012c39c893b1070ead31c49a821db04ded46df2332f7b67e8c6dfaa6ff51565f89085b8e6da2e4cc9bbbe4fec1f28efc4c9a2c1e9cdc7f8079d6fcc37a2bde76f54bd4e7958c46382c55b9911d2347253cbfcccf1200a3b7233d91c19e0f2b35a66c6b09a4e6cefd4d0b602300000000000000019a7d0175f5d4f76289cb7122c516db9379f2f4b83607763b6d2283871a4b41d6780d1a60c2a86dc12aedc4f79f5fa9cdaa3382f1e2fc88383be9f29b7b183d78269ae7d3bcc305b593a579b4934df0084dc982434995905d04692b00e4eb08284c139480db938baab02980a52ee917870c346575077e4c0fbe0cdc9e3ae8d02b728274dc77ed0d519a8ed280a00e550ac64de7c9bf42b800fc0b46090ed02c4b8e0881ba866ea8ccb438cdb1449445c74b0a14f3d276f4f9fc797ddb3978eecab3a42ba9c6b5f36b4c29ef375f03783dc2803333a845489e438279cfb8b8665e4a5c29d53a7d28427266ed83bba351a2beb16b3fd7c35c1ba065fdeebda15c4d734914ac9162946b2bedff41f3f6fbadb6ab559fc5092c6a9ce70a587051df3bd47fbe667e1e54bcabef8dc5307e3b298f3cbb44f96fba1a2e8ec7d01226e475afe2ca30ab88c46a2c031cb54a8cf990fe7fb56990b086e3e40eb6ea9a894e841b1716917e2aa6d800eea8484a977a7497a05757b20946ca3a0b72c1c67e74cf259d0a22318888079a01ed429cda4a076ebd93e56fac4b11c6acd1026f86f785f86308615b022a573c191f92a3742f6ce934bc94d33380b5d49f9da0933cdf5ea865ef96658865bf65595508bd6cef14b5716ebe0841583591dedb61e65d2790cead0f8fba931a1d423302727f8de00afedcb4228d8dd520ee5aef2a66620e0f8bfb412e9760f948a129f5a4686197f70470306b5f79a7e68c032969a84da2d71792596c3225251759956a4f1be2a04c0fc31cb9725267df4a5529e5a5a80b2f28ae154bcde8a0cbd21b476f67fa3a578ad27ce510f6b6ee17b74117e8d604640103f69a7c5ae23c2f9ce935dd4518c8d82b0b9e2ccc7c4148c323a26d22111b44e2d25eb3d42544f0a4ced00406e7cba4ede189f1461428e0766c396a76cb545b903d9b63cc3b7fe0220d18d433a024d90fd0de3cf6a48e902c2eb5627003eb880a4c91ee0a7c11efbd46c60afa45ba4e439e2e5d845baa0148393db5094414b61f2889c7aa27a1288abc46650c41d52e4ef9b62cd9ced77288eb48a45dee06f6f48d26691201d0f47e4b9cd2af46c96f5af747d0ec8d02cb47003e6ed75b7b1aea92b5e53174b4057bab06b5aad3086eff94987c3308bd802f6229d93e9b46477f464b2fc18d44d09a0778aa1d6f2bf46a1de88f492644f8e17d64b1c3a8a1839bf1423128d675d3c4167591f29a64e3b8749ea49a87950767fad8fdfce9b7e59cd1d65be2a4d5d39207f79dd466a0c363a6262a5a2c5dda413ab79b22a57cf768c2dbe2f8f02ae3efdec483e233cf355508752f59cd5793ea9ad319ada1774151bba0c5d21a098d9416d90e60eba1d5db39a90d97668a225e037fcacfaab1e9d2bc128c3824300c1ddecf5c911cfd31b440b8a216856627213ba144482130e57e7be8a5d257b31199b74da505e0933a15234cc069d2521665b09dd336764eeb51157aa0917cb72cb446da2faaf5e06b12b76da35db6610de955808c9199a4c372d42ca22b93f37ee155700b7d8ceecf789996b30cfa26318d1950e86eead810345e50cd0c7cafa1ab3b3973eaf3d6a53b17b5b87c6a73d2402852eecc8f0566ecad97ccd3c8c6db35be0e3e8d635fbff1166683cc3e74c3d240a1d90623c0acd8d56f501a04f3ec1ac7670a66f0612731080cdef26e3570b6a96cd2c6e7fc681034e7dddb2516c71d1dc103d6efc90d452fe7cb056ae2199776d5fb016a447b5055e65913467f134f9e28ee5ded033eca70db6e65aee4c419c5904a01a2c272f96562d9e016b506af1045ffdeed8b15a235f75a07a03e5f9f678115c58150ae8efc7e1fc9f8c21654d8cd425384d382e54baff59a6be0b81e93db007b02d5158d053f33178e5189c91a7f3c1293cd0c45316f20a311c9d516984f746fe89ef0684a6747d8767c75a95f85441263a4f8531b51b7b113ad782ad2d059990357ddeeabff3e993cb3493061f696e9f6185fe0920ed685b37f3e086664260c35d3ed8dc15719a310f10d8858fc03e6df450681261ac83d5690196b37484309fb27b504c4f1f3a8689d69625fce32e46325e572577f56f6c6c5e3321973ebececd9c5c6b08be9bb63ce3693b8f600460d23ab745a95e94f676aa9e12ca046a1c1d7c06e992ac1a8fd427384191c1463ebb569a07a79a9c6d629921fa8bec62c777cc04e7f825e1bf504afec47af6202ff0c4492e112963b2fd4d4e7a040761a7043e7b857ceb65530ae79332e169df43b0cdbda6c6621866c0f161f0a88d5aea0e2ce63e37581e8acbdfb2642e43d04df7a19aa26346b6efd91d8ecbd63ce6933239b37c4d70b8530825e2b63ab1d525bb6f29c3d72c7823b140d36d1e2d2c136732417d91a3fbfc64e8fcc1aadcc4a892352784fb98b3e72745949e86b27e6b5a08481c5a1e41cc32f18a36c5ed5af6a717c8df5b8420f118cc85fc8657e92b7476308d585eea8a94d26464927aa53e414db9dd2ff67175be02b43562f464680454bb59777f64955c8154719bd2a277b68f33b8ae0f5002edf15f278b6e28bd74a991f22807835fcba0cb18d984897ecff2001b1424b67981989d5fc1730dbfe4561aa7a74be0b671f27b7689c1bf70248df78a3d2dfaf9622c224de020a273045fc95619be991abedec954fcc524ecbe61c32ac050ff2534463762edfb2b566fcca397f28be3f52ad07312ef130cef57527ddf3f6253b6d39ef0703474fe42e19ec79d9d9bfd801a0f11d3c40657c76f038095ff8393bc9cc07bc32d55ec0622a2f1162321339fd147470ff2b0139dec0f864c67bdd0dd40b371b0da3ba1451eff29d23be29f5fc9f78ae739417991c4dca759bdbfe8a3716c18892edd4bbe701da393608c2de70b3ca6be7097af5e000aff45763b8b091dbef5dac4b1f460d471146bacc5197b454838c9423e52881b32f791ce25d7c931b616af39e97adf4748fec2278aff12012e8c3dc64408eb448bdf6b69578900c1a032624bff10f65b3a1e64ba256d4293f7b9c72f3379aa0d3c7b984c72ca21462cc308a7ae2698ac1360b7ed0c243a758a18ecc732c95316b517ba26443b9f3ae91cae5c63646e46f393a9337c83f2639d9bbc48bb7e17825623069f902008cec5d0205aeb6a48ef60c783578059a93aa9d203c1613c78340d7533d0745c5275a9f1ac619d93b9794a3d6cdad47ed9e0a79edadc31195d64846e6855568b84931b07a7e5961ea1535f23f22c7f68729520e0f03be5cf90c4f62ffb57a5467bb06bf70ba74689014ed6c35efb70c8ce517911cba60e95a2d86a77d1eb38fda134508c560933030ca69fd49d90917034f6c2f94fb28aa508d98602b31aa75e04b92290330110ac07bc412caf984eea7f0106d4717325ffb716a4d6fcc0f2e7e550f57e63c880773280c52baab969b9ab6ae78170fefa76cf3a5d4344093a4d4dc2b95aede64f1d78c604a6c6b7e1b0ec547f46dcb8510df28fe94eff2c09b8d8da07da67e84287ca5112d8f317f157d381d09f588ac42e257ba76e29df52ff8efe844b8a8bcac8e9f844e69cf323a495e70cb730b228907fa1a655ae554d983008536a1170c6ff71fe81de70ceae52f284ec0f7bbe164ae656f145cfcd8748c3bd495bc1c0ec9d9ada640d493a955d6d89e994747204ed87631e7a41eab5c64acbb10663bba94aac82fe63df0f3d14dc5b5e040394e41c2c2c71b86c36a24d6a17ddf4a036a3e3a12f7a4211a91c9eca6c6be79ecef83090a9c0d0e53b8240f739dc68abbc2d0cf3a634eb6cdce6dce0bc27673ff05bd00b871eb7ac122afa1547e7b6de30684cfe1bb1ad4dfa4ff06003172d614e26ad3210550608a519e427aca03b0dc3efcfbd56b5b16c1dc168971071b9eca89ed5974a5b4104089ab2876f08474b0fa63792c5b435b7e01a107890ee5f720ea0f6ff19a8893d2784445f24ac6b569cb48d10efea60e5e4a85d4541266b0e36b17a7a3c1d4150498206d1b18914cad27092226b74b2820c554cb4166dace5f7b53dedeee47aea9bd0a78d3e143838f07b11b4124c23ffe8304000db52741699f630dfdcf79b1d117edb05db79f6b7a97cdabf1372c31d44224b2178fd2aaf18e3934ef5ce7a642e6818d59e9d20b1be5e6ea5ce1014ff03bb9dd61e0f098f6eff8073d65fc0ab1df02836d2e5c5614f642431b308b632d6605bd3c70fe336f27020280610e3d01657449150d8a5e135f6c1114351d753ab702663efd4d0b60230000000000000001e22c00a90ed6d1f0a39bdddfb752b6edb5e45d0b15c495916941538eb880b2e27779938582fd2d693f8687e8edd39c3b4fdf6fce6f704268e771364721c153af2ebe80b62be2747b040b2be283f3c21d5dd17d2665a16603f07776ef7cd4a5088b2c84e821d662a533ee660e6ab2808bab306a7ea84ed4d5ca6ac9d37da790f9300bafcd9107060f30c7d095e6c9f7c98ce2213e94c2f86b53bda43a2d9f80ea63757a4a0ac018623236657c30d2c97d6efc7842536ee2da497953c2065a861bfc54304b182cbe0ecff7e41661334a94e0771d6732533000b37e47cdd49a00587bda4388ddf0a9778d245d9ce2ea95f43621893eb6df39df695884b8ce23dd5347b83a6d19cc5a308d76b2c0e6518d27dde60e32fa84ee537dfbe38d918b07b3309c0737c390349c19f60bfa51f33737ca78fc2d1ea5524c7a68fb9ebbdb93f3ad0f56227cf3cdb489d41a5e0093e50955a04cf2f0fd45664f8d4eb5f155980f8a9694a9c7d5015980ce018d16d83706b52663457feb715470b9638dec937b4df4931804bac5ca3cd54df1311abe6a4842a5a967fb09448bef589ac8eea0f7ffca4cab5313bb86e48f3439e5695d13a9b14fbccff80f607d28b1299f47dd7e672f5ea1900fba11cc5653900a6558272dce476d67e331837a84901a8820dcb2172e5eacf61eb1636e12452b24fe9ae8f8e9bea8d009fed9d93a3e256bc1ea5583ef3593880a27eb2de37cb3c89a7c34ffe202bbcf681564823ab12102faa50931063909ade938005cf24de06fdb89dbae2c5f3090366ae1441949b79906e677f4d3c88afeed08605e8a7b79e5b88f5c30a456193bf666a3e41b9a458eebac8a89c97049750ec1ccb9489215961a7377acd8d73c50df07b5ad8dde521bac2bf1b274b3c9c0ae330843e8b60717aa044159e859cc7dd3cbc91c8702a10dd5f1ecd6f171a061f4ab227625e2fbce01ab88e6ff5bf6bf7c097add48ed5a540f7f9f17551bb44d54502ffcdca918e574338fc2af98c83d3ca3b960295196b0fc74369b785f2372992794bb12cd0266a7cb8429c2a4bc58bf62e2663d3d562602386127f21256f8910b469f451d5aefa58cc7a9e7622326c26c61dc34e670ede78fa5a87ede8c66bd51933c5f93d3124304e3bdaf9e82a512962ce994399a1e2f7c4cecc9896d7d70379ed5eeee5371c5a830dcab92520b70bea4642991cfe1c51d6efc7e54328d3c84ac249e5800525240e31945ea1e45a2b438e1f4695ba5229835345881c1cd43acb567cb656282f75620dd0caa66e1b8c7eda9a6e44f6a04c22789365f23ba0554a1e1c76bbbb076259bf67d8f58f6b74c02cb80fe5cfd50a4d73b5bf816dc9a23b6fec679de26d50626d985e60da215a6290b72aebf88c1ced3cbfbf69ab91cb29e6e77f6bcbbc7cce6aa9edb2ccd135ea86aa068f7b8c7b67aed42b0f32dde4fef55bee4db9199871f887aee24fcf94d9939b9cd1245daed5568d0c81e0e36ef5be934b7eb12dfdacec093ee985e9dbe0cb6e6a60a125ac34c515d95f0fe3b2383b9d0d3885fd699cd754fe2d53215c73c01b2967cc80d12c5f408b2ffec4b3e2ccd822c2dc556f44d879e6068496d3240f199ec34e30d90d7196df9b1a622cedad63712a539974b26e2cd3ada7ee653bf587f9ba81fd4b21ebfb4c7775fcba6dbe55816d1edb20d486ce2348f81dfe9809f74a502fef13ebc1d9079a5bac29975459caa983575a90c208e6e719eca5d736c70c2a9771a7cf308fec34caf46db10ec2638866da921989caa947407cadf586489f64b9c18f1e7a83c67e0049267266223d11040bdd506aa11dfd7784f9bc7260cdea46b6de0322046e8382327ef8282b7255ba56fb55773e5db32f85ba468817955dbd8e74fe47ac47befc276fe2faad5619700b25d684e414fbdf2af0570f3df3b8fa60c80bbb616359718cf542a07d886ed99acf36f8c546deccb4d25643765d1ff92d46292f2dda17f59789ed7af3989002f59f3042fceb9fed0a95a5826b4ee6228452d8fd74de26bc8774bc2876dca7252fd850750d4e6ac637baeba488e61b9861c3da3bb500a1699ab28d6e6a6f30a5f6b7b26471a9f13646e5a1dd1243bd1a9880f05f6b777813b2229bfba3ec287610b68779d522c2bb9d133da211ec00751aa714b2b458a8bd6c3130ab517156b9fd2207190a30dfb32dc05e2a48a2d3255e047cc3e312db6e415c9e533a86ea8936dcce9462b102a3e0a8fc0a75b2fe3a27be1b6e4c5d974b022961023911422b5faf931aab0a589fda4473f017071f6993b777c3e79085717d97f80cf488cf9d92c1dc5aa2b3dfd996f655767ac9a593bfe056b7412c9a791ef09997c554b93b6363ca07a474972cbfaebabfc26345a1212f8363f762cb8267bb7c6901b82159e014808f9c45308ddfde0f57dcb020e5e2e4ea8a494d4e4158984886032ee66e9519e070b321054702e837a1e5179c627ea2cec32349e3833606829c1218a2f9b8d5a53d101fc6ee3cfccb6a84e8d0552ada1fdae4f62e4d0ad0d8ff12d6bbf80f3b04fb9d4333d76cac221cbcfbb841e8b31341f22902a8cee6f0721cd44e20b40aa0da0c6c8eb9af27723cffbb4b88581d84d7a9f98eda597c53ec325ba109a995d8593298a71511efecd4bbd6423e3129ae62890587a7352df28bfd8aeff3a50dd9598a4930b587557d916726c5be3a57d4cb73502a516a93381501b154e8d73d8d6380eced901738ff04a25fd2678c2cdf0b58de8164a400e89828c8bfa1c8c2174b4ed101dcae7d77a74965a959c10867c94da4a5776a2c91c80ad7d1231c0be1a4ad3cf3a6651e1a49a5a8396262d0805bfaa2f6ec57052e2bbd607c2f0924403d743777b8ebe03d87b5192c79a7f92502684b0c04608329c516afa0edb4548ab95eba3a991b675df089d6adf57b69c54e68275cc8ee00d9172e3ffa4e2c2b0e09524fd4fee23ff0941ee86274e4ee13ab6bfdbf98c1ed9e6d8c8b93b924cd459247639c229404ef66edc875267e7cd2887a862ca9690c0565db77f74a3c361415c913ae5a0a54b9dc51eeac5fb14fd6081f8138ba38d79b889f90f36f9e5f383f83eb37d106d7306cf9718857a1494afbac62b2d9d674c41f8fb095bb9729e0412a7e088ef96025c82679b1e19ca680302c4e86357999cddeea9a0023b5e339e5f5729f6ddb2d4a5cd1128716528ef0267ad69aa8647527e956fb3f7a7c03d7fb27b9bf7bace443a8e8512605284d2d34ae4f1cba246fbc52e08d5d09e1e21c2eb761a1cf9434d210c48d18c568efff698fafd2d26e4078a03439db8b1303a72cd46bd3e25a83315f5157944b333537b0a59862cb91c9585dec23bed5b91089b6d5cd2aebc91ecb524179be9b3c92c8a9b2da0508ca852390cdf0bac6d52413770dab9712d3e0aa585f7d2e9f4490488622a0522de14b0cb91b1f0c478153f2f5fdf230cdd1bc68ff07859aecefd79e4c96f3c4aef8f4d0d5f0124206219b903f3fa7bf3ef920fb10f12f3c05b8d82783f73c59b76281fcc28bc576b3804cf0b4e74e1c58f05575bc942ca7567484bd3f5b2e6d86bae425ee3b4f2ceaa00ece64f79054b0d099b5e600e87d19b0f25c76255ed7ab5eb0da328497e95594932eacfa24b3f7ee499a6f5884160263e608d9ac2120d776d9d0b5d0854b0f93c5bb3c69a111a6d0c2c72410a74feffb295752b9ac726917b0984097e2329e16182cf2ba18eefcab9dd505f0475ce773d59749c81a7806e6396e36286a50a1b9dbe7b1dd7dacb0e77e9541526668a2f3ee349c776500e7fea3beaecbd34e3ef9303e29ce520e00f50c6bde3c134c82003bb11cf34126c083364d58de657b4dcb8074c9e88493a209343bcd6d6c680abdc9c29d642cecf19392fd86bf11671cffd9d6d32284dcce10f38bafdaaee0f1d79a066362d9f6fdcfff904d6d962ff77ca42ffa9cd3534dbf54ef40e0e5f85f5a3265b6da34f3593d3efbe10384833c7d9bfa1ea780bf771a83817a6cb1d9b428ee97226fdc0386982ecd5077c6b329737b185c37fa3b46c3cac78d751741ef9d243df59228c928304000dc932d8b0ceb8e2012d3be6febdfd2e4935253406efb8065df7d75119a02a06576a0b3e85dea9fb4c0351d3910429f9fac98320c2e4ea10eae93a691c29439e116a1d75aadea3e9c06159930468e3d0dba1732ac158add2cb238789078aa5c42be5ce3e9a8a5bcd764496d20004da392882600413567a0ce2d96a67ab5bbcf9e5fd4d0b60230000000000000001f748009b319ccac9035952c75375fd343e537cc60f8b128842cd4ea61cd7846093cf02967787a539366829e3acf7eda4c6eba2100d760f57f54549574a4c96352a38310ade23949e30e3d5a8e3089e0a70aaa95b3c0e0c28912687c5e897232a724fba01ad8ae0acf9b2237c66e4cbdff061df0c437d6460baab7c4f32ac80ff1d7abae426bf7a6fef5925f8d46e5fe3d050c310cd634fc75947233bdb8696fd230cb67b65c844e886a672b57cf27feb8dd903fec0782b6cc8904d4d9c93298f04df14162bb21689d4fddddbaa2cbc0658eb73214e26e1c3bda255b8c48ed5fa0487c73f8978e4df1faeba7f77e375c70da2630fc81b3b095998780c68037b26de0993f548864c5d565a7e9d8902647143887e6b69ee63fac25725a59ea4ff38fada373f4a9dd3f276786f25d77f7514c1a5d402cde7d0b9eecfbdb7fa93cc7ffc6be15fb1a69753db859a5b6e1677b88f09ca54edcae453d8f363cc30735def110fac621ae7396b34caa5c3869cf99098d04e489148dd21da7ad4ffebb4cf95af9b84a2b8f467a5c1f9a416a62a3b5e76e9f3d2111da60fb69b299397e0a54eb4f6789896e3addf83677a26d85296bcfc0c4f2891cfbc72c7177e218d1f23b9e516a918cfa9c27bb7efefc75c6c995e6205f4ff0626a1bd2ddf63353afee451a077ae37bfa2861a2b2a3ed4a5807a20aab202e304d47a2ae83e1005c893676b95100e9253b18812b7e8f19667298800944c07a625775ea792492f291414699a8ef7e2515c3cdec0da7a04350393f8b75382e4913e94cc187ffdf6450e59f0bd45ef4bbe7740d4e2fdaae66f39be668b68d5f70c58a84de1f0b17cd0eb29aade558e6b05b56a8ce2b2313757a4b9dae9ca7e4ec532f979cf9ee169b5b4cc073c4293b4459da028a8910b4a21d0db88888259fb019ea8e2fb1a2165d2757c03f162ee00bf49b20a03d1f7edde9f727ac789943778c59549d707588ebd2348489fb533013d203d439c009e5674a472a7f2cc1d2a0da8016ea59c598d8461edda888d15b36de938d7b94e14d2cc7124a70459a0d11712f18010b5f5720daf554e9f94f980aff76991577f19d738d6ea53aa63a26ba1e7e928d8a7f00e140132de96b254a9378dd809277fec913f1a9c31482c6a380d1780769e848c37ee16fa52a98a4b0977873a4f5dc3a115ba3e12eeffc4d08fb76b1fe117d01613007c872246e8becde831b38305bcac70e290c322801cc803facacf70c9a346e1fe87f0617cd206db32227108ad08feb0dc838f89da2abc72cb90323b18fdc6d6be93407f7be4e90f27b044bb5d40ece670fe8a0c2540cd263e1000fe7ce306f515bb09fa35d7b317696f1d00896bdd9fae4835dc26294d0f4e3ab3eee94378713c1c69e45117d3ed3c6e11db1461d61168378cd2caa02756e4601fef23ce463e50fe2be491de5ae0c5e67207bcc614ffec1beeee1cd21db4be5716063faff11667d12f0a8556674d16567a4b44e2601096f4f85a7035a359869caa3063f6799f940e62779f93f68f2560c058a8b4df4e37d8e0700c0462363e85301fcdc2908667c608c5a0c5452f3ccb2f7211b2ba3aadee8eafba5ff98ae2cc55455031270fe1f6a5d687ce1e4594aa7405418e485b2268a8a8d0ad06ecf45a63a3fe5066bf1c4c09ce72c26cd736373a40d64043543885ae85ea50a77db90d871765e98869102e8dd5154c385b09ec0b273f4aeb4d5408942a43693c6b8a70b636828d7243004cc1b1cca35e3e5be579f0312bc620629bdb466beb2e9e6fcb3e6adb0ca16d2a5ef70bbd46cc75978a410f925336ffdafc5b8438adab517fa4642ce67d7a58d41b44e53791dec4ecab750cef1e6a6c0f2c1f8081b981e185a4d0ed9874ece9ab8e1002b0597bc9a026a24bdabe41db5d728a1a04d030cc728ea16ba6d579f273121dccc8183df8c903fbfcd083d85a6525417c97eeb6805feeaf79bd56736e51bc27c14f10753d6bb7c5984fa5ecb5fd72948d0093475acee733d6a7747a5bc3c91d9d10b9da93b385a6db8ce845fb62d3ab63ee6fd04900b2f543a99bdd5ed0707662ca68754c72cef87ec36d0f413b83486a29ecb5473e55b761389f3129f790ee5fcba0bb96f77e718b2b411bdf3454eaf7c5a792b1d412cc01184532f734412ba05a56cdba81d69115ad552e58c4c91c295121cd83e90377cfb2527bb08a0a1154b0e89c84f0fee64e10b2f8bf634e319ae2cb1ea782e0f3875ad7f6797723a909a90ba8634a8a38b12cc92534f26a5444ea970489acf1fcc92888a4b55a260d1600064a1799d526131103078e2a9928ee018ef1c2d25f17c86735a4bc2c25b1a22769dd0ddab46b8100c65e40f249a26302f125b853fe680551b26f70ba75b6efce0e4fe4f1527749816ff2611d4ee650a79a22625c2a4ec003626eded355d35612dc5c533d7bcdab73267ddf9313b80e401732f3f54efd5117710002efa1af33117dc1f8455884da304bb682b9fff25b35c4ced0a6919102e7916f76a5a900c2506923de64a7b5cc17fb0ce8ed8492e50d7121edb06a5421584593b3264b680412a5f405ecade928c4b7f220cd25694a47dbf78fa363bfeea4a6f3be189dd265703118ff23d1d64e937b7b2a7d1208297d62cdb5f75130a6c0534216934ec847d37c78bb43c356a08830d64a3b5ffe4a7e33970a70aab5bffd39b85e325a8c19f33a24035f5fd4f086d8999d35d52dcbf1802e4c8ee6526e8b0caf9c1fe3581a117027d7762862d3cddb9dd2cefa199ad06b3248c18adf438ba3ad5c4b718b474e22e7999b391139f5443495f12dc0504e7d727126bb80a85ca3f512b1709d2ff65b9e9a230643c1183e57caa07017455af491281c62026910ef572b5f0a78b527aff5aedee5b366586798a56c09d0ef991d92377a46d27704b3d3229190e0f5f0f928bd1af643dd401f1011a602497feba250bb00c360f2f1a079e072a7aec9cca1499411f88b8cabcbdb467296194c8aea0cff17dbfd45c3e45767fd6eae990e3e2013a60b6b14243c2b3a26e6e5e477780657d30fb1976af2c880e992510c91c2a5789ee8dd4a3bc1747e49624297509df9617eff96ef6f0280c52e92c80a854ca6557f1b1eb3995cd84102c1b5babe692277b3f798f9f9499305ea46744bda2ee0c281ecae1fdae3b64bb8752d90915be50ba697ad75e586c5705d32dbed1590edd61cbdffbee33c29670a12dfcbea4d382eb0b516343452fc7e047d39711e126461a650c135ef6f8889e8878d952efbf984f00ef85e4077ecf4deef718dc4c2aff7fc7e8bc7f147fe758f6bce6a6e25c67dce713c04ad12fed523388a844b062d45e136b3ff614020a8011e6bac57f7c962c94d79b2e566e18f8233144306703daefbad2184c3e11605381fbf4a619600aca8d7e074ddd4cd0978c67c7024a0b744d517d282a8721dd06c72b6e0eaedf3acbf1abd1f258d3a7707d59a296b2082ac3f504d696d63625567f5636ce40cde159370c8293fc5ce2fdf603cf662fbbfdec74e228720791f4146ebb34048dc6129e33472520e680da3f15f7ac87aebd8a19f42c3380b78f0762d4109b97ebfaea7c80643fbd216d0897233cd80616f50f8f52400def14182afe79374eac9f1a25fdba26f37e203ea468fd206838a80e18a6ee2b4f93dd2cd752c0cb821b2babf230fc0eafa1d20372e76287d82b533e90496bdb1078151da527f9e9ed986cbddc11b9d064fc76fe9bae842a877f7a81ec536d81b683bf9070398533359232303f507cedbfc762592b0ca11a1f2ac617bbe304d9abe3cc92d120af0a8a074aeb04729619c192d270c61b22f74061246b3e2396527429c38f91fa1545c954a592d8ef6040028cfc7b072849b744f68ffb85fd325970a1eeff5a31f1daa9d0171ea45c146310671b113e5c5f578357455f4e09c6a80a180b78e4890ee360cc9e65302dffe508a1ebf58ff1b5aed170f11bbf055a3045adf27e36c5916e2630d5750cb3f427ef34044e3ebf780f4c439018ce5e34ef8be0754182e51ee5ec29647d19876db3b723e764308afe752776c6e1ade8304000e44cba1aabc206a065fc00cd2af64318888ad2220d6404fe9c93a1314117a20d7b2054d682f619ca88497dae7559dae0dc86cc9f216f9b11fe983287c2415b75a427b3409f1bc1a6092e26da2b602afe5e348ad804a9b3ebef94675b120593aeda84a5d215278dffc2e5aff082d22ee7790e7ace972063cfe3d1000745710ce53fd4d0b602300000000000000010ac301f10e7e4b173a76d8d73c6f90547100dd782d2ff6a1ad19285d9442fcbe65d12269289d6010e0c3c7134f717cf0ac9265683828e00b99f1a20f45811f389578b9362737fc7df0380335c08b5a6fb51b9eb25ff5abbdcde18042e6293501c3518d1ac1265389d49efdd6a255612248341cdbafa6f51b403461eb9d3fda4f71f704c3754511f3ec05f15daff6f3d9c01de29e39ceaefdddbae6c3a82ec6d6f2a84f944b5c739a5bdea0ecfc1c723c70e86f78915a7cea684f5786e2b68e79aace3359539627034738668fbb40e59705862cf7fc6b97dee52af20ae3143a2e69593cf6f75dedb70d636046256d1c7eb5c726bff911c05c8f69163bceddf2575c3145d399d54f7d2a50c69925951aeff559a1ba7dacb8461ed13af856c10571378a0fa3e59adcfa2f8f21c5bff06ef4a91ee976854a2c1bcc8e09e399e9259aa7cc778aba09356750b57fb1cfa5f17f4f934cf9d25978e20e8d01465dd5eb5ba2b78a911995e206802762f3f4a61505948f7f1f9ff8c2c38020c0529bd5d9b16cda708179f338522711cde0282691f56b416714ce0904e7c29304a1d12881ebd85e24da96a90cf27e1eeab18318079e3ec849fcfb7a785d59a752bcfb18c48de8c1f1878697c8d2b76bfe98a2b3445b34761a45c19741827fab1d5770feb4829d59abb3a5f162ff20205e88337ab07b708ddb31671a599ed2c0a2889eb9bea9035a50a2922a105a7f58f40aecb2a85553d19e89ccd7bd9277c4acd4f03968274f123b57044bcdd39b9b86d4bc0591138cfe072b5cad8d273d102e302819deaf6010920b34e42482565575d3ccc2592f0e4657791ac633c2b674e846447e52cccedf3350d042c84f31df773f62497a34e81edaec1310efe6f2993b7117727431e2272b80502cb2a2b73c10f6a3001e05dddd3c30ebd5a8bbda9955b710a8e3f6dbb74b39181d066437a9c838a47b55b67b75689703aca44b9b9a1a0b936797b9524065a216494b19853efa555b262cebd1487781206734b4f0eb1bde1bdbde872f0fedd4d209fb233f23e763396d940c550c71687f797d306b0b76c54aa30f0fe6780a8627faf27128f25650a600054efd28691a8943a1afc104cc9af02dd298eee2dc1b78e60f02cfd70f4586bdfa4046a45f63773fefadda2d947db508cb0a4e388d3f5e032b48b330deb93e5a5c8201cf2130ced36ee295eaf7987a03d20011b33569f3e64c29083dfb9ec2eb711a360c6f0967da4923c22ad93d3938f1e5bce62af599b9cbf7633a90af17df103e98be9ac5d6b530e0ea8089a2478c9c42238ec56f180a8d6df94a2690d6bfc4ed738640e5ffe6d8d90e637ce496cb521d13389e31cf31084e86e00e5d6c9a62f8ba4801d13c2797db5914fa8685435b214f27646bfe7cffb105add5a84beb5a434041579de2c4ccfbd5b41022a921ebad58afca8bf6eb9789c630114ef8cb03cf8ca3658bf7a89c7871ca10b5711d8a7e20414b368f846fa14807d1eb2215966a8f8cf737b569cb1cdc6df1b6d913fc31e590bce15b53e82ffb3c409d57c937d5ac60ce38d189db8d7574f5f27b1c606628d756624c093566f51de2550483eb1c609a4f9bc6548dbccc3c52c085a52fb54a92b18decde23b98ac2d9303d989f2fa4838032433e5052416a5c502045c56dfa9a0196a907fcf51c5fa840a16980d3eb5e0461135b051ebd5abc1a773bb4ea6a7372b54f0ac154a74991660ce192721c0b30b1dc9c112461f130e7b667693247c230556e330d050442b284ca452882f487f4cf6356e870679db5dd920f625b721f9d9c9a21f3e22bd7edd38eb65d0f30b3b240346a3c83279eafcca9f40e4788c191e68a9bf1731f32dfe0d19ccd3c3f353a594f2057416a5f7de7200585c0d64ed4bb616940572bc2801a22d5581991b3618d43d82190e5aba723126541ece8b5e6831ed1962d989a17fa19e2a4be6e55b0128f28f8dfb281f63d40444f3a9ad820b837b5b240ce39a247f5d0b83660a3f8fd0271c8729ed8a36e3a7380b40df6042598e305b20176f73e05f1cf45424d717d81bf905b331e2b5b17b9566839b11a23565a89999480c53c833a6158b2f9e87149d8c25f25ac916a1c7bd685163383a9f9d885297f9480725033b58beec4650bb8c2598dcc9f065592e5ead996fb140dc3bba98997697c9ef32d5c18b5a1b0cf52310407e74fdc6c10fcf07677dc9d28461ccf2f8fe89257338fe487ea3155a82524dfe0871c6e76aa5e3e5f5fee5905cafb395f542db5722a56b39b2efcd637d6366a12c3267a785f843b25a93af27e91cc9650f8cbd62ac06d8dd9c7bd03c237451343c3dc9b43376b66b53093e124ad9d4b0fa3439a8bd4f5e2c8349bb20a480fcaad47814db2ed7f5e193b6ea63b27f70823bdfc891702e6ad5528fe9a7be54ccd8a7b75160809fa514c6a204f0e8079fae6ebbbee35390e613dfc492aa5f4765cae5245282930e20ba99b7a8d019280c552cc9526d157a81386e24a3d2963d4f4f92bb6ede985d23d3e2ba73153d5834fb07a4be3d74e0a31abf26cb338f070777e5bbe83113c53d69ab169948068509002a42bb6c33162b16f16f7a5fcab1c05aa98edf921b460b18d24dda04cd79990785209917bedfdaa32f7a93f621d24429246f4799898ba2cc83cbb7ace24d5e91f4bff5e4b1bc9b2e0f7559cdc25b4f43ae0f0fb83298fd9925257fd3846ec6337772740da59e8d837a2ff0eebbc74f72f3306bd05d42acfe1612b5471198405927f599d864fc4366ef20c6e227dae8a966263fdb218c0c5a10a79d2fb91f31362172969e26f58d5f2461e91c8344e0b9ae727ce4c5e6e4ee38f64fecf69647a3f463d49a36cbbcab0cc89e5b02397e0cc8dd9b224eb2a13db4fde9c7f12ef8f47c67797a0313c5788e7cd5ee5d570447581f1dee91ab175a4aa9b921fc0b329f2a64b0f49b6eaa08ae63c24b38bd1f455bf90e48472084a7992f1b739509d468986a2026f7251d6c7cecb87808bc556b35b2d49f5f2bc0a96704a0a3c9080fb5735d44e2bfe7f8e808c85ea51319ff15b2542fcad460b1f717ff126d2bc80bcf1a41ffb2db66950e5c8c3c77ab6955801c1b239d2e5e32b5171a6a938323170eeac7aaa6d1a28f3b4fb097f4a5de26c9f83bcd2133142ea5d6349a3a5ad13a2d7a0f02faf59b05c89170877551ae40be68a3dd519ed99af7a633f62613f6ea5f216f00704818e34e4ec866bf93edea474b94a3e338d51886b2d5f081f1803915a84dc994e0457b56b339bd1bd0b11bcd92a802f75fdf78b9da3b80fed4c9c414c41a8a5e0b7d3b0fcaa88fca9d8eb8d68075ad942796127a7bbdbccd93a14d78302749f4e868c197160ada636e6c35301dd6c4ceaf99ab6e247367135f7388a74c11ad390b0baf1139dc8ee4877bde7b5e09b6c1b3c5879ac8ce13958984b3541cc1533b9ac91608f874e2409bdcbfbaa42e985c2ea924d5ab53b63746f2f8c922600267230393a68711a15a2fd994f8c424f86aadceb3d301f6ea0e960d4b37e6e45d00703c4b489777cc8d88e71d15bed8441628561e3550cf28ff7f0ecabe0484472310bd680d4099e970d1973b98cc706dda293f88d9850ffdf3724cb622053eb1004823d5a5d76265522e0f62e150febc7edcda0340594c7ab76b52879e8cf0ce1682d3acb84512874823b651f640c05b655435991082964080f66f5a1f0fc0e2e55e9b74f13a991d38c4c12ac0e7d382b8ccf6e4cf01e48c9b3c91b6487e28d78369204d0aa06986018dbb32fd29d39e740a2f3ff9c779f8109718820cb168ad1a21c2232993c460394a94b1b2198dcb1524b9612b178825431f8236acfd97bfe25ebcb024d4f16075375f5a3b9e1a0b5d1afb37c40c273a4a5a95ca03444bdc5ce38f9ccb8f15b1fad5187b75a26b9aaaba7e134f1a2f3529f1d0b357e62fed8fec93bc539b149719e8a8862bb668871b4dee5ba58509a5caff80b5dfdf9586f9c861473ec8598988f702fde410537f50f126bba9c1ac6abc82be37258cf195d7becb83ec633d38531dc7d3768e2cbeef619e0e09a1ca6d60000';

  const pubkeyList = '03d64695014417be1e0f14b908326310569ca10def36a47144df68aa2e743aa298,' +
      '02f9fbf4d41bd2e1bd2b18ef23caa7690d4fd9be9bd89a82e627abb3ead60c442b,' +
      '03ec0a41a61b4b252ec3799701b80d91fd19e0963336e431fb82e14e6709cc0def,' +
      '02c78ccf8261737f1ae2bc9c7a43182236bc017191108f520295e1350a140a6c63,' +
      '02b66fb83127311fa28de1ded3a275dc97d34c813c03e3116ed5d2e6ee2dff2527,' +
      '0218e34d824a6a9ed9b91b60dabff0f2db114ed7ffac1be85bbe2bdacb2dd91091,' +
      '03fc55b7bc182d62029df1c72ea64c5ebf5daf1d36802e931fe44ec42d55c89207,' +
      '02c0d961b2bc2ccd5fa339a8722adf735ea89e0daa47ef4e9c94677d333e89acd3,' +
      '0306940548470213c8d5ec1ea29fc0a0b5f3edfbfbde7c53a86b9d6b1681855e24,' +
      '03e58277ad1f18680ae216644c767422b28b9a9e1914ba2f2d543863cb11069b2a,' +
      '0390304bbf375964640e10afb4954fe0cd719cee7af8e621ad10902005bc553375,' +
      '039882db283f5d1aa04a9cc724ec57329362e4b5e777623901aa4aa0e0f8eb0b8a,' +
      '024bdde81798f9fe81ce6abb3e4491164bac3b36a0c542c1d4da2baec2f4612c70,' +
      '034c89bee99aa9935d00fc4f730d834c9105a2949146043e9ecae692a58c735217';
  const signUtxoList = [
    {
      txid: 'b6ed6fd49eadec0101a04fadff5f4a07575cc160e5d87d95b588d5ca7d6416b7',
      vout: 2,
      bip32Path: 'm/44\'/1776\'/1\'/0/12',
      amount: 0,
      valueCommitment: '09606bfea1ac0b8e59dac55d9ef37e6f43cca14794224f14207f854aa924fb8a77',
      descriptor: '',
    },
    {
      txid: '0bf19f67bc7c39c37b5fd940d4b2f00612bacf6181ab75a6fab31a251911963a',
      vout: 1,
      bip32Path: 'm/44\'/1776\'/1\'/0/3',
      amount: 0,
      valueCommitment: '095e923581a02ddddc49e96a7b224a19050f219e92329217f03d19b7c2f595e84a',
      descriptor: '',
    },
  ];
  const signUtxoList0 = [
    { // fail verify (other ledger's pubkey)
      amount: 0,
      bip32Path: 'm/44\'/1784\'/1\'/0/10',
      descriptor: 'wsh(multi(2,03d16352b6b2f3861fbb4acad75241d4e875ca6106b6077f77ab646a40fc24f19d,033d62b96bca95840a3a89a861ac0a6850c2389f4a78a300018b157e45a8948033,03c05c228038c244a82b7584043ccfc59807e4e8e4d84d726e098ce71a0fceb57b))',
      txid: 'b6ed6fd49eadec0101a04fadff5f4a07575cc160e5d87d95b588d5ca7d6416b7',
      valueCommitment: '09b8919045ac71494ef8c6ae9dbfccfcaba32edf810763ab8fb5bf117133ba7fce',
      vout: 3,
    },
    {
      amount: 0,
      bip32Path: 'm/44\'/1776\'/1\'/0/13',
      descriptor: 'wpkh(0370ce7d236beb4b82baa1744ba53924de4eb0c7ac01faa1dcacb1301d068a7fca)',
      txid: '0bf19f67bc7c39c37b5fd940d4b2f00612bacf6181ab75a6fab31a251911963a',
      valueCommitment: '095e923581a02ddddc49e96a7b224a19050f219e92329217f03d19b7c2f595e84a',
      vout: 4,
    },
  ];

  const mainchainNwType = (networkType === 'liquidv1') ? 'mainnet' : 'regtest';
  const liquidLib = new LedgerLiquidWrapper(networkType);
  const connRet = await liquidLib.connect(0, '');
  if (!connRet.success) {
    console.log('connection failed. ', connRet);
    return '';
  }
  const pubkeyInfo1 = await liquidLib.getWalletPublicKey(
      signUtxoList[0].bip32Path);
  const pubkeyInfo2 = await liquidLib.getWalletPublicKey(
      signUtxoList[1].bip32Path);
  if (!pubkeyInfo1.success || !pubkeyInfo2.success) {
    console.log('connection failed. ', connRet);
    await liquidLib.disconnect();
    return '';
  }
  const desc = `wsh(multi(1,${pubkeyList},${pubkeyInfo2.publicKey}))`;
  signUtxoList[0].descriptor = `wpkh(${pubkeyInfo1.publicKey})`;
  signUtxoList[1].descriptor = desc;

  await execSign(liquidLib, txHex0, signUtxoList0, '', true);
  console.log('signUtxoList:', signUtxoList);
  const tx = await execSign(liquidLib, txHex, signUtxoList, '');
  console.log('*** signed tx hex ***\n', tx);
  if (dumpTx && tx) {
    const decSignedTx = cfdjs.ElementsDecodeRawTransaction({
      hex: tx, network: networkType,
      mainchainNetwork: mainchainNwType});
    console.log('*** Signed Tx ***\n', JSON.stringify(decSignedTx, null, '  '));
  }
  await liquidLib.disconnect();
}

async function exampleMultiTest() {
  for (let idx=0; idx<continousCount; ++idx) {
    switch (idx % 4) {
      case 0:
        hashType = 'p2sh-p2wsh';
        break;
      case 1:
        hashType = 'p2sh-p2wpkh';
        break;
      case 2:
        hashType = 'p2wsh';
        break;
      case 3:
      default:
        hashType = 'p2wpkh';
        break;
    }
    await example();
    if (idx < (continousCount - 1)) {
      await sleep(continousSleep * 1000);
    }
  }
}

async function execPeggedTest() {
  const txHex = '020000000101854b02c68f24ba640251b17f98c1230bb263ea781331eadcdac1cc32c2d4bf890000004000ffffffff030125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000000079b440016001475f7cda67f3f421152d438573282f16e1ec394660125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100000000000001f400000125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100038d7ea4bee2c8009e6a2006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f17a914a722b257cabc3b8e7d46f8fb293f893f368219da872103700dcb030588ed828d85f645b48971de0d31e8c0244da46710d18681627f5a4a4101044e949dcf8ac2daac82a3e4999ee28e2711661793570c4daab34cd38d76a425d6bfe102f3fea8be12109925fad32c78b65afea4de1d17a826e7375d0e2d00660000000000000006080080c6a47e8d03002025b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a2006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f160014ac15c9bd0ed1641999c41fef64fb3c9ff48ce29dc002000000000101424aeb8cd9e48964d693f0395d4c228064de9c878b0c758f4db3d5c0b33059980100000000ffffffff010080c6a47e8d030017a91472c44f957fc011d97e3406667dca5b1c930c4026870247304402206ad339157f0eacb080eb4f956253582adab6c6381a314d6f2a7b9d22aa10f21c0220422c64d1a4f7f1d70b409a4482bb9fa07aa206a8110eed7794f91f91430fd9d6012103a075171877c4e93df48a3f9a078b12863e1053c3f62315abe7b8f23333c1c108000000009700000020fe3b574c1ce6d5cb68fc518e86f7976e599fafc0a2e5754aace7ca16d97a7c78ef9325b8d4f0a4921e060fc5e71435f46a18fa339688142cd4b028c8488c9f8dd1495b5dffff7f200200000002000000024a180a6822abffc3b1080c49016899c6dac25083936df14af12f58db11958ef27926299350fdc2f4d0da1d4f0fbbd3789d29f9dc016358ae42463c0cebf393f30105000000000000';

  const signUtxoList = [
    {
      txid: '89bfd4c232ccc1dadcea311378ea63b20b23c1987fb1510264ba248fc6024b85',
      vout: 0,
      bip32Path: 'm/44\'/1776\'/218\'/0/0',
      amount: BigInt(1000000000000000),
      // valueCommitment: '09606bfea1ac0b8e59dac55d9ef37e6f43cca14794224f14207f854aa924fb8a77',
      descriptor: '',
    },
  ];

  const mainchainNwType = (networkType === 'liquidv1') ? 'mainnet' : 'regtest';
  const liquidLib = new LedgerLiquidWrapper(networkType);
  const connRet = await liquidLib.connect(0, '');
  if (!connRet.success) {
    console.log('connection failed. ', connRet);
    return '';
  }
  const pubkeyInfo1 = await liquidLib.getWalletPublicKey(
      signUtxoList[0].bip32Path);
  if (!pubkeyInfo1.success) {
    console.log('connection failed. ', connRet);
    await liquidLib.disconnect();
    return '';
  }
  signUtxoList[0].descriptor = `wpkh(${pubkeyInfo1.publicKey})`;

  console.log('signUtxoList:', signUtxoList);
  const tx = await execSign(liquidLib, txHex, signUtxoList, '');
  console.log('*** signed tx hex ***\n', tx);
  if (dumpTx && tx) {
    const decSignedTx = cfdjs.ElementsDecodeRawTransaction({
      hex: tx, network: networkType,
      mainchainNetwork: mainchainNwType});
    console.log('*** Signed Tx ***\n', JSON.stringify(decSignedTx, null, '  '));
  }
  await liquidLib.disconnect();
}


async function execPeggedTest2() {
  // command: npm run ts_example -- -peg
  const txHex = '02000000010103ae7c6c1dac6f9b83c100e5bbad2e6262ae3f1932ede271150aa0613e7a50990000004000ffffffff030125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a01000000000007a12000c16a2006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f1976a9146fa03ec68aaeef6f429ad9267f29ae98d0d2b58b88ac21031797e767f8ea79110c2d911379ef8210ccaba0f06a0721a1c570806305b31b0a4c6102b52d98d53b15559358aa0e037f77ce6eeb10cb58e8aafc6799fa20b2f0525cb155005226b39ba21881e8afb5c8a0330c58f7b7337bbe4d88ae03e9d6e446076a83aecf7a46e25c8a37ed81aacf5872463d48c241f7ab5b7d865faddf3cf0c54c0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100000000000001f400000125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000000079b440016001475f7cda67f3f421152d438573282f16e1ec39466000000000000000608583e0f00000000002025b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a2006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f160014ac15c9bd0ed1641999c41fef64fb3c9ff48ce29dc002000000000101424aeb8cd9e48964d693f0395d4c228064de9c878b0c758f4db3d5c0b33059980100000000ffffffff01583e0f000000000017a91472c44f957fc011d97e3406667dca5b1c930c4026870247304402206ad339157f0eacb080eb4f956253582adab6c6381a314d6f2a7b9d22aa10f21c0220422c64d1a4f7f1d70b409a4482bb9fa07aa206a8110eed7794f91f91430fd9d6012103a075171877c4e93df48a3f9a078b12863e1053c3f62315abe7b8f23333c1c108000000009700000020fe3b574c1ce6d5cb68fc518e86f7976e599fafc0a2e5754aace7ca16d97a7c78ef9325b8d4f0a4921e060fc5e71435f46a18fa339688142cd4b028c8488c9f8dd1495b5dffff7f200200000002000000024a180a6822abffc3b1080c49016899c6dac25083936df14af12f58db11958ef27926299350fdc2f4d0da1d4f0fbbd3789d29f9dc016358ae42463c0cebf393f30105000000000000';
  // NG
  // const txHex = '02000000010103ae7c6c1dac6f9b83c100e5bbad2e6262ae3f1932ede271150aa0613e7a50990000004000ffffffff030125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a01000000000007a12000c06a2006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f1976a9146fa03ec68aaeef6f429ad9267f29ae98d0d2b58b88ac21031797e767f8ea79110c2d911379ef8210ccaba0f06a0721a1c570806305b31b0a4c6002b52d98d53b15559358aa0e037f77ce6eeb10cb58e8aafc6799fa20b2f0525cb155005226b39ba21881e8afb5c8a0330c58f7b7337bbe4d88ae03e9d6e44607111111111111111111111111111111113d48c241f7ab5b7d865faddf3cf0c54c0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100000000000001f400000125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000000079b440016001475f7cda67f3f421152d438573282f16e1ec39466000000000000000608583e0f00000000002025b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a2006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f160014ac15c9bd0ed1641999c41fef64fb3c9ff48ce29dc002000000000101424aeb8cd9e48964d693f0395d4c228064de9c878b0c758f4db3d5c0b33059980100000000ffffffff01583e0f000000000017a91472c44f957fc011d97e3406667dca5b1c930c4026870247304402206ad339157f0eacb080eb4f956253582adab6c6381a314d6f2a7b9d22aa10f21c0220422c64d1a4f7f1d70b409a4482bb9fa07aa206a8110eed7794f91f91430fd9d6012103a075171877c4e93df48a3f9a078b12863e1053c3f62315abe7b8f23333c1c108000000009700000020fe3b574c1ce6d5cb68fc518e86f7976e599fafc0a2e5754aace7ca16d97a7c78ef9325b8d4f0a4921e060fc5e71435f46a18fa339688142cd4b028c8488c9f8dd1495b5dffff7f200200000002000000024a180a6822abffc3b1080c49016899c6dac25083936df14af12f58db11958ef27926299350fdc2f4d0da1d4f0fbbd3789d29f9dc016358ae42463c0cebf393f30105000000000000';
  // OK
  // const txHex = '02000000010103ae7c6c1dac6f9b83c100e5bbad2e6262ae3f1932ede271150aa0613e7a50990000004000ffffffff030125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a01000000000007a12000bf6a2006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f1976a9146fa03ec68aaeef6f429ad9267f29ae98d0d2b58b88ac21031797e767f8ea79110c2d911379ef8210ccaba0f06a0721a1c570806305b31b0a4c5f02b52d98d53b15559358aa0e037f77ce6eeb10cb58e8aafc6799fa20b2f0525cb155005226b39ba21881e8afb5c8a0330c58f7b7337bbe4d88ae03e9d6e446071111111111111111111111111111113d48c241f7ab5b7d865faddf3cf0c54c0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100000000000001f400000125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000000079b440016001475f7cda67f3f421152d438573282f16e1ec39466000000000000000608583e0f00000000002025b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a2006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f160014ac15c9bd0ed1641999c41fef64fb3c9ff48ce29dc002000000000101424aeb8cd9e48964d693f0395d4c228064de9c878b0c758f4db3d5c0b33059980100000000ffffffff01583e0f000000000017a91472c44f957fc011d97e3406667dca5b1c930c4026870247304402206ad339157f0eacb080eb4f956253582adab6c6381a314d6f2a7b9d22aa10f21c0220422c64d1a4f7f1d70b409a4482bb9fa07aa206a8110eed7794f91f91430fd9d6012103a075171877c4e93df48a3f9a078b12863e1053c3f62315abe7b8f23333c1c108000000009700000020fe3b574c1ce6d5cb68fc518e86f7976e599fafc0a2e5754aace7ca16d97a7c78ef9325b8d4f0a4921e060fc5e71435f46a18fa339688142cd4b028c8488c9f8dd1495b5dffff7f200200000002000000024a180a6822abffc3b1080c49016899c6dac25083936df14af12f58db11958ef27926299350fdc2f4d0da1d4f0fbbd3789d29f9dc016358ae42463c0cebf393f30105000000000000';

  const signUtxoList = [
    {
      txid: '99507a3e61a00a1571e2ed32193fae62622eadbbe500c1839b6fac1d6c7cae03',
      vout: 0,
      bip32Path: 'm/44\'/1776\'/1\'/0/12',
      amount: 1000000 - 1000,
      // valueCommitment: '09606bfea1ac0b8e59dac55d9ef37e6f43cca14794224f14207f854aa924fb8a77',
      descriptor: '',
    },
  ];

  const mainchainNwType = (networkType === 'liquidv1') ? 'mainnet' : 'regtest';
  const liquidLib = new LedgerLiquidWrapper(networkType);
  const connRet = await liquidLib.connect(0, '');
  if (!connRet.success) {
    console.log('connection failed. ', connRet);
    return '';
  }
  const pubkeyInfo1 = await liquidLib.getWalletPublicKey(
      signUtxoList[0].bip32Path);
  if (!pubkeyInfo1.success) {
    console.log('connection failed. ', connRet);
    await liquidLib.disconnect();
    return '';
  }
  signUtxoList[0].descriptor = `wpkh(${pubkeyInfo1.publicKey})`;

  console.log('signUtxoList:', signUtxoList);
  const tx = await execSign(liquidLib, txHex, signUtxoList, '');
  console.log('*** signed tx hex ***\n', tx);
  if (dumpTx && tx) {
    const decSignedTx = cfdjs.ElementsDecodeRawTransaction({
      hex: tx, network: networkType,
      mainchainNetwork: mainchainNwType});
    console.log('*** Signed Tx ***\n', JSON.stringify(decSignedTx, null, '  '));
  }
  await liquidLib.disconnect();
}

async function execPeggedTest2max() {
  const txHex = '020000000101e46aa5d11fb7f2243e75bbd90ad94e5ae0d1992c4a5c0d6ba71a77e73df8e23b0000000000ffffffff030125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a01000000003b9aca0000fd62206a2006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f1976a914844d3afb2081df687e6c0a83d2a5e0925c4fa01f88ac2102f6e02ce0c684096337672d7d72bc33c5129f9079c50447452aa7139ef3632f4e4d0120ff35654cefcf08494febe812923c9a090c2f7dd23e931d237cbe0b72d1d3a7d5f27cfae0e02d5538473849bcfef9fb2205a061ae68689d4c9d343ad0d440157c9a10e08040b5b7c3674bbe6a688585ac259d6b9ffe2f2a40bf4b594c99b2777983e6eade1e04dad6e3748efa8f5cb54c4a136a6731d8f368bd30fcba4328df095a3b806a09bc10f11a7fd85b875f5c07eb9dd70531a32d57917b37d107d624b408d4360876fed359744f4e3b35105054738f13a8e29a87773f66254c1fc0af6ab432e8b870b7363564b7a0c51df934c49b8eeb9cf37da26d9e2fd57ca2c93ff790017cd3be01478f68cd8a5234c7bd4cb4f4a50c0756cc97b73afb21bfcb7a41e0fbfe0cbc1dd257f91271a097fa25e4b01cd1ef8ea5063ada55236e2731e22071f84d0a769826b69fefb81e52b45ba1e12f08b82532e98ad2484242b22a21d8f1e50adfb36f2e98232c47a39ebe1bc96bb20bfd23e54a79436bc56addec1ef25ab71e109054f0faa8e13fd6277f3108be3d11142e420e99e091f463f7853246c8a23f765ff2ff34f95da51a5ab6639764b967d3551def549d077f1fefde98640c1f659db14d11b7ef39b9bbb7a279a749d344b930ea850b2f3f45150ac7636477e42b4cbc4b46aa25519819de67cf9d03d1d184d14fee2202ef777c5c8f7c9504779749a979d0245707529acf004549d4aa82c37942a1d8a7c45993067e4643c809a253fb2bcce3c7a1428bcc56f9845a2132a418be8d186b8dc828652f6c5e8e12932686d09921eb91d5e644b3e3c6317e11b13dde1df7b5533ab9e7e3b441aab50e4f93ce6ae525109a153b09b5d197cd071b4f4e018e2f85fcb3064cf5f6c2db25e7d84db0af3690f83dbe258393b21fb3568d5cff217a9cf07c27c07de46582b529e7ce5ca0346eb649bce851f1dac85338a4f5261a956a4f515a71e462c85526908fd692df66305d6d277c8ce9036ed862aa0d658189426e9a6b4e68b35b040166c8af265fb5d5cba9c71c6ac03637fe1e60cdf4bdbb36bc5a10ac6eebee79a4bd7ec8a5f170e6da1737c769888a2719ff72fc4f7460ba374c10dd606d0fe0a91cf3075981a9e32fc9b7f12a40a8f3d70d540ced45cf981a82a98b62d3f2cf2c7a129a1a835581f3dd2926f3cbddc986040ee9f479fef5e7801c3fded2012fd1ba2e286000adb01941b3990578f2ae1cf2e9b01e72ebc45cd0acd7b1511bff0bab0b3d7e3e1806dd6d75df59a0149ab1526e5e04b464bbdd6a2ea3809cc1965a65908acdfa166514970ebdd83f2033080d097f818b1566e8b4700d17864c35cad2557032694603cd09cf0fb356fe3264239b98abe75caff578e9ead7bdef4603e666770f343cc2af9c3f07cd61469f37c7f6e5fadb66c4864830d1f8fc84edfb1cd5412b28af07f30db7f9aa78ec25bcd988c1858b4112c858d86c8f11953a47e39b302ee908f8eca68accd23af273ff3d7fe940ea03dcf1c9d0f96cd17e933195e1e90895718597091ca1db5214c094148939dfa33a8cbb016808c4159adfcafb3cde9f48fa80e9bec83589beb7bb92d8912ea08ee7e44245a74339d90978ee276cabae5d62de369d4f134765e6e46c00d1d762150a4b67b61ae75e5039ee609d3ce9a73bc1c0a3068f0e4242e47b2043685924ba8d617d3d0bfda8da19cb6e977423006f73bd72bf2e94eab3d5d8359ac402e47aa6b034296c1704ee1859c7a3760b962fd9380a4f6798522e3c99b8bfb9bb5f5c323669e382d788bdf4ebe1e82a1d0d5e1243af36b304c5805f4fd616a03ed212ffcaa28a9ca303317b3901fe23ce700ca6e7eba196e9b38ac918cf4ec167ee42c11ad3b4259f659582bca967211a8382620977588aca4d043c24d319776c8a17d388a0b521a42882546bd185e08b860c82ebb10444074726c277309bb12633a3e2966d8b0bbd8336112abe147e229d75da7c61e54166f7e6a2b5bab8ad1b23430066004ded5c6996fdf9ad04a91908c2f0c26ea3ac71e8c77a64c187769845f8ead3586e5988d9fc4c918b4eb324f10cb8261b88433e8f57ce476f5a62ec992bb7ecb5418fb348474be5aba6bf0cb33400059d353c5c8982c221564b1479f29c15442cec40a3c3eae5935fe34589a366eec7543c49aa29c90fceb2065cdf640acf9d5384c57a24b3ab2951ad6b6cb4105d88c26f64ed0db52a09f41dc1855b88d639ff585d44761f4765aaacc552a103dcb093e22b22ea7530bcc8d63b64b0ac048e6803fbd80fe9e99a4483403718c8de908ffadbb52404cedee3df481c02515f709e564578745c3cf102bb61654653c5217109527f2e770e43f84237649c138d963f049402a36f7a152a20c410b88426011ff3dc32dd9d6a6ba295d66f2329f8cb54b0063d8be28ff32dac675169fd50d57ad65bb5c1d076f51c0b999b27e963d824cd70ba00c9f154544d43b214fcf8e16f6b206ec5dde511b6691ae1c8bd9e7c81ae206a75537218689d2b831c6bf920ed2b65775300183c83257ddd1ab2517c7716a709c96f2e3660428623d5aeb932472cb523ef66644a677bbff862f6934464d2d8c9a12b74799ba17466b1cd7cf60927181f74c494b478a62c2b923d913bc9a269b60beb6341d7255f3e175214848081a8d12fa66f45e2c36cfe74d5cd42eb488d43067558b723384528fe59b89df3967a84504806adfad8a41594b0201b73c59bb0739bc4f9ebd00c390c3ae304e570ac4de8a0c77c3da24a2e53d58d9f8aaa5c59d7fb4294b18a41a0be27027a05055283d694ff50314057a535732e881d647c85a68efbb72b5399ab55d9cfa4b7a6ccc07079e34327888090043ac0ace550b9997f5b74355ee34943192bb8c91de389f3f747a70cdf1426c9f6f3d86204ebcede78e5b3c97c3955d1a84cef4ad0b51c1b72246ff6ef3778a6406ee3900fea6283a4a6664ba92abaf9ff2975d8ce3aeb7567b84cfbe8445595ad9e5f5eec2d7fc27802eb0e13bb322ace3e5bfcda117f00ea72df73121a9f6702fa71f15b07a459d0a3d96fc25f1b77c51a91269f771f2e571de688163599b92b46ac7c6c317d6fdddc5ea400ac2ac847ec9bd2f835434bac1da4e67a7b814c2b8be00dd930a68f62d43c36d346b2c655d2f5e9b9801d3b4aa2f07841f87d2eb5e19f5a5c2bef02a8a274819665ab6783e203d588e64d79e6b422379525b6a4d33bc5b3625d8170e0f133c4ef2de13f71e51f49c78323da8945d38a265a522f9391175ff4e3da3fab89337968a8d106f1407fb59d6264ecf1ddeefba23b62ffb448e441d9f525a2904d26e9c9255242c2250bfbf15c016746d24fc978434c49946afb627fdc47488e180a1500eeff22e04758130105e8bcd553c33177a79d67d4b9693ee679722f86360b79bdf3188f89d17b237eaa7324f5b8237c545b77bdfed0b747160467ea4b7f6fad12b7b730da55aa73b66368eb2aa11e0a125a0eedbfa43dba18c027148d16c5cc95ae324edc7f27ebbe1575bd134569fdaac209e9010f9d9fe1cd7d9c00f0b4f97349be7b7b3673bdfed2a50dd82b6d9907d74df1c4f3100f2c323226df0a2edf6c813a6d2ab7b9fceccdbd94e68c0d0279be4b981eea195c54d73af920c38b640d2bff77817f84819f751edea74ae8ed69aaa8b05323114831d54e8e38aaaabaf0f90db0824a29637932b48b04c1d2ec7b3dcbc2aadd713f955871eb441210d0267875ec21b42585a21111a8061b975b3b9ad63243cdf01fefdd02533dd5bbe7f2be389b5feff5226672e9487faf5db1fe8c9c9ee9d974a9cc80d8361189bbcf02e1ce8b0debc30c28c07b8295f5bb3644498a663c888937dcc6fb58e675eb7f958be2c34b789e6e037ddc15037f54e0abfc80f7131a9bb52f78544446897c28e2160a7678606c9f509738940819f4765b14727d1878a49cd5370bae4729d98504647045ada57bcea8752f2bad4d5b697b7749dbd69fea828a0b4ba7cdb3417b2a27b4802ab17cb9e95911d848c0c5553ba649498344de6535ac3453d5bd7448d42b5bbcd40a8100b20a3e146de13a30454f654d53254ab4c547829e9352093f4c7fe79824b4896dcf7756cc70913e21a88f36a002eec43692e8d938874ad39c8141ce75562f11353ac9c3716715b72e89ef395660cc5dbf6d1074f9245e8eb3078ddcbbd03fe6630c157ba5c5462666dc49398921dfee5246d81b9484c7492fe58be8e798c18a194ef459282420b214bd145b77f5ecbbf4cb008dcc3f900480226fc65b6a59824fc19b4c482192e99c0b798352127718bd7bf50ac11e932e081cc133b8d7d47b7c44ba8ce6c5384ef9ee0a7bbfa4c34e19f7cf7a4ac7ec27b61785949d6daf87fa157fd67e296f0e6ec44405a247db9813079c09977d9afad075caaa41b91252ff9b969dab6da3ae4ce576754ee9e60e1e2ad9ac881b59d8305d1f3197b3eb1a1ff7c3e6d5302a3967ff1985ecccb1526034347ac5bf1bd5c8a740ba82f1a5a8f52ee9e78b17334404b8fe9594ff182d8a4bd17ad7adb2eff7f7f50e9184162991c26468aa70d2fbbfa9e83d590a43a28b865d409847c533cee630795f46f15ac802a10974c5ef9bbbec0363e768200ee7b1a21f4479c99a63fef8b3f4e5c232e1dc2be04bf06e695635ff1b448001faf5c62f641d50a9bf534692fc4d082fe1ff98199468624b21cb27a91067d5de6b36d9f81a06c8383aba3c4fedafec377725b811e05bd2b1d5dad7258495a9ed9e0b17254222930a13e8d1b25509b5fb5d940742802d8b46c6ea76ee91525b366c2fe5bd2cd20dab6d8d6a84ee53b5ce65ea71124dd6a0c0015c58b1c55e7f0f53bd0cfd9ad0360693c8f9cbeae6fd3dc56c6188e741d0155e44c9529a359606b1d6eaecfd7774ba762de718f6a096e188fb7d9b3a6f3d19e57c63f3a2d197dd6433a73e42df6ab385b32dbdd31e2e2f8cbc344c20606239c96ff1fe30e5ae4a76324bb9268e9dde07c496dbec9e95c955d2c06ca48381b8a6577296c7f5e745f72889abe52c68caf750fda30cf3582b012f4c8373f65f28a4f42a4a30dc91738eda685bdf21f238293c6e1f4519d98efc92c55c428652f2d912524da63576d2d858c21717dea912cd86c5d402d9a8d9175b4bdb61039cfe81ea3982641afacc6945e271732fa714f1d56045a721d770b212b18f6ee4d3b798af9d7a3b2ba51d86a82de9c7a48fc1580884cb8c77a32b43f142dc96dbad19ffc3f6bfdd99950dd20ab9f49e9e04e5df3d9afc568d1243a7d1134085ee7ec499a55e50e2e217663e5a2e44e1a14b05743572aa7caa4b581b0692578be4d94ccf922aef04b14dc7112091c5c0ca4087f63fcce6c141020cbb5f192e155a19111326c4933443ba379e856d9e05ba6f4f57f50258e3ea21a07178af305783ac22d6157bb1f55d20b6dcafdab3e40b4db129956c9eb494c6df7ae74fcd551f72cc6b2c60b2385730b161866e4054162aa3c3b997521c584eb3ee6d8f1b4480fa50618c14a6c45356b0d9e8e078645d74ec1a024ace1f2d68550077e5a75e2c4604a88a4d8f5d0ee2b1b177ab019b5ffb51cb299adb8bccdaba1203f0e2f5adeab243a5447ecd5a2072440041a5c7473ec58e95deee46df5b8d912bf6563528904c98ff42d893dfd8285bc96f7817698a9d28dd8a97d2d6cd3f1c8555826279d7940342a9d87181b043ddb5f7b37c4e3d7e4751879f8ab3ab7abd5b894a8b527f8114c6a608738734cad9441ad1f607b1152dfc91a37ae6abe6dc9d834506d61dd123c28ba957ae636d3927c280c596e4a1ed6d06cdb0188010079d33176d93563419f97f33fc019fae36aebecaaa1ae2933580e17afd2413dc484d71d17334ca072472a18671e2a7eda528822c44baff7a322f044f3318b78ccbdaca129a095bcf3ec0d1ca1c367aed353ff1aaa0022ee0bf902516a24ac07aca24ced5143d4537065e4651548a19de7917340c8d35f76f833c637ad0aed085a593b842b5854b97455b47f1bf44a2d050288fe0b5a5f88f342347948458671fd49c83b297111086b2026c5d6b2764f2abbb4e67261ae3340408fdf6d0f22a7df4d4da1186b7cf35198598b41516ee02e268cd14a3fb013c26afa25530ee310bdcdc805a3d76ee116ba74f752934c30eeec57a8b6c2f928729daad32fe3f3e955452ad58c917c5898d08b1a44786c85a23025b54eae72d1939d32ef8872a5dd3ed66c844e9412c5db80c6cc6e821ec23e1e058e9b90b7f5d5ff9e265695c82a7aa53cf7e5637d2fb7aa7a67d919db926b73a4a29ea0f2540dd148ffeec39b2d0a93b66524d030d62500adc24fd59f6016e9ecd4762cc004eb0a4392edf2cea8cf349b2ddcd4970ce0578cb7a5935fac44709328147dfde8a8a7fb7caf296406c7e521daaa38d3c299928c6818fa3b70c3df54b2e68677db779ccbd85907d37fbd65b97b660ecd7ebaf1a13d934966ff0380916673c1722539eafecc411b0f70cfbd7ec7b6e46ad59d7cc46851f73c691d08b59c22594ed58cc30b7d0072fde2963c43bee5d8f6f29c2d268c2a3f483bb53d3ab9350d24d6e2105954cc8e8acdd74542170b61faf2773e95e78a02befcf2067a32f5fe5e6a5d6d9b6236f976102cf2b169122750e0292dff84b5f7be0e80a4793af3786a529c2d78176ac02df35294b16a033c75382c9e449e5a6decbe2a7ae7f70638a9e89efd2c85a83d6eb123452348835c83f1b908dad28f9478dc9f2fbb66ca14b8ea5fc9cfd823d2c7e8075e3a6b6db6abaf917b024a776fbf2c5d207befc7893e62301787e8436da58e718885ae1edd1d32d94c5a671cceb4f63639ad5e0040c634ffdc152d27bc57be3b6d0cbd7be3c2e15aca7b8c93173d08a07a2e4d98523e528e30688cce0d0b73a04f3b1330fbf1257dd6e685c7a623f0a6f27deb929e4d5253656ceed03a109c537edd849851b9e98dfd2d8fda4fa00f884040f6d78d04f8ecac98e3d7686c075b9000920a13782db5a16cc4d4c4d1dcd391a890e2c3b7c5331af12ce312e6f7bda29304dcd1edc8ef478c5e11de2eaf8378abc34e5968be2a52f11011618a51acf6de6707975b03b1235fef8e5db61ed237009a55ddbb1c7064a8bc41b2ab450b2e6c97cce23add97cf7c6e4faf492f8c63853193e5eca8e5fffe600eb415f5fe17d89464c55e7a9ab694d04bdaa9e449529d6d46dde7bb4fed1560d1cb04596fc705954e5dd2230e3b385bfbc2fd5ef5ccbd5294ea5e5f2eefa0d00d8620f9baef135963e96980a4d8f3eda4c4ac32efc947e9d10fbffd1ffb097efc56720db1dd489be715a85c32158d794b4413a8fb61803292aacf5418e8565848ef2b438ddea13a464a29679fad20e839e846c1d22e6c89b7a6fe5a7ba5d30e75b5d9616d4e9b7f722f7eace678be28d29127b091d0db4de19491e4d8c9412bec0ad8391facfd3bc120bbfc9ccae8108c534df85d05c70169fc21e770b5f425ddb5f9e2aab2ff7fde88e0450db70b4dfd69aabd4392a6309fff8f7e80df9d48efd4df4650e348dfacb1d26fe632ba2469755e11d165c180b1a0d3873e21f3aad8895ab5cbb01972140a08776fcb4afee6b236902eba62ddc1fe0802ff12ebfa30606b9847843a99a810ba98d7aa3e77106412f5e9e7b342c888850f5c3c7bd7f60e3925ea17a0693664bb412d1db3e1b3d938ef70d821fff51de78280fe023ba3988d63ec00009a3c7a5db73faac4c92e866f5230dc59b79fd4f905da5b9406daee7276442ea25a330890ab39f4906087c32fcf266d168b7c93cab7625eaa6d68b02f0c15e5bf6433ba1b528f1ddbcea82b6c48733257ed797d5e3b6b0f0dc2d42e39e8d1897e5ad601aa7c464a1b48112328e5eea3ae646f3bc1d902645c264ec55abd1a6ea1eab92f1972ab329a5e7cb3870cb74611612a44d981177b177fd8bb914cab7898d8c996f20d791ad32ea751dc8f690367b483e8e3e14b9a8b5eb3ad255108dcdd7d09abd032d0b4b5a6957e46972b634fe5331a48e3cbb16500c3a16518dd9122e89acb85a0385a2a9b505ea372555865ccea8918eefbd35c15f66332315f6fa86fc862e3189f76fd4f8c8ff6986594a6555fd461b357807ce87755af7f6fd0bddb0fac1732a7df049d6fa68bcbfa504a87125d748afaa30c4541b72d8ec1f3f9c4185d97018656d460032eba586ef1f9aae2a59717ca7e15fe81c72da8d597f7b541b1b0f395ed93d88bcc1f3c30309993416e1e34c83feccfbd80a50b7ab4b68fb9c87e8d4a207b9eb432d4185a43e74071b726cb3d10bca8ba82deddf728f40cb267f9b71181705bf32768c164762b62823b50e083560fb5107a3b8d25ce3c29dc126e07aa6fa87eb483008aa931bcb9c77381b57a2b9bf15bb1ea711c559a5b380baaa7313a5c48b45742fa47763a0dfa5d9f9b02c4e1cbebd6ad83fab483edbce34b5c6e04123b8bd6796ef02b1b0c39780fb613b498a9b917f276c95ce666aec78ea2ad177fb1ce1dcd624d37e30f8fbdc8683533abcad5fcecdca7d536b6a25b20050e9807b8782ef97abc926f0fca63d3a18b56124309e6b7a2af512b259bcf134fdbbd2ff8809e7fa82fefd755783fa8f76d8ab4a003fe4350f9eaef76166d5d8fc93fa3911b1f9027110674aa282656e6a755a698aee8fb07a0d13d53704dee26d428891a28dd4b5cffcf9e9ec3cc7863cd61f3136c0f950ffe5f88402d5100f44752e0a53324872cccee664d830d04db73cd283a4caf6121522da8fddcd23c5f19e5742b87966adb2b8f1d20ff20e443e81720151a0bb6ebe9057758ccdc87bec5e9bfa9cd3cb40f52e625610effc742d27498c1b7cdacd9c658dae27afc7ddab2cbf1dc5cf6190e0dd330d3b5f526bf519f10d2014dba23a4fe96f60a5aac7b626a782d208c7c4f3e27069ea1d04f7d5d0a1ed1a812a47322a403e886991b4402980c95a86523a473843bfdddba960b662662fc300eab9ec9fcc4acb996c0860e68aa9510bc52dbda992d3567331287ec3bae6715f3d16898228de8bf0dc27b04d329d08b2381db9a183c306cf09d1573caa14e1fbbccbb5b9d8c0476e9979b7826c97d2e70b4d8367e36a9b0c28fea6ea749fd77e493131d6f3b877ea3efdfebdfa0678ef13c752f563d798bfadf0bf6ec8a61e8baf84050ff552f39cba0525d442d4b83d443a8c23af1bf0086efd46018ee6455454c79db3e780f6f31c7f5db7e067855e6b21af6e09c75ad327e7edfdfdb85d7fb51fa5dd75ddd6913d54019b75d2f504b3e5b8cbbc041b8485f8be1a8e6a0a5d4b9265e8b82a7c11afa796438c7130df3d9db80383d05ddc41604976aab152751280ce9469385db841e94f163ecc7455a46f80d82c7af1a4ed9fd21ac78715b19bc6f8f84ce73f36e660fb078a61b1d2f418314aeea4fdcc1222497448549383f83d11589fa9b6486a06bdb0b580780fdfc516537480463b839dcc9fb14c4b18b480a3cc431066291078b7473de0290058798cc8bcfdb43e24f47ee36266c98415848e9fda0cb248507655816726e244c9e5574840e10d4b4c036937f800dea36e65d6964f6985f463fe74e3a4f79896144fc5e14a29b1642685ac3f06ecdce63afd6e69d5fb6144334c3f076b2db71018ad5df2cd67f678a6eae144a5f6507dac782f2c30ae2430e6248b7383d2ca575a06ec9ee0e9bc5c552de334bf4327020b3b8d2225f229aaaba48b9b72c2223f496a385eba8a98027322732a5ca1efd56cddcef35a0c7977c79e4deab9b8b1945902d9bc345172d6aba5d11d28bbbd2c252aac7f4893c885bd68ddbcab26eb760ab269149d1e3a68cb5de77208e75a12d2491d22e2b15b243723f2aa8b4fac6aac922d144f59e0ac086ede43762cbd15d51b7590d8d949ac5d0ea2e6b4f048da54f31712d1d7a13722a7e76fdabc59e24f65cba5c4d018c37e70a5cb72391b08d82080b13c46d801d15ce260e5cdc199b3231a0371b4e4d2974728ab920d4f65b3066727f784d8031648b19bc3247dba6d34b2cb17103e413cf8ee3f5930dc19039468bebe8227f1eb42193a535a8388758b870f8864d6d8e72f61fbeecc3394cbf3bad61a64038884637603d8739b2c6dc4724cc7eb67bc455a7a57539fae947f8cb69da1bb76731ca9d2440d6f502940b73c9f1b77486351159df5ee9d9e3d2d7749937eb252508e4304e9a98bbbf6e21509643b5247302d9e4ed3f74874a8b7556809a8b4aa763842d7f81c9872046d7fc50474ee289e29bc5128d85e4bc7cf586149349aae27076330e308da07f89528ded6a2103aa1120d862705a154b0f302ddf5012432de3c6e8c3a9966c04cd4cadca34b769f1e3f0e2b0d62c10adfc2df4d509615b8d8810f6f12a90c705faa8c17424ce81960c1922fa51ef6e49487738630703698c19c6e4cca8fb72f6ecf3e21cd3791eb3c558890a6b166b4f30d2274b9b978e44c10b5b5b2ad6cef714840cb6ccce273029620836a8d80c152bab09a2ffd39f17eb7459fead45b00ea7fca960b23736be59d4ec4ce69ce447f64c2fa03689636ff014580eabc16fde9bbdb23b7bedf56956bfc536cb517207de6bd5157734cecf561ad69671a9aee32049f595044c86fe6f6ab40c124179221b7c9c3da2491303b7fd40d216e366be05f5f70b6c609956020feba820cbe865903578ba47dd39bcb127feba12b950ae145d761bd7f7064c7ee94da82fe01bea54965a6a29546cc8cda179010910f964f1f860c5ea4ce1c8c5ed49d9ab344578ed51cc70426f31ce5d34538dcf9578b6695f5fcbc8ec75196327fe21c016cc94f0bb1c65bb4969631d779155c3d3c026b6d5f33a9286e20f2ca4606336d888d9dfa4f4dc4be9ed6b9f82bedea156613be1a472e41d1cb4eb7e9d73946aa22d83cab340c8d2833eb09c47c410413170a15c72eaea11cc2ed1b39c25edac9ef1567aa04aa3bbd23efa84ba5728c6099f00ad132f507bf43252d8a3ff40c490642c77abac408fe192511566a3926bab3c99e35a86b91d9ce204a7f98b79e24da45f46e2dcb85b04c8f1951fa799d646313bda7d65a5f2285af9e1a532bd11a0e8f2d8a8df166a81b6c7ee3060440c610ea9303f9b81ad3e2308ddd1fdab75a2a0dd4b7bb3f9cc511217a7d7662f52fbc59b162d94a43153fbc8c7c70c5e9ec39e7b977a462457a78ec6f6fabc40bd0a92fc9cb8405ab51ae3f54e92562751e3a94817c6f1ca680d7a7af9e589bae5aea51ead20af826291fbd9b8872cb9b378c5dfe51df72612365766aeeec4436d838062162ca950a1700065cc5080ba4b3190ce66c29e287ed354615f17ba5a0c3df9c9ae9b4644fc82966c14a5f3d0770002399b9f2e575e47f8bb78ad2a11cb49e7c06f9e2e7f45201b6f6cb63f5b0563da68972a0521bb3703ef1e21b6fff3173be6b125c87197d4bf164ec7427a68c345e31fc5521bbe45832ff8fd9016debd607f236a954541e6876a37244d6f9ba134eafc74f8f944b4c33871850ce4e067507789ce0f486259808b834dba4db22d3e9e4be8b7226ac06966fc6bf8e04db627dd239b15ab7d38d7a2f79aecbc4cc9933a5eea92dd551bfcfb30420a0310125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a01000000000000057700000b47d1e0e34666cb060a677f8719464af6c948f4b73ea863f6dff0a6d040eff4c809bb7074f6ee5ed0754601941aded3c7cbee9c3963bdf9dddeee9d756e2dc9b2b5023cfb4719e4281fb35c69022252dddf2a138033f3f25981a63c4ab0b6dd1cd83a160014f5f67358a0c64ff9336be2e316f99b04b548521d00000000000000000000000043010001af793a323c66071330d9ecebba1e46523d4f52d93c537f19f18f1efeca4a7a61e4429f90f6682dccf3ea471cb8d17dca8cc5f3e679a7f8bdac1014ec73d70772fd4d0b60230000000000000001ef2c0079b29c3eee5c43db74a3af11d0f9422dca2d30e0f09bc80c48d920b7821d24f0fcb0d669e0234f433a17b1b71c7d48f7b01194c652e910c0f853e6278fd47221506f8c9127b4e125a16b4af7d556c38ff5d0d42ff31dd89ca9eca48b9ad252893673c8a3d2f19a0ed32515d01f9b9c61e32bfc4609aadb5ba275eac1b0e783da8e489bcf9883c8280909d574e43f63e84d3262f1d0e21bcd814ce3151f8d5b76a00b3d429adbd3061eb3f6fc1e9b3a80ad4d5863a6be96b858b77481bfb4186eb2ca4e5a296a6c05eb8ab94e54c20e563714818bc43d177017d473e830396b501034330d3d14c3a97667822a33c75057641390eba81170b5111088a28b07bb873fc7753ff57c816b65376bc6635f2711cd02bcbfe9663930fe02c79d402f1ea24ede996e57ef9e92a9e45f2e7c3d286e9655c49c6268a7e49ab5d00badfe6ad69310768de3e2f73fa3265f12e6cad8e1375bfc99bc01df938d047ee2eb52c8b5c948f507aeeecc09ba90dbbc381ef0a3063d8fe0ca17213449ab72349e13a8562d0b45a37a49567940f7cd51e0c581ecb3ed087db145b51c7f006a326e1c9249ecf2a02632ce4ae98a414149a727cb07d050cefd3aba4707be13ab835fdcc583bb7983e5d9f09c2d6d976f3d80810d27cffe83b2bae0e512f72e21db7e893990c91ffb62efe819c0838854ddb1d195a07ba8cbe48d38c1298d3c8df4b04da6213640f775df8cbd29d8220852e6aa219387bd397a2e18469a82ed405b3894397bf68ca2831f8b6aa6adc8db13a27c2d559cc0d54c062e419dfe963087ed0b668e4b5364ee8db90da4b2d9a7639af2a911497195b295b9088a948d9941c9f8d4609d8df025a2f6780ed9211b60f506ef947f5aa76f65f7b142968dba7b4562833dce294e0beae2e4aba4ee3b1f2c9a94c0c372b0ce9a00b6f07fd84c6cd30982474bb4c6af49d6ac94025941aadde4e5bfe5c71abf2808935dd0133a07e5221f3ae1ad30e71fa380344d59c866432a02fb340bc9722b7c3a7ae0cc2970e20e4e189932af6e7d4b6ce53d9f87010cbb8b4ccaa4a4347ab86877ef46ea41d301d84b302474ca88a4335aefb2a0e6a12e49d595849d6618cf8bf71a35ec1177daa64c35eb85a5146df1f2eb4fb73ef3c00d59babaaafc3ab03013b34d621fc21d0278053ae670e5d9754bcf3b41d97d831638bb6a2ab9a1a84ab07f4ddf15e7351213fa69976ac03d91baa70a82e220bba424b8f928aed25a3f5620fc613a5ea26e05310bd91a457fbee9b2c7b7ad4486142835744aa54a8a1f69a212bf08e674fcd8b32ae3b717d060a79ece7560887bd551823d606d1a765d2dbc6e79b89696e405a7c18d20c4e3764cd2656afd03277e909db8ab081b9ee94b5ba94bbe4adbc085b66ee7bd66c22ace3117699732793de06e86ea3d704e586a17b36a6b1a131bd59b781f977f68d83f1063082a56333486c6bd94197df7f9f07e502f7e4bdd884b10f1ce1449846edae93cb9ff46eb46dffa0e91764da28769539e66312a68dc9fd2f6f1048fd08562823286af7921a3824f80aafc73c432add2f5ecdbbe86fc9b0d12e8e7cb09355942488df3ae6eeef402415f0338ebe25ff85772ec4d433d2c2839b828a5840ce96d427ff1258d946abe2ea5097a0de51f5af65894490840afb8d547fe9ca3e9eb9841df5c960b8941a24c8fedf2a362a23f560d44df7b03fb76335986611eec595adeaa0f17c960d8cb5e8089d85ce7dd0d93bf28d799b1753d12e11139d818b4cbed4b3aa824628748f4ba1c41fc66f203b550cb1874e1027353bc3da1860d1c922bb8d36d6006175ce54f77753419d023695d3ab4a09f94f67f2eee1a8d7a32b4fa87f4b95059ccc9b14fc62760574d665034eda941eb8c91236649c2a07a49841c596de2399a1b0d63c8f329ddff3b9b206b9d6f49d93c5c6611a3b1a26ee81a39f11893a16831b66449c5c6eefe5e84389432b1f761fa01c7313d8e0e9295f5636ce923e4ee65c63add48629d4e2ce37aa624f08195915843bec3d2d1df65980327aa037f3ab0640459c31daed12e5f77c339935071f91444785ce794ed693732b61fa40ea06d06423377383e5b8d68e6da158374f56e1635433650589d087fa89a3e11596a459110a4b0066ec4e7313f1ea82d3f15a406f8fad98b206fe42ce1763dde2668fe042ab6017acd9a22af72e2429c91d2b10117d8ac74f760f0af3990d5df3d02b0e1a76a267a5d66eb22aea8a24e129f78c2cf740fb25f708020a9e8b6f1cb2e79eaae1caf1061f476c739f75d20d1b4f85adec92356154bd23bfb4c9ab5591d8e57e478ae051f50ca9ae0b88463f4c83ce7575bfa14c9a1d0191225e58cd05ca6523149642a46879ebbdc4c1d4b2de4642569b5b5fbc12160e22975c33ec0ed34f90be9a8f8a559b211073a01d86d8f66eaa1ba0b1718daaca0d70725daf1c4ff58177c70fe76edbabf5dc169be1e1cc448b2cc9b50edd1a9a9cc692e6f250abc8e4c171fa753b0e67267eceb23385266c0065496940d23d97ce0edfe5c1d05f01688997fdd5fe36911cd4e137d230c064cf33fa24d487cc9518f0162c39d3c6d5941d54cdf5028053f23bef5878adbd6b5a257f31704720b551ccba2de3371602bdf28544982e649bd9c73fb95505df494cec5e5bb011a8787bb723afc81a2451cd12dff728f07452a2a82c1e9200fbe5f0469384dd461b7906a1cde7398438021643c2c567988a0857be046232e79275a6cf7997945c1c78a644048cc1e7b9c1ccc84a82a30cb49e88a5938669a1e6b752d61d4e1b7d651c089f3ba1c85e93a9a426bd4c18b48f4b955717b711f5d81435bcf7dabe38ffbcffd28f763389bd152556cb8c30f6b481670780fb977769dcc683e3c0b6fbfbe454faaf766e5989c810d760fe67587a44d7c0ae180972ba1ed446776b883df4c8e163e02a76fb68b8c94bce88593910580df0d884d0daedf4c2fef6c319f4a1af5d650ce1c8cf48b38aaf1a4f1b999de83611140ff273a8bee89179a9fe72391d5c2130f4b014310c762dc932c653a1c0f8a8a70b850c8220ed34d060e037a4f03a84434a96a310b2648030b733cf7e2731e2460e4108d6701ccb5989a1c8525902e5dab2fcdbf4ce8b07a74fa962a80581aced34bc19fa7ce1c11a71231ba7cc8c8fd2eedff3c1f8a6f4a68f461891633287019fd77027250937328b83853392f03ae5c61d78fd0ad7cb1dce8ed7089ced4a1a5aa4ecbd8eb25c018955a2954fda4c1066067b9e54b37df5c355aca13c1d975f48b29ca53bd9b45f56d2920d87cc279b99d1c3c30fe292b5f2ca8fe992ece94e8c24270bef761015d7089f3d70f2fe01881e545d6778b88f832af41f9baf517b1f8e92bccb7ea31b8eb776c92300c6c804889c228887788333dfe4a72e973050aa42fc673ae2eab74678c1d8bce8859a67d61d9024230fde34a1acd8d207fff51fa7feb6f49eeb540d3dd16f9eee8e016f38b6ad319ce088726d25621bfb25e2885227825dde7e774dae022b3132933299286edbce2ddcad9ecc4a8f5a05e36f2d4390efe124249a0ab4b244d8e4e7dfa710e5834d757944d87198aaa1225b097c744b330c03a35084751a071c2c5e48d63699634643b63bb199bd6918734fd0cab3953da3f992e7047dd7f52d59c2e41707d4302c07731bb4fec4ddc1299e504e55dc0575b41701fd24ee8fec2802e24c02c56e262bdd10d15d7123133931e07b6217995c77b30d51741bca24ad003537c40ad531ec2c7b1e5cc2c996dfb0b7f4c563389127cfbe9420cdf9e6a95627708efe500b0ed30fc009f3343bcd0761c4a023b63ca44e0ee24ac131f3390676b002e971d9a4ae5dcab1cbb6792969a77dd51da3945ef34af6eb22152ab73787ba38b6d0b32b3509275c4178d2960dfd6ce69e7eee7111c756cb106a69a43d2b450bfe8d1f0b5c1f4a1a48804e6b59172a3a3d7725946e366a9973f19ad575c50cf466d6da56ede13ddc73c16332568887f5b6a5d79c4684a33af42eb09808531d3792b4ac73dfedf7077f84c706ec99f1675a1e5';

  const signUtxoList = [
    {
      txid: '3be2f83de7771aa76b0d5c4a2c99d1e05a4ed90ad9bb753e24f2b71fd1a56ae4',
      vout: 0,
      bip32Path: 'm/44\'/1776\'/1\'/0/12',
      amount: 1000010000,
      // valueCommitment: '09606bfea1ac0b8e59dac55d9ef37e6f43cca14794224f14207f854aa924fb8a77',
      descriptor: '',
    },
  ];

  const mainchainNwType = (networkType === 'liquidv1') ? 'mainnet' : 'regtest';
  const liquidLib = new LedgerLiquidWrapper(networkType);
  const connRet = await liquidLib.connect(0, '');
  if (!connRet.success) {
    console.log('connection failed. ', connRet);
    return '';
  }
  const pubkeyInfo1 = await liquidLib.getWalletPublicKey(
      signUtxoList[0].bip32Path);
  if (!pubkeyInfo1.success) {
    console.log('connection failed. ', connRet);
    await liquidLib.disconnect();
    return '';
  }
  signUtxoList[0].descriptor = `wpkh(${pubkeyInfo1.publicKey})`;

  console.log('signUtxoList:', signUtxoList);
  const tx = await execSign(liquidLib, txHex, signUtxoList, '');
  console.log('*** signed tx hex ***\n', tx);
  if (dumpTx && tx) {
    const decSignedTx = cfdjs.ElementsDecodeRawTransaction({
      hex: tx, network: networkType,
      mainchainNetwork: mainchainNwType});
    console.log('*** Signed Tx ***\n', JSON.stringify(decSignedTx, null, '  '));
  }
  await liquidLib.disconnect();
}

async function execPeggedTest2maxMiddle() {
  const txHex = '020000000101a38845c1a19b389f27217b91e2120273b447db3e595bba628f0be833f301a24a0000000000ffffffff030b33ee5dc5cebfcf70ffdb2957db56a111f60423806707d5734797b632f5264da909bb7074f6ee5ed0754601941aded3c7cbee9c3963bdf9dddeee9d756e2dc9b2b50299ab95f0094422481af5a03e0fbecd68fb9c02ffcccee12629e4b084b42c242b160014f5f67358a0c64ff9336be2e316f99b04b548521d0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a01000000003b9aca0000fd62206a2006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f1976a914844d3afb2081df687e6c0a83d2a5e0925c4fa01f88ac2102f6e02ce0c684096337672d7d72bc33c5129f9079c50447452aa7139ef3632f4e4d0120ff1f6812267a5600bb08104520b0c63003b7f674c2395a586ba052fcb5fb4346902a8d7f1014f920b8011119bdff1a1159c566b0961d4475e054aeb5bed098c023fd260ef73f838eb0f2794b86ac71cebb12882425be4c5ba7a145bcbff637aa4bbe26c53d486e4d4520b0a17a353a3fa758c080a2bb7cbc04d9bea4189487b80bf31aa26874035a8e6f5a7f7d1b414abb5da9adae630f2760505919954787a4fac4f58ac65b7706bd3828e09cff6881092024a69b844d9d74222d1cd902a3d699137c28456874e187f885364c1976e1ecff4363369fa2e3176f1b03130ff0164c809f3ec74729a4c26a5f2da3f202055e17d79c588e88c324181b2f022a1eaee47aada011176ebfa40d24d1158d2c2a214a61ddbafbf7894b21f1f17e6d64abb6ba5309b3de48a66782ba73dda0d5bf8e59323be2980e1078ef3925eb360a919bb3bbcd7d36d4f00b986f946cc30e0db1b3a4ee2178a517396ad12f4418c40e7579918c5a8bf4ae4e0ab1b4a748f7750cfd7fc86d92d699daff5777bf3d6278b525617196cd076538349043616d212918a02b1792b5932e3741b322c90e099db3976fda408999cb57a66b41e9e6efc158edd8ae95dabe77139f5f79c4cf6813e886d549aca9b372defcfbcfd0e5294b2a4efeb83e50d13869894188664df8b541b41bab6c58b36e003c64cdd1cb57dcc990344f2f37e37af28eb8b0888d86411eba1082069763f128c418d441a5266cb5aeb76d46671cf6f4a56f507af483b58f32223705e0e72b29398304b366296f51159143b56de93d4dfdfe5be186ae141ec4612d0ca1beee085622b78b9a91cc87abb49adab9609b34ebc9aa4447ee4c23d0db1fcccc97040cf06e38e4d1bb3d40e01465b1128a96a8a4f81fe96027d6225d1fd77af39bae6a5e63ab5b2588a23c45ce62012e8c808d659b5435de4cd7ff923146e41f5872a19beda531781973e03112fe5f7a4b4b65416540558a8a6b2c5e3ca6404e2887786aedc99f8b3b4bbe43890257cb6b4ae9779860efba82e30a270bb6d901427e1ac82e49e0dc7acb86b19e3922ac107143570e79c6b25a2234b13898e9e2b832af2bbe80a8065a2503994334b2b21d9a8043904cb5be8a0b5797715c8ddafb16df902f6c180625561a5ce187d5a266dd9198705c74892c59aab9eedfe168fec60b4faccef6c5dccc7bf42e5a6daca9453a969bb7ec9802e2511ff14f762db959611a4e9c433c8fec5caf73bd558ceee719318233adc5cd84b1c16c728da5480663b6d3df66c3b0fc6fe740147b00bc8a258142e23a3be5734883812e8ad0f79b58c3e1498b2e9c53a988ccf0d64af068f5e70d3033f8e4ae8ac9aa6cfd4183ddc521563685f8169dc087b2ff9e5f0fa73e718dcf79a0b10604d68038666045ea1d5b355136b2c7c8971b71377f0cb25173db3ba0d2c2c76ba5fb3ddc49c7463ed7947b700d589101a73ec8d4a5f34596fcfca5d8c251fd1f9783f84c67ba5fc8fb95fb97c6e2943455509fa9be9cb3cded7da368a9a8cbaf010c4b2cf3972726bc6163d5c90b84f8e19d11ad53f18284b1d046af68bc6f59ecd274eb6e50d3e00c315f961a3be955671326f675e77bebc348b6fad79d57f5a92cf2eda5be4f501e257d682f09f23ebc26b09d76e9df0faa13f1c0822351fc75e369c70890140a4b327e4fb7abec69ba38b4481bfa4cb727be160f197691f99a3f78e28a5f246ccadccda060cec40a1bc6004839d24bee98052a8c11cacf7727e09fb200f8fb4fd46dc755e6b9b3cc692c7fde3e6ed27a37ba8e7789eddb6e53a0c6b1b079ed41854bdd24d085c0ede394e8b70012f007fa580240af5622f4cf0a9159bb95c4bf2579a848f4f6bff179d5b4d3aabc481042391d139009f225597e557aeececc239dc1630b7249e48c6e98db8f835fbb3998fa7c81354a9b7187cafec62d1b1fd4aa0a03d3511f329f52292bb185829fe746512d68241e0ec5a0c5da33f4bedc577287fc2ede49607967d0f848d6c1611a2aaed70fe2689d0867b7c5526e53875642f567c3f102727c40c1ea4503297643299cd4a408bb07a17482b5911badb790d7fe9df62ad277d97e553d2f0f94dbf2e3fe34699cc8c39c0ffd77c17fbcc1f3c36c01b32465e917e033cf5856b42446840076dee08cd53447c9d96198201e91a02b893a5dab11fd2ee16a2161f86297d2290f5a0ba0e8d104fda4e73aac4011c8c0ffad3a15aa7be0c972f3dc1798316ba19e88be4cf4296ad634d377d0396aa93b8395529b70f3ab702647fdf69abdad61647272f02b8cf0406a06695fa1902409b59b1dba5c338df9c490e101283d7c25ece7cc8e9f7c2cb3eaf2a6d11e6a2415014b21d4f23b97ac12e8167bbc4c7d1827d9d66cd849fdbc53282f150562d56807b4da70ce32c3d436695adfba9ea1384014820a1758779701fbf8cd5bdf87267ce3b270112bce22a35eb080c4f7393a5e435e88d2b0d2e43085b698e00def8de76fddf1896b34cf1fc79e42266fe1412b1b168b4e81b8eeb9013e948576c2cf9ac2ee97aa1b85a6cd4f2205037ea3e7badece9bcc6e4271f5d7624f704c5e488391e215e4152d15f026417d3e73873ee641a534c4517caebe8f43e37892672d2944dc7ad5d0eaa98037a8a639a55f957dc0faae4689aff8d62f3da4eb3bca4ef75189699af1bf78a1b1d04a771db5a2944204d1ac88948721e902eef0dc43a2c3b95250a24444ae26b9c8c1c870c406757cb327bfe540b171c9f860a27d7321f117a246e83acdaa3de623fba9099f36384f359ca24535c01278b732b6e5d3eb5a3d755d909931b8e2589b1d30d29e48d3023c18e7dd2d06b4119cda61c0145eab406ebe82d10570ccb649acfc0d325f93257ce550695b8c9706c6c1da45e6fe874f91dae5a31389a9d760cc45895ec7e6b69fcc27023890368b298cf0299ccac7cc61f968f4bfda6965620122e9dc13e23611345dc79fd5e569ccc9093741645c6894b51d1b47ee221bcc5ed2834a9240277ec433a4ede0277374b404e8b42ab41b0c8a69a64a1ab8a68e5e5c140751e9e7612f734cfda02d29a55288a876b5f096cef17de0d26e47d2903015cc4690027364eb71ba9e76494a7042f3cbff3225ee7573e12c34f174baae7bf5fafc6c33f3c03b0682ec3a42ac83066c46aae508a4a0d26b136fb3c27fbfd5aefd74a0688d31f2aa93a3fcd167b24b70d4333643d7bdcd429bc8aaaf7507f718942a792d3a935a6f5308951863cda2ab153ad7b2fe384825d9171c56a5271013d4e6cb5cc94633aa8ea04798ed9a7d67ef073dd76afaae41ed2f8b16c079173be55e808e5a3d89a9770803f4472cdf9092ac01faa37005b6ccd2aad94e0e4f9b9a7c781715555be587e72217a8d1d1c84679dd588eef33ca318188910d0224f7ae59caf096832026fdaff10ee6176dd5c5f6d68fee475fcb1bc7a8ad71e5073769a9bb7bb21bf1ed286af2f9445da4ad01ab3a48cb8e8a5f16f7b90f4f57843fc1df96e17c607b86b2b55ca01c631f5c02deae467e711e1482b37d931f45ef16ead06cf9d99e64c9992a660e8441d11e4366a22c20926591947f9cb6c78e5b3aafb6d2f2d489fa4ceeff1ee96a9a313341696e26cb17b787f51ae9336c2b4ddcb4210317cb770adcffd7d021541a8c6619b0da72402898dd993472836663c6857f01b7b60bd9ce90c22727e1f8714063950211a8c7c1bd63f21a8615765d9955c6e0bf02de8b4e9729ab94fffca94b3c4bb161452f4ce6574a8a5bafc26ca3b2b3ddb5ec2d3df53d3c45cdf74975abae5558b381f93945b3e97ca8808d88f24e6fe21b12e7ab5ee9bac0b20fe463e5052418aa7c24f788bc3b0c50976b9450de9dc5614e25ca92f548e39ce38f3e9c2e952b8fbcaa47963f4cb01ec70548913414644ad022b9a52d40989ea811d3ec347562a2dba729f1b4990d1e1e4bdc9bce55c3f557d6b20b7cdb188a1470cf81136e6f5dd9b48ff56778aca4c2a06a90049eb6b26a880b68f60e340612211a87f80787f856dade8b424d88e2a809d44383b445fab9d621e31942a7e0af3e682bcf746bef52c2d14209bf6d949b4cc9f8898121f391716efc00cc52cfce79a5817cb4c6bfcbfb0961a0e6d303a25cf79bcc8c48abb9da34927026188d4dca6d9c26f1cbd1a09f528b2306a74fd1d25adf81d82acf7145609f00d8c54367eea31a7234a361cd72bdd47ebcf42d2a2a2abda30aeb947a5d6b6dafab66cd8609a2b197305b9cecc4abdb8d440e205c39945d638a58a2775906594ae44e312099da10e9b3a195f3fe58092cc56496fbf5e63db189e09ab5af121ec6dc5ff543009fc0586302ae93051bc33c217b77eadbb88a35475c5e1f920e48975333795bb78a1bba441cbac919635fcc3792989c693aae0caab9558a872e33a717688ec915437e46c62a0f80888bf5cbd8f67e6a5933373f50fa3bf841f1579439df9737ac623ce07de3011cdce16a1deae5a460354d611adf4fdc0b5dce7661477eb53498233fc83dd6333f6b4986ebdf407c4b960c5c972b31933973729a0b69b10d734f58387b1fc5737e17903ccaf8fcc65fa48282d91a01765602d243de7a8b8fd44458d74ce7e1da153f7d95861c93b62df00a73ba4148a032cdff2d51f5867ae20120f3bfbf9cdd8d0e297d10c6acf71d77b44b368a91b9bf06da4afcdb010d82616e0d683a11e4fa7d644dac2ab9bb65feecec5f2b013a74da0f0af3089f8bc2dbdfca82c805abd66e8fdec4b0ecf5319c71c5ae95698bac5ac629e0f7ed8c5120fe5ba4750a7de245d9abe131208978782e6c4be86931349ad8385085bb3a24fd28aaff56ebe61955832017e04662819528787454667ee64077c4b7883175b3b3be3224c6db1858e8aadfcba64b2f3c25f8b983a70493b42e4f1338329ff5aee6ed4be3508b62bbb445ea6d4f4ba027b39abecccd5bd9ec9cf38788069b337ddef42ab50c9eea01c6e4dca5ddb5bc932c22a7b8650fbfa5cd39f380db0dffe0deac51243a5887f868388ffc29032810342666b214c81d4ecc51bf3ab890555a5b1d607e8ce6795418b1f78e2a6b1bc0f69f86b0f92cfc7ed6006e313b01d5ce9eec82f5bdb6ffc8bf526a3a42f4846a77776b58490d16e992afe9221e78879728cc995923be8c1049cac6a90f7eee0d5706eca6fc3fe3cec0fc7fa717e4295dec105e327ad42191fad5bf42bdc8a070188eeef3b4729097476d219ae8a3d06eebbb12bfcfca780ba6f5b9b9b7b88c9bee2764c7c04b6c32a00be4312d3701ce5745be6eaf7be917c62c3c70b6c7dda0f08b25cc50950bace0185f21317811c9924e919fa6a7450692feaf5a35024fa39c9e8435b8815940c68cda2267e74abec203d2d9063a8d1fed908fc26d7d90c7deeab1e65cb6f5f0e2af246a3ee0163710c2a963fd047c2bce4021af09e44abf6180d08ab047dd5592e4ae347232c3f6cddaf14cdc0e6ec3e3c7f6fff0fd14ba66e0f881ecf753fe46250898162a796cbd87b59bbe423a3453157f343c93e29f4150e9c56d3edc6c748791a18d8dfee9599a22cbdc95d411486df729dc0738f82e8580307fb741d268e6885568f39f74dc57ca550cf318b20f510c6e25fc9f63a35c040e5916713765f6d15114dd26c5b636979f25b82679a96a8f1da62c5257e8a632a2fd3f928e32218e607b2121e38f4222000c5d188666b34d661d2253906ec1a181834379463341cf6172f169245bf3eb3734966c7af8912824599ee349a02277a80dffa401aa764b16a83c7f7138fbc8c577480fe4fc39008e2677feadc447f616766b9d56401a314ff9bed85953e3d6894a68b010474d2cc77f9980db498d7c4ebbfe11e866db19691a1dafeedab15d23e107dd5e62279c5bb7d4bbe60e4e1d09fc601a15e333ba238baeb7abfbc37facb394d138b53ed8698df70d05daad24c74d65b05829d8a713e41f3508c96f1712afb4145f60e9d71ac35ec132493ae91207865f2a21dcc37e8d300aa1a5b2be2e58ce0ce02ae4c5ec3a04715a2ea03cb4773d2318d3f42c5a43e02e2718f4d1a516ce40771355eadb427f5bc9fd3d097ef9d803b0edafd0beb3a62e651adb7d3e234485ae053bae8fabeffa3fcb7ab5e7dc7997f7a26b2a575035c675a57dd1dd021f49bc3cdeae6cc98bd877bf9ca8447b3799eb7a62f527bef21e48201ea61aae46bbefcc330d48f83ea567d5b6be3674a35098caad479f76d0648417bc34525a0d97c76a371bec9db2f3fb109f2eb38f890030b51ba802f2c027bddc78d82480ec4b52dc4ad45650ffb8c5428f3cafd88c17cd48b677bc35d0001c89bb8a377a7b970c5f31330cbd6a4d4ea6cc482c767bcc4cab52857a4203b0bc41105efe8287a100315bd717125e931e6a08c94982c297ef3535d7e813b6d1af0dc2d428eb69edbf904c03fd273123b8d599d43392fa3ae85b96bb1ffbd1a263ec4b8c0779433df263a2201fb1a31bc0188d8cefdb35d592413d312260df2a40d7c1ae9447f3d1fea868c66566d9350157c5922dca712966a9896c40168b01a66930e67ffbc64020ccc02ccd3f2f76698a9e58564c4d59ca8b610347cc7d844cbc4e2c36e08fe57df9fd7c65865c8260658d69bb4f84dfc82a1cdce1707828e5668d84c1c0eec4a6c54cea7db68763345a5240c457cc66a439d7c7721200126a03d7c2d7c3d843ebd3b8f0382e6e7fe7580689ab828e5c5775e45920627a64cd3ba8f1606c9e06be5c6171b13f1f84e8f7ccc9489def4933188c370f6d33225ed30c7df9f45c68fc38f8342b84547347af4dbe691fdfa80a4673cff414e9f322ecf38021aff63f47bed448be7f26abbda6f3e0c9051adc3f50888e33f40021e82a08a8df464d183f217920ab0f076b71be1d85319bb6a6cc17642722cd0b7c24f6f4a865d6ab0556ba0d3d1cb25159cf1b6d9287f74ac1a09a811b4f2f39ea3d61ca18c09c68fc3944bc51f3384b615370b0a729d8f16205eaac3a6025f1a55ee37b0400cb6e94100aec5732eb67d3b9a7dd783d0bc4838c95c85254151104061e25c878916047a0ace181b744771dcc78a3d70e268bbed9d9d2be23dea0020cb3cea2e11d3f6ffe2e9d6fd352db69e6dccf11459af45e99a4f307d9e5094c455fde8ca0bca1809d516ef9424350fc81c3263e243eecc8c0fc4e0220611dbdbe7601c18156f1e90d0fe6e8a59aca9d6dc9f9c58ecd9414d22df800abd83a0421eda67429050afad7cc6157af763e99e9e93c9ff36bf345405e69a2f3ccd8ce1544e072309ab1cbc65daf71fccda950eeae0f6f55c71381deda4d9773979657e446a6d67ba7a207d082c13eebad2fb97328dae64b1ba764b1dec5b0216a5a0e3874d810a0085635ceb8f87f9b198ed35360d5797478ac322782af36e62e8eb55cb41505463ae590432e8b302001894a261db07081bc4cc2e43dbcda454e12d7f60b4464546bca4d2ca731254554e7b6d29e9093e84e317e5a6de27c0116b048186357a0fc1d6afc5a3717d8727d01c568922c2df32c74ff070b95be1729c73f359d9bf61f10c7a0623e2a0bf77892404e83ae98efbf14550a53e966307c00457c063616fd381eb25d736daa32ef14241c529bb5c78bc9ef581a435cb4d3f73097c7918080f861c9beeab04b27b75ce15922393b82cab3edf1c9ec5e53f66bac8e375921c02ad7edadbf3bdf5a2f10f9934f2ddeca206beed4cf231e4132ab7196af7ee894652efb6f8d80dacb8e9b97172cc3f20ad3b135e84000b0673bc10161ec883f566ff917f6e1b74c1c818007528681a3735d1e38de429835c72b0ee2d4f567d8773df44926664378fb2ae6f90f9373eff73463e7795a1df4907387341ea7e27f7878b5d4922ec6e7ef6bcb54c07f1f4fa452f9356d4a095bbae5d9e6e93fb496acf112f18a0812822b6183c03a5229984374e80f8b01f6fe537cb3e4f141e5062e95ffd28a930c1080d2475a0c2f2f20625348c95d335cb0f732abd2adff1a8aa5e31c877d1689cfcc36f9722e5c54ac05078b44d13f728129bbad55bef37db0144d962eef458a6e974d41f0d02f68ed660714e8f8edd304ca23080b96b26985e69cda1869174e671b24ed78fbc6985c5f3a3f022628b538ef20badc26dbae29bd21562b02ac8da262d2dd2537e1f2594b88520ce375e90153d423fbcb33aae54a485620a030a20eb06cd898496c77067e768f4281ae4abceb0d6b278adac3c9ac8b1dec17c6a9a783e49d2c864ee2b3f5fa7155974c8e46c7bfd7ce25925c67422710b606bcc1962bd9f9d0e5783ece6e508f7f224d7de51cda2f4ae27f57926ca09b0e9336f67f4b77fc10662b66296cd60b75b59231ae3d6b6a5135cffe11aba067333ae20a7fd8fe4e96d4c2809dc6ed79f85e4d71edb29a94752581af739b89fa25130e2191c2e81f26fac62ff98254356d278f5d18076906b2b5125552c41d75e058720f6af0c269834a1d60589e0eb14542d50601fd875a2fe8c2e8a12c2ef2b38671eacaf8217beadd133e95c0c51b2231823ff48431244462bdb144bda4f5b0f115ed397deda7e711b6efb28b88a27dd02bf39ef4f2c511f99c5d656e61d866280103851a507c1119769ba448f2d51a782cb5518836a518af88def6eae2477fad34296f2cb2939ae6edcfd55513b604dc2c4ce3d78ba6bd34ff914597fd5ac8e60cacc813fc5684fea058ec0fd0b0aa6ed36a37c60b8c371352d889f2bf28a69a9a7069238e8c0eba38ce8dec4f1179a7ad254764db7580214da56c76372a0f75e1a6bb8345409dc9b461bf58146f6664a76f5dcf0b2cce04b673d5503d2c33e9f16e3e571ef2dcdc3b9443fc6272c6d0c9b95ad78b61a2de99d4029bb8408c9af5281bdd92dba380e0e38fff301b4adac207a80449b4124c348419f9d3cfea06f85e8138e755ddeb21c336260ea584a50eadf0d968772836363bb0ea0b764d38902db5446cf8293982f917e01e35d3bd55cd38b3bceb6549257e8e83622d46e7b8ce447fa4f478eb344f50ce0f76f9eb5814c972a1ec4066c201c95404fafa09e3506646bb440b1ecef1d1a2780c0a6af55aa96d39a05c8a94d78129fa44c4c4421f2caf8e3918ec85fc06e1fe66bd67ae58c08f9d73c064d595beee1cbdf623b890f5192d86d10b28714aa0102e548c31ea86d97226d9460e29fcb36881973c480ae9228c0a8d161648cc1dd40d5cf8fe50b148da6b5eeda1f665cee701ac7fad3655f6a69c2368112f8fe4ac0efdf77283a4ff07f21c807b175b00970e26791d064b2e808eed37a9ba827f4e5755e10003c8052fd6e2e9505716aebf6e4654ffc04c95fd890423b4c9e9fbe3e5720071393b07c0794658bc440ef555988f51de922c3cee5989733dda0435e3a70ae2374fc05728dfc33fc0cdaa1edb440815eb943339871cbebc4e5c862fb476ede5955d551141a21b0a53fab2a2cd1e2bb5fd875f98decb317b427314af6afc63079d68fefcc2f089567ec3ab78808b764d3308822786a25a2b43987c069bfd2a490d29c6bd8ffb3d599be03728c5cc915582fe93f4402a9ebd9b6041110c4ea9b91cb9a3e32a1e0c2b68d56a8c55e235a10e6e30ddfed75af6dce9fd4bc7f751e3c47f0e98fd5cd4ae35c0eea4092adc4aff790ae9c8537fa14fd5c8c12ac16d1f15ae2c6c5cf1555fded9a1eba38fc4c6c338f9205e0eb7f1e71b01784bfaf90b0cba5543fdc5fab435c91d71929ae05edcfc4934def06e1b18a28ceab12dd0e9541849d8c766222d76055b4f25e0d4994d65c16f448a8031f0b95e435c4ebdc7e377dc482133a679df5986139f4328025f7c291173c5af8cde1d41580b4ca92e120b796aaac9ac95ad9586b0a0b9fd5b20f6c324c3a798f9794ea1457e8b5783ec3937470abad17aa9126a3a0927a760c1d6c4142a68ae9f33b19401cd8fcaad4bbe0eecb798257ee8eb690a9d9eb660cebf957831b84fd2f42cdbfa8b318315eb219b3e71cd1b441417ad0844b17f80add5b9c9b7052b277648711b21e8a15a09e318c8c9de1cc81baf5e681c13542311e3a2bd26e3211375790dc981258db52c6faa73a6ceb9d8749c8e18adbfb9c33fcb5681001d36d0d398e7e6f92e3f5fe1d7d93bab560ce12460a46b906fd47b31aa7a96582151d84e675a3dedce76b154f9062e4c369c1d2b6c236a6ba244fa45b0cf28542e89a3f2ae0c711764a5f56bfb646c9ff2953e2d18774c347c617a8369d7881b1e0cf716c7065279cb320cb4585fec1430650913612ab878151796b35eaece428aa67e70017045be1530e629ec415523def8600a9ba279a242a92c48c225d882b660bd9d46f36bcc547c8171fca60bd024ebced972f0ba8250678bfaddf1ce1498cde478821725e4cfc97e0917433e154108996a37251b237092016fe29ac0ae280be2629b4d79cd20172ba6d0bb72d4feb36bdc424d47a3b965385e83b324a3d8d51dd07f1e63648bcddf3f521dd8758a8688f7af0dd124295dc029e5e9576c320571b4dea86892415af9a2bbf21b1449eab2ddca8ce70ee0deaff3ce02bade1c7f049711bc9f885902d133277c4261b05a622d4d567f437556d76e70d5bd428172dd6df90289c75d8bf59497e33452791494dbca0511b0497eb0cabc70cdd98f106546f02c9eb33d557c37141bed3d44a368e8b6563f1176562033e58806e053fe752d861a6783002adba755b35c00510a0036c9796901e4e11e8300ed474cf0310efd3f8a8efe2624e7d4fbd41edd2efd85e88a617d5cdbb75b2a023f4d1ae5d1f57286dd9743e9e46bad30e71054e7767b37115a45f6981b4e6fcd8d260c0494689890d949fc0a24f46ab5628495f915d837d68448cd587313bd859e8ae81279752be9a5609461905bf962de4f24351ba12ccd33bd495c9c1058a5483ee58a06ac9edc1a0fa92da2c370077bacc987c2c7b1b5d51c8ad3f7d2ccbb5f714a5d66e67cbbbc70e5964d60dceb9bde99c5fd145007637104674c89889af3656dafc4367d78757eb262c41adfdd17fc011cee10430fb5ebead4a20f264e6d329dfe59969228d39ea01a55474f94eacda5cdafd763b2d615fafb06bbf765c9770b0dee013319af3ab52dc06555f4108772a8ccc4db5a4c4bcbed94165647ca62e50e87563f963695750a7c24bae5ceda0be7d29b1001bcf2d582e33d4827bc692a6052f409d5870e2d5133d8753aba063f29eda2b7583417636e8eb5e79e159adc8f658061608440c44dcbfbf4131404450dd27139bec684d9f5a2397e76adbc123404777835466a9d442d5502e4f4089afd49845ae8daf1ea59c88ec2871984350aa1193ffb76814f92d90d89177a2b4634c05ad1b373fc88524942c24745684c2ece7411153c3f56ccfbc8785f219a1d37039ea6cfa76a694c0506b9a282d6aba168224608e7a7b8737478da697b96698ca46ab40035d06bb4952424a47390a5871e52343350cfd2efde7a718a94642e2c18cd5cd1544a444844fb34222f565bc81eaed2c7e78f3daf611a34fcfeae72578da982def60f98e3fe813421f4d81e5329ff45a006d35af991b39bcb954c0f190125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000000000577000000000000000000004301000109d056e065bae0f1b3484492db483b8f89c02cdcfd8452a3b657a4ce5ce3f23dfeec2cddef3107074bedd0496d418002e1454928bc30ac29c765f6327c370392fd4d0b60230000000000000001552d00a55930afe3a8b85cf39e5eb217884051efca44750b08930e1f2ba4d5793670e366a4c72b0af3b8730f1d4cd85022db82a990272a5e94f13bb6d67f4a5c4bba3e95c67c9708ba4760b45b747ca337b75ea537ced0aadae8e2d709b81ebea64ce4aeeb3ab37516b588ad7647806e086a6b8a7e875f2f701537cabfb8229720f6d6a036783190e4220fc7b01114134cebb383acdc775f24349c2a817e9fab2e6938f0b3e812e9b3a0ac60f2e736bb5a283fac55689b094b792ac81cb6403e40cf11030f14ce3c6b4f1c30a0fb1e6eaa4e9cdc514dd9d3066ed0fb12161c0a40752cdd7adc50523a9e5b9a8f6a93bf2f5b12099b38097acd70d38153746cb82690c743f033c5d730d6dbb778c4637df80289214c018a5f76f072120d1069a03a159b055ccfe6e4a055585c9529c11693710f3a95a160c504fc1123e139fce36f02747c4702b87dfde86f16a871cca6e1461c53410e379ecb70ce7a7a758572926c62911cf7233147c1173f9e39e8d023a408fcd808373b8d6ddacb3c6cce7c27799a16e70d5c2084657ac78e2edbbc3c295423f99b307da3481275d9f3d46f89e27cd3723435e38f241eae19892150b65b872e60b01dcfcd623b3539d644709a50c241a6de68b524b2ebd55c68de38a1a1ec6434e17b70c21aa318bb13d484380786554ee3f1a272d110a719a5d6697f09ab4928473613c012d5a4bf6ff626a58eb32f72f5a5d18be667d679e3bca4bb342147b21f4a6d677afe936952aad5a87e5b04ee9e87a81d9f4f1d6447e174c5c34fea59a7c6e9c27cfc82d35c64d4936bbb09b43ecd012e71ac9a2d5a8c664e3e75231c87999666d277849bf266c5ce021c4139ebf22a306c2136065577b8bf8e4712f1531335b3669ccb733ad4d227d882e4dc90cb16eb5816cab265e53361db386d5b7274c5d46ebb24353c70af2974fb42854196cdc8ce94386e9cba4323d343595eac2862c9f98b400b4962d4e8f4038c1d5a2379b4bb4d284575f51ebedc8e4699a7382da2802ebe8586966a23fab9fc2680458527e5aa12151cd802a2dca28d5da4e1a9d0684e7f3780f65ec33292d9c7c98b5942d230d5242d339b8dc01881910dbcd5bcf58bb607cfaab22b6334fc8a72b7bf3452b5f2805176d243c706dbc1610e87374cf0286061c8149d2873148ce3594e94d581e7b075ad56aea6ceddd63c697404054b605c4b37ddfb825e7bc453df4191dad41322a00c0804960cc7028653d0c6ff623c3699b82e33ef2c91360fabd7b262ffec9df90379840ab96c80dbcbbedca0c4141a2cfbe079b71c45e474e41c7cbff7db43d8cd87a4195629fa6ec85b290ad1f8a9154ab7a17843f652ff9b4396cdeac17b1006cad45c4aba3c07a755be7612021e370e5078e3c769b65cb7646974de0b5330fcdd5a416d74aee5deebb2dfc7e77faf4a2d9e87e40a445ff1883ff5ed21bb8c21e47e6c20d180756638d1ad9e4481df20c7d5d72bb408f07cc8e148bc01ae8a41453200ceee01c3ae127d92c9911bcec71144b229703cb38abc67beee399420626237a0bd43ff6f4d00bbfb300f5e7eb1d1065cca627a272a4cfb8bacc0c676d0101234187f92fb573a175ab2ce66b4730613e5213c0c1c01b230d3b96f2b4a65554f0360d62c6113bbc019c48b51c244fcd46780003b4e6bcb74664239b199bf984457d5503a2bb065ac85e97b2868e8f1b15c63cf204bae49237dea4b5bc872fa3b56125904ebec0007c5580e2960acd6dd849514795bdcfe9f2522c5303da2a4f28af9d3cf6d6111a12bd9d7a8fc14a1f1e5d23c15ab4905498263461d6109aef96a2757a3e859c28ddc018cca849e2fe3b83e615baa9243ef0573bc1ecf5079824ba5a8689620629558298502282ddbb0beded382ac29c38cd597c8730f81c4f4037db31e228301bb7a5219f607da8e4a7037071a2cb910e70c8f53a1f319934412b1da9756e4d56c8280ca1d5da78f70b7612d72b982fa59f22d54c067367a18b8c7ed346acde803cf3b7ef9a7f10428ab0aedb2ff88441ab4ebdc860921fa9d4da97414a8056ee56ad17b39f41428fd06a6c4568d060ac9c9bbdf93b6f25c29228796284bd8c66c0f7b71566340045a9d35722426face4ead0d3132103e5a5ee87c512b3523f06a5dd78bf6eafa6615897a882b71a9918daec50a8b6cc7d862c1cc6d93ec0d4b2b09e6be6de65a4cce1b3f8ccc8becec3f244393b9c4f710056b85e530d9f603b27b170374c4c52bb49c7e06e971f357aa65f25b9d940998cd55327fe94447db6cf5634d95078bd9e9fbb0d9e050c502102095d45dd0f6db603dfe20bc629cc0ced7c078e8d68e35d098d30404bb134dde3979449bbbb1766a4ada53585e47be1c2ba6112d4d831456d0ec63ee538df68df4d50c17748f8d5378aba25ae285850f2daf711d035890c97d38e99d4483f39dc66257f08585bdc03343bcb17eb37ed8b660ccb58b408329b4fa0005d2073c0bd22540fd63f537512b9aac864dff5b38c65c1ebb2c024f1066e1aea0a45cb841853550fcb2fce3c57440a9f3afddeac4bade5677aac8b0482b5b734f5fc6c92beebae4fb18a6866094b93daf6f45815e8d93a54aafd585b93f1449f3fe71bc52d06fafa0209b78cb756a96e7b4a7d11090822cd5c02922b91351892855bf746e3fb88b9f2c023f8c52be3be9570bf29089dba91f56a5dbd7dd10facffb5ac653dfd32156124c71bb29afea2af494c175ac023a7f3e1022f36c634ee34976877ba6ffc0989a66b6859812a08b2d92329bbe2683b00ade513764a1c85659f47a94979c3403d829dd19be17f9c77eeddce34e82ed649b610d17b8ed37c6a4e482bf28f22e53b377571ec7a97142d801a8985c53c92f649b9e408fe96b5d85ca612f9ab45e2be9e4029b4e4b2998b4823341ef50d045cca95f8fa3eb13e8be4e234d2e3c6b5b7f8012229f77fea4aa8bbc4dfd7367da2fe6612fe1f340ff835b6d25696c1db5c8a3a0a2ccd6716c0af73708c71747dcde2b3427fc686afce724ea78d3da3730812c57d80ade75a0ee7919ba068b4bf47534983cb94b859d9e0268da6a0716aad218930a2b8262666c346a8cff24d2972617d1ef52d73dc928c3f97e3875076b3d70dd9576e4e923417042052c39d6a7f0df3aaee11af119a6440eae3d029bab4f781bfcc11389028e5fadf90de1708cc9e4975986014b95ead7ddfea867c4c3e123920f99b0d5f01feb65c0e97c21c6d6d0e9fa0dbc963fcb0d82ed2521070bca6df41bc343a9457d1a58863cc57a92616d4b93ffdc1615ce01f50717ee0bebc02cb731b6d4c59170d6ab919e48867e695a2b2ceb0a323f26f336c9c666e989a40665bd3f74d6a5b683a0133cae733abc44cbdcea7c088d03c1689e573a7f531c270b1231476a5b438230f3dd701c3d16f9cd49554087471624a4dd701e31ec06ea91c03b1941839ddd56c767c77628af5fd633a7692acc0d92e906ef95b5c73e01b4621e4fdf214a6485e20a15b5cfeac823ef576167d09637262b3c658041963064a72064b98385b7146d93db21bd68dafb09010892d61a108a11546d1693e6a3c41d559ce3d38eb39f1ea2424c733d58dff19a82689b6a97eba76343f8b883006aa3658d686555e23142339b3d766dcf4b98b364293b3465c8baa364fd7c8fbf96ec41b9e0e1ed9e1bfc7266ee9106245f99f4f163dcb503a23d73889d4091cef9d3f73bb21ae0b72beebc19fe69b317c5574e297220386be3d8785860c295954a53457e1ae7cb856efa82d51025d6ad89c2b02b8f1c8ba149e1dbd3440c4e879e979ef2f6787695f45d322e6a472fed998be344d99f0c6287772e5a0fe3a1b3ad6b633f74017b887b7e71be89d625d3840946ac2aba4f9d1377657df50096877c415d5eb6eefcd971a897201b3254cffe26379b89148792e51f74594adda09bbd76fad403fc649f9f4be465edcf20768742d35a703279ba845aab3075112ad5d48d80d2b6cbd451ef5b94c4866d8bd39340b72cef56053d33576f5f1733af62db1f0371d0aa91297d94c0fb2d9a39c6e824a31d00000000';

  const signUtxoList = [
    {
      txid: '4aa201f333e80b8f62ba5b593edb47b4730212e2917b21279f389ba1c14588a3',
      vout: 0,
      bip32Path: 'm/44\'/1776\'/1\'/0/12',
      // amount: 1000000000,
      valueCommitment: '08b760fd74cae28eaa41126b3c1129b2d708d893e17b4e61bd9d5a5b12a1c7643b',
      descriptor: '',
    },
  ];

  const mainchainNwType = (networkType === 'liquidv1') ? 'mainnet' : 'regtest';
  const liquidLib = new LedgerLiquidWrapper(networkType);
  const connRet = await liquidLib.connect(0, '');
  if (!connRet.success) {
    console.log('connection failed. ', connRet);
    return '';
  }
  const pubkeyInfo1 = await liquidLib.getWalletPublicKey(
      signUtxoList[0].bip32Path);
  if (!pubkeyInfo1.success) {
    console.log('connection failed. ', connRet);
    await liquidLib.disconnect();
    return '';
  }
  signUtxoList[0].descriptor = `wpkh(${pubkeyInfo1.publicKey})`;

  console.log('signUtxoList:', signUtxoList);
  const tx = await execSign(liquidLib, txHex, signUtxoList, '');
  console.log('*** signed tx hex ***\n', tx);
  if (dumpTx && tx) {
    const decSignedTx = cfdjs.ElementsDecodeRawTransaction({
      hex: tx, network: networkType,
      mainchainNetwork: mainchainNwType});
    console.log('*** Signed Tx ***\n', JSON.stringify(decSignedTx, null, '  '));
  }
  await liquidLib.disconnect();
}

async function execPeggedTest2maxEnd() {
  const txHex = '020000000101a38845c1a19b389f27217b91e2120273b447db3e595bba628f0be833f301a24a0000000000ffffffff030125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a01000000000000057700000b3db124ff32e6afc75c7bd7d2f687b8aca7ac57698e4f526b21f98d8bfb89be3709bb7074f6ee5ed0754601941aded3c7cbee9c3963bdf9dddeee9d756e2dc9b2b5034e6739b39e17addad80e8807002d7ca9803cf084fdd142fa8c978966f6bb81f4160014f5f67358a0c64ff9336be2e316f99b04b548521d0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a01000000003b9aca0000fd62206a2006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f1976a914844d3afb2081df687e6c0a83d2a5e0925c4fa01f88ac2102f6e02ce0c684096337672d7d72bc33c5129f9079c50447452aa7139ef3632f4e4d0120ff1f6812267a5600bb08104520b0c63003b7f674c2395a586ba052fcb5fb4346902a8d7f1014f920b8011119bdff1a1159c566b0961d4475e054aeb5bed098c023fd260ef73f838eb0f2794b86ac71cebb12882425be4c5ba7a145bcbff637aa4bbe26c53d486e4d4520b0a17a353a3fa758c080a2bb7cbc04d9bea4189487b80bf31aa26874035a8e6f5a7f7d1b414abb5da9adae630f2760505919954787a4fac4f58ac65b7706bd3828e09cff6881092024a69b844d9d74222d1cd902a3d699137c28456874e187f885364c1976e1ecff4363369fa2e3176f1b03130ff0164c809f3ec74729a4c26a5f2da3f202055e17d79c588e88c324181b2f022a1eaee47aada011176ebfa40d24d1158d2c2a214a61ddbafbf7894b21f1f17e6d64abb6ba5309b3de48a66782ba73dda0d5bf8e59323be2980e1078ef3925eb360a919bb3bbcd7d36d4f00b986f946cc30e0db1b3a4ee2178a517396ad12f4418c40e7579918c5a8bf4ae4e0ab1b4a748f7750cfd7fc86d92d699daff5777bf3d6278b525617196cd076538349043616d212918a02b1792b5932e3741b322c90e099db3976fda408999cb57a66b41e9e6efc158edd8ae95dabe77139f5f79c4cf6813e886d549aca9b372defcfbcfd0e5294b2a4efeb83e50d13869894188664df8b541b41bab6c58b36e003c64cdd1cb57dcc990344f2f37e37af28eb8b0888d86411eba1082069763f128c418d441a5266cb5aeb76d46671cf6f4a56f507af483b58f32223705e0e72b29398304b366296f51159143b56de93d4dfdfe5be186ae141ec4612d0ca1beee085622b78b9a91cc87abb49adab9609b34ebc9aa4447ee4c23d0db1fcccc97040cf06e38e4d1bb3d40e01465b1128a96a8a4f81fe96027d6225d1fd77af39bae6a5e63ab5b2588a23c45ce62012e8c808d659b5435de4cd7ff923146e41f5872a19beda531781973e03112fe5f7a4b4b65416540558a8a6b2c5e3ca6404e2887786aedc99f8b3b4bbe43890257cb6b4ae9779860efba82e30a270bb6d901427e1ac82e49e0dc7acb86b19e3922ac107143570e79c6b25a2234b13898e9e2b832af2bbe80a8065a2503994334b2b21d9a8043904cb5be8a0b5797715c8ddafb16df902f6c180625561a5ce187d5a266dd9198705c74892c59aab9eedfe168fec60b4faccef6c5dccc7bf42e5a6daca9453a969bb7ec9802e2511ff14f762db959611a4e9c433c8fec5caf73bd558ceee719318233adc5cd84b1c16c728da5480663b6d3df66c3b0fc6fe740147b00bc8a258142e23a3be5734883812e8ad0f79b58c3e1498b2e9c53a988ccf0d64af068f5e70d3033f8e4ae8ac9aa6cfd4183ddc521563685f8169dc087b2ff9e5f0fa73e718dcf79a0b10604d68038666045ea1d5b355136b2c7c8971b71377f0cb25173db3ba0d2c2c76ba5fb3ddc49c7463ed7947b700d589101a73ec8d4a5f34596fcfca5d8c251fd1f9783f84c67ba5fc8fb95fb97c6e2943455509fa9be9cb3cded7da368a9a8cbaf010c4b2cf3972726bc6163d5c90b84f8e19d11ad53f18284b1d046af68bc6f59ecd274eb6e50d3e00c315f961a3be955671326f675e77bebc348b6fad79d57f5a92cf2eda5be4f501e257d682f09f23ebc26b09d76e9df0faa13f1c0822351fc75e369c70890140a4b327e4fb7abec69ba38b4481bfa4cb727be160f197691f99a3f78e28a5f246ccadccda060cec40a1bc6004839d24bee98052a8c11cacf7727e09fb200f8fb4fd46dc755e6b9b3cc692c7fde3e6ed27a37ba8e7789eddb6e53a0c6b1b079ed41854bdd24d085c0ede394e8b70012f007fa580240af5622f4cf0a9159bb95c4bf2579a848f4f6bff179d5b4d3aabc481042391d139009f225597e557aeececc239dc1630b7249e48c6e98db8f835fbb3998fa7c81354a9b7187cafec62d1b1fd4aa0a03d3511f329f52292bb185829fe746512d68241e0ec5a0c5da33f4bedc577287fc2ede49607967d0f848d6c1611a2aaed70fe2689d0867b7c5526e53875642f567c3f102727c40c1ea4503297643299cd4a408bb07a17482b5911badb790d7fe9df62ad277d97e553d2f0f94dbf2e3fe34699cc8c39c0ffd77c17fbcc1f3c36c01b32465e917e033cf5856b42446840076dee08cd53447c9d96198201e91a02b893a5dab11fd2ee16a2161f86297d2290f5a0ba0e8d104fda4e73aac4011c8c0ffad3a15aa7be0c972f3dc1798316ba19e88be4cf4296ad634d377d0396aa93b8395529b70f3ab702647fdf69abdad61647272f02b8cf0406a06695fa1902409b59b1dba5c338df9c490e101283d7c25ece7cc8e9f7c2cb3eaf2a6d11e6a2415014b21d4f23b97ac12e8167bbc4c7d1827d9d66cd849fdbc53282f150562d56807b4da70ce32c3d436695adfba9ea1384014820a1758779701fbf8cd5bdf87267ce3b270112bce22a35eb080c4f7393a5e435e88d2b0d2e43085b698e00def8de76fddf1896b34cf1fc79e42266fe1412b1b168b4e81b8eeb9013e948576c2cf9ac2ee97aa1b85a6cd4f2205037ea3e7badece9bcc6e4271f5d7624f704c5e488391e215e4152d15f026417d3e73873ee641a534c4517caebe8f43e37892672d2944dc7ad5d0eaa98037a8a639a55f957dc0faae4689aff8d62f3da4eb3bca4ef75189699af1bf78a1b1d04a771db5a2944204d1ac88948721e902eef0dc43a2c3b95250a24444ae26b9c8c1c870c406757cb327bfe540b171c9f860a27d7321f117a246e83acdaa3de623fba9099f36384f359ca24535c01278b732b6e5d3eb5a3d755d909931b8e2589b1d30d29e48d3023c18e7dd2d06b4119cda61c0145eab406ebe82d10570ccb649acfc0d325f93257ce550695b8c9706c6c1da45e6fe874f91dae5a31389a9d760cc45895ec7e6b69fcc27023890368b298cf0299ccac7cc61f968f4bfda6965620122e9dc13e23611345dc79fd5e569ccc9093741645c6894b51d1b47ee221bcc5ed2834a9240277ec433a4ede0277374b404e8b42ab41b0c8a69a64a1ab8a68e5e5c140751e9e7612f734cfda02d29a55288a876b5f096cef17de0d26e47d2903015cc4690027364eb71ba9e76494a7042f3cbff3225ee7573e12c34f174baae7bf5fafc6c33f3c03b0682ec3a42ac83066c46aae508a4a0d26b136fb3c27fbfd5aefd74a0688d31f2aa93a3fcd167b24b70d4333643d7bdcd429bc8aaaf7507f718942a792d3a935a6f5308951863cda2ab153ad7b2fe384825d9171c56a5271013d4e6cb5cc94633aa8ea04798ed9a7d67ef073dd76afaae41ed2f8b16c079173be55e808e5a3d89a9770803f4472cdf9092ac01faa37005b6ccd2aad94e0e4f9b9a7c781715555be587e72217a8d1d1c84679dd588eef33ca318188910d0224f7ae59caf096832026fdaff10ee6176dd5c5f6d68fee475fcb1bc7a8ad71e5073769a9bb7bb21bf1ed286af2f9445da4ad01ab3a48cb8e8a5f16f7b90f4f57843fc1df96e17c607b86b2b55ca01c631f5c02deae467e711e1482b37d931f45ef16ead06cf9d99e64c9992a660e8441d11e4366a22c20926591947f9cb6c78e5b3aafb6d2f2d489fa4ceeff1ee96a9a313341696e26cb17b787f51ae9336c2b4ddcb4210317cb770adcffd7d021541a8c6619b0da72402898dd993472836663c6857f01b7b60bd9ce90c22727e1f8714063950211a8c7c1bd63f21a8615765d9955c6e0bf02de8b4e9729ab94fffca94b3c4bb161452f4ce6574a8a5bafc26ca3b2b3ddb5ec2d3df53d3c45cdf74975abae5558b381f93945b3e97ca8808d88f24e6fe21b12e7ab5ee9bac0b20fe463e5052418aa7c24f788bc3b0c50976b9450de9dc5614e25ca92f548e39ce38f3e9c2e952b8fbcaa47963f4cb01ec70548913414644ad022b9a52d40989ea811d3ec347562a2dba729f1b4990d1e1e4bdc9bce55c3f557d6b20b7cdb188a1470cf81136e6f5dd9b48ff56778aca4c2a06a90049eb6b26a880b68f60e340612211a87f80787f856dade8b424d88e2a809d44383b445fab9d621e31942a7e0af3e682bcf746bef52c2d14209bf6d949b4cc9f8898121f391716efc00cc52cfce79a5817cb4c6bfcbfb0961a0e6d303a25cf79bcc8c48abb9da34927026188d4dca6d9c26f1cbd1a09f528b2306a74fd1d25adf81d82acf7145609f00d8c54367eea31a7234a361cd72bdd47ebcf42d2a2a2abda30aeb947a5d6b6dafab66cd8609a2b197305b9cecc4abdb8d440e205c39945d638a58a2775906594ae44e312099da10e9b3a195f3fe58092cc56496fbf5e63db189e09ab5af121ec6dc5ff543009fc0586302ae93051bc33c217b77eadbb88a35475c5e1f920e48975333795bb78a1bba441cbac919635fcc3792989c693aae0caab9558a872e33a717688ec915437e46c62a0f80888bf5cbd8f67e6a5933373f50fa3bf841f1579439df9737ac623ce07de3011cdce16a1deae5a460354d611adf4fdc0b5dce7661477eb53498233fc83dd6333f6b4986ebdf407c4b960c5c972b31933973729a0b69b10d734f58387b1fc5737e17903ccaf8fcc65fa48282d91a01765602d243de7a8b8fd44458d74ce7e1da153f7d95861c93b62df00a73ba4148a032cdff2d51f5867ae20120f3bfbf9cdd8d0e297d10c6acf71d77b44b368a91b9bf06da4afcdb010d82616e0d683a11e4fa7d644dac2ab9bb65feecec5f2b013a74da0f0af3089f8bc2dbdfca82c805abd66e8fdec4b0ecf5319c71c5ae95698bac5ac629e0f7ed8c5120fe5ba4750a7de245d9abe131208978782e6c4be86931349ad8385085bb3a24fd28aaff56ebe61955832017e04662819528787454667ee64077c4b7883175b3b3be3224c6db1858e8aadfcba64b2f3c25f8b983a70493b42e4f1338329ff5aee6ed4be3508b62bbb445ea6d4f4ba027b39abecccd5bd9ec9cf38788069b337ddef42ab50c9eea01c6e4dca5ddb5bc932c22a7b8650fbfa5cd39f380db0dffe0deac51243a5887f868388ffc29032810342666b214c81d4ecc51bf3ab890555a5b1d607e8ce6795418b1f78e2a6b1bc0f69f86b0f92cfc7ed6006e313b01d5ce9eec82f5bdb6ffc8bf526a3a42f4846a77776b58490d16e992afe9221e78879728cc995923be8c1049cac6a90f7eee0d5706eca6fc3fe3cec0fc7fa717e4295dec105e327ad42191fad5bf42bdc8a070188eeef3b4729097476d219ae8a3d06eebbb12bfcfca780ba6f5b9b9b7b88c9bee2764c7c04b6c32a00be4312d3701ce5745be6eaf7be917c62c3c70b6c7dda0f08b25cc50950bace0185f21317811c9924e919fa6a7450692feaf5a35024fa39c9e8435b8815940c68cda2267e74abec203d2d9063a8d1fed908fc26d7d90c7deeab1e65cb6f5f0e2af246a3ee0163710c2a963fd047c2bce4021af09e44abf6180d08ab047dd5592e4ae347232c3f6cddaf14cdc0e6ec3e3c7f6fff0fd14ba66e0f881ecf753fe46250898162a796cbd87b59bbe423a3453157f343c93e29f4150e9c56d3edc6c748791a18d8dfee9599a22cbdc95d411486df729dc0738f82e8580307fb741d268e6885568f39f74dc57ca550cf318b20f510c6e25fc9f63a35c040e5916713765f6d15114dd26c5b636979f25b82679a96a8f1da62c5257e8a632a2fd3f928e32218e607b2121e38f4222000c5d188666b34d661d2253906ec1a181834379463341cf6172f169245bf3eb3734966c7af8912824599ee349a02277a80dffa401aa764b16a83c7f7138fbc8c577480fe4fc39008e2677feadc447f616766b9d56401a314ff9bed85953e3d6894a68b010474d2cc77f9980db498d7c4ebbfe11e866db19691a1dafeedab15d23e107dd5e62279c5bb7d4bbe60e4e1d09fc601a15e333ba238baeb7abfbc37facb394d138b53ed8698df70d05daad24c74d65b05829d8a713e41f3508c96f1712afb4145f60e9d71ac35ec132493ae91207865f2a21dcc37e8d300aa1a5b2be2e58ce0ce02ae4c5ec3a04715a2ea03cb4773d2318d3f42c5a43e02e2718f4d1a516ce40771355eadb427f5bc9fd3d097ef9d803b0edafd0beb3a62e651adb7d3e234485ae053bae8fabeffa3fcb7ab5e7dc7997f7a26b2a575035c675a57dd1dd021f49bc3cdeae6cc98bd877bf9ca8447b3799eb7a62f527bef21e48201ea61aae46bbefcc330d48f83ea567d5b6be3674a35098caad479f76d0648417bc34525a0d97c76a371bec9db2f3fb109f2eb38f890030b51ba802f2c027bddc78d82480ec4b52dc4ad45650ffb8c5428f3cafd88c17cd48b677bc35d0001c89bb8a377a7b970c5f31330cbd6a4d4ea6cc482c767bcc4cab52857a4203b0bc41105efe8287a100315bd717125e931e6a08c94982c297ef3535d7e813b6d1af0dc2d428eb69edbf904c03fd273123b8d599d43392fa3ae85b96bb1ffbd1a263ec4b8c0779433df263a2201fb1a31bc0188d8cefdb35d592413d312260df2a40d7c1ae9447f3d1fea868c66566d9350157c5922dca712966a9896c40168b01a66930e67ffbc64020ccc02ccd3f2f76698a9e58564c4d59ca8b610347cc7d844cbc4e2c36e08fe57df9fd7c65865c8260658d69bb4f84dfc82a1cdce1707828e5668d84c1c0eec4a6c54cea7db68763345a5240c457cc66a439d7c7721200126a03d7c2d7c3d843ebd3b8f0382e6e7fe7580689ab828e5c5775e45920627a64cd3ba8f1606c9e06be5c6171b13f1f84e8f7ccc9489def4933188c370f6d33225ed30c7df9f45c68fc38f8342b84547347af4dbe691fdfa80a4673cff414e9f322ecf38021aff63f47bed448be7f26abbda6f3e0c9051adc3f50888e33f40021e82a08a8df464d183f217920ab0f076b71be1d85319bb6a6cc17642722cd0b7c24f6f4a865d6ab0556ba0d3d1cb25159cf1b6d9287f74ac1a09a811b4f2f39ea3d61ca18c09c68fc3944bc51f3384b615370b0a729d8f16205eaac3a6025f1a55ee37b0400cb6e94100aec5732eb67d3b9a7dd783d0bc4838c95c85254151104061e25c878916047a0ace181b744771dcc78a3d70e268bbed9d9d2be23dea0020cb3cea2e11d3f6ffe2e9d6fd352db69e6dccf11459af45e99a4f307d9e5094c455fde8ca0bca1809d516ef9424350fc81c3263e243eecc8c0fc4e0220611dbdbe7601c18156f1e90d0fe6e8a59aca9d6dc9f9c58ecd9414d22df800abd83a0421eda67429050afad7cc6157af763e99e9e93c9ff36bf345405e69a2f3ccd8ce1544e072309ab1cbc65daf71fccda950eeae0f6f55c71381deda4d9773979657e446a6d67ba7a207d082c13eebad2fb97328dae64b1ba764b1dec5b0216a5a0e3874d810a0085635ceb8f87f9b198ed35360d5797478ac322782af36e62e8eb55cb41505463ae590432e8b302001894a261db07081bc4cc2e43dbcda454e12d7f60b4464546bca4d2ca731254554e7b6d29e9093e84e317e5a6de27c0116b048186357a0fc1d6afc5a3717d8727d01c568922c2df32c74ff070b95be1729c73f359d9bf61f10c7a0623e2a0bf77892404e83ae98efbf14550a53e966307c00457c063616fd381eb25d736daa32ef14241c529bb5c78bc9ef581a435cb4d3f73097c7918080f861c9beeab04b27b75ce15922393b82cab3edf1c9ec5e53f66bac8e375921c02ad7edadbf3bdf5a2f10f9934f2ddeca206beed4cf231e4132ab7196af7ee894652efb6f8d80dacb8e9b97172cc3f20ad3b135e84000b0673bc10161ec883f566ff917f6e1b74c1c818007528681a3735d1e38de429835c72b0ee2d4f567d8773df44926664378fb2ae6f90f9373eff73463e7795a1df4907387341ea7e27f7878b5d4922ec6e7ef6bcb54c07f1f4fa452f9356d4a095bbae5d9e6e93fb496acf112f18a0812822b6183c03a5229984374e80f8b01f6fe537cb3e4f141e5062e95ffd28a930c1080d2475a0c2f2f20625348c95d335cb0f732abd2adff1a8aa5e31c877d1689cfcc36f9722e5c54ac05078b44d13f728129bbad55bef37db0144d962eef458a6e974d41f0d02f68ed660714e8f8edd304ca23080b96b26985e69cda1869174e671b24ed78fbc6985c5f3a3f022628b538ef20badc26dbae29bd21562b02ac8da262d2dd2537e1f2594b88520ce375e90153d423fbcb33aae54a485620a030a20eb06cd898496c77067e768f4281ae4abceb0d6b278adac3c9ac8b1dec17c6a9a783e49d2c864ee2b3f5fa7155974c8e46c7bfd7ce25925c67422710b606bcc1962bd9f9d0e5783ece6e508f7f224d7de51cda2f4ae27f57926ca09b0e9336f67f4b77fc10662b66296cd60b75b59231ae3d6b6a5135cffe11aba067333ae20a7fd8fe4e96d4c2809dc6ed79f85e4d71edb29a94752581af739b89fa25130e2191c2e81f26fac62ff98254356d278f5d18076906b2b5125552c41d75e058720f6af0c269834a1d60589e0eb14542d50601fd875a2fe8c2e8a12c2ef2b38671eacaf8217beadd133e95c0c51b2231823ff48431244462bdb144bda4f5b0f115ed397deda7e711b6efb28b88a27dd02bf39ef4f2c511f99c5d656e61d866280103851a507c1119769ba448f2d51a782cb5518836a518af88def6eae2477fad34296f2cb2939ae6edcfd55513b604dc2c4ce3d78ba6bd34ff914597fd5ac8e60cacc813fc5684fea058ec0fd0b0aa6ed36a37c60b8c371352d889f2bf28a69a9a7069238e8c0eba38ce8dec4f1179a7ad254764db7580214da56c76372a0f75e1a6bb8345409dc9b461bf58146f6664a76f5dcf0b2cce04b673d5503d2c33e9f16e3e571ef2dcdc3b9443fc6272c6d0c9b95ad78b61a2de99d4029bb8408c9af5281bdd92dba380e0e38fff301b4adac207a80449b4124c348419f9d3cfea06f85e8138e755ddeb21c336260ea584a50eadf0d968772836363bb0ea0b764d38902db5446cf8293982f917e01e35d3bd55cd38b3bceb6549257e8e83622d46e7b8ce447fa4f478eb344f50ce0f76f9eb5814c972a1ec4066c201c95404fafa09e3506646bb440b1ecef1d1a2780c0a6af55aa96d39a05c8a94d78129fa44c4c4421f2caf8e3918ec85fc06e1fe66bd67ae58c08f9d73c064d595beee1cbdf623b890f5192d86d10b28714aa0102e548c31ea86d97226d9460e29fcb36881973c480ae9228c0a8d161648cc1dd40d5cf8fe50b148da6b5eeda1f665cee701ac7fad3655f6a69c2368112f8fe4ac0efdf77283a4ff07f21c807b175b00970e26791d064b2e808eed37a9ba827f4e5755e10003c8052fd6e2e9505716aebf6e4654ffc04c95fd890423b4c9e9fbe3e5720071393b07c0794658bc440ef555988f51de922c3cee5989733dda0435e3a70ae2374fc05728dfc33fc0cdaa1edb440815eb943339871cbebc4e5c862fb476ede5955d551141a21b0a53fab2a2cd1e2bb5fd875f98decb317b427314af6afc63079d68fefcc2f089567ec3ab78808b764d3308822786a25a2b43987c069bfd2a490d29c6bd8ffb3d599be03728c5cc915582fe93f4402a9ebd9b6041110c4ea9b91cb9a3e32a1e0c2b68d56a8c55e235a10e6e30ddfed75af6dce9fd4bc7f751e3c47f0e98fd5cd4ae35c0eea4092adc4aff790ae9c8537fa14fd5c8c12ac16d1f15ae2c6c5cf1555fded9a1eba38fc4c6c338f9205e0eb7f1e71b01784bfaf90b0cba5543fdc5fab435c91d71929ae05edcfc4934def06e1b18a28ceab12dd0e9541849d8c766222d76055b4f25e0d4994d65c16f448a8031f0b95e435c4ebdc7e377dc482133a679df5986139f4328025f7c291173c5af8cde1d41580b4ca92e120b796aaac9ac95ad9586b0a0b9fd5b20f6c324c3a798f9794ea1457e8b5783ec3937470abad17aa9126a3a0927a760c1d6c4142a68ae9f33b19401cd8fcaad4bbe0eecb798257ee8eb690a9d9eb660cebf957831b84fd2f42cdbfa8b318315eb219b3e71cd1b441417ad0844b17f80add5b9c9b7052b277648711b21e8a15a09e318c8c9de1cc81baf5e681c13542311e3a2bd26e3211375790dc981258db52c6faa73a6ceb9d8749c8e18adbfb9c33fcb5681001d36d0d398e7e6f92e3f5fe1d7d93bab560ce12460a46b906fd47b31aa7a96582151d84e675a3dedce76b154f9062e4c369c1d2b6c236a6ba244fa45b0cf28542e89a3f2ae0c711764a5f56bfb646c9ff2953e2d18774c347c617a8369d7881b1e0cf716c7065279cb320cb4585fec1430650913612ab878151796b35eaece428aa67e70017045be1530e629ec415523def8600a9ba279a242a92c48c225d882b660bd9d46f36bcc547c8171fca60bd024ebced972f0ba8250678bfaddf1ce1498cde478821725e4cfc97e0917433e154108996a37251b237092016fe29ac0ae280be2629b4d79cd20172ba6d0bb72d4feb36bdc424d47a3b965385e83b324a3d8d51dd07f1e63648bcddf3f521dd8758a8688f7af0dd124295dc029e5e9576c320571b4dea86892415af9a2bbf21b1449eab2ddca8ce70ee0deaff3ce02bade1c7f049711bc9f885902d133277c4261b05a622d4d567f437556d76e70d5bd428172dd6df90289c75d8bf59497e33452791494dbca0511b0497eb0cabc70cdd98f106546f02c9eb33d557c37141bed3d44a368e8b6563f1176562033e58806e053fe752d861a6783002adba755b35c00510a0036c9796901e4e11e8300ed474cf0310efd3f8a8efe2624e7d4fbd41edd2efd85e88a617d5cdbb75b2a023f4d1ae5d1f57286dd9743e9e46bad30e71054e7767b37115a45f6981b4e6fcd8d260c0494689890d949fc0a24f46ab5628495f915d837d68448cd587313bd859e8ae81279752be9a5609461905bf962de4f24351ba12ccd33bd495c9c1058a5483ee58a06ac9edc1a0fa92da2c370077bacc987c2c7b1b5d51c8ad3f7d2ccbb5f714a5d66e67cbbbc70e5964d60dceb9bde99c5fd145007637104674c89889af3656dafc4367d78757eb262c41adfdd17fc011cee10430fb5ebead4a20f264e6d329dfe59969228d39ea01a55474f94eacda5cdafd763b2d615fafb06bbf765c9770b0dee013319af3ab52dc06555f4108772a8ccc4db5a4c4bcbed94165647ca62e50e87563f963695750a7c24bae5ceda0be7d29b1001bcf2d582e33d4827bc692a6052f409d5870e2d5133d8753aba063f29eda2b7583417636e8eb5e79e159adc8f658061608440c44dcbfbf4131404450dd27139bec684d9f5a2397e76adbc123404777835466a9d442d5502e4f4089afd49845ae8daf1ea59c88ec2871984350aa1193ffb76814f92d90d89177a2b4634c05ad1b373fc88524942c24745684c2ece7411153c3f56ccfbc8785f219a1d37039ea6cfa76a694c0506b9a282d6aba168224608e7a7b8737478da697b96698ca46ab40035d06bb4952424a47390a5871e52343350cfd2efde7a718a94642e2c18cd5cd1544a444844fb34222f565bc81eaed2c7e78f3daf611a34fcfeae72578da982def60f98e3fe813421f4d81e5329ff45a006d35af991b39bcb954c0f19000000000000000000004301000140180363729c7dcc5976d4bb6d289c5897bd1e570e39f91b948ef5974383ad09795a851f535ded75f29a9a97a9d8d29680089e484197bf0cc5131b1864b34552fd4d0b60230000000000000001d15f0146c62403a9486f41872b100789f50e055a92d3244348c317e0a16b475bff7fdaf2114ea0389b7cf8c8c96990d04edc088635a26d72aba6fd35666e5bfaac08e420a91684d44a2d31e33980e3b4856bb2ae2b761347874e3060f5198c6ba26477a15e8173e11a636bc7b3735cd2a4954f092cc8c7ab75a3fc7d42582c3a57ebc5f96fc2df65b992cd4478bb5c1af5d16032005f46a49af2350597c7e1c0330edf10306635509ad01963bccc7a2f7e8736ba5fd7c70beebcc5f8e693c2675e877c2575f5f8a24948301648f47a6c4fc9c5413bd90128a6ce9969a244108d9fe18f9b67b4fc36300d72391a02d7f0f1449910a59613704b1edb7acf69c3c973d6d88b400f60cb5ee79860cbc642eeef04d3335df8d33d22b8044ab8f5ff54ea7d61ee73fc9589300c1264efe2988163f427de2cfbe556cf84ddcb223e0cfa36d9f6adc14cb30b28a2651ade04194acd6c090f48689a1ed0f74728e4231e0fef323609a7266b2030bcdfb92b89492a16611f851c743d3b44c92f276519b7e1a3538a183ae180bae815ca52eadd2f6134113c56ec86914e321539c27bde01453e644532c7e8ea88d4f192c294cd01222a0ee0b40e8548fc0c3cea675f27fd63efd2e30ea3f34ebe344f62aa16c5b5ea0006837b2cf98bfbe9cd14e92cffdd3ada9e72e48ebf1bb2b4c7a9f9e0aa3beb7e7b0d65955d172c530f5512032d49c7cac0f56d2c7f71cae2c849c58b09a9a9124afc7fe766c7b28c84313f4bee620f6b1b5c4a547f5493712a0bb9e6b20b2f1f1158aa296b467e30f601b7aa295f607ab519a35f535c1d2213d5fd3eb47cac8e315b2e2fc18b16e9803a2553f22f185e6cc6d4d21373669516c81852e6f0f905615bd003f1dffb2712147fa9ae2678234015935246e0ca87f0eed6a2599607d6509481cd64eb426f3769b5d9a6623096669a57a38d5eafd7959375097b972bb2c40837a4864f107adfe9e39093b75a913b793a2b47de772be5d3814a836d6912be8e1b42d913421fd0c98e7fa8efd9c4a1f352ed8580f21fd0eaeb4e1ab3a43745317b19ea86fc1a67001d72d28456893575a2c1e0ccf800ca3e5980c673019978477963eff624cc2611c220ae7f4a76be3704e40b4eb67c11146563679db24c79efde58a177324459da00722f9ce81c0f5fef82844649e1a4c7ea723fa0f4d44bdbadf1c7827fe11fcb1d66b24a21c6e0a3d09ef95a9295f547fd806a0456054efa8f6c2ed15dabb17ba476bfa7e110de20161e28b77db0dc32f66959d0411cbb9ae7689ddf498daeb018f63bfa41d984786a3859060f06a1cc75d28b4cf542f321d5784eed082e6d2265c606b47f219d35969f86317e9e57a4670be55f9d214ccc37735dda0cb16d800ccc3fed79ff0279edcdda02e99fd38529eb3d44a9b14c45978357aad44d543ea75b084d323f3d6fc57344443062356ba9e0696b32f5fb11c5d62dea88916343c9c8b5cda618118b3ca1432c5caa3478c2257432999b4b159305d0999bdc9d9f322f7699696f0a1e466b65faca163c8db731145da831c11eaa4aaaf7488c6310e9694cc16b55f92c13a154d83618570cd8c93c9aec10b31807bf387816ce4e881ea588b6edec8f996ffc561e2c79e99e5486f4aaff9cea6b33612f789c0ddf31fc042d647389bc7352247976e9ea5518862f40cbe19de106bda8214c027fda374ed9e6a2f7e863b25123714acbd5243a6d3bc7337bb83ae4b19c49b3f5c0f8b54188f8a806d894e8b59b0fb7c61df53b5c008b6372c9495353148fa0afb85e1e4ddc1b9aebebbcfb6ab9066acbafe7550656c92ad87f72b4eb0a9e8189c4dcc955098ad0c6c73d73b055083105e372f5a4fb019f7cc8e49e1c18d5fb212bb215eac93e49903acd3c45c9b6e5c4c97561a374c01385019e4337aa3e21e1736c463135b3b5a8a79a21df6e5f39a4381a9b45653fad9781cbab82fa1f1fb6590dec5592cb41b9440c0916258125656158093d5c23e12578935d944fef797629e0c1885e3c8f37ee0e78e4fe6afd75bbeb76a2290715853442bc40399570e9cf38bb43eacf64474f0ef5b64c41c992dee2c08eb097ae3eadabce831fdcb927eed3e85a8da8228a8ac9cbec49d46c714675a87d1e2ff3d0c3e46d3a09a66e022800235a34829649012bf3aee003e0425402575b11565bcaf3ed3b85bd0b654112f8cf6fad2ab5f0e55c071e61c1d020ad4dae1a9e7682d460b2abc1739213f6b1b9d0068d0dd6d73e5dd2807e3bf48437a9c1f47dd2a03439035c3d20da1f085644c485263373e9ae297d034baf539459227b398b19f638846195de9a18446ef52c334a1f6ccd6ae78865a618b9e41e3c62c95f6b938ca55a35462bce68343bee15d9a9fe511f12fdb587ccab22a13b37e215ae222867123dfa1777df7f5b0b96c67c8c19818e2a46b00d3bd974a0e18d63ebd87ee2486ddaf7cdbbf1c0bf081615090dbbfaec000ef4c72a88313dbf5ba803f32c593f862fc1fde8943b3ad12dea16bdb6256b7f3ab2e7f59ee71a8ae3a78e0a1c03bb4118f812ca7de18e379a8cd2d2efca9d65610105a7d7f6e758c238046b3965c8b428d10112df108f2735824f16bf16735a60b7e48355078eae5d9490647d1b0f7e8d7d0da16094f2ac586cd4d26f4b0db620bd4d76ae020c26d4dbdd0061fed980691a0d5ff1dcf1592843ae2dadb4d9c59d88c2429d63e54872afbfa8f00c3e29a08d87af7a5563e9b51f9922acaa6961cd417bc9d20d6735bc46b6d197d4b7957819aeeaaa05d022206a10af1704b15a60f7724a22197ed0e70c65db8e86bf80c0e19bb2d6769db778d1ec0d4af50f185b7a857ccbb3a9d49f74214388e1b3b761d510219f2d78df98e1f8d6c1308c6fba7692eb92ce23098e2a5c914408226e8be1143d0597174451624bde6c53da2206397b1516d43f3a49d64b4b42de06ce7dfbd25d54745cd5bae8996cc4628d674209dcb634e933df0ba675aed3ec7b66a9e501b2029b14b17016da609bb6bddb73785062bb797c238e6e1948823399c8e04cbc7cd7a51ba940074ac5654e3c27ccf577de9aca2f40fb517a885620d649cdce4069b4cd58cd63caea04a1690673608e0897448da7961e390bb75638cda24273c8d9f29891112504deba478e8a7327d4bfd653ca03d55bc2931c1a86440d436798c8c0343422fcdcde5e68ec977878095bafa94c06d39e79638a772bcd964c36ef9c375870376ad10a1587fa52f49519d7169665a2373d85572dc6722a3cb7f89b14decd2815ce7dfe7086cde956ef7cd6b7fec55eb3c9132de7490cf52c218b07a4d99818444e28c4844b2be58d731087acf8f9ad35eb4f4460d478cc2edaba6890b08d0a5f6799a370c8b43111ada63e619b9987b785ffe1b606fcbb0aaad0657c3fd987c53a95ada0b054d5343ca945104a1bb24a0c2dbbb1b57dcd1ad4513da0424bf3f87daf0f86e73e0b8be1a88ea652e06f21503568e49041fbc7a4774b2018796a2f8f19dcc3c60a86feb2689b3528bea2ab251eca2ad2d9fa7d3d671fdde5232c2d9dedc19fabbdf2b245fe2ea0fc9f1b6412005e14edda4d947880bd39ed99697214a70404143bff0fe8a9fbd65d1ba2c8381f8e718404d0a4dfaa8ff734bc1d328bb385828f545225a50716ee84e7447d8ce69d7114b688e8978d796fa5d1ccf2b409f6322a7e213f1f04a284dcd2cecd183b06083afe843b72505ce648e01d37cc37d33a38b60961179e2d1c2b60e020438f1621ec505458a09db9389434fcb7c6d720087f34627e6c9a192db1a6703055e7349f90a2410acaf006be91891e52077de6d7de0c291d7da70c7f5eed7736941f9e43a070e8d24445ab3e60150335cf7aa1e69ec82a4e8370e6dde4bbd59c2309214f1aa6b2d16920076b58e6a16a5ecb34f6da91e3f417b3afd59e4dfcaae23340b51e7e71c2e20af5916b6b6ab8714cf0a1e853336d47f48faf735f5f4264806e4fd617bbf6c7b82b70a55c62726272f0eb8fb0b95b38f45444b7e840c30b7f709db70d4d0175186fd37a341cdadabb48f358a0b9f7b4eab70000';

  const signUtxoList = [
    {
      txid: '4aa201f333e80b8f62ba5b593edb47b4730212e2917b21279f389ba1c14588a3',
      vout: 0,
      bip32Path: 'm/44\'/1776\'/1\'/0/12',
      // amount: 1000000000,
      valueCommitment: '08b760fd74cae28eaa41126b3c1129b2d708d893e17b4e61bd9d5a5b12a1c7643b',
      descriptor: '',
    },
  ];

  const mainchainNwType = (networkType === 'liquidv1') ? 'mainnet' : 'regtest';
  const liquidLib = new LedgerLiquidWrapper(networkType);
  const connRet = await liquidLib.connect(0, '');
  if (!connRet.success) {
    console.log('connection failed. ', connRet);
    return '';
  }
  const pubkeyInfo1 = await liquidLib.getWalletPublicKey(
      signUtxoList[0].bip32Path);
  if (!pubkeyInfo1.success) {
    console.log('connection failed. ', connRet);
    await liquidLib.disconnect();
    return '';
  }
  signUtxoList[0].descriptor = `wpkh(${pubkeyInfo1.publicKey})`;

  console.log('signUtxoList:', signUtxoList);
  const tx = await execSign(liquidLib, txHex, signUtxoList, '');
  console.log('*** signed tx hex ***\n', tx);
  if (dumpTx && tx) {
    const decSignedTx = cfdjs.ElementsDecodeRawTransaction({
      hex: tx, network: networkType,
      mainchainNetwork: mainchainNwType});
    console.log('*** Signed Tx ***\n', JSON.stringify(decSignedTx, null, '  '));
  }
  await liquidLib.disconnect();
}

async function execPeggedTest3() {
  // command: npm run ts_example -- -peg
  // OK
  const txHex = '02000000010103ae7c6c1dac6f9b83c100e5bbad2e6262ae3f1932ede271150aa0613e7a50990000004000ffffffff030125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a01000000000007a12000bf6a2006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f1976a9146fa03ec68aaeef6f429ad9267f29ae98d0d2b58b88ac21031797e767f8ea79110c2d911379ef8210ccaba0f06a0721a1c570806305b31b0a4c5f02b52d98d53b15559358aa0e037f77ce6eeb10cb58e8aafc6799fa20b2f0525cb155005226b39ba21881e8afb5c8a0330c58f7b7337bbe4d88ae03e9d6e446071111111111111111111111111111113d48c241f7ab5b7d865faddf3cf0c54c0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100000000000001f400000125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000000079b440016001475f7cda67f3f421152d438573282f16e1ec39466000000000000000608583e0f00000000002025b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a2006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f160014ac15c9bd0ed1641999c41fef64fb3c9ff48ce29dc002000000000101424aeb8cd9e48964d693f0395d4c228064de9c878b0c758f4db3d5c0b33059980100000000ffffffff01583e0f000000000017a91472c44f957fc011d97e3406667dca5b1c930c4026870247304402206ad339157f0eacb080eb4f956253582adab6c6381a314d6f2a7b9d22aa10f21c0220422c64d1a4f7f1d70b409a4482bb9fa07aa206a8110eed7794f91f91430fd9d6012103a075171877c4e93df48a3f9a078b12863e1053c3f62315abe7b8f23333c1c108000000009700000020fe3b574c1ce6d5cb68fc518e86f7976e599fafc0a2e5754aace7ca16d97a7c78ef9325b8d4f0a4921e060fc5e71435f46a18fa339688142cd4b028c8488c9f8dd1495b5dffff7f200200000002000000024a180a6822abffc3b1080c49016899c6dac25083936df14af12f58db11958ef27926299350fdc2f4d0da1d4f0fbbd3789d29f9dc016358ae42463c0cebf393f30105000000000000';

  const signUtxoList = [
    {
      txid: '99507a3e61a00a1571e2ed32193fae62622eadbbe500c1839b6fac1d6c7cae03',
      vout: 0,
      bip32Path: 'm/44\'/1776\'/1\'/0/12',
      amount: 1000000 - 1000,
      // valueCommitment: '09606bfea1ac0b8e59dac55d9ef37e6f43cca14794224f14207f854aa924fb8a77',
      descriptor: '',
    },
  ];

  const mainchainNwType = (networkType === 'liquidv1') ? 'mainnet' : 'regtest';
  const liquidLib = new LedgerLiquidWrapper(networkType);
  const connRet = await liquidLib.connect(0, '');
  if (!connRet.success) {
    console.log('connection failed. ', connRet);
    return '';
  }
  const pubkeyInfo1 = await liquidLib.getWalletPublicKey(
      signUtxoList[0].bip32Path);
  if (!pubkeyInfo1.success) {
    console.log('connection failed. ', connRet);
    await liquidLib.disconnect();
    return '';
  }
  signUtxoList[0].descriptor = `wpkh(${pubkeyInfo1.publicKey})`;

  console.log('signUtxoList:', signUtxoList);
  const tx = await execSign(liquidLib, txHex, signUtxoList, '');
  console.log('*** signed tx hex ***\n', tx);
  if (dumpTx && tx) {
    const decSignedTx = cfdjs.ElementsDecodeRawTransaction({
      hex: tx, network: networkType,
      mainchainNetwork: mainchainNwType});
    console.log('*** Signed Tx ***\n', JSON.stringify(decSignedTx, null, '  '));
  }
  await liquidLib.disconnect();
}

async function execPeggedTest4() {
  const txHex = '020000000101b95841a5c58524f50ef927d9dbc12e563a1b44835c4d892beb64e4debefb5eef0000000000ffffffff030125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100000000000927c000c16a2006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f1976a9146fa03ec68aaeef6f429ad9267f29ae98d0d2b58b88ac21031797e767f8ea79110c2d911379ef8210ccaba0f06a0721a1c570806305b31b0a4c6102b52d98d53b15559358aa0e037f77ce6eeb10cb58e8aafc6799fa20b2f0525cb155005226b39ba21881e8afb5c8a0330c58f7b7337bbe4d88ae03e9d6e446076a83aecf7a46e25c8a37ed81aacf5872463d48c241f7ab5b7d865faddf3cf0c54c0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100000000000000a000000a0ca7476a54e4dad4fd2b89d2af530f979f917d8577bb52fa7e0bef673cb1ded309c97315f2af4ab625925ab4bd7e84d10320fed30b704cdd1dfe1ced5fd657bbce03837fed6785bb0bbea956f3a983ce42a0549fcc8860a7bef7c2d96679ee0a1f481600142fd09be108caec098d43be8667b5075a2f4bb537000000000000000000000000430100017d674753286a3cd35dd38d3bfb38d11c323df9805dec5634dad67f1be58487dee55bb862f8467ee3fdb22b60716978f8e2104b65e49623c88a843226db9d5038fd4d0b60230000000000000001694701480d071104b7b9af792ed5224f811b272d4180f8a87ef451ec6c6ad41f6d946d265374a46d1665a41b39e4a7e54603f207d338e80a4ed4394f788e6168039037857545f70e6ccc5c2a4549fd0d8efa64cfb799089ebe4cf49bd71b57b519f8a4617873ceee9c3c9bd007538f781759f59b482f450b7510e5c3f3e1fbf7fc3fd13d048ff8440a7632cbf4786ca282a8d977f4cb48d69ce77ac9d62a4a5ae03f7cfdd4b4e52d593f91ecf29a17949f71fa8f941c64fdcc462e86aa99f068ad22a634ec1a4e0bb8785c928e0b8beedaf11707f481fc8242201482d5fb1098b33543073645ad78d4d0c6f198ff14810f737e269424727b225ebf20e64dc19524867d89769ded3e04727525efb58168c71b13e47b823ddb4cdf1ce4a044e3dbb16d8886b5a2b8b7a0f181154db184d0b3db598f026ca45763274d87e1d818c037daee5b3ce80a4ff9081f50de7c385a1287629271574133a7c501deefa5c80a21c497d3d139f573d80d741caebb6303448a4e0f3ee3147b7dd58e24dd96031d1009d4820bea173afa62edaac6e1d4fb82b1ff02d4cd9dc66a044a13f49457f9d6c12b4b06a49ff0b4b4ed71d5b257d1c947d049e390d6da4a5d14997941b0055f05dd5b8214a237026852191f3efca2abba7110513951e57a9115825f9071659f9068a665d25f92e6a1480feaad09198244282ff70fe93502f2d272ab3f60e0326e094a56b91b756c3d6c648673a8a609254712d261d2496b40625fe394e6a41ded96439fbab92fe8e2a466caab792186b8b9f4e0dcc39aeeacc65aa8b240d10eead67788ee1370f92712e9ab31ca4420fa148c343d67cd1c3b277fbee9366729695132163684c486bf2da2bb0e5197ab49c2ca71189f67d13bb95fbe28e80f42fcd9a712341d645fd7c8f48196298854aa629678836720f114266607e2ea6a6df3d4c20f5b91e270c29aec4b5572a35049b686b2306f78f899ac3cedf5ba15a3e312529856cfe6c62fcf252bd5dd3ca01317f03142bc3dcdad662a29e2aa91859a9144128242a8c6159fbcc45185791d10a79c1d58a2a4fd135b4eece26871629103e3d50548f3aeff5ca3b3dee57567fded6e7af6229b47a65cc2218469e99b08c03507f46a4bfcfb680fd770d6bad6b00d3d9bd2ba9ed087fc7b5485e798660bb6830e348f2f05069cc8b3190aa9ae1f7dd1d004d7761c25b971d8f2feac58bfc8b6080d5ee126d7c28f8c06a4a688aea0375314a7d5a9aae7123f899d8455156ea2521b10a46998028d2094fb46e0eafdc0e94d0d8643a14bf40dcd118b99790086c688d7d771908c1241531b005f1ed1f07197f76819b984b9fa4644ad0a1813d1a34fd08008fdbcefb95d23bd0abde9ce1bc903c4b6a78a7702ed6288057f7e00aab4cd47483128dab5d1c33b8636f759d245818564cb0ebd8fdf599f9b991cb4defadcbaa71c4b1fa76f3aea1f5b08eb6c4d33d4a8db6a4c0021692048f2dd8d2e37f244313b762e681d1a0dc3650c2ed963ddfbcd480715bd26e837c3542246562502b2a7f977b5081c3b96d5375d44fd8adbc8b036927eaf6a4f6e238c54921de2a1f31654504fb24c0f056f453038c3f65e29dfcd3c3676c0e77fa53da9fabf661edd90ecf72e999dfb799155292958dd5c5c083fa6c27642ee6bf8dba347673d3998048aa85f4046f3d97ad15f0bab71ac5169a2b932fd2c6bfca631e6368fb85875add5f01becb10eecb5b4e772d27d6f45059b65db6e2e939a30243066afbb97efa89f7d1edb52cdd70971dde1667b95e225acd7b1a96dcbeb05914b81bc9a21431b4d35815ee5e79d3c780049c3b55e7379b6d290e26d5f89417c3faad6e9d090e8d0d59bbcdebe427f3086b8f7c27e44db620993cc9ed369c9533c26d54b6d330e6c7f5eeb2a3c8fc2e19b62af6ef9ec847043cc73970b97bea1d49a2d88b07b43294e0b91c44f9e2c9928060c2023ec8f806b47fbe978cddf300452343155b312daf6958cb392ef6a74ba743df3212c49a6b6dee336e09a2de3791a723f1a3161e8bacb11bc09c7e017afeee711033a31e281717404dc5e10d8c64bcbee2c72f87cd79515a9885e225d14b4dc56f5c2a0175d8e947741d3a7f8625cb8b78185b0e98a36367770b3465ec52908334ac639c5f265f0c5a87100cb248e89d2deee38c5df63b04a73b57fd71bb286cab62c49cd8c914f91eec2f7b722a90e536a31b82ee50c989e0e03ade7279bf547e9d7c88766c7c76ac66a2cfb929929c244508bbecedd63e06f826f74fc1e64179e247cf841c574d6df9916e8bc3d0d2590057cef09f39dc2a614d5988e33b7cae70297a186e2ebfd8c3d0bd71312dc202338c9008cdcb06ed5c94e67d6cae2e1ef8a7557fd2626dd5a1159e5632e17ff1d78f80942cf23f652f554a5e1851d086aaef4980a415c1c30143ebc8d339fea7b014d6290e2d018be71a59fdc9e5d994335cc8db52e7a1732e5fd92bff8d72267fac063eddcd3b92d45b12dcfef19d07dad93d1f739ea8686c8955122fd6b9ee9a0e64850b2faf7cca79eac4a99f3ed04247fafe10bd5514c70f6f1da855e0fd807e2add3a8f59697926514b199553cb67e38597f461e6150714d0a6f0fb27326828a4afeddb99a5125d734a82eeec91d3ff251030991493c0f6054216fecd0d3b9151acfc1afd3d26380bb1498f751cafa434f61cdf095fc7a75c19cafb3512889fec9e22996c2a3c4b9a1b2255118011f61997478cdbf99fa0531ec8a6e8c79d74cc811913c5ddfd53b329a81b4c5062032c725948a40c5a003ba37831d44ab6333e9c523c88c106f9626110f3fc72e259b806b5f9b4b9d7d41fcf1ae483c45aad4c9d1580ce289292a6415f6140b4ed3d6fb3a6824867fe1dd9e6b198d2b30c302dc42d3ac6568be0c15727e0600350cf5703852e8ce89b641d9160d07af9b4262f265fe64b4433c8b807845a2e9b47071de3039b4197cf89367495784ce5ef1ac35e7194900a0bf12127a98d265ff8a9fe83ea7e61aabd427f38c4485a574cc61280594a8feeef23de1c96fa1ff9d6329fb9ade90743ee952917a5ec32e7850d9ef07653e304135ddd725c33dca963f65643ad667f773b527d5cec1170ac9cda06fd6572deaf33eebf83f40af02f7d22a65a283d03422b87cb62dad3b97c705b374e02b1b6efc91889306d7cbb082d6c8c28ec10d5cc5e687c64d5610469643168d8e64e08b9871b7703fc9b57eda458e4663c71d848a9fa5077467520060560ccaee5946106d819a4463e071dc39cc76cf9afe8ec17b5df30b7ed9675ce64807583a3d70e901dce5bee5636b764b028dc28114dcb54b1a97f99a4538ea9ae450827ac1645ed971dd3d49ef7abd77b0007de66ed437ebd5edb248a54f9dd115ee995d3f9fbfbb7fc3c9299328919dd6eba70e39676135e9c7a998bf417ec2eabc3d7011d9a0d5a4fdf4a4cf3c5b7fa8e017647dfda9c451c93446961949e79ec02825cf6eed99beebf7ba83d81af43faace63680a7d79c8750d5655374a33d769d8dee911b292e373e885be03ed31d0852d537dac106e86a1b7f873138adf992102b6fc1720acc67af2d276c6140262763a477b656698ab08944253b55038fbaaf13782c3cb933fdc86a8e21307761f5f5cbbd13ebb0281e33734973ab3faf8ee9b2fd189a28dd2f1c705540c82b1d7c2442ab33b1bc25fa64e7aea16dc1cef0c1bfbb83419a8e056f820fb6f945d4398d89646247f45b854d48b6630d6e94c8a01d28e23b06b16ec4d5c579c046b57c9aba8243a4c020a9b1be41f467db382272fde0408e3269a52cf64e6c40392e45809572ad59270ba19818556057de4356113f2d9ea8306101c24466b84db1531a1414814cd2447dc0f5776131141c8121492daa9d8f1dedad49767846ae8c178d07a30bfad378f1ba01c0822815154f2701e11a116561bd17465093552b19446cf9c4a3aef9868041d77b220e3340e8d9c885a553f3ca5237ce9456e8cefb6ca8d4b9601ef39ac6bd618570f1529cf2f2cff88e1edc5f4be90a17f28f4beb94c8cb388ed02064c58a857de';

  const signUtxoList = [
    {
      bip32Path: '44\'/1776\'/72\'/0/0',
      txid: 'ef5efbbedee464eb2b894d5c83441b3a562ec1dbd927f90ef52485c5a54158b9',
      vout: 0,
      amount: BigInt(10000000000),
      valueCommitment: '09b44c652a806959643742a0c80f06d72fa2c8f4e7db34889067ad94f8d3f64199',
      redeemScript: '',
      pubkey: '03acfd9f2ef7cacf72787febd78130d5c1f785545f964c5dca1cea139b3aa176a9',
    },
  ];

  const mainchainNwType = (networkType === 'liquidv1') ? 'mainnet' : 'regtest';
  const liquidLib = new LedgerLiquidWrapper(networkType);
  const connRet = await liquidLib.connect(0, '');
  if (!connRet.success) {
    console.log('connection failed. ', connRet);
    return '';
  }
  /*
  const pubkeyInfo1 = await liquidLib.getWalletPublicKey(
      signUtxoList[0].bip32Path);
  if (!pubkeyInfo1.success) {
    console.log('connection failed. ', connRet);
    await liquidLib.disconnect();
    return '';
  }
  signUtxoList[0].descriptor = `wpkh(${pubkeyInfo1.publicKey})`;
  */

  console.log('signUtxoList:', signUtxoList);
  const tx = await execSign(liquidLib, txHex, signUtxoList, '');
  console.log('*** signed tx hex ***\n', tx);
  if (dumpTx && tx) {
    const decSignedTx = cfdjs.ElementsDecodeRawTransaction({
      hex: tx, network: networkType,
      mainchainNetwork: mainchainNwType});
    console.log('*** Signed Tx ***\n', JSON.stringify(decSignedTx, null, '  '));
  }
  await liquidLib.disconnect();
}

async function execLargePeginTest() {
  const txHex = '020000000101cc416e87382223cfa9d82d9f465d81481f5c5d83a39276b4dfc36c641e8e99ba0100004000ffffffff030b249f7ca912b420cf9883b3c5074d4cc3998dfaff2400327eed94e730e812811209171a0c9a59265bcfa51531f5bb6063d2146fc6500364dd2d741812423aed111c032dc4c13adbdbaf233298b05519f76914242dc11714d863e9290b7f4eb4a9bd1f016a0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100000000000002d100000be18f3ba66f211a9172bc62e19366807f739613973f811f27ab6030b1c10e59fe0812efd5b90d7223d7538ba60ccab8be4a3d6d4570efb14c6a73f4fc03a4833f1603743e3f89b60e8d1f8ae02ed6a9e84bb784330ab1dfb6b80bb74afc7842ca2b8216001445e45f6bf24481c8c1a23db851d4023875e1ba0300000000000000060800e87648170000002025b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a2006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f16001445e45f6bf24481c8c1a23db851d4023875e1ba03fdfe3802000000000162b16a9fd3c549ae37d932ed65ea08bd0666bf2bec297da32a3331c869a4a02d310000000000feffffff847ceb94b0c986bbb2b938904dc6999a57cbd54ca5785252aa6d9a49729f09290000000000feffffff5d3fef1a5595c8fcf44dd27ca01515c328884cd610abc93db5a93946e1c18be90000000000feffffffa481ffcfb2c7487e4d1d471726debeb7b5d73c922cb142f2c407e9744596c5780000000000feffffffa18bd7050edf28d9353061e2e8b8f10395e18a025cb72492763430e5f3961d000000000000feffffffd425af9d0057729ca39eefa4ed8eb6eb754f91192d14a5e73ca305f8cb7e6b090000000000feffffff87f80ab97bba4a1c09661a011d1fa4d3ad41e83991879c6b8e3d99c837f308830000000000feffffff3873860ba59d36336837b39e1d474bb62c479e4dde6f5d0dd6f3728a784738950000000000feffffff1624b9cd40b92d33f0ba60b0f71471b0d43e47a516ed58dc0bc173e7d75a69800000000000feffffff4222857f8b18c4af18225178a7fe62f351058fc42c9e44130f4495e6814b0bb80000000000feffffffa3bee4c9dd202bb60c8f67cc04b3778300d389410416b27d1455e9db10f35c3c0000000000feffffff831a865ad9dec7d46471e7449cf9a8fdc37a5ee81e65870f6894713f63e7063b0000000000feffffff7c1b847ea8ac74df10d018c6f335ee40aa9cb62718b5ceed1b700ce1633459ae0000000000feffffff43272aad102641e7855a8a3db2402e90ffb05bd4a25e0a7181395b6b601d71190000000000feffffff7a4dbb1b4f949a875f5717c283464f66bb3458ed207023af6281dca5a2f5c1bd0000000000feffffff1709ffeee289577553eb087270384e79596b81eb0234e377429a0cb6571b3a560000000000feffffffdb0ccc8e4a01ec3160a26e860383530f7cba046125839769bee3ba5f84f8450f0000000000feffffff53160180d58e23a1b4d450580971639c0a632bb1acac053fe69fbf2108cf645c0000000000feffffffabd98c794bd512a8a65bdfe8c411f4566e8a7844a0affd6b431507391db577ab0000000000feffffff4d1f4ae118020a0b4cea18986398b55d267cc1bcb403eb873a26e396213bed050000000000feffffff9ae758d4ae77f8ebbaba1431db0ab6e53b43f8e93a5d14fc2646d1fd4688edd30000000000feffffff6794e784b0ef5fbd6b2811fc9585364b3e379bc161c82c3ce6035693c1df11750000000000feffffffcfe24c4ee9e42922c8fadfabdfd3e21a5c91505fc4ec552c36f4444dac2e9ef20000000000feffffff707114ae61129c1f3daed73cddf1c40470fa9019102953173905792b9a3097980000000000feffffff9c135eecb7b7c50c5e84e1abe323e96078aa697a81ccf6b81d3b9f5d3369a6760000000000feffffff31cd4600b0c368e16cea0a4cd850788af7b78d3349a4fd101632b8867cd5a5c30000000000feffffff4753cdfb050fd633d7c7097c18bf2eda6446a075cfcfe619e167e351dcf87dd50000000000feffffff4dbd43a09fc8a78a1aceadf1ca0c42854c971c7b4b4773ee5afa41e6dec4721a0000000000feffffffa35c190ce245dcb0fac1ec614373f46e754d7e82fb640fec94730878eed3d5240000000000feffffff27061f65ca96d6426815eb0d7b563af4d1c69536fde1aeb23b5c078b1e537d320000000000feffffffa2f77bbccd69fc998eab99f0e46543124e93127e53ef422716d6929dc940a5ef0000000000feffffff134e7ee04bb5f74734fc10c0db199896106810950442269e0a5fefe8a2efd1f80000000000feffffff4217ca62c16731b47a14674dc149923e2c2a1df96203255501491b33d3f7eec60000000000feffffffb4f7f976c918222391d7311b9f8bcb3af06bfc66542c38c2984f2ff7ab6852b50000000000feffffffe16ab78cd2e7543834babf65f8e18cbf3dc9602b0b3eaa8c0ac9914e68c7e91c0000000000feffffff5bc2314a7897615a144601fcf71ed1022ad60e01e8a4ac3778f0a7cd858fb3110000000000feffffff0bca52b750d5978749c8dc2b0c76b293ac95249f2c060605fb980825cadfc0160000000000feffffff093a97a4112b015deba571a09a081096dcdafc0b8eb0add1548f34ffa741bbcc0000000000feffffff2fd702f440e333c0f6e9f2ee37f9fc3fb12a823b4421b6aba23b182bc25de5910000000000fefffffff50332ad5f8777b95a8c9b1e1b0e0f88f4535fcbae36f2bebcad97c0d99c5c650000000000feffffff3562afeec889c49aa1f5792bcbe922248e4fe3fed8e0098e0d6154ef40861e540000000000feffffff0631f1e9b3b1aaec654738c3bb92dd11432b66e8b58a6ea0cb2ca5a67f5a69520000000000feffffff6228e893505ff69ca408502bdc75c57bf45189afb7c397114e7e7562578406030000000000feffffffb3399ef340045fb658ebbfc60840f50b66740b0bd003c9813976a484275fce790000000000feffffff9b2b4977a1e62139fa9387b8fcbc563ac115760a9eaaeee786750ad9e721398b0000000000feffffff2c7d32ae96494bcec8773278a27ad2b5d870740f638891a4792b81577579ad2f0000000000feffffff1e28f65b2159944729ccc7baaa4ac3d05f041d9e5b997d6aa51d6183449f823b0000000000feffffff27b2ad888ed210de4c5769af6569be598959f5c1154adb8bf69712f8924014200000000000feffffffe8ae8bd5d46f0bf54fa725c3ac47b5d03b4b1f85213076399db34cecea68e2a70000000000feffffffb6e52b66a086fd55cf476e74cc985673eda611709f4c5cc590283c1d1424b8570000000000feffffffd069b7822b4f3d74586428cdcaeef03b4e5a522a7cc6995e75b4378cdaa630740000000000feffffff90631d49089e043c546af1c3da6eecd141d4888c5b84444f5484508a822052a70000000000fefffffffaaa882ee2d7efc0cd0098c2a726a1ae7a8b5d1a1e5256c18ba79cd0061554e20000000000feffffff487ca1e022fb485a879001f447f1e4694b450f6bcdc984c5d3e501a3f2f335160000000000feffffff236455e378c2c09d49735d54729955e32752a4c53d983cb09cf16b7054f6f18c0000000000feffffff2037d2e6fdc4a327d3347394d847064c82883c5555b0ef9ad15ee3005a999d190000000000feffffff129d7a1152c5935673123289069b767f60e43c48c73de6a660f9d688b8880f300000000000feffffff9262adf668182a241fb9e211fa9ffb7ab03164466a9408538e7abd2c584791300000000000feffffff59d19797bda557fafee11486810e2fefe62db96cffec48dd9cb65c224a7dd2ef0000000000feffffffcda0c46c1d27777d93c865d5b7e982a639f24a30102c6492c47e83eba2f5e79c0000000000feffffff20e6282a7553af9c0c3ca28623caff570608a997b668064d2c70a67867d64d8a0000000000feffffff61821c062a84394a235f6d450e5de7b8fdb693084ca18ae8f1bd44f670d8aa2f0000000000feffffffbc9ff373e8dd2887055802ca27f56382366121a44f03508bd04e5022c059b4700000000000feffffff47d59639cdef0f71d7a3c8a0755f832d28ad689d7abc1377309b533dccadf2c30000000000feffffff845377fcc3dc039e628688cd69353ce494136d73dce61d9e28aa46f8c87c19100000000000feffffff162d48866020989d7b5e992136a568d29c40e8e9e8506d08d314de485cf227440000000000feffffff90b438345cc611c3910791b0ceccf3aaa34db3917db0148774897cb5639833fe0000000000feffffff3336d09f5c5adf25575f1c9b633022fb177a940218f1042c0cdf0abf2c8bd84e0000000000feffffff43af6ee8005dd355b0fc0478c065b2a4fb55e0cddfed6feaeed89c4013a23a300000000000feffffffce561592a6f14fb84597e98ca02496e7bfae80676b86c5a3220f2bc19eac40290000000000feffffff3e60604e68703bce78eb099dc24402de123891a84d50991fc7a7392716897cae0000000000feffffffec318e6fbe30cf502cba1d970385661a98c15f2e369a20dce3e53436153c008a0000000000feffffffaf348daaa9c6eea99f2dc2c3f7bb2018ee0973723e5a041537c682fffb1ec7050000000000feffffffaffaf440ba55aee64f5f8d5bc56eae31e401c975d9ce977bc5434735621e86e00000000000feffffffb840fe9d8caeeb27caeb27cd24a70c9c7636da0075378ca6696c9697aab903980000000000feffffff399795d6d80bc0e468c58d263313bff72f0b5870a59578064d6ba484ca8b0a310000000000feffffff968e05f14b27bfd0adb5647bf5e03aef917362fcb14713e3b487a58cbb8143220000000000fefffffffaabbd488069b72994e2ecb11ffa0674ad041985001722ec80e5383c98a4510b0000000000feffffff07d246e1c260fa6871c0c98b3e3783b25ebb5d75a78aa42904e69e26829c86290000000000feffffff514a5afc6d2596a3a37bb3d26a5a5416ad3d35cb11287b687de88df9176df0a70000000000feffffffc18f88a1f11e2bc07a6d7ba430836f597b78e815f50212db6d3e5c0a4e2ec01e0000000000fefffffff88362aaba7db3f530642f1d438effb2965cbe31181173918585d5a3db4f57a70000000000feffffff3654bd3a76902c9dde575323e293e8299212c7afe2503474148d1d2e26b4e3120000000000fefffffff984e118391a4df87d9f245c2f135943d7369bb46faeaa65bc6a3d97e1ac653d0000000000fefffffffe8e60ed7bb7634c8d552cd8fcb207c63b03a57c0e07bc0d27d7bdbd264155410000000000feffffffa935591c956860b77b9be96114120c190d36a84ca87e5375a3dc18b0b3899d710000000000feffffffa9ea2eabf0475e66761b68da1e666d71097a9d3e37ff51c108995bb1c84461b50000000000fefffffffaa3e0215e5a62f1c170bb2db658de4b6a38e87fde8d84dddfb125e77c766ada0000000000feffffffa592eda7c19fb8637177357b012877c64260af8cf438b328913c7d228f1b52e60000000000feffffffc201f015dc3d1e8882aae20bdca4d62629cf36537e3b37ccc22632e434d9e0e40000000000feffffff917687e609fa8d6ee150e085f4e2dfd9989611a0195fec2df82c1e4bc3d68a360000000000feffffffab53347250aa09d2a7157cc128f158cfe644abb465dc461715804b349887671d0000000000feffffffc9f6a3eaa1fa71c8e0999e105bb898ce0d04b31c511fa1b34b51d9eee287e3310000000000feffffff6efd27df9bc90d1460d40197472d245fc8140862e246f59031502c7ef9f7ca650000000000feffffff78ba2f9fbad47d227ce806cb50f8a59f992bf404253b1fb1942790fa77e0adb00000000000feffffff9532520648e7ea16cc0224659d53919131694c64122817029943dee67e2db4670000000000feffffff838c779af18bc7cb30cb8f580690526097403e7ecd8fe104b2d0349f872c67210000000000feffffffb89ba942b83043fb31b7112dbb9a5c4fc5614650bdda0537af35ca23fb9bef450000000000feffffff02bad4930200000000160014f26b3cffd614c3a043e8f74bdd75b9b61b97e6f400e87648170000002200204ecb96526ed28b19f3ac2f5144893038d336dec0485536062260173a5e607caf02473044022042ccfebc3cbd79da84b04d1648b99b88d01ef0c431c6fabeadf75ee871f4cce3022002bfec08459a9c098e0dbb3155cea57be3c4e424c8ebd1029863dd96f53f0447012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe802473044022051fa247b80bf6a704f5ad5a507ec727c3ada16c56bce712492627270312f20c00220338777a3c516e16a935cba2cc638e394ddbedb0df7daa4b05c2e923d85d5810c012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe80247304402207beca300a153959b0be68d075efbd9d029dbb2c061b802437e6d9fe95bc721c40220352af21fa34b588f52d7b48602af39f050af369bc63e9b3559c4154e1725093d012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe8024730440220648aa550f66e67f26421e588e2ed4f16de883214cbd693acc33654bccbb12e6a02202465b1a506fc42bfcb81d2a70c0feb9876aa86f5ea60e9248aea68e7c7890aa2012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe80247304402205c93a38cde8f23df779c192dc97804bb28bf9bc807d1d1fd1f2eb8541c9531d602206dfba0f58d2fe963f7d9b2a5f5e6b943c933ea563e3d5756484b8c51626a52d4012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe80247304402204a3599e5e4ca4bd43dce118426efe023f27abeb939f3fabd009b6483719cbfa70220717946bfe65b85a98f969442c1eebedf65c759f524df62ecf9ad39097e519c68012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe8024730440220057144283216bc3b61a1cb7ba94a38f285c6d54adaf00683d4eea48caffdb3d002207116d94d179e39b963dc8749de72ed3cc51700656e81a3e5ec44322d95e5af8d012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe802473044022043bdbf1dc4f51638cb1d5b2f98a2ea31ba3767e9ef72c97771a0cb0b19cff920022005b190a09dab639a9c148fab2af52bffe306b10e0e16fccef389e9a5723cddc0012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe8024730440220282f85459d37c7bc9803523b6199375618eb2a4d0e9efa872e00a20444a1e1ab02203cccaabc18b15d18df138c706d27c6986897ad5909d0bf0cad8c434144e2e899012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe80247304402201c79faba96499422b93fc4d2bfd1a3f32089c96145f54429ba136d8d7df651130220434641b9de00a0c4062de0b66366e9859d5695e6e03eb7bc0528cadc34d4d45a012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe80247304402204d3eebb30f3bc9a2205f2eef7134bef27ab1be85529b2eecd0fe784e09c8842c02204ba80ea18a38133aeab004ace9960b484d30a672c189c8d253db30b37cb6c145012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe80247304402207423c4fd88178d908d6c322fd18daab9a034131c7f16edc4fc15b0d0ba0547da022070bbfb2cf53e6dc5d40b955a3c73415d7446e9646285735737c6646f671599a4012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe80247304402206237e3588c69f8de12b79efd272597085b0e249a5027a5f6f8a35975ae2f1e0502206eeb124fb9af7ae8808dca3303c1d72335f9b2adcccb8b0c73098ddc2ee03e4e012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe80247304402201265c0b2b5744564dfb0ab21e603861f99a5ef41309ea397392c11dbe4a4368902201253b7a0bbc80724facab14d2cd43b442fe4d6c93e12c0563dfddc42f3d4f62a012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe80247304402202644e7e92e3ba2f68df8d0ef55d91d98429ae6cb204cbf183f74c686ac7390b1022055f1bdfb164a6ef139430ecc222ac4809b8632d058a8db20984bfd8c4521570f012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe80247304402202882f4bb440b98c586d55f9f3efd81007a7dbf5d168480bb7adfcddaa7aad8bd022003e3a3fc3c3a42810ddac86683ec03d3fec880e9f1dc2c3c4a87c6c1ea333659012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe80247304402207f21e5ca6b105d4388a7d8f38ce8f4bd9a527fb95b8294d655e3d2ff8757bf3702200885e8bea564fc327a38d56b5751036e417a75a9edf1430ee9f478e4424bf934012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe802473044022062d2dff780fd4b0e0c3350cf2e3544ac5e98638275c58e98208544315cb51afd02204ced9e4b4d38fd6f798f73b71dc77d349d369f7611be5d36913414c899c62b9f012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe80247304402207fb3e4ab71e6aab5d9a801db04fadfc19d1229c2dc0ce8b0f1c09cb14ec315c102205a3450db3ff8f6fa44e4949429b7812b67f8eaabdde3d49030626a85de308c7f012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe80247304402204803c5e4730769c1818071633f261876798df9ab352078b30ab85eda676036cd0220514b8b5970d5d55ff20a797c7a846ce3f948b309b16d05b8bf2ac949a8842b1d012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe8024730440220666bb16631cc9147f15da461ebb3059a3494a7bbfac6da24daa7abac4b50822302201331d8a2e4a723eeed2e53b6353aa4048886156b05e4417c6c40feb037fca34b012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe80247304402204107c1de8139cf69528263dd3c0a878fb90382cf22a6c1c007436369cd9033dd02205e1a324dffce68eb7c49cc335cb3e0c54d67bb6eb77ddc8644e45627aba9155a012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe8024730440220728d02e85c43618779df33cbacc89a92962ff7584218fcb54703ac6bcd8fe28b022033aeb438418a64f842be53725f65706c9db423557f8acaf07c18fd0186389665012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe8024730440220649bc4a1056b61bacb95631f88d4afd8b65bc056cb81d7817daf8d2e4455cb34022008097f27886aef87e26d2595eaff17339e38d36d66575cd30f3186bde90f05f5012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe802473044022012ae0a82abe16f9bbfa3312340d5aaf0c0e26b1a6481963dbc4e50cb6e97e90a0220124d0c41499c432938fc914519213196d1a2922493c039532d8e46190f0ec11d012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe80247304402206127d5a2f456fa84da50e23a1d5b0a24c0965751db44e6ee20fbb4fe581b202e0220271214abf21fba202a7d3dc0fb8147660ca43439980ec20509e01ea0dee54570012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe8024730440220733c06704f640c6487508a09a0dc27c794c40477e3353827095dcdccc977ef220220481aa03fa0a52b165b1587f8251920a3aa2351af233c3ebc079f067a908ca756012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe80247304402202cc4a812b3b3e45fd426cc2280bce42a1e61bb0be3d9e3631980ad1872373a1a02200da0f871158ca628f9f80e5c8e2469a495333032a93a5424a5ed3fb36bba6d0b012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe802473044022018aaf940ca8e1aa5b7ccf720abf86c35ded6866237a4dbd6498e5760d39a440e02205584858e54cff36b20e47d46eae577859cb803a6f1167c3941bcd09b257960e3012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe8024730440220601df606179e7cfc364eea676138ae480791ef51f9cd26239715ea3f79e9b582022007fd0cc9d6a11e00c59c0dd6c2e40327d0bcfb83f6384a91c5eb7d06ba39ce7d012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe80247304402205d777f1dbfda4a0da73df9daa75c1bd20676edb47242cccaa133079a935fdf3202203a7f4df9a5bb51dce704d12a09656e0c6bc32285e1c7aba2daff172539169192012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe80247304402205e2a3c11279074fe2ddbb2d7fe197fc6dd1cc2d67dfabf0be55c2c7732a5d98d02206fa617e78d9c834f96819652f134799d3c0aaddaca05cc0942325d51284ac472012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe802473044022022bd5b4be7a6007b1b1350c5bc898dd732285e9aba4665b0da3cb141a0b963f0022021f02b51ec9a6f44451099727aa10d2cbb724feb44f7e2356d7349bec4d0cda3012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe80247304402202cb28549b410fcbe9875c5d7c168603934d7efae352639b4d5f6fb6e7acef22e0220357012acdbf688ec758c9ec957f3556c98af17c678d0a8c71f72a5085d275d9c012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe80247304402202cd332ba21692b0644e660738b3e86aba8cff894e62d50c8b639964120b004de022050e7d00c5c4d9981f6130c5c9da49d2244ddf01fdca8b852ef875a39e274b501012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe802473044022018be4a88ff79815769b23c93c4b967609a6652c78d1df3752a2c0d8aae6631160220366abadc590403d0f69a6c09821e26259e2730fdfbd47dd6861a651257e564e5012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe80247304402202758e4b3605838a3828e38dfed24db9779b803459bfe765dd43b15962c09d6be0220476031823023245f90a951a1ed80bf73d654f7548fce74cbfd7c1a531217a9fb012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe802473044022055916d5349b70b447e1a357b8d05bad7f36f7f01f063321e46b949913186ca3e02205f886d6ca191d8c2fc1eef0e4f5e070a1283f14fc3b394c03ca5805a4e03ac86012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe8024730440220490f5928c50d3160cb8a0925eb880aee43040d8c30343910ccfc5c29a448f5df022005020de940319d4435058bceb35b59db9c3de496157a6f5e55f4ea705ad58160012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe8024730440220747d6998b9acf12bd8ee19900601ba8cdebd769a6d4a8ead51712e4e1e27e21f02201df4125bfa6e2ab1679e18f0240a4266413cf744052acf98bf15aedd8d1134a8012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe80247304402201bc152260c1748dfaf1068ef0c58340952a2e3c84514c75f722981dd1d5bea7c022033d009aa41fb7b97353c0ab84c3840e749457aec7dca8b02a3047b70b6f57be5012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe80247304402204c4799c9ace62721c6a820c169f8a08bd1f16f6b5f466c1bbed0c820153e60240220137d918d4c5e3b04ec90e15cd8b6a7c373805e9b1f99a1d70326486e22c2ee32012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe80247304402205bf45a6533c7331f7aab7c0da6f16f1266065d99edbbb237441ff5bf3f26b798022042967ea0f82ae7721baff651cb603e632002102484cfdb68bd9c88d5ab761e5d012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe802473044022002027ea793bfa421ca13b46c49d6516eadab71275b2ce814ff4f55750780195c0220666ffefefbf342235bd3f6711861536699aa6114b4ae4aa94005b1f89a5f6407012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe802473044022076d85602ec0cd9ee9a84d14cd09308f520a33d16573399cbd3fbbc60ed7d8e0002206295a01b22ce2a3ba8530ef71afd3f4261b1fc5f5c3226ea74a3a0d040d099c7012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe80247304402204d26dd3dfcae6a118499db1ceee0753dc2d8e27b26c237aeec5fe51410479eb6022013b09312305f3da49fc7deda8f89cef52eafd497dab2bfbac9feee095b5964a4012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe80247304402200df0f1dcd3d6ea0bb9630f595ac21f4cffeec27b6bff92a9a54b9a8742c41a5c02207b3558ff6c7fb414114940a64392ab723b5d240cedbfbd7b40c25d1010d67a98012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe80247304402204fc14777cb96ed989b29dfcc2aa9e64b511ccf9d397a79f6c998df7b1209f5e802207e4f914f6d1e4e517247ccaa86f256a6f7e95d4591639a3c531eb42753605650012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe802473044022028380f55676e8a878c6ec76c5650bc36ab838bf2913f6bc4e18dadded14a406e022050761b588b592a3f062aa9bd99b3107b555f8ce270829f146f10e750ba22a614012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe80247304402204daae11215b7bb3586c369a7a0f7016251cc9e261ca2c813c59f8b00a2bf4026022070f6331a3c0e5e98d1f045375ed5431bbdde3afb1a586291ce8db983148ffcfe012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe8024730440220534bb81545a8444355b8ac90eaba0641356d9cbb9780d3ea2c7e6bbfcabcbc2602203234da72442b0d454f571b1b4beb110ce7f6e558829d71d8973d8c3ce51c2532012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe80247304402205b84bec4571438ba749daacad3e8aeabc8008c5d1fe4db6a4777e92e8c42ac0402205e578e7feda43aac1f0476b4a22ddeb2c7cc7b3b8e4272a2504cc56b244c6e96012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe80247304402200804db1e39b11ecf64b19de4de851b02e291edf92262fccd267d4f97c866e15202207940697c394aba7c188a06ace9df39d10669da1014aaa022653fc7581e5741aa012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe802473044022044f31b8af091aa907f1a00801f03858d579cf6df03773370c7adf2c2926693fe02201f6eb505cc662756b34fbcb781de8dd66f5c306ae08ef27916b893b2d575217e012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe80247304402203c2eed5901e224737f7c3460b56f36f4a9fa5078a15a3fd860ca01111961ff4b022027a74c1fa067da2fadbdfcdaa1516d05694d0c8c4adc45c25ba4c662713bcae8012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe80247304402206c2123653e380685a7edc137043f53a176e8e29f2f286e76b0769c2c9cf7abde02203a7010a87d0330c7cbe5771e7e9c7cc356a2d62b121911359b4cb07d2cf958bb012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe802473044022055ffef633fb808cdb0bded0f255b490af9c82758e0987e33f3e100c8dee1011502201f116874729067c118d017ca623dafae326e23e28f7586f6cd6f869d39ef71c5012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe8024730440220257b52a6fc98212663baf0bf3058260b47873655cbb59e65764dffacf80ed29902202a9a7eee05aee0fda4efffbb2bbf77289fcc03b90229ac8b886fa73801d2842f012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe802473044022063e2e9456614933bdac0dcb215399d5fefe9cbfaf05543e8fe21b8ec0a4ace780220255abbbdcaa151f7146021c2c4e14239d9ed81aed111d797f2cda4d3428caa8a012103ee6187af51484254f6a0fa5b733ba68884798cb3d3bb7cd242f0bbb9831a998702473044022068aa9bb03aa4c8f766c05e93c8b7232d0bd730df1b19c8d0835301e072053f650220389ce3d23a41de7df2acb666908ff2e02c7e9a847d5ff6091f4e28be16b60a78012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe802473044022035d8a318acdfc1d6824b960c7d2ced33faf4976c65e7f0796e559ab4c0b2737802200323736a064aecfe24a68fc06282de56c0c863bdc52227d2c132e0f8cb3dc90d012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe80247304402204b95e5b449a46332d4421eb8cc82f8f51835b0508c3a5826ad0045c30ab3ae99022039d294f1007c356dab38b3094f77155c521c3cbb371c043d7adb2c45376732d8012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe802473044022002e948701981438e6ac572b565548f2fabb85a6463deb6cbb29a78762c1676140220296f358f9c9461b53d6b3aaa354534b039e0ef1d07b5d5298755f7a9d9ecf0be012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe80247304402202103f2c1bb12bd3e42113b81a80095cccd337f90b9b05b268194fb2b51a9d93f0220399dcc5f0b419f5a64a98339925cba88be0c73d8ae3a14ccc9bd14387e3f228a012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe80247304402202ca1eee0f67713485bf7f6d5db772e729c8599eb6e9e446f4deb4aff05fbd874022005b886f7420abbbdcc7b4d2e3008d6e33ea19e8140b9145af809dfd17f6ca316012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe80247304402204ca767fffba5d03dd5f35349b5ef2464764cdb6e46a0bbc8abf8f5234375805102200b469beb57ac1c6ebe8a0c9bc6f7a7d54063543c4b79a241f3ec451d5ca4c158012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe802473044022062787dc291e1b4633c338abb395854a3f93e451b2a5d225bac393f8258a5b29a0220766e62e7d530358181105cf88ed7f8018314118eb55e050ebf024462483de804012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe802473044022026a559d2c5f06a9be0c2bf0dd4cc964c4f11bcf3b8c43c5c91402e6a5ce495ee02204ff26aff133798b04c711fc60a82abe95cdc448385cd397160783373b693c4c2012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe80247304402201924dfc28c03b1d4ae2353958e4550aa5a3084b24f8666e34b5a7be1e3ba12d5022013a197ca23121276b177a66dacd0bf723ecb91660d10a52ed7bdaf06d64568c1012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe802473044022069ccc1a42c0c92a8655778f5a8f4806c857e745b81ae4457e0c322d349f16ca802205dc7755702710d49d71b82d7a64cbafbe865af877ee68dfc1f73b3b5986cd731012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe80247304402205923e982cfa2888e21ef7552bf9dac256cc2d032e4c1168a89fab0352034741902207104b573c53c3fa123cc023d1d3d944fe2bbc5dea990a8453dcdeab53e4df402012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe80247304402207511eefcc5f1c4396ced98c794595f8e8fa5379f6b5aa37785217f857db3a49e0220310d33e73272080f704e90aa17eace06fb1e7adecd3220fd3c81582703fbb59f012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe80247304402206b098f20316df8180ed37ce6980ae641994405cce52078bdb2c004a01670752502201a8e67e6dfdd693b68cfbfa00b5bf04e9925265522f309c2249896ece5eb7246012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe8024730440220012f2c1c185118d5c87868343d92c9d2627ebe42c18defbd4424c8676520b0c102204e011d69276c5069d94d32c0a74a279ade78d7749a7f3ac4ece4319980bc6a07012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe802473044022041133f637cd241e97762964f98ce0fd4b30e1d0dc0700c45ca04f35fe0fc50030220309ac634b15a2668557b64410d916510deddee16686921a665000505edb79eaa012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe802473044022047604511a60e2efc0aa3341cb6831a56e52feac45237fbff7021477fb04caddf02206ddfffc863d2af7accaefc66ea73150b776c566b1c7f49e985425124db374278012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe80247304402202c8b15a60cdac4dcf91a8541bf0c8d756f7cfa993aeb2197a62ce4aefe31c60f02200262f5732d3dff96a0a7cfd31bbc201da8d99c9bf09453f493b9d11af45e2d10012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe8024730440220575c4da0d284fb0fe29cf5e2b49c3f5874573e8874b0b0c952d393fd56ebc94d022008a359e192fde5cd53cbde9c8afd79dba1ad059056c0509185c907bce6d0a612012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe80247304402206020810b639655677e89a4bb71b9026381bf2f2574c92273d44f46a3cf2c21ed02206196453e17bbe07fc2a9436debdadc621be4ca58f8951cbd75b8b28f38184dbd012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe80247304402206f3fc1d1255b3f597eaf1b7765a6282a9bdf6d2e4a150a4f0190abaf6b90d490022011b6249cce77dc53cee06d79406ef6120f62bb90dcfe09ea56670e3f2e81c65f012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe80247304402200b48b3347fb308d33384d8e8c30b65014984097e0d16a1817a84b1a7a5d57bcc022071661e86479df35d00ac124c4032a4eb81f9d99af6ba1f87d96784cdee40f4ce012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe80247304402201eae865120d7a6505d2b2fc7a0ae2e673451e650cb7b09a2d533305a38be2ade0220655d15afb0f4c3cda02fa5bade5dcbf7cd560b4412dc0bee1ed2c0e8734d2e00012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe802473044022020130557421b8a5c43436b7879d76837ea5b4ceb63c7b0fe5e55c6db4655ec05022031ddb06a9307776d6f8b575f6538815291222e2c1f07f7e2b9b14c8651982e0b012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe80247304402206eed285915fb9917bbd834a0e7bab8abaf7c3507ee3fd9bce3ffbd07623d4a0b0220174b13d9748dbc1f36074c80bfae9a92d56accab9dd81883f07c99166c6387ff012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe80247304402202cb776f03800a3e1694b8f07308f5c9529ac48e0bd897fdd3ed89786e225aa5402202797e754855f69e12f7d172ca982f1f53268eba382e734817ec48721b207aa1f012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe80247304402201df427531a57adcdd0c7731b8f5598afd8693e1db8d6be30889b9d8d49426c7702205dfe74be22c33b6e1a9b76f2171a28499fcb548bab7994705629062e306ac700012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe8024730440220333a46ff45971c7adb9156ef29753c0ab491e6cc15188c6104b0e3c51a952a5f02204caada0c403e34e4cc7a8f6b907ee1e21702bb2d828badc7979b9372171e4066012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe80247304402204736003cfca3bfb3ff7c115c7f4a4f89dce89e80605e1fe9a8e33a67e1bf8149022035cb01160c5705b6ccfcaf7ce697d3cd129e02881c852a795c8cc3bf3caba1bf012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe802473044022032bf1ba4e5e6a51eadd5777e8e2170c62c61388f70cd40203efa7999f29e72ef02206df08ba37b2110e13d1e363f1e5f6d700b1a859fe1ecf498c61f07aa62074bf3012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe80247304402203fe38777e2486487742a29aae7be56927de7b7e9c0ba850f57cbd348705f6efb02203075cd30ac7c6f63ef8db3acc30cbe9617c0fd7328ea2029eea988fb85d6ba2e012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe80247304402200d33219eff8248000fa86efcfb4d3d8761bcc0abbbbd4efabd0a45b0b2a6cc4502201bc7ed67f53424998c9172b834139009a6737f1fbfeaf41ab73b1253628fe9d7012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe80247304402202382a4d56e34a6607d37153c3d4863d27c9ec37a4b4abef754388c899b52083602207e8aa8cb740ff4b0310fda8b5d0887d0dbf71ca8c725b0adcb3bdb7c845dab0a012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe80247304402203063c98afd68771fedefc36308cd34a1da3cd2163253f0509acea8551ffb0851022024e018b1b95bd8529adabd899f12ebc3c1001e9c0eb01853ffdbce5f0f853aec012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe8024730440220573eb0bc6c6bc61c0c585523ce024d50228b57c505091b20cebc5bf7d7094cca022066abc8234624834db1a8bbe252b407860419a527855c1f4b062e461e99e32324012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe80247304402202e2117e469e888054d2fe435b9ea2820f03ceccab9fb138426b55732db995e0602201dd2e0ecd12b93ae8af8ee15a4f9ae121632ede651ea2a0136296111125dd1d1012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe802473044022006c7b660af000ea132416d93e59c06479d2d5392ac91a48e8867fbb1b26723b202204b7c9883c728edbba6fb97c2d615e42eab64c3bc77055d50286589648fd4aa82012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe802473044022050882ce8774198a0fa10f95e7281593bd0e9abbb90a0a1fc4299d00a4d6211f20220285ae7a9b4e542a07d8985b04008cb36b58dcaf79d80cc98c5e8032caf813f7c012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe802473044022064e856fae64a9516e2fa1814b8c07466b8b6929e4da04eeb8146f0aaaf17a60d0220409c364ee7263420f7a598cdf344b1ff9b1cc7aa5da512dd8261248cb5863dee012102481af96b05f38e2ad6c8430eb9e27a00384c4b2ac9a8ef3d8932195ecc2abbe8000000009700000020e77fe209b8a51992ea64013315594cb3888b60f707a58e77e95abaa79d75d31bc5938789e01c71509512719b1bb697635ecbee4d754d59aa8274358624db509134acad61ffff7f20020000000200000002c5478d32402d0d9c5788d479ef2fe5f676118ebe04aa635818e7344c91125189cc416e87382223cfa9d82d9f465d81481f5c5d83a39276b4dfc36c641e8e99ba010543010001593af4f3dc72eba686423b79c7339c6e318a33ec0fd160a9d8dbf7264ea039b2f308e71dda0e71377aec6a354317e8d9196a905a3ecbfb53ce4c1b93b54b6404fd450b4023751c01dba9ccd67544834e42dadfb1e71f158a4128345da1d4d46f9cd70607608f2e45c1fe1bc10a3dce2ebb3cea5fcb54284aa34e0875d11c5cdc0456ff6acdfc01ce6400b8b3627d0c1a21459b07c743ef9d357018c7e6d11a9d2f729e7d327d014b0600dc43fda078d40f173b38b7e1576ec49b410b1bdd0ffc95876e93ad7ab680d7c0267f2a7544d50d3a0c9cf242413471a29b37710ed13e97d48163162736c4368d1c852495b57487ae7bf9627cef2df8d5d7fc59c7ae27aa1d293615f221e1b2b46afd6cd448626ca7a93588f10faf44b045103103923709dd2902b3705899fd02ddd7ebbe6ad702064c487844c7588a11cd9c348a4555b7fe11be3151bb786a9e427e03a3e08d9a25d04f73bf26116bbf3d520937325138bb4bc083c01b1fc096f13d066f34e6f8166f721b4955e5016a21c912bc3405c4ed18edf55c650be3f6f96c454a58cc6913321cc3ef044ce14d108af457f2a2b396b5e2f8b08cb857e1e9bb5b88ea3ec9ac11f4678ba57e0c103555b20f14c1b6acb39079671d5d953457f6a74b7999cc56cbbd535168aa06ed4d33d09c59b6c3532e9caddac0bf27687c7a17427d531ab6b98918332669a9035d750f54af0ea4031a705dc0602b5a1437ce4e4aef0687529aba56139096eef8b4740bdd4b7a124e5145a75bf97d0bef72044182be3535e3223d23d7e0c14ffec91a3ac09346c09706d56d290b0ed7ad1b8c42d401aa2386ae9aa30456f9087f2ffa26ae28e4a17ba1ebc1d5a3f64b11b36e180ba844897e256b0f28836f8dafae43720e696fff97b00c441b4ff6d3b42add9c3ebd9917eaf2bcff7794d5144ba39ae5a660ea97eac27565dd68042bbcc2f3445278dd786cc33b1d252a4a69db944c78ac9a394bc5cfdaffc4e5141c945575cdcc6c2b737811ccc2f8681ca3a491fcf42505cd6fb29533aaa715c466ea9d3b3e94b4a3eaf97502d877d282db9e44f7e825e80dfa430354a671b92f9190b5aed007fbfef5cdbf0d7544617885cea51656fb205a8ce2fbce662c3f01d7919b85cc2979b420cddc42119a501ffded1233b97941bbffb5489c0a593cddddb166b1fbd35ac32b8785d4bbb9ef9449edc665626edc8ecf7274c2bf445d4119747564d8c43c9dbd5e9cca84d9faae729a79dc916c498bd6bc4ae11f11bca4a356c98d356ad956785d0732be432a31ba1bbf74d5a1fa7df42ba9bd1f513862b3dcb76a76408048639c47f0cc8e608f57e3a2c1d019cfaf89118b9f1ac64575478425e880d133f9429f1b5a4bb578a06ad4ee17333b7069e1d80294bc794447e428ed0c49813cd221e30d1a58d3540c2749c69328aa9e6d3992246be415eeeecd180637c7811e185f909edc1c0f5f2514ef7211ce0b38f3c1c1f034a54790be9cbb2284669ff17bd98a12da51de79250c98880d6faf9eaba4d75885e03d0ee8f0c46152ff0307539c8c807778599c1c21015493f64fd1265527d83d58fbc97bb1c472ddce0b9ce03c6af0605e7d672f61c8833041907c3be299d921481d66c96de822ece6de4246fdfb7f4514d96a0d7c963461a8c9400a7f4692ba618156a58184b2739a1aff3e8c15b07998634a9c65cd3007f8fc2f8f593f41f7f4ecd654fec06aeb9a53a1fc0eba9c73511fc000a82b115ee7d182987ae6ea8de43356171cc51246c01c1ae92265eb74e1dfcef4583176f1cc271a3250d34e1a7037435d3fe39030e97d4b294fbe785ba99db5f77b8f2b82699400d1c665156114aae08ea6285c8bf7dbf06a8e6e949d0f6aba8df22f747d8bb414207a0a5cc7aca295c0beecb93fd0ae46e0de9579fa257603e014db97cee4236902faf335b6232f9fa133a60032cb55b16b64fd55a0f78c410de99a26b9db7e77b03b66a2fb9856c7cb361122dc04676eef30fc0fa4cb2e00703266b5e7016bb529aee7d3bed7e494faf9df43c2b2e28003958f7dfd614f72d237524828e44403df91d3bd81a48a156dcd0b69e0ed96779bc249213e4c7fba2d2b05b84bb035764cd8f5e3b520755e736ac2d25e0b4d2d4b44bcb4ae8dfe17b1f6eba8a11f9d06e5f97c77b24ff2efbb790fe15b5e25eafbd067717fdac899e2d18a6a2e0a0252b810f406fe20e67a865456ae343883a734b5b765785b573c757f650a6fa3db84454e2cbf2f94e5e6fcc259369baad4878cd40fe84d592397f875f3d932f6c39daa22bc72d3c6c94aeb07c91b44d34c0aac70efa50c1014e0e66a31a504cb22991dee171bed2d357a189b4280134a8abda8cb971899dc5909258aa02caa91ccc923d76babfd2730b590bc9016663a3daea149326b75973c6a97db62b69c54eaba4e8392137309d087bde608a30b25a054e8a997ff023d9d8a1c44e19b4696bebd15b723afd7bf80245d7fd4e69eecbc297a6c7a9f9dd1b280d2931920799cca97a0b14f115d4b94a9f24cb1537f2c8336a12720d19083f661c6b05f4ff972f4ff48a470e4e6c44b9a9c4c062ea1fc184155f40987997d6f23ae8003bbed91eca5300ba91f0de82b167dbf06b642718278bfd8b4ae8534442f3b6d05d0d1a896e629ea11cc63d49a06b884bcc599eb49aef90be60bcd4a9f6ec32d388b65ff7224d3082c651f80b33716e2d9e43a954551a6f077d8e29919a5e52b8b1232605fe3143073602dab1d30764b6c08e946de0710bfc1d370bca61b55165860fe00468d5e040229782e93c2fc94489126bfed37df6664860aa4f274d4fcb6bdaef0d3a34b06b3267531017dfbef4cecab3f4dbfb12be3f36170b5363d180526dd3431bf9906a2022ae2590a9fc158d6b4df796c49fd1022074c6c22e8667f5f86ae9e3d6cb997579ce37153ef0c15ef521d63c5ca14a25b414c53a625296f9a2165099a2a1b3bc711abbba396c08a9a12bd343665c5c5759f64f7e025bd9ed7e21ffba599e1d31a9c6024663b89669dcec1ccffb244a227d1e29cd18085713d1898299ae8b4fd666d12b9361cba8af0b80d0c7fc01c8e944035ff2342aae0136a769520102461abb5b04f6853e9e0db2a1c6fb4a89f6a428ca96ecf6db2e2c880fd710c72c17c542f3786d304e9b2382ec580b0b0087132a2448258de951ad966897d0f9dd9d07c52005aa5963edbf6aa033ad1d4e18d2f74a0f86587197a1d32916a567b274a85e3968fbe6af6e75e18178628cb645b6db8ea0e80e773f90203a3b510763100a11429cb36aef2c637386ed6834a96fcdefbed4f416d6d3faf09d52528070a2139de399a4df64ec6339aabd99f77c923a659617352c5decc08413f7fcfb5134628d078b27d8b9c681ad61f52281fd850d2c1d3709e6d81bec9509d61b54304f116ce4a481526bf4ca15b7329dd10596972f4e7aa0a85acd953f7a36b347d3afe2e607239852f696ebcd26c579d5a120bea4c99940dc43461f421aa0c04522fa4e240bcc2cf7293b862f27b45b6a557878a21ac1c7949a3a0551a34d887eaac5a501bdbba4e2e73648539f1108d2b5067f070cfba7809ac7a557ae23a614a1361d9eae76dc4c0c7e3d1a7a0bf24fbd4c5d0fef260ea11d0ccd4725774a1af4628ceba8c8bd89ec5ab4c11f1fff58eaf9d5a822ecdf90b1519fb9253e42502e3669e6686118830914227d0da4fea2b3425ca2098106ff731999e28f5f530fd39660744482bd77123105f807234415ec7cf2dd640444a683c4f47ec7ed19f90e786723877fb60c14adf39687c4f647cd7da225b636ae7733fb7663c8e76e3e2ab9d4b7fc3ac8fb1f3c0e8781634860a84da514dbc735d9a56de4c0e26d5068890d353784712d1c87143c8f511704e8d0bb69e05fa74e37321518d1c17eb208e00b7407c46f4d24be80fd4718840828e3201ca26622ff5d44061c63fd9d9f65d5c34d03ae75a082c31b6174fac3975e1d3d3c6c775c2cdbf302183ea958e9c002dd27856a592f5a6d2040e941ab261793cbc6b3592d32940b3977003f62cfa848085756047bea7550270db3c66a040f191b53fbc0cc5c3946d2691d4d34ee002e827d2ef265d6fcb0d1fd1a7a62b7b915f5df61a5a4fa23bb432fe606d0fcfc08c6673d9bac66a8c000043010001fa227bae1e9f2a9d2594bc8439e39e7f56c265167cae3790f9e5446f53145eb2d6ec06c555d966bb9b2169871eab8d89d33e0a4d98873ae4d1723b5054917ee3fdad0b60240000000000000001713f00ad59c8cfc29b52deb574351f9394999ffa4dbce9edc37901ed7d92c105302e9ad8eb8439c8a83942bf9ee2c7a0791669ee808332f9e40e300799b8ee77604ae94a3ecc8890c0ce3baae7d3d39faec82995d09ad9b9bfd6373cae3c9087a198169c2541a121567f9a82759700e22816c8cdedc3d144e9ee22b6b9aa6817b43c282e4bafe066cd432e1d9e558dbcaf32c24a3c0f34e0296ddbadb3631a4c2f252a358819b66d23c339eb69d6ecaf7972afab1de488cfcbee4a4d53472ce9025e9e7e18269096b0395a903fb87000308dc3a89cdd75ee01a3ab3eb6d88c9b42a0f66052582b93c9322b89c613c3a8a7c6a2917fe3c169e7d4ce020a8f58380b83e4383db8669804a49cd91918fd56b41edae66df64648677de7a8133bcbbf0096907d04c92b4cf6c389800f90a58e3af6350d310cff5096d52df4016d76804876431a212b31e0d90cbafc33e6803ee2db4dc485a4f20be94d9f27d9e824b2b9d67f852d78ec30e6a6559f001b3699ecb7265977fe0cfcdd02a4037b0655d972d819cbd250dba86348f93255061dba7409bccaf8a89bca08bf3b1a3fc206e78e48d87a9a7423f1e49445bb73bfbc4a91ea2b47f34ff55be9157b3d8a4639d24468359e2083a5b7c82ca1ebbcd9b777d50650ec8f92335de253a4e2a729f446cc8308f7d89341875db3e4b2aef038c13bfac1f78ee35f829ba7e1241e7d3ebaf7064a2c99b9ce2aaa10f526140d593c8b2255fd32d252a55487ad2ca5619c794036bf9911a244dd42666e4621eda0efc4beb998cf079af1116576bbda85afd6e1466faa59690eb218db890e9edf5df42a1adbfcf97150b279d4e23f5f4b7892a9faf6fe39f15f5356c437a269ec1fe9a49acc48d4a6e76c73e2078abf2ec091f81e640e503892422157050822856ffed87cc3f25a610963d89a910656363fab3e6940805a5afc7f83064eeb110dc19b76a6309345732fa5c55d33b20c97e5715a124358ce71cca0e8aba4a3390c6abb48db8f3b6737dada28d7bad58be50791f93d6ccaeb48cb15f41a370c5c3fecc0b809bed3f68f780a40d5dada80e60db91ab036ed8fe45f4cf1634ebabced3cce51f3d8cdef769e5fbdeadfd6e6832478e7f5b1f9c0417ad635981b331fc909abbceca5748c69bda26e35b96dd4d6085f63ae92f3e212129cf0fb705d87dd531f6e2ace94ace1ac1a0f0b15511f8147c958cab539776a542b2c7c534319239b5b0096f984c161043de0254d3c236bbf85163a2fe8ff2afc4efca87e02345941faac21b78dbbe577cbe5782748a6e3a45dff992794484afaac3580da570642d881a7c048eeaae81fa3bdbbe7ce8faeca26895358448d045bbe6ed21f6c193306846ad38ccce54b2f39aa4c9e012ac0b3e1c696a314ff85292e8c63a7cb3f418caed2dbed9c98042b23ada80c45fb8bff202807eae108d5e7c724f840777d8ced9b281fcaa61020bc360a6c9405206340e1243b587a6e18533e894af916c3af9e7e3ef995ada0ed92b67db0a7abf05bb4ed48e75d74ef2cfff01b44a9e2691fa3996abd9c7c3c3299efe901d09ede0299f03a62df7b9eb59169064adc7d8a50405cb66f741a08e8d1973a543544a5c6f546bfc6169a500f880a1f1854b80668f0f1f30447f2daa70639a9b301e0ce7b7c7412ae2460d0c35d3009a47f5dc587926ad579d9ca2e590c949b999c0e8554f8b1afd28c4b1efc5e705725682725766067dd05376052e396735dba37b9dcf242b8ee9f7d96eafcc68343892c2642dbf14221ce90e63aefb70c717fc67d00552bc408d74178dadfa19091a0ad68c0be7b18528d6f6002e59eee69722a43c98936fc8192ff7d16256af94fea7c668c6b06e6a21e25f1db78f2f6f9d21e3a3f9784392774feccbbcdbdc34c2345bfce119640aa74d9c7663a8459d3d2cfbf8f3139a0860f9b872a5b9419c0c268f3a890d3b0c274c43fca81ba4cafbe3fa8230432ec43ec6c7bec334074ac4d98fd6ab8a3012796c953dca244b7fd0cff0788797df171d28ce38e3d4f464bcd63dfaacdef2f2e39da4d111ed7e9ef9eda887e1da690a3b12f77db4c459a9ee8cfbf5ba2f5df2865c5c540c9789654a7fe3bf9d05df4e2dc4637e66e09208bcc79a3c05b6adb769336973773d39cfe4140b574fefb46acca6b6a9f4708c2379cad8364c7c06a6a55fded16fb704d88b0db9b9ef1a4d5a6c00b70978485c5816a7db4946c1979a0ce24c13bdfc5ba13dd715cbbb0611d200a66b78db7cc80d25a3be995afa4d20263b0b79d661f1a016ea98d0ecd17753033c91e70bb5b4786eb3748eba3f3d948e7d09e728366c61a46f2d6bcf595a9cce2c68808c22e319b9e11d085ceb27794fba0d26244267a23a7260f50b824cd7f69dd28c7bc5568eee72d70a482c249f10216fdf2fa764007555cdc447588c89bdcb228f0a8259667ae3f40d2ebd9567efde7d1c785077332c17afaf69317cd4e3b4ffc1401afaefac9ad2578204740c1f8b4f1b4e1e1ba6b68d43512867bdd73ead3c1ef7d1ca78825876f144fb8df5a6ff3d97d3efc8389e35c55e1d6707aabe9de76c79f9889600440b23fea2fe4f2849131cfb55e7759dec1c90f882eb2175297598dd8e0cfbc3fdb20a8a917d2aa2d5e22a28371083772571ba7a604ea8f64715b4a7fdf236537a81f93d0ee62b167e79e71dd6c883db3daaf28d940b945bcf6002dcf2dce7d48ee12989cc078b654210e2a566f740cf1fbf4c377a3412ff959c79c6eab392f823f8e3161ead08193cd426bb7ab2c327e2e8e77d810479ff6ebe289a51b1b0201f3b81a43b9d72fc24d0073113561ff7a6b22b3fff290715c6866e9d705c77440075886e6844da9718beca169d23fd37d7a3f742ecf153b8ad171ea5a11d7dba0f987a3c76b0a6e9b959596e314fea6ffc82742dcc5472322dd9ae31d41e82a15918581430ceb7088b5dcb4c6b4408245e41ac1b3ede0e41d482555582edcb50497cf50418cab630f75b4f652cbe99ce01d047141efc983a184235a9b05eafd43e00899eded8d0a7e828f47f648cc7b2b325e55d73087da808811f8bd6f69d3ca01b2f0a521c1dc9f5d1f34c78fa2f9d343c7a64ec7c2364facf25b1a971c61664c4080f63d136623d1c58eba09d656b8abd3b397a7c53a2f220cd95b356d86e2e7fb3d1d924245af81cbe3c30595b807c567a63db232ac648434264535608e76559fe1f5963d1015cef9755802144cbf9a13e89f405559f0ffe66d18418e5501038394320fa0d41271e505e65a87f805872a38e72707530b4912571aa22bec6bf885867535b007f92a758c38a0446ee0215bb7c9240b0102b5368291a66773cc3d471780c55b9a73792fc79ffaf6f00833d011054bff0601305dfc917b8755b27af4b1114e3a0a151772ddab8909e95ba506b8aa329a25c59fd2d6033ed3e76f43ed6c584a77e78e3f9b1d4cb21514618018334386477513408d02f65b31ebccacce6a79ad376214e4a34e305017f2b43d29aa78bd34018bd66b87e3cdc5b1deb8fe174ca8d3405d412d1cf07c6d5c47192e05d9c79446e7a37dc18ab998bab29619f2a031ba3adebadbd6c58c90be0c96a8daa9274a732a3c29a55802fe6892d0589565e38f55fae6ff3f816c75178e59e9e7c2b1e3543062d63e3308ec266bbd44eff409b4117486f6f355fbb5459e16981d7598945edd8dc18c6d164fcb4080a9cf3461d73dcfb36baf889f3d79f1c2f0c9969b5e1e4f34287fe61345a0f7c91e1bad1e9d02ad0ec4c3abfc0efd5b0c7af1757924197089959afd6d990ec23f6d3065c06e49a346144d3aad490e65e6a4a65685d01f91c443787d888d735b9cdeacc54885cf9a4d84f174e7548eca9f32cf7898ae872f8e432183870669b0ac9d541610eddc623a8e33fca46d72cdc502b4496c79e7d8a95fec791fa0f6949b2497acefff1272cedbb13080909a98bd06e0533a2637eaa59e6f0bdf5a59bb28a5b42571b6cc96a5adff4e0fd0024608e362f73f8b183720509461c312cb56e5978db2f24b1800654176268ac0f00e3c0c5247935decfaf0793761470adab21a634f7a6288ab8781644b513c49d4665a0baf0b7052acd0a01019438a366c3e1eaa4184d08abb49157c91c8804b7176aa81e1b63f8e5b63654bef79e00e548b4e23fe65a2d987162cf72826aeaf76678889aeb9aecfc7953d';

  const signUtxoList = [
    {
      bip32Path: 'm/44\'/1776\'/218\'/0/0',
      txid: 'ba998e1e646cc3dfb47692a3835d5c1f48815d469f2dd8a9cf232238876e41cc',
      vout: 1,
      amount: BigInt(100000000000),
      valueCommitment: '',
      redeemScript: '',
      pubkey: '03a6f9bfb75ef976308fe1996a26187fcb4b0aa3c2d506f7b6b44d0065cca98c80',
      descriptor: '',
    },
  ];

  const mainchainNwType = (networkType === 'liquidv1') ? 'mainnet' : 'regtest';
  const liquidLib = new LedgerLiquidWrapper(networkType);
  const connRet = await liquidLib.connect(0, '');
  if (!connRet.success) {
    console.log('connection failed. ', connRet);
    return '';
  }
  const pubkeyInfo1 = await liquidLib.getWalletPublicKey(
      signUtxoList[0].bip32Path);
  if (!pubkeyInfo1.success) {
    console.log('connection failed. ', connRet);
    await liquidLib.disconnect();
    return '';
  }
  signUtxoList[0].descriptor = `wpkh(${pubkeyInfo1.publicKey})`;
  signUtxoList[0].pubkey = pubkeyInfo1.publicKey;

  console.log('signUtxoList:', signUtxoList);
  const tx = await execSign(liquidLib, txHex, signUtxoList, '');
  console.log('*** signed tx hex ***\n', tx);
  if (dumpTx && tx) {
    const decSignedTx = cfdjs.ElementsDecodeRawTransaction({
      hex: tx, network: networkType,
      mainchainNetwork: mainchainNwType});
    console.log('*** Signed Tx ***\n', JSON.stringify(decSignedTx, null, '  '));
  }
  await liquidLib.disconnect();
}

if (setAuthorization) {
  setAuthKeyTest();
} else if (fixedTest) {
  execFixedTest();
} else if (peggedTxTest) {
  execPeggedTest2();
} else if (peggedTxOkTest) {
  execPeggedTest();
} else if (peggedTxMaxTest) {
  execPeggedTest2max();
} else if (peggedTxMaxTest2) {
  execPeggedTest2maxMiddle();
} else if (peggedTxMaxTest3) {
  execPeggedTest2maxEnd();
} else if (peginTxMaxTest) {
  execLargePeginTest();
} else if (dumpPubkeyMode) {
  execBip32PathTest();
} else if (connectionTest) {
  execConnectionTest();
} else if (connectionMonitoringTest) {
  execMonitoringConnectionTest();
} else if ((!signTarget) && (!txData)) {
  if (!continousCount) {
    example();
  } else {
    exampleMultiTest();
  }
} else {
  signTest();
}
