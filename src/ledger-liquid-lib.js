/* eslint-disable require-jsdoc */
const cfdjs = require('cfd-js');

// FIXME やりたいこと
// - Pubkeyの取得
// - (Pubkeyに紐づく) signatureの取得
// - 不明点：blind次第ではconfidentialKeyも。

function convertErrorCode(buf) {
  return buf.readUInt16BE();
}

function reverseBuffer(buf) {
  const buffer = Buffer.allocUnsafe(buf.length);
  for (let i = 0, j = buf.length - 1; i <= j; ++i, --j) {
    buffer[i] = buf[j];
    buffer[j] = buf[i];
  }
  return buffer;
}

function getVarIntBuffer(num) {
  let buf;
  if (num < 0xfd) {
    buf = Buffer.from([num]);
  } else if (num <= 0xffff) {
    buf = Buffer.from([0xfd, 0, 0]);
    buf.writeUInt16LE(num, 1);
  } else if (num <= 0xffffffff) {
    buf = Buffer.from([0xfe, 0, 0, 0, 0]);
    buf.writeUInt32LE(num, 1);
  } else {
    buf = Buffer.from([0xff, 0, 0, 0, 0, 0, 0, 0, 0]);
    const high = num >> 32;
    const low = num & 0xffffffff;
    buf.writeUInt32LE(low, 1);
    buf.writeUInt32LE(high, 5);
  }
  return buf;
}

function convertValueFromAmount(amount) {
  const value = Buffer.alloc(9);
  value.writeUInt8(1, 0);
  let high;
  let low;
  if (typeof amount === 'bigint') {
    const bigHigh = (amount > 0xffffffffn) ? (amount >> 32n) : 0n;
    const bigLow = amount & 0xffffffffn;
    high = Number(bigHigh);
    low = Number(bigLow);
  } else {
    high = (amount > 0xffffffff) ? (amount >> 32) : 0;
    low = amount & 0xffffffff;
  }
  value.writeUInt32BE(high, 1);
  value.writeUInt32BE(low, 5);
  return value;
}

function parseBip32Path(path) {
  if (path === '') {
    return Buffer.alloc(0);
  }

  const items = path.split('/');
  if (items.length > 10) {
    throw new Error('Out of Range. Number of BIP 32 derivations to perform is up to 10.');
  }
  const hardendedTargets = ['\'', 'h', 'H'];

  const buf = Buffer.alloc(items.length * 4);
  for (let idx = 0; idx < items.length; ++idx) {
    let isFind = false;
    for (let hIdx = 0; hIdx < hardendedTargets.length; ++hIdx) {
      const hKey = hardendedTargets[hIdx];
      const item = items[idx].split(hKey);
      if (item.length > 1) {
        const num = Number(item[0]);
        if ((num === Number.NaN) || (item[1] !== '') || (item.length.length > 2)) {
          throw new Error(`Illegal path format. [${item[0]},${item[1]}]`);
        }
        // const value = 0x80000000 | num;
        const value = 2147483648 + num;
        buf.writeUInt32BE(value, idx * 4);
        isFind = true;
        break;
      }
    }
    if (!isFind) {
      const num = Number(items[idx]);
      if (num === Number.NaN) throw new Error(`Illegal path format. [${items[idx]}]`);
      buf.writeUInt32BE(num, idx * 4);
    }
  }
  // console.log('bip32 path => ', buf);
  return buf;
}

// GET WALLET PUBLIC KEY
async function getWalletPublicKey(transport, path, option) {
  const CLA = 0xe0;
  const GET_WALLET_PUBLIC_KEY = 0x40;
  const p1 = 0;

  const pathBuffer = parseBip32Path(path);

  const data = Buffer.concat([
    Buffer.from([pathBuffer.length / 4]),
    pathBuffer]);
  // console.log('getWalletPublicKey send -> ', data.toString('hex'));
  const apdu = Buffer.concat(
      [Buffer.from([CLA, GET_WALLET_PUBLIC_KEY, p1, option]),
        Buffer.from([data.length]), data]);
  const exchangeRet = await transport.exchange(apdu);
  const result = (exchangeRet.length <= 2) ?
      exchangeRet : exchangeRet.subarray(exchangeRet.length - 2);
  let pubkey = '';
  let chainCode = '';
  let pubkeyLength = 0;
  let addressLength = 0;
  if (exchangeRet.length > 2) {
    pubkeyLength = exchangeRet[0];
    if (pubkeyLength === 65) {
      pubkey = exchangeRet.subarray(1, 66).toString('hex');
    } else if (exchangeRet[0] === 33) {
      pubkey = exchangeRet.subarray(1, 34).toString('hex');
    }
    if (exchangeRet.length > (pubkeyLength + 1 + 2)) {
      // address length
      addressLength = exchangeRet[pubkeyLength + 1];
    }
    if (exchangeRet.length >= (pubkeyLength + addressLength + 2 + 32 + 2)) {
      const codeChainOffset = pubkeyLength + addressLength + 2;
      chainCode = exchangeRet.subarray(codeChainOffset, codeChainOffset + 32)
          .toString('hex');
    }
  }

  return {
    errorCode: convertErrorCode(result),
    pubkey: pubkey,
    chainCode: chainCode,
  };
}

// LIQUID GET BLINDING FACTOR
async function liquidGetValueBlindingFactor(transport, outputIndex, isAbf) {
  const CLA = 0xe0;
  const LIQUID_GET_BLINDING_FACTOR = 0xe8;
  const index = Buffer.alloc(4);
  index.writeUInt32BE(outputIndex, 0);
  const p1 = (isAbf) ? 1 : 2;
  const apdu = Buffer.concat(
      [Buffer.from([CLA, LIQUID_GET_BLINDING_FACTOR, p1, 0]),
        Buffer.from([index.length]), index]);
  const exchangeRet = await transport.exchange(apdu);
  const result = (exchangeRet.length <= 2) ? exchangeRet :
    exchangeRet.subarray(exchangeRet.length - 2);
  const key = (exchangeRet.length <= 2) ? Buffer.alloc(0) :
    exchangeRet.subarray(0, exchangeRet.length - 2);
  console.log(`liquidGetValueBlindingFactor = `, result);
  return key.toString('hex');
}

// LIQUID GET BLINDING FACTOR
async function liquidGetTXBlindingKey(transport) {
  const CLA = 0xe0;
  const LIQUID_GET_BLINDING_FACTOR = 0xe8;
  // const apdu = Buffer.from([CLA, LIQUID_GET_BLINDING_FACTOR, 3, 0, 0]);
  const apdu = Buffer.from(
      [CLA, LIQUID_GET_BLINDING_FACTOR, 3, 0, 4, 0, 0, 0, 0]);
  const exchangeRet = await transport.exchange(apdu);
  const result = (exchangeRet.length <= 2) ? exchangeRet :
    exchangeRet.subarray(exchangeRet.length - 2);
  const key = (exchangeRet.length <= 2) ? Buffer.alloc(0) :
   exchangeRet.subarray(0, exchangeRet.length - 2);
  console.log(`liquidGetTXBlindingKey = `, result);
  // liquidGetTXBlindingKey =  <Buffer 67 00> -> INCORRECT_LENGTH
  return key.toString('hex');
}

// LIQUID GET PUBLIC BLINDING KEY
async function liquidGetPublicBlindingKey(transport,
    authorizationPublicKeyHex) {
  const CLA = 0xe0;
  const LIQUID_GET_PUBLIC_BLINDING_KEY = 0xe2;
  const scriptPubkey = Buffer.from(authorizationPublicKeyHex, 'hex');
  const apdu = Buffer.concat([Buffer.from(
      [CLA, LIQUID_GET_PUBLIC_BLINDING_KEY, 0, 0]),
  Buffer.from([scriptPubkey.length]), scriptPubkey]);
  const exchangeRet = await transport.exchange(apdu);
  const result = (exchangeRet.length <= 2) ? exchangeRet :
    exchangeRet.subarray(exchangeRet.length - 2);
  const confKey = (exchangeRet.length <= 2) ? Buffer.alloc(0) :
    exchangeRet.subarray(0, exchangeRet.length - 2);
  console.log(`liquidGetPublicBlindingKey = `, result);
  return confKey.toString('hex');
}

async function liquidSetupHeadless(transport, authorizationPublicKeyHex) {
  const ADM_CLA = 0xd0;
  const LIQUID_SETUP_HEADLESS = 0x02;
  const authPubkey = authorizationPublicKeyHex;
  // console.log('authPubkey => ', authPubkey);
  const authPubkeyData = Buffer.from(authPubkey, 'hex');
  const apdu = Buffer.concat(
      [Buffer.from([ADM_CLA, LIQUID_SETUP_HEADLESS, 0, 0]),
        Buffer.from([authPubkeyData.length]), authPubkeyData]);
  const exchangeRet = await transport.exchange(apdu);
  return convertErrorCode(exchangeRet);
}

async function sendHashInputStartCmd(transport, p1, p2, data) {
  // FIXME split send.
  const CLA = 0xe0;
  const HASH_INPUT_START = 0x44;
  const apdu = Buffer.concat([Buffer.from([CLA, HASH_INPUT_START, p1, p2]),
    Buffer.from([data.length]), data]);
  const exchangeRet = await transport.exchange(apdu);
  const result = (exchangeRet.length <= 2) ? exchangeRet :
    exchangeRet.subarray(exchangeRet.length - 2);
  const resultData = (exchangeRet.length <= 2) ? Buffer.alloc(0) :
    exchangeRet.subarray(0, exchangeRet.length - 2);
  console.log(`sendHashInputStartCmd(${p1},${p2}) = `, result);
  if (exchangeRet.length > 2) {
    console.log(' data: ', resultData);
  }
  return {data: resultData, errorCode: convertErrorCode(result)};
}

async function sendHashInputFinalizeFullCmd(transport, p1, p2, data) {
  // FIXME split send.
  const CLA = 0xe0;
  const HASH_INPUT_FINALIZE_FULL = 0x4a;
  console.log(`sendHashInputFinalizeFullCmd send = `, data.toString('hex'));
  const apdu = Buffer.concat(
      [Buffer.from([CLA, HASH_INPUT_FINALIZE_FULL, p1, p2]),
        Buffer.from([data.length]), data]);
  const exchangeRet = await transport.exchange(apdu);
  const result = (exchangeRet.length <= 2) ? exchangeRet :
   exchangeRet.subarray(exchangeRet.length - 2);
  const resultData = (exchangeRet.length <= 2) ? Buffer.alloc(0) :
   exchangeRet.subarray(0, exchangeRet.length - 2);
  // console.log(`sendHashInputFinalizeFullCmd(${p1},${p2}) = `, result);
  if (exchangeRet.length > 2) {
    // console.log(' data: ', resultData);
  }
  return {data: resultData, errorCode: convertErrorCode(result)};
}

async function sendHashSignCmd(transport, data) {
  const CLA = 0xe0;
  const HASH_SIGN = 0x48;
  const apdu = Buffer.concat([Buffer.from([CLA, HASH_SIGN, 0, 0]),
    Buffer.from([data.length]), data]);
  const exchangeRet = await transport.exchange(apdu);
  const result = (exchangeRet.length <= 2) ? exchangeRet :
   exchangeRet.subarray(exchangeRet.length - 2);
  const resultData = (exchangeRet.length <= 2) ? Buffer.alloc(0) :
   exchangeRet.subarray(0, exchangeRet.length - 2);
  console.log(`sendHashSignCmd = `, result);
  if (exchangeRet.length > 2) {
    console.log(' data: ', resultData);
    // mask 0xfe
    resultData[0] = resultData[0] & 0xfe;
  }
  return {
    signature: resultData.toString('hex'),
    errorCode: convertErrorCode(result),
  };
}

async function startUntrustedTransaction(transport, dectx, isContinue,
    amountValueList, inputIndex, targetRedeemScript) {
  let p1 = 0;
  let p2 = (isContinue) ? 0x80 : 0x06;
  const txinHead = 0x03;

  const version = Buffer.alloc(4);
  version.writeUInt32LE(dectx.version, 0);
  let apdu = Buffer.concat([version, getVarIntBuffer([dectx.vin.length])]);
  let errData = await sendHashInputStartCmd(transport, p1, p2, apdu);
  if (errData.errorCode != 0x9000) {
    return errData.errorCode;
  }

  p1 = 0x80;
  p2 = 0x00;
  for (let idx = 0; idx < dectx.vin.length; ++idx) {
    const header = Buffer.from([txinHead]);
    const txid = reverseBuffer(Buffer.from(dectx.vin[idx].txid, 'hex'));
    const vout = Buffer.alloc(4);
    vout.writeUInt32LE(dectx.vin[idx].vout, 0);
    let value;
    if ((typeof amountValueList[idx] === 'number') ||
        (typeof amountValueList[idx] === 'bigint')) {
      value = convertValueFromAmount(amountValueList[idx]);
    } else {
      value = Buffer.from(amountValueList[idx], 'hex');
    }
    const script = (inputIndex != idx) ? Buffer.alloc(0) :
     Buffer.from(targetRedeemScript, 'hex');
    const sequence = Buffer.alloc(4);
    sequence.writeUInt32LE(dectx.vin[idx].sequence, 0);
    apdu = Buffer.concat([header, txid, vout, value,
      getVarIntBuffer(script.length), script, sequence]);
    errData = await sendHashInputStartCmd(transport, p1, p2, apdu);
    if (errData.errorCode != 0x9000) break;
  }
  return errData.errorCode;
}

async function liquidFinalizeInputFull(transport, dectx, confidentialKeyList) {
  let apdu = getVarIntBuffer(dectx.vout.length);
  let errData = await sendHashInputFinalizeFullCmd(transport, 0, 0, apdu);
  if (errData.errorCode != 0x9000) {
    return errData.errorCode;
  }

  let p1 = 0;
  for (let idx = 0; idx < dectx.vout.length; ++idx) {
    const scriptPubkey = Buffer.from(dectx.vout[idx].scriptPubKey.hex, 'hex');
    if ('valuecommitment' in dectx.vout[idx]) {
      const index = Buffer.alloc(4);
      index.writeUInt32BE(idx, 0);
      apdu = Buffer.concat([
        // Buffer.from([0xff]),   // signed data flag
        // index,
        Buffer.from(dectx.vout[idx].assetcommitment, 'hex'),
        Buffer.from(dectx.vout[idx].valuecommitment, 'hex')]);
      errData = await sendHashInputFinalizeFullCmd(transport, 0, 0, apdu);
      if (errData.errorCode != 0x9000) break;
      errData = await sendHashInputFinalizeFullCmd(transport, 0, 0,
          Buffer.from(dectx.vout[idx].commitmentnonce, 'hex'));
      if (errData.errorCode != 0x9000) break;
      errData = await sendHashInputFinalizeFullCmd(transport, 0, 0,
          Buffer.from(confidentialKeyList[idx], 'hex'));
      if (errData.errorCode != 0x9000) break;
    } else {
      const asset = reverseBuffer(Buffer.from(dectx.vout[idx].asset, 'hex'));
      apdu = Buffer.concat([
        Buffer.from([1]), asset,
        convertValueFromAmount(dectx.vout[idx].value)]);
      errData = await sendHashInputFinalizeFullCmd(transport, 0, 0, apdu);
      if (errData.errorCode != 0x9000) break;
      errData = await sendHashInputFinalizeFullCmd(
          transport, 0, 0, Buffer.from([0])); // nonce
      if (errData.errorCode != 0x9000) break;
      errData = await sendHashInputFinalizeFullCmd(
          transport, 0, 0, Buffer.from([0])); // confidentialKey
      if (errData.errorCode != 0x9000) break;
    }
    apdu = Buffer.concat([
      getVarIntBuffer(scriptPubkey.length),
      scriptPubkey]);
    console.log(`txout(${idx}) = `, apdu.toString('hex'));
    p1 = ((idx + 1) == dectx.vout.length) ? 0x80 : 0x00;
    errData = await sendHashInputFinalizeFullCmd(transport, p1, 0, apdu);
    console.log(`liquidFinalizeInputFull = `, errData.data.toString('hex'));
    if (errData.errorCode != 0x9000) break;
  }
  return errData.errorCode;
}

async function untrustedHashSign(transport, dectx, path, pin, sigHashType) {
  const pathBuffer = parseBip32Path(path);
  const authorization = Buffer.from(pin, 'hex');

  const locktime = Buffer.alloc(4);
  locktime.writeUInt32BE(dectx.locktime, 0);

  const apdu = Buffer.concat([
    Buffer.from([pathBuffer.length / 4]),
    pathBuffer,
    Buffer.from([authorization.length]),
    authorization,
    locktime,
    Buffer.from([sigHashType])]);
  console.log('untrustedHashSign send -> ', apdu.toString('hex'));
  return await sendHashSignCmd(transport, apdu);
}

async function liquidProvideIssuanceInformation(transport, dectx) {
  // unused setting. send 0x00 command.
  const CLA = 0xe0;
  const LIQUID_PROVIDE_ISSUANCE_INFORMATION = 0xe6;
  const p1 = 0x80;
  const data = Buffer.alloc(dectx.vin.length);
  const apdu = Buffer.concat(
      [Buffer.from([CLA, LIQUID_PROVIDE_ISSUANCE_INFORMATION, p1, 0]),
        Buffer.from([data.length]), data]);
  console.log('liquidProvideIssuanceInformation send -> ', apdu.toString('hex'));
  const exchangeRet = await transport.exchange(apdu);
  const result = (exchangeRet.length <= 2) ? exchangeRet :
   exchangeRet.subarray(exchangeRet.length - 2);
  console.log(`liquidProvideIssuanceInformation(${p1}) = `, result);
  return convertErrorCode(result);
/*
  def liquidProvideIssuanceInformation(self, issuanceInformation):
  offset = 0
  while (offset < len(issuanceInformation)):
  blockLength = 255
  if ((offset + blockLength) < len(issuanceInformation)):
  dataLength = blockLength
  p1 = 0x00
  else:
  dataLength = len(issuanceInformation) - offset
  p1 = 0x80
  apdu = [ self.BTCHIP_CLA, self.BTCHIP_INS_LIQUID_PROVIDE_ISSUANCE_INFORMATION, p1, 0x00, dataLength]
  apdu.extend(issuanceInformation[offset : offset + dataLength])
  self.dongle.exchange(bytearray(apdu))
  offset += dataLength
*/
}

function compressPubkey(publicKey) {
  return cfdjs.GetCompressedPubkey({pubkey: publicKey}).pubkey;
}

const ledgerLiquidWrapper = class LedgerLiquidWrapper {
  constructor(transport, networkType) {
    if ((networkType !== 'liquidv1') && (networkType !== 'regtest')) {
      throw new Error('illegal network type.');
    }
    this.transport = transport;
    this.networkType = networkType;
    this.mainchainNetwork = (networkType === 'regtest') ?
        'regtest' : 'mainnet';
  }

  getPublicKeyRedeemScript(publicKey) {
    const legacyAddress = cfdjs.CreateAddress({
      keyData: {
        hex: publicKey,
        type: 'pubkey',
      },
      network: this.networkType,
      isElements: true,
      hashType: 'p2pkh',
    });
    return legacyAddress.lockingScript;
  }

  async getWalletPublicKey(bip32Path) {
    // TODO(k-matsuzawa): notfound liquid option(0x10, 0x11)
    const p2 = 0; // = 0x10;
    const result = await getWalletPublicKey(this.transport, bip32Path, p2);
    return {
      success: (result.errorCode === 0x9000),
      errorCode: result.errorCode,
      errorMessage: (result.errorCode === 0x9000) ? '' : 'other error',
      publicKey: compressPubkey(result.pubkey),
      chainCode: result.chainCode,
    };
  }

  // async getWalletConfidentialAddress(address: string) {
  //   return {
  //     confidentialAddress: string,
  //     confidentialKey: string,
  //   };
  // }

  async setupHeadlessAuthorization(authorizationPublicKey) {
    const ecode = await liquidSetupHeadless(this.transport,
        authorizationPublicKey);
    let errorMessage = 'other error.';
    if (ecode === 0x9000) {
      errorMessage = '';
    } else if (ecode === 0x6985) {
      errorMessage = 'CONDITIONS_OF_USE_NOT_SATISFIED';
    }
    return {
      success: (ecode === 0x9000),
      errorCode: ecode,
      errorMessage: errorMessage,
    };
  }

  async getSignature(proposalTransaction, txinUtxoList, walletUtxoList,
      authorizationSignature) {
    const dectx = cfdjs.ElementsDecodeRawTransaction({
      hex: proposalTransaction, network: this.network,
      mainchainNetwork: this.mainchainNetwork});

    const amountValueList = [];
    const confidentialKeyList = [];

    const utxoList = txinUtxoList;
    for (const utxo of walletUtxoList) {
      utxoList.push(utxo);
    }
    for (const txin of dectx.vin) {
      let isFind = false;
      for (const utxo of utxoList) {
        if ((txin.txid === utxo.txid) && (txin.vout === utxo.vout)) {
          amountValueList.push((!utxo.valueCommitment) ?
              utxo.amount : utxo.valueCommitment);
          isFind = true;
          break;
        }
      }
      if (!isFind) {
        throw new Error('txin is not in the utxo list.');
      }
    }
    let ecode = 0;
    const signatureList = [];

    ecode = await startUntrustedTransaction(this.transport, dectx, false,
        amountValueList, 0, '');
    if (ecode === 0x9000) {
      ecode = await liquidFinalizeInputFull(this.transport, dectx,
          confidentialKeyList);
    }
    if (ecode === 0x9000) {
      ecode = await liquidProvideIssuanceInformation(this.transport, dectx);
    }

    if (ecode === 0x9000) {
      // sighashtype: 1=all only
      const sighashtype = 1;
      for (const utxo of walletUtxoList) {
        let targetIndex = -1;
        for (const index = 0; index < dectx.vin.length; ++index) {
          if ((dectx.vin[index].txid === utxo.txid) &&
              (dectx.vin[index].vout === utxo.vout)) {
            targetIndex = index;
            break;
          }
        }
        if (targetIndex === -1) {
          throw new Error('wallet utxo is not in the txin list.');
        }

        let redeemScript = '';
        if (!utxo.descriptor && !utxo.redeemScript) {
          // bip32 path -> pubkey -> lockingscript
        } else if (!utxo.descriptor) {
          redeemScript = utxo.redeemScript;
        } else {
          const desc = cfdjs.ParseDescriptor({
            isElements: true,
            descriptor: utxo.descriptor,
            network: this.network,
          });
          if (('scripts' in desc) && (desc.scripts.length > 0) &&
              ('redeemScript' in desc.scripts[desc.scripts.length - 1])) {
            redeemScript = desc.scripts[desc.scripts.length - 1].redeemScript;
          }
        }

        if (!redeemScript) {
          const pubkey = await this.getWalletPublicKey(utxo.bip32Path);
          redeemScript = this.getPublicKeyRedeemScript(pubkey);
        }

        ecode = await startUntrustedTransaction(this.transport, dectx,
            true, amountValueList, targetIndex, redeemScript);
        const signatureRet = await untrustedHashSign(this.transport, dectx,
            utxo.bip32Path, authorizationSignature, sighashtype);
        ecode = signatureRet.errorCode;
        signatureList.push({
          utxoData: utxo,
          signature: signatureRet.signature,
        });
      }
    }

    return {
      success: (ecode === 0x9000),
      errorCode: ecode,
      errorMessage: (ecode === 0x9000) ? '' : 'other error.',
      signatureList: signatureList,
    };
  }
};

module.exports = ledgerLiquidWrapper;
module.exports.LedgerLiquidWrapper = ledgerLiquidWrapper;
