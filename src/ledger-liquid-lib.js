/* eslint-disable require-jsdoc */
// import * as TransportNodeHid from '@ledgerhq/hw-transport-node-hid';
const TransportNodeHid = require('@ledgerhq/hw-transport-node-hid').default;
const LedgerDeviceInfo = require('@ledgerhq/devices');
const cfdjs = require('cfd-js');
const usb = require('usb');

function convertErrorCode(buf) {
  return buf.readUInt16BE();
}

// eslint-disable-next-line @typescript-eslint/no-unused-vars
function debugSendLog(funcName, buffer) {
  // console.log(funcName, buffer.toString('hex'));
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

function parseBip32Path(path, parent = false) {
  let targetPath = path;
  if (targetPath.startsWith('m/')) {
    targetPath = targetPath.substring(2);
  }
  if (targetPath === '') {
    throw new Error('empty BIP 32 path.');
  }

  const items = targetPath.split('/');
  if (items.length > 10) {
    throw new Error('Out of Range. Number of BIP 32 derivations to perform is up to 10.');
  }
  const hardendedTargets = ['\'', 'h', 'H'];

  const length = (parent) ? items.length - 1 : items.length;
  if (length === 0) {
    throw new Error('Out of Range. Number of BIP 32 derivations to perform is empty.');
  }
  const buf = Buffer.alloc(length * 4);
  const array = [];
  for (let idx = 0; idx < length; ++idx) {
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
        array.push(value);
        buf.writeUInt32BE(value, idx * 4);
        isFind = true;
        break;
      }
    }
    if (!isFind) {
      const num = Number(items[idx]);
      if (num === Number.NaN) throw new Error(`Illegal path format. [${items[idx]}]`);
      array.push(num);
      buf.writeUInt32BE(num, idx * 4);
    }
  }
  // console.log('bip32 path => ', buf);
  return {
    buffer: buf,
    array: array,
  };
}

function splitByteArray255(byteArray) {
  const array = [];
  for (let offset = 0; offset < byteArray.length; offset += 255) {
    const maxOffset = (byteArray.length > (offset + 255)) ?
       (offset + 255) : byteArray.length;
    array.push(byteArray.subarray(offset, maxOffset));
  }
  return array;
}

// GET WALLET PUBLIC KEY
async function getWalletPublicKey(
    transport, path, option, parent = false) {
  const CLA = 0xe0;
  const GET_WALLET_PUBLIC_KEY = 0x40;
  const p1 = 0;

  const pathBuffer = parseBip32Path(path, parent).buffer;

  const data = Buffer.concat([
    Buffer.from([pathBuffer.length / 4]),
    pathBuffer]);
  debugSendLog('getWalletPublicKey send -> ', data);
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
  let address = '';
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
      if (addressLength > 0) {
        const addrOffset = pubkeyLength + 2;
        address = exchangeRet.subarray(addrOffset, addrOffset + addressLength)
            .toString();
      }
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
    address: address,
  };
}

// GET COIN VERSION
async function getCoinVersion(transport) {
  const CLA = 0xe0;
  const GET_COIN_VERSION = 0x16;
  const apdu = Buffer.from([CLA, GET_COIN_VERSION, 0, 0, 0]);
  const exchangeRet = await transport.exchange(apdu);
  const result = (exchangeRet.length <= 2) ? exchangeRet :
    exchangeRet.subarray(exchangeRet.length - 2);
  let prefixP2pkh = 0;
  let prefixP2sh = 0;
  let coinFamily = 0;
  let coinName = '';
  let coinTicker = '';
  if (exchangeRet.length >= 9) {
    prefixP2pkh = exchangeRet.readUInt16BE(0);
    prefixP2sh = exchangeRet.readUInt16BE(2);
    coinFamily = exchangeRet[4];
    const coinNameLen = exchangeRet[5];
    if (coinNameLen > 0) {
      coinName = exchangeRet.subarray(6, 6 + coinNameLen).toString();
    }
    const offset = 6 + coinNameLen;
    if (offset < exchangeRet.length) {
      const coinTickerLen = exchangeRet[offset];
      if (coinTickerLen > 0) {
        coinTicker = exchangeRet.subarray(
            offset + 1, offset + coinTickerLen + 1).toString();
      }
    }
  }
  return {
    errorCode: convertErrorCode(result),
    prefixP2pkh: prefixP2pkh,
    prefixP2sh: prefixP2sh,
    coinFamily: coinFamily,
    coinName: coinName,
    coinTicker: coinTicker,
  };
}

// GET FIRMWARE VERSION
async function getFirmwareVersion(transport) {
  const CLA = 0xe0;
  const GET_FIRMWARE_VERSION = 0xc4;
  const apdu = Buffer.from([CLA, GET_FIRMWARE_VERSION, 0, 0, 0]);
  const exchangeRet = await transport.exchange(apdu);
  const result = (exchangeRet.length <= 2) ? exchangeRet :
    exchangeRet.subarray(exchangeRet.length - 2);
  let version = '';
  let flag = 0;
  let architecture = 0;
  let major = 0;
  let minor = 0;
  let patch = 0;
  let loaderMajor = 0;
  let loaderMinor = 0;
  if (exchangeRet.length >= 5) {
    flag = exchangeRet[0];
    architecture = exchangeRet[1];
    major = exchangeRet[2];
    minor = exchangeRet[3];
    patch = exchangeRet[4];
    version = `${major}.${minor}.${patch}.`;
    if (exchangeRet.length >= 7) {
      loaderMajor = exchangeRet[5];
      loaderMinor = exchangeRet[6];
    }
  }
  return {
    errorCode: convertErrorCode(result),
    versionString: version,
    flag: flag,
    architecture: architecture,
    version: {
      major: major,
      minor: minor,
      patch: patch,
    },
    loader: {
      major: loaderMajor,
      minor: loaderMinor,
      patch: 0,
    },
  };
}

async function liquidSetupHeadless(transport, authorizationPublicKeyHex) {
  const ADM_CLA = 0xd0;
  const LIQUID_SETUP_HEADLESS = 0x02;
  const authPubkeyData = Buffer.from(authorizationPublicKeyHex, 'hex');
  const apdu = Buffer.concat(
      [Buffer.from([ADM_CLA, LIQUID_SETUP_HEADLESS, 0, 0]),
        Buffer.from([authPubkeyData.length]), authPubkeyData]);
  const exchangeRet = await transport.exchange(apdu);
  return convertErrorCode(exchangeRet);
}

async function sendHashInputStartCmd(transport, p1, p2, data) {
  const CLA = 0xe0;
  const HASH_INPUT_START = 0x44;
  const dataArray = splitByteArray255(data);
  let ecode = 0x9000;
  let resultData = Buffer.alloc(0);
  for (const index in dataArray) {
    if (!dataArray[index]) {
      continue;
    }
    const inputData = dataArray[index];
    // Use "==" because the value types are different.
    const apdu = Buffer.concat([Buffer.from([CLA, HASH_INPUT_START, p1, p2]),
      Buffer.from([inputData.length]), inputData]);
    debugSendLog('sendHashInputStartCmd send -> ', apdu);
    const exchangeRet = await transport.exchange(apdu);
    const result = (exchangeRet.length <= 2) ? exchangeRet :
      exchangeRet.subarray(exchangeRet.length - 2);
    resultData = (exchangeRet.length <= 2) ? Buffer.alloc(0) :
      exchangeRet.subarray(0, exchangeRet.length - 2);
    ecode = convertErrorCode(result);
    if (ecode !== 0x9000) {
      console.log('sendHashInputStartCmd Fail. ecode =', ecode);
      break;
    }
  }
  return {data: resultData, errorCode: ecode};
}

async function sendHashInputFinalizeFullCmd(transport, p1, p2, data) {
  // No need to divide because the transmission data unit is small.
  const CLA = 0xe0;
  const HASH_INPUT_FINALIZE_FULL = 0x4a;
  const apdu = Buffer.concat(
      [Buffer.from([CLA, HASH_INPUT_FINALIZE_FULL, p1, p2]),
        Buffer.from([data.length]), data]);
  debugSendLog('sendHashInputFinalizeFullCmd send -> ', apdu);
  const exchangeRet = await transport.exchange(apdu);
  const result = (exchangeRet.length <= 2) ? exchangeRet :
    exchangeRet.subarray(exchangeRet.length - 2);
  const resultData = (exchangeRet.length <= 2) ? Buffer.alloc(0) :
    exchangeRet.subarray(0, exchangeRet.length - 2);
  const ecode = convertErrorCode(result);
  if (ecode != 0x9000) {
    // console.log('sendHashInputFinalizeFullCmd recv: ', exchangeRet.toString('hex'));
  }
  return {data: resultData, errorCode: ecode};
}

async function sendHashSignCmd(transport, data) {
  const CLA = 0xe0;
  const HASH_SIGN = 0x48;
  const apdu = Buffer.concat([Buffer.from([CLA, HASH_SIGN, 0, 0]),
    Buffer.from([data.length]), data]);
  debugSendLog('sendHashSignCmd send -> ', apdu);
  const exchangeRet = await transport.exchange(apdu);
  const result = (exchangeRet.length <= 2) ? exchangeRet :
   exchangeRet.subarray(exchangeRet.length - 2);
  const resultData = (exchangeRet.length <= 2) ? Buffer.alloc(0) :
   exchangeRet.subarray(0, exchangeRet.length - 2);
  if (exchangeRet.length > 2) {
    // mask 0xfe
    resultData[0] = resultData[0] & 0xfe;
  }
  return {
    signature: resultData.toString('hex'),
    errorCode: convertErrorCode(result),
  };
}

async function startUntrustedTransaction(transport, dectx, isContinue,
    amountValueList, inputIndex, targetRedeemScript,
    countupFunction = undefined) {
  let p1 = 0;
  const p2 = (isContinue) ? 0x80 : 0x06;
  const txinHead = 0x03;

  const version = Buffer.alloc(4);
  version.writeUInt32LE(dectx.version, 0);
  const inputNum = (inputIndex === -1) ? dectx.vin.length : 1;
  let apdu = Buffer.concat([version, getVarIntBuffer([inputNum])]);
  let errData = await sendHashInputStartCmd(transport, p1, p2, apdu);
  if (errData.errorCode != 0x9000) {
    console.log('fail sendHashInputStartCmd', errData);
    return errData.errorCode;
  }

  p1 = 0x80;
  // p2 = 0x00;
  for (let idx = 0; idx < dectx.vin.length; ++idx) {
    if ((inputIndex !== -1) && (idx !== inputIndex)) {
      continue;
    }
    const header = Buffer.from([txinHead]);
    const txid = reverseBuffer(Buffer.from(dectx.vin[idx].txid, 'hex'));
    const vout = Buffer.alloc(4);
    vout.writeUInt32LE(dectx.vin[idx].vout, 0);
    if ('issuance' in dectx.vin[idx]) {
      vout[3] |= 0x80;
    }
    let value;
    if ((typeof amountValueList[idx] === 'number') ||
        (typeof amountValueList[idx] === 'bigint')) {
      value = convertValueFromAmount(amountValueList[idx]);
    } else {
      value = Buffer.from(amountValueList[idx], 'hex');
    }
    const script = Buffer.from(targetRedeemScript, 'hex');
    const sequence = Buffer.alloc(4);
    sequence.writeUInt32LE(dectx.vin[idx].sequence, 0);
    apdu = Buffer.concat([header, txid, vout, value,
      getVarIntBuffer(script.length)]);
    errData = await sendHashInputStartCmd(transport, p1, p2, apdu);
    if (errData.errorCode != 0x9000) {
      console.log('fail sendHashInputStartCmd2', errData);
      break;
    }
    if (script.length !== 0) {
      apdu = Buffer.concat([script, sequence]);
      errData = await sendHashInputStartCmd(transport, p1, p2, apdu);
      if (errData.errorCode != 0x9000) {
        console.log('fail sendHashInputStartCmd2', errData);
        break;
      }
    } else {
      errData = await sendHashInputStartCmd(transport, p1, p2, sequence);
      if (errData.errorCode != 0x9000) {
        console.log('fail sendHashInputStartCmd2', errData);
        break;
      }
    }

    if ((inputIndex !== -1) && ('issuance' in dectx.vin[idx])) {
      let data;
      const issuance = dectx.vin[idx].issuance;
      if ('contractHash' in issuance) {
        data = Buffer.concat([
          reverseBuffer(Buffer.from(issuance.assetBlindingNonce, 'hex')),
          reverseBuffer(Buffer.from(issuance.contractHash, 'hex')),
        ]);
      } else {
        data = Buffer.concat([
          reverseBuffer(Buffer.from(issuance.assetBlindingNonce, 'hex')),
          reverseBuffer(Buffer.from(issuance.assetEntropy, 'hex')),
        ]);
      }
      if ('assetamount' in issuance) {
        data = Buffer.concat([
          data,
          convertValueFromAmount(issuance.assetamount),
        ]);
      } else if ('assetamountcommitment' in issuance) {
        data = Buffer.concat([
          data,
          Buffer.from(issuance.assetamountcommitment, 'hex'),
        ]);
      } else {
        data = Buffer.concat([data, Buffer.alloc(1)]);
      }
      if ('tokenamount' in issuance) {
        data = Buffer.concat([
          data,
          convertValueFromAmount(issuance.tokenamount),
        ]);
      } else if ('tokenamountcommitment' in issuance) {
        data = Buffer.concat([
          data,
          Buffer.from(issuance.tokenamountcommitment, 'hex'),
        ]);
      } else {
        data = Buffer.concat([data, Buffer.alloc(1)]);
      }
      errData = await sendHashInputStartCmd(transport, p1, p2, data);
      if (errData.errorCode != 0x9000) {
        console.log('fail sendHashInputStartCmd2', errData);
        break;
      }
    }

    if (countupFunction) countupFunction();
  }
  return errData.errorCode;
}

async function liquidFinalizeInputFull(transport, dectx,
    countupFunction = undefined) {
  let apdu = getVarIntBuffer(dectx.vout.length);
  let errData = await sendHashInputFinalizeFullCmd(transport, 0, 0, apdu);
  if (errData.errorCode != 0x9000) {
    console.log('fail liquidFinalizeInputFull2', errData);
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
      if (errData.errorCode != 0x9000) {
        console.log('liquidFinalizeInputFull ', errData);
        break;
      }
      errData = await sendHashInputFinalizeFullCmd(transport, 0, 0,
          Buffer.from(dectx.vout[idx].commitmentnonce, 'hex'));
      if (errData.errorCode != 0x9000) {
        console.log('liquidFinalizeInputFull ', errData);
        break;
      }
      // errData = await sendHashInputFinalizeFullCmd(
      //     transport, 0, 0, Buffer.from([0])); // confidentialKey
      // if (errData.errorCode != 0x9000) break;
    } else {
      const asset = reverseBuffer(Buffer.from(dectx.vout[idx].asset, 'hex'));
      apdu = Buffer.concat([
        Buffer.from([1]), asset,
        convertValueFromAmount(dectx.vout[idx].value)]);
      errData = await sendHashInputFinalizeFullCmd(transport, 0, 0, apdu);
      if (errData.errorCode != 0x9000) {
        console.log('liquidFinalizeInputFull ', errData);
        break;
      }
      errData = await sendHashInputFinalizeFullCmd(
          transport, 0, 0, Buffer.from([0])); // nonce
      if (errData.errorCode != 0x9000) {
        console.log('liquidFinalizeInputFull ', errData);
        break;
      }
      errData = await sendHashInputFinalizeFullCmd(
          transport, 0, 0, Buffer.from([0])); // confidentialKey
      if (errData.errorCode != 0x9000) {
        console.log('liquidFinalizeInputFull ', errData);
        break;
      }
    }
    apdu = Buffer.concat([
      getVarIntBuffer(scriptPubkey.length),
      scriptPubkey]);
    // console.log(`txout(${idx}) = `, apdu.toString('hex'));
    p1 = ((idx + 1) == dectx.vout.length) ? 0x80 : 0x00;
    errData = await sendHashInputFinalizeFullCmd(transport, p1, 0, apdu);
    if (errData.errorCode != 0x9000) {
      console.log(`liquidFinalizeInputFull = `, errData.data.toString('hex'));
      break;
    }

    if (countupFunction) countupFunction();
  }
  if (errData.errorCode != 0x9000) {
    console.log('liquidFinalizeInputFull ', errData);
  }
  return errData.errorCode;
}

async function untrustedHashSign(transport, dectx, path, pin, sigHashType) {
  const pathBuffer = parseBip32Path(path).buffer;
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
  // console.log('untrustedHashSign send -> ', apdu.toString('hex'));
  const result = await sendHashSignCmd(transport, apdu);
  if (result.errorCode != 0x9000) {
    console.log('untrustedHashSign fail =', result);
  }
  return result;
}

async function sendProvideIssuanceInformationCmd(
    transport, data, isFinal) {
  const CLA = 0xe0;
  const LIQUID_PROVIDE_ISSUANCE_INFORMATION = 0xe6;
  const dataArray = splitByteArray255(data);
  let ecode = 0x9000;
  for (const index in dataArray) {
    if (!dataArray[index]) {
      continue;
    }
    const inputData = dataArray[index];
    // Use "==" because the value types are different.
    const p1 = (isFinal && (dataArray.length - 1) == index) ? 0x80 : 0x00;
    const apdu = Buffer.concat(
        [Buffer.from([CLA, LIQUID_PROVIDE_ISSUANCE_INFORMATION, p1, 0]),
          Buffer.from([inputData.length]), inputData]);
    debugSendLog('liquidProvideIssuanceInformation send -> ', apdu);
    const exchangeRet = await transport.exchange(apdu);
    const result = (exchangeRet.length <= 2) ? exchangeRet :
      exchangeRet.subarray(exchangeRet.length - 2);
    ecode = convertErrorCode(result);
    if (ecode !== 0x9000) {
      console.log('sendProvideIssuanceInformationCmd Fail. ecode =', ecode);
      break;
    }
  }
  return ecode;
}

async function liquidProvideIssuanceInformation(transport, dectx,
    countupFunction = undefined) {
  let isFind = false;
  for (let idx = 0; idx < dectx.vin.length; ++idx) {
    if ('issuance' in dectx.vin[idx]) {
      isFind = true;
      break;
    }
  }

  let ecode = 0x9000;
  let data;
  if (!isFind) {
    data = Buffer.alloc(dectx.vin.length);
    ecode = await sendProvideIssuanceInformationCmd(
        transport, data, true);
    return ecode;
  }

  let allData = Buffer.alloc(0);
  for (let idx = 0; idx < dectx.vin.length; ++idx) {
    if ('issuance' in dectx.vin[idx]) {
      const issuance = dectx.vin[idx].issuance;
      if ('contractHash' in issuance) {
        data = Buffer.concat([
          reverseBuffer(Buffer.from(issuance.assetBlindingNonce, 'hex')),
          reverseBuffer(Buffer.from(issuance.contractHash, 'hex')),
        ]);
      } else {
        data = Buffer.concat([
          reverseBuffer(Buffer.from(issuance.assetBlindingNonce, 'hex')),
          reverseBuffer(Buffer.from(issuance.assetEntropy, 'hex')),
        ]);
      }
      if ('assetamount' in issuance) {
        data = Buffer.concat([
          data,
          convertValueFromAmount(issuance.assetamount),
        ]);
      } else if ('assetamountcommitment' in issuance) {
        data = Buffer.concat([
          data,
          Buffer.from(issuance.assetamountcommitment, 'hex'),
        ]);
      } else {
        data = Buffer.concat([data, Buffer.alloc(1)]);
      }
      if ('tokenamount' in issuance) {
        data = Buffer.concat([
          data,
          convertValueFromAmount(issuance.tokenamount),
        ]);
      } else if ('tokenamountcommitment' in issuance) {
        data = Buffer.concat([
          data,
          Buffer.from(issuance.tokenamountcommitment, 'hex'),
        ]);
      } else {
        data = Buffer.concat([data, Buffer.alloc(1)]);
      }
      if (allData.length > 0) {
        ecode = await sendProvideIssuanceInformationCmd(
            transport, allData, false);
        if (ecode !== 0x9000) {
          break;
        }
        allData = Buffer.alloc(0);
      }
      ecode = await sendProvideIssuanceInformationCmd(
          transport, data, (idx == dectx.vin.length - 1));
      if (countupFunction) countupFunction();
      if (ecode !== 0x9000) {
        break;
      }
    } else {
      data = Buffer.alloc(1);
      allData = Buffer.concat([allData, data]);
    }
  }
  if ((ecode === 0x9000) && (allData.length > 0)) {
    ecode = await sendProvideIssuanceInformationCmd(
        transport, allData, true);
  }
  return ecode;
}

function calculateGetSignatureProgress(dectx, utxoListLength) {
  let txNum = 0;
  let issuanceNum = 0;
  if (dectx.vin) {
    txNum += dectx.vin.length;
    for (let idx = 0; idx < dectx.vin.length; ++idx) {
      if ('issuance' in dectx.vin[idx]) {
        ++issuanceNum;
      }
    }
  }
  if (dectx.vout) txNum += dectx.vout.length;
  txNum += issuanceNum;
  return {
    utxoNum: utxoListLength,
    txNum: txNum,
  };
}

const disconnectEcode = 0x6d00; // INS_NOT_SUPPORTED
const accessingEcode = 0x9999;
const accessingMsg = 'accessing other command';

const applicationType = {
  LiquidV1: 'liquidv1',
  Regtest: 'regtest',
  Auto: 'auto',
};

async function checkConnect(transport, checkAppType) {
  // console.time('call getCoinVersion');
  const result = await getCoinVersion(transport);
  // console.timeEnd('call getCoinVersion');
  // console.log('getCoinVersion =', result);
  let connectApp = applicationType.Auto;
  let ecode = result.errorCode;
  if (result.errorCode === 0x9000) {
    if ((result.prefixP2pkh === 0x39) &&
        (result.prefixP2sh === 0x27) &&
        (result.coinFamily === 0x01) &&
        (result.coinName === 'Bitcoin') &&
        (result.coinTicker === 'BTC') &&
        (checkAppType !== applicationType.Regtest)) {
      // liquid mainnet
      connectApp = applicationType.LiquidV1;
    } else if ((result.prefixP2pkh === 0xeb) &&
        (result.prefixP2sh === 0x4b) &&
        (result.coinFamily === 0x01) &&
        (result.coinName === 'Bitcoin') &&
        (result.coinTicker === 'BTC') &&
        (checkAppType !== applicationType.LiquidV1)) {
      // liquid testnet
      connectApp = applicationType.Regtest;
    } else {
      ecode = disconnectEcode;
    }
  }
  return {
    errorCode: ecode,
    application: connectApp,
  };
}

function compressPubkey(publicKey) {
  if (!publicKey) return '';
  return cfdjs.GetCompressedPubkey({pubkey: publicKey}).pubkey;
}

const sleep = (msec) => new Promise(
    (resolve) => setTimeout(resolve, msec));

const networkTypeDefine = {
  LiquidV1: 'liquidv1',
  Regtest: 'regtest',
};

const addressType = {
  Legacy: 'legacy',
  P2shSegwit: 'p2sh-segwit',
  Bech32: 'bech32',
};

const currentApplicationType = {
  LiquidHeadless: 'Liquid Hless',
  LiquidTestHeadless: 'Liquid Test Hless',
  Empty: '',
};

const getSignatureState = {
  AnalyzeUtxo: 'analyzeUtxo',
  InputTx: 'inputTx',
  GetSignature: 'getSignature',
};

const usbDetectionType = {
  Add: 'add',
  Remove: 'remove',
};

let isStartMonitoring = false;
const notifyFunctionList = [];
const usbTimeout = 5000;

function connectionNotification(type, usbDevice) {
  const deviceInfo = {
    locationId: 0, // unknown
    vendorId: usbDevice.deviceDescriptor.idVendor,
    productId: usbDevice.deviceDescriptor.idProduct,
    deviceName: '', // SPDRP_FRIENDLYNAME or SPDRP_DEVICEDESC
    manufacturer: '', // SPDRP_MFG
    serialNumber: '', // <device-ID>\<instance-specific-ID>
    deviceAddress: usbDevice.deviceAddress,
  };
  // console.log(`## connectionNotification: ${type}: `, deviceInfo);
  // console.log(`## usbDevice: `, usbDevice);
  const vendorId = deviceInfo.vendorId;
  if (LedgerDeviceInfo.ledgerUSBVendorId != vendorId) {
    return;
  }
  if (usbDevice.timeout < usbTimeout) {
    // The ledger device may take over 2000msec to respond.
    usbDevice.timeout = usbTimeout;
  }
  if (deviceInfo.productId != 1) { // ledger top view
    return;
  }

  if (notifyFunctionList) {
    for (const func of notifyFunctionList) {
      func(type, deviceInfo);
    }
  }
}

function detachDetectedUsb(device) {
  if (isStartMonitoring) {
    connectionNotification(usbDetectionType.Remove, device);
  }
}

function attachDetectedUsb(device) {
  if (isStartMonitoring) {
    connectionNotification(usbDetectionType.Add, device);
  }
}

const ledgerLiquidWrapper = class LedgerLiquidWrapper {
  constructor(networkType, checkApplication = false) {
    this.transport = undefined;
    if ((networkType !== networkTypeDefine.LiquidV1) &&
        (networkType !== networkTypeDefine.Regtest)) {
      throw new Error('illegal network type.');
    }
    let checkAppType = applicationType.Auto;
    if (checkApplication && checkApplication === true) {
      if (networkType === networkTypeDefine.LiquidV1) {
        checkAppType = applicationType.LiquidV1;
      } else {
        checkAppType = applicationType.Regtest;
      }
    }
    this.networkType = networkType;
    this.mainchainNetwork = (networkType === networkTypeDefine.Regtest) ?
        'regtest' : 'mainnet';
    this.waitForConnecting = false;
    this.accessing = false;
    this.connectAccessing = false;
    this.checkAppType = checkAppType;
    this.currentApplication = applicationType.Auto;
    this.currentDevicePath = '';
    this.lastConnectTime = 0;
    this.lastConnectCheckTime = 0;
    // getSignature's state
    this.getSigState = {
      utxoNum: 0,
      txNum: 0,
      current: {
        state: getSignatureState.AnalyzeUtxo,
        utxoNum: 0,
        txNum: 0,
        sigNum: 0,
      },
      lastAccessTime: 0,
    };
  }

  static startUsbDetectMonitoring() {
    if (!isStartMonitoring) {
      isStartMonitoring = true;
      usb.on('detach', detachDetectedUsb);
      usb.on('attach', attachDetectedUsb);
      // usb.setDebugLevel(4); // debug level
    }
  }

  static finishUsbDetectMonitoring() {
    if (isStartMonitoring) {
      isStartMonitoring = false;
      usb.removeListener('detach', detachDetectedUsb);
      usb.removeListener('attach', attachDetectedUsb);
    }
  }

  static registerUsbDetectListener(func) {
    notifyFunctionList.push(func);
  }

  static async getDeviceList() {
    let devList = [];
    let ecode = disconnectEcode;
    let errMsg = 'other error';
    try {
      devList = await TransportNodeHid.list();
      ecode = 0x9000;
      errMsg = '';
    } catch (e) {
      console.log(e);
    }
    return {
      success: (ecode === 0x9000),
      errorCode: ecode,
      errorCodeHex: ecode.toString(16),
      errorMessage: errMsg,
      disconnect: false,
      deviceList: devList,
    };
  }

  getCurrentApplication() {
    if (this.currentApplication === applicationType.LiquidV1) {
      return currentApplicationType.LiquidHeadless;
    } else if (this.currentApplication === applicationType.Regtest) {
      return currentApplicationType.LiquidTestHeadless;
    } else {
      return currentApplicationType.Empty;
    }
  }

  getLastConnectionInfo() {
    return {
      currentDevicePath: this.currentDevicePath,
      lastConnectTime: this.lastConnectTime,
    };
  }

  isAccessing() {
    return this.accessing;
  }

  async connect(maxWaitTime = undefined, devicePath = undefined) {
    const waitLimit = (typeof maxWaitTime === 'number') ?
        maxWaitTime : 0xffffffff;
    const path = (typeof devicePath === 'string') ? devicePath : '';
    let transport = undefined;
    let count = (waitLimit < 1) ? 0 : 1;
    let ecode = disconnectEcode;
    let errMsg = 'other error';
    let execConnect = false;
    if (this.isAccessing()) {
      ecode = accessingEcode;
      errMsg = accessingMsg;
    } else if (this.transport) {
      const connRet = await this.isConnected();
      ecode = connRet.errorCode;
      if (connRet.success === false) {
        await this.disconnect();
        execConnect = true;
      } else {
        errMsg = 'already connected.';
      }
    } else {
      execConnect = true;
    }

    if (execConnect) {
      ecode = disconnectEcode;
      try {
        this.accessing = true;
        this.waitForConnecting = true;

        while ((count <= waitLimit) && this.waitForConnecting) {
          try {
            transport = await TransportNodeHid.open(path);

            const ret = await checkConnect(transport, this.checkAppType);
            ecode = ret.errorCode;
            if (ecode === 0x9000) {
              this.transport = transport;
              // this.transport.on('disconnect', this.disconnectNotification);
              this.currentApplication = ret.application;
              this.lastConnectCheckTime = Date.now();
              if (!path) {
                console.log('list start');
                const devList = await TransportNodeHid.list();
                console.log('list end');
                this.currentDevicePath = (!devList) ? '' : devList[0];
              } else {
                this.currentDevicePath = path;
              }
              this.lastConnectTime = this.lastConnectCheckTime;
              break;
            } else if (ecode !== disconnectEcode) {
              console.log('illegal error. ', ecode);
              await this.close(transport);
              break;
            }
          } catch (e) {
            // console.log(`connection fail. count=${count}`, e);
            const errText = e.toString();
            if (errText.indexOf('DisconnectedDevice: Cannot write to HID device') >= 0) {
              // disconnect error
            } else if (errText.indexOf('TypeError: Cannot write to hid device') >= 0) {
              // disconnect error
            } else if (errText.indexOf('TransportError: NoDevice') >= 0) {
              // device connect error
            } else if (errText.indexOf('cannot open device with path') >= 0) {
              // device connect error
            } else if (errText.indexOf('The device was disconnected') >= 0) {
              // device connect error
            } else if (errText.indexOf('Must be handling a user gesture to show a permission request') >= 0) {
              // device connect error
            } else if (errText.indexOf('No device selected.') >= 0) {
              // disconnect error
            } else {
              console.warn(e);
              console.log(`connection fail.(exception) count=${count}`, e);
              ecode = 0x6000;
              errMsg = errText;
              break;
            }
          }
          if (transport) await this.close(transport);
          transport = undefined;
          if (count !== 0) console.info(`connection fail. count=${count}`);
          ++count;
          if (count < waitLimit) await sleep(1000);
        }
      } catch (err) {
        // do nothing
      } finally {
        if (ecode === 0x9000) {
          errMsg = '';
        } else if (ecode === disconnectEcode) {
          if (this.waitForConnecting) {
            errMsg = 'connection fail.';
          } else {
            errMsg = 'connection cancel.';
          }
        }
        this.accessing = false;
        this.waitForConnecting = false;
      }
    }

    return {
      success: (ecode === 0x9000),
      errorCode: ecode,
      errorCodeHex: ecode.toString(16),
      errorMessage: errMsg,
      disconnect: (ecode === disconnectEcode),
    };
  }

  cancelConnect() {
    this.waitForConnecting = false;
  }

  async isConnected() {
    let ecode = disconnectEcode;
    let errMsg = 'other error';

    if (this.accessing && this.connectAccessing) {
      console.log('sleep start.');
      sleep(200);
      console.log('sleep end.');
    }

    if (this.transport === undefined) {
      // disconnected
    } else if (this.isAccessing()) {
      const curTime = Date.now();
      if (this.connectAccessing && (this.lastConnectCheckTime < curTime) &&
          ((curTime - this.lastConnectCheckTime) > 500)) {
        // disconnect or during connecting check.
      } else {
        // The connection with Ledger is valid because it is being accessed.
        ecode = 0x9000;
      }
    } else {
      try {
        this.connectAccessing = true;
        this.accessing = true;
        if (this.transport !== undefined) {
          const ret = await checkConnect(this.transport, this.checkAppType);
          ecode = ret.errorCode;
          if (ecode === 0x9000) {
            this.lastConnectCheckTime = Date.now();
          }
        }
      } catch (e) {
        const errText = e.toString();
        if (errText.indexOf('DisconnectedDevice: Cannot write to HID device') >= 0) {
          // disconnect error
        } else if (errText.indexOf('TypeError: Cannot write to hid device') >= 0) {
          // disconnect error
        } else if (errText.indexOf('TransportError: NoDevice') >= 0) {
          // device connect error
        } else if (errText.indexOf('The device was disconnected.') >= 0) {
          // device connect error
        } else if (errText.indexOf('Must be handling a user gesture to show a permission request') >= 0) {
          // device connect error
        } else if (errText.indexOf('No device selected.') >= 0) {
          // disconnect error
        } else {
          console.log(`connection fail.(exception) `, e);
          ecode = 0x8000;
          errMsg = errText;
        }
      } finally {
        this.accessing = false;
        this.connectAccessing = false;
      }
      if (ecode !== 0x9000) await this.disconnect();
    }

    if (ecode === 0x9000) {
      errMsg = '';
    } else if (ecode === disconnectEcode) {
      errMsg = 'connection fail.';
    }
    return {
      success: (ecode === 0x9000),
      errorCode: ecode,
      errorCodeHex: ecode.toString(16),
      errorMessage: errMsg,
      disconnect: (ecode === disconnectEcode),
    };
  }

  async disconnect() {
    if (this.transport !== undefined) {
      try {
        this.accessing = true;
        const transport = this.transport;
        this.transport = undefined;
        await this.close(transport);
      } catch (e) {
        console.log(e);
      } finally {
        this.currentApplication = applicationType.Auto;
        this.accessing = false;
        this.currentDevicePath = '';
        this.lastConnectTime = 0;
      }
    }
  }

  async close(transport) {
    if (transport !== undefined) {
      await transport.close();
    }
  }

  async getApplicationInfo() {
    let result = undefined;
    let connRet = undefined;
    let ecode = accessingEcode;
    let errMsg = accessingMsg;
    if (this.isAccessing() === false) {
      connRet = await this.isConnected();
      ecode = connRet.errorCode;
      errMsg = connRet.errorMessage;
      if (connRet.success) {
        try {
          this.accessing = true;
          result = await getFirmwareVersion(this.transport);
          ecode = result.errorCode;
          errMsg = (ecode === 0x9000) ? '' : 'other error';
        } catch (e) {
          console.log(e);
          ecode = 0x8000;
          errMsg = e.toString();
        } finally {
          this.accessing = false;
        }
      }
    }
    return {
      success: (ecode === 0x9000),
      errorCode: ecode,
      errorCodeHex: ecode.toString(16),
      errorMessage: errMsg,
      disconnect: (!connRet) ? false : connRet.disconnect,
      name: this.getCurrentApplication(),
      flag: (!result) ? '' : result.flag,
      architecture: (!result) ? '' : result.architecture,
      version: (!result) ? '' : result.version,
      loaderVersion: (!result) ? '' : result.loader,
    };
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
    let result = undefined;
    let connRet = undefined;
    let ecode = accessingEcode;
    let errMsg = accessingMsg;
    if (this.isAccessing() === false) {
      connRet = await this.isConnected();
      ecode = connRet.errorCode;
      errMsg = connRet.errorMessage;
      if (connRet.success) {
        try {
          this.accessing = true;
          // TODO(k-matsuzawa): notfound liquid option(0x10, 0x11)
          const p2 = 1; // = 0x10;
          // console.time('call getWalletPublicKey');
          result = await getWalletPublicKey(
              this.transport, bip32Path, p2);
          // console.timeEnd('call getWalletPublicKey');
          // console.log('getWalletPublicKey result =', result);
          ecode = result.errorCode;
          errMsg = (ecode === 0x9000) ? '' : 'other error';
        } catch (e) {
          console.log(e);
          ecode = 0x8000;
          errMsg = e.toString();
        } finally {
          this.accessing = false;
        }
      }
    }
    return {
      success: (ecode === 0x9000),
      errorCode: ecode,
      errorCodeHex: ecode.toString(16),
      errorMessage: errMsg,
      disconnect: (!connRet) ? false : connRet.disconnect,
      publicKey: (!result) ? '' : compressPubkey(result.pubkey),
      chainCode: (!result) ? '' : result.chainCode,
    };
  }

  async getXpubKey(bip32Path) {
    let xpub = undefined;
    let connRet = undefined;
    let ecode = accessingEcode;
    let errMsg = accessingMsg;
    if (this.isAccessing() === false) {
      connRet = await this.isConnected();
      ecode = connRet.errorCode;
      errMsg = connRet.errorMessage;
      if (connRet.success) {
        try {
          this.accessing = true;
          const p2 = 1; // = 0x10;
          const parent = await getWalletPublicKey(
              this.transport, bip32Path, p2, true);
          ecode = parent.errorCode;
          if (ecode === 0x9000) {
            const pubkey = await getWalletPublicKey(
                this.transport, bip32Path, p2);
            ecode = pubkey.errorCode;
            if (ecode === 0x9000) {
              ecode = 0x8000;
              const pathArr = parseBip32Path(bip32Path).array;
              const extkey = cfdjs.CreateExtkey({
                network: this.mainchainNetwork,
                extkeyType: 'extPubkey',
                parentKey: compressPubkey(parent.pubkey),
                key: compressPubkey(pubkey.pubkey),
                chainCode: pubkey.chainCode,
                depth: pathArr.length,
                childNumber: pathArr[pathArr.length - 1],
              });
              xpub = extkey.extkey;
              ecode = 0x9000;
            }
          }
          errMsg = (ecode === 0x9000) ? '' : 'other error';
        } catch (e) {
          console.log(e);
          ecode = 0x8000;
          errMsg = e.toString();
        } finally {
          this.accessing = false;
        }
      }
    }
    return {
      success: (ecode === 0x9000),
      errorCode: ecode,
      errorCodeHex: ecode.toString(16),
      errorMessage: errMsg,
      disconnect: (!connRet) ? false : connRet.disconnect,
      xpubKey: (!xpub) ? '' : xpub,
    };
  }

  async getAddress(bip32Path, addressFormat) {
    let addressRet = undefined;
    let pubkeyRet = undefined;
    let connRet = undefined;
    let ecode = accessingEcode;
    let errMsg = accessingMsg;
    if (this.isAccessing() === false) {
      connRet = await this.isConnected();
      ecode = connRet.errorCode;
      errMsg = connRet.errorMessage;
      if (connRet.success) {
        pubkeyRet = await this.getWalletPublicKey(bip32Path);
        ecode = pubkeyRet.errorCode;
        if (pubkeyRet.success) {
          let hashType = 'p2sh-p2wpkh';
          if (addressFormat === 'bech32') {
            hashType = 'p2wpkh';
          } else if (addressFormat === 'legacy') {
            hashType = 'p2pkh';
          }
          addressRet = cfdjs.CreateAddress({
            keyData: {
              hex: pubkeyRet.publicKey,
              type: 'pubkey',
            },
            network: this.networkType,
            isElements: true,
            hashType: hashType,
          });
        }
        errMsg = (ecode === 0x9000) ? '' : 'other error';
      }
    }
    return {
      success: (ecode === 0x9000),
      errorCode: ecode,
      errorCodeHex: ecode.toString(16),
      errorMessage: errMsg,
      disconnect: connRet.disconnect,
      publicKey: (!pubkeyRet) ? '' : compressPubkey(pubkeyRet.pubkey),
      chainCode: (!pubkeyRet) ? '' : pubkeyRet.chainCode,
      address: (!addressRet) ? '' : addressRet.address,
    };
  }

  async setupHeadlessAuthorization(authorizationPublicKey) {
    let connRet = undefined;
    let ecode = accessingEcode;
    let errMsg = accessingMsg;
    if (this.isAccessing() === false) {
      connRet = await this.isConnected();
      ecode = connRet.errorCode;
      errMsg = connRet.errorMessage;
      if (connRet.success) {
        try {
          this.accessing = true;
          ecode = await liquidSetupHeadless(this.transport,
              authorizationPublicKey);
          errMsg = (ecode === 0x9000) ? '' : 'other error.';
          if (ecode === 0x6985) {
            errMsg = 'CONDITIONS_OF_USE_NOT_SATISFIED';
          }
        } catch (e) {
          console.log(e);
          ecode = 0x8000;
          errMsg = e.toString();
        } finally {
          this.accessing = false;
        }
      }
    }
    return {
      success: (ecode === 0x9000),
      errorCode: ecode,
      errorCodeHex: ecode.toString(16),
      errorMessage: errMsg,
      disconnect: connRet.disconnect,
    };
  }

  async getSignature(proposalTransaction,
      walletUtxoList, authorizationSignature) {
    const signatureList = [];
    let connRet = undefined;
    let ecode = accessingEcode;
    let errMsg = accessingMsg;
    if (this.isAccessing() === false) {
      connRet = await this.isConnected();
      ecode = connRet.errorCode;
      errMsg = connRet.errorMessage;
    }
    if (ecode === 0x9000) {
      if (!walletUtxoList || !proposalTransaction || !authorizationSignature) {
        ecode = 0x6a80;
        errMsg = 'Input parameter is null or empty';
      }
    }
    if (ecode !== 0x9000) {
      return {
        success: false,
        errorCode: ecode,
        errorCodeHex: ecode.toString(16),
        errorMessage: errMsg,
        disconnect: (!connRet) ? false : connRet.disconnect,
        signatureList: signatureList,
      };
    }
    try {
      this.accessing = true;
      this.getSigState.current.state = getSignatureState.AnalyzeUtxo;
      this.getSigState.lastAccessTime = Date.now();

      const dectx = cfdjs.ElementsDecodeRawTransaction({
        hex: proposalTransaction, network: this.networkType,
        mainchainNetwork: this.mainchainNetwork});
      const calcInfo = calculateGetSignatureProgress(
          dectx, walletUtxoList.length);
      this.getSigState.utxoNum = calcInfo.utxoNum;
      this.getSigState.txNum = calcInfo.txNum;
      this.getSigState.current.utxoNum = 0;
      this.getSigState.current.txNum = 0;
      this.getSigState.current.sigNum = 0;
      const appedTxNumFunc = () => {
        this.getSigState.current.txNum += 1;
        this.getSigState.lastAccessTime = Date.now();
      };
      const updateAccessTimeFunc = () => {
        this.getSigState.lastAccessTime = Date.now();
      };

      const amountValueList = [];
      const utxoList = walletUtxoList;
      for (const txin of dectx.vin) {
        let isFind = false;
        for (const utxo of utxoList) {
          if ((txin.txid === utxo.txid) && (txin.vout === utxo.vout)) {
            let value = 0;
            if (('valueCommitment' in utxo) && (utxo.valueCommitment) &&
                ((utxo.valueCommitment.length === 66) ||
                (utxo.valueCommitment.length === 18))) {
              value = utxo.valueCommitment;
            } else if (('amount' in utxo) && (utxo.amount)) {
              value = utxo.amount;
            } else {
              throw new Error('invalid amount or valueCommitment.');
            }
            amountValueList.push(value);
            isFind = true;
            break;
          }
        }
        if (!isFind) {
          // throw new Error('txin is not in the utxo list.');
          amountValueList.push(1); // dummy amount
        }
      }
      ecode = 0x9000;

      const utxoScriptList = [];
      // Collect redeemScript before startUntrustedTransaction
      // because you need to call getWalletPublicKey.
      for (const utxo of walletUtxoList) {
        let targetIndex = -1;
        for (let index = 0; index < dectx.vin.length; ++index) {
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
            network: this.networkType,
          });
          if (('scripts' in desc) && (desc.scripts.length > 0) &&
              ('redeemScript' in desc.scripts[desc.scripts.length - 1])) {
            redeemScript = desc.scripts[desc.scripts.length - 1].redeemScript;
          } else if (('scripts' in desc) && (desc.scripts.length > 0) &&
              ('key' in desc.scripts[desc.scripts.length - 1])) {
            const descPubkey = desc.scripts[desc.scripts.length - 1].key;
            redeemScript = this.getPublicKeyRedeemScript(descPubkey);
          }
        }

        if (!redeemScript) {
          const p2 = 1; // = 0x10;
          const pubkeyRet = await getWalletPublicKey(
              this.transport, utxo.bip32Path, p2);
          // const pubkeyRet = await this.getWalletPublicKey(utxo.bip32Path);
          ecode = pubkeyRet.errorCode;
          if (ecode !== 0x9000) {
            break;
          }
          const pubkey = compressPubkey(pubkeyRet.pubkey);
          redeemScript = this.getPublicKeyRedeemScript(pubkey);
        }
        utxoScriptList.push({
          redeemScript: redeemScript,
          targetIndex: targetIndex,
          utxo: utxo,
        });
        this.getSigState.current.utxoNum += 1;
        this.getSigState.lastAccessTime = Date.now();
      }

      // console.info('amountValueList =', amountValueList);
      if (ecode === 0x9000) {
        this.getSigState.current.state = getSignatureState.InputTx;
        ecode = await startUntrustedTransaction(this.transport, dectx, false,
            amountValueList, -1, '', appedTxNumFunc);
      }
      if (ecode === 0x9000) {
        ecode = await liquidFinalizeInputFull(
            this.transport, dectx, appedTxNumFunc);
      }
      if (ecode === 0x9000) {
        ecode = await liquidProvideIssuanceInformation(
            this.transport, dectx, appedTxNumFunc);
      }

      if (ecode === 0x9000) {
        this.getSigState.current.state = getSignatureState.GetSignature;
        // sighashtype: 1=all only
        const sighashtype = 1;
        for (const utxoData of utxoScriptList) {
          ecode = await startUntrustedTransaction(this.transport, dectx,
              true, amountValueList, utxoData.targetIndex,
              utxoData.redeemScript, updateAccessTimeFunc);
          if (ecode !== 0x9000) {
            break;
          }
          const signatureRet = await untrustedHashSign(this.transport, dectx,
              utxoData.utxo.bip32Path, authorizationSignature, sighashtype);
          ecode = signatureRet.errorCode;
          if (ecode !== 0x9000) {
            break;
          }
          // await sleep(20000);
          signatureList.push({
            utxoData: utxoData.utxo,
            signature: signatureRet.signature,
          });
          this.getSigState.current.sigNum += 1;
          this.getSigState.lastAccessTime = Date.now();
        }
      }
      errMsg = (ecode === 0x9000) ? '' : 'other error.';
    } catch (e) {
      console.log(e);
      if (ecode === 0x9000) {
        ecode = 0x8000;
      }
      errMsg = e.toString();
    } finally {
      this.accessing = false;
      this.getSigState.utxoNum = 0;
      this.getSigState.txNum = 0;
      this.getSigState.current.state = getSignatureState.AnalyzeUtxo;
      this.getSigState.current.utxoNum = 0;
      this.getSigState.current.txNum = 0;
    }

    return {
      success: (ecode === 0x9000),
      errorCode: ecode,
      errorCodeHex: ecode.toString(16),
      errorMessage: errMsg,
      disconnect: false,
      signatureList: signatureList,
    };
  }

  getSignatureState() {
    const timeout = 15 * 1000;
    const result = {
      success: true,
      errorCode: 0x9000,
      errorCodeHex: '',
      errorMessage: '',
      disconnect: false,
      currentState: getSignatureState.AnalyzeUtxo,
      analyzeUtxo: {current: 0, total: 0},
      inputTx: {current: 0, total: 0},
      getSignature: {current: 0, total: 0},
      total: {current: 0, total: 0},
      lastAccessTime: this.getSigState.lastAccessTime,
    };
    if (this.transport === undefined) {
      result.errorCode = disconnectEcode;
      result.disconnect = true;
      result.errorMessage = 'connection fail.';
    } else if (!this.accessing || (this.getSigState.utxoNum === 0)) {
      result.errorMessage = 'not execute.';
    } else {
      result.currentState = this.getSigState.current.state;
      result.analyzeUtxo.current = this.getSigState.current.utxoNum;
      result.analyzeUtxo.total = this.getSigState.utxoNum;
      result.inputTx.current = this.getSigState.current.txNum;
      result.inputTx.total = this.getSigState.txNum;
      result.getSignature.current = this.getSigState.current.sigNum;
      result.getSignature.total = this.getSigState.utxoNum;
      result.total.current = result.analyzeUtxo.current +
        result.inputTx.current + result.getSignature.current;
      result.total.total = result.analyzeUtxo.total +
        result.inputTx.total + result.getSignature.total;
      result.lastAccessTime = this.getSigState.lastAccessTime;
      if (this.getSigState.lastAccessTime + timeout <= Date.now()) {
        result.errorCode = 0x6000;
        result.errorMessage = 'ledger call timeout';
      }
    }

    result.success = (result.errorCode === 0x9000);
    result.errorCodeHex = result.errorCode.toString(16);
    return result;
  }

  calcSignatureProgress(proposalTransaction, walletUtxoList) {
    let analyzeUtxoNum = 0;
    let inputTxNum = 0;
    let getSignatureNum = 0;
    let ecode = 0x9000;
    let errMsg = '';
    try {
      if (!walletUtxoList || !proposalTransaction) {
        ecode = 0x6a80;
        errMsg = 'Input parameter is null or empty';
      } else {
        const dectx = cfdjs.ElementsDecodeRawTransaction({
          hex: proposalTransaction, network: this.networkType,
          mainchainNetwork: this.mainchainNetwork});
        const ret = calculateGetSignatureProgress(dectx, walletUtxoList.length);
        analyzeUtxoNum = ret.utxoNum;
        inputTxNum = ret.txNum;
        getSignatureNum = analyzeUtxoNum;
      }
    } catch (e) {
      console.log(e);
      ecode = 0x8000;
      errMsg = e.toString();
    }
    return {
      success: (ecode === 0x9000),
      errorCode: ecode,
      errorCodeHex: ecode.toString(16),
      errorMessage: errMsg,
      disconnect: false,
      analyzeUtxo: {current: 0, total: analyzeUtxoNum},
      inputTx: {current: 0, total: inputTxNum},
      getSignature: {current: 0, total: getSignatureNum},
      total: {current: 0, total: analyzeUtxoNum + inputTxNum + getSignatureNum},
    };
  }
};

module.exports = ledgerLiquidWrapper;
module.exports.LedgerLiquidWrapper = ledgerLiquidWrapper;
module.exports.NetworkType = networkTypeDefine;
module.exports.NetworkType.LiquidV1 = networkTypeDefine.LiquidV1;
module.exports.NetworkType.Regtest = networkTypeDefine.Regtest;
module.exports.ApplicationType = currentApplicationType;
module.exports.ApplicationType.LiquidHeadless =
  currentApplicationType.LiquidHeadless;
module.exports.ApplicationType.LiquidTestHeadless =
  currentApplicationType.LiquidTestHeadless;
module.exports.ApplicationType.Empty = currentApplicationType.Empty;
module.exports.AddressType = addressType;
module.exports.AddressType.Legacy = addressType.Legacy;
module.exports.AddressType.P2shSegwit = addressType.P2shSegwit;
module.exports.AddressType.Bech32 = addressType.Bech32;
module.exports.GetSignatureState = getSignatureState;
module.exports.GetSignatureState.AnalyzeUtxo = getSignatureState.AnalyzeUtxo;
module.exports.GetSignatureState.InputTx = getSignatureState.InputTx;
module.exports.GetSignatureState.GetSignature = getSignatureState.GetSignature;
module.exports.UsbDetectionType = usbDetectionType;
module.exports.UsbDetectionType.Add = usbDetectionType.Add;
module.exports.UsbDetectionType.Remove = usbDetectionType.Remove;
