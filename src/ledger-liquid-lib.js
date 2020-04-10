/* eslint-disable require-jsdoc */
// import * as TransportNodeHid from '@ledgerhq/hw-transport-node-hid';
const TransportNodeHid = require('@ledgerhq/hw-transport-node-hid').default;
const cfdjs = require('cfd-js');

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
  if (path === '') {
    return Buffer.alloc(0);
  }

  let targetPath = path;
  if (targetPath.startsWith('m/')) {
    targetPath = targetPath.substring(2);
  }
  const items = targetPath.split('/');
  if (items.length > 10) {
    throw new Error('Out of Range. Number of BIP 32 derivations to perform is up to 10.');
  }
  const hardendedTargets = ['\'', 'h', 'H'];

  const length = (parent) ? items.length - 1 : items.length;
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
  // FIXME split send.
  const CLA = 0xe0;
  const HASH_INPUT_START = 0x44;
  const apdu = Buffer.concat([Buffer.from([CLA, HASH_INPUT_START, p1, p2]),
    Buffer.from([data.length]), data]);
  debugSendLog('sendHashInputStartCmd send -> ', apdu);
  const exchangeRet = await transport.exchange(apdu);
  const result = (exchangeRet.length <= 2) ? exchangeRet :
    exchangeRet.subarray(exchangeRet.length - 2);
  const resultData = (exchangeRet.length <= 2) ? Buffer.alloc(0) :
    exchangeRet.subarray(0, exchangeRet.length - 2);
  return {data: resultData, errorCode: convertErrorCode(result)};
}

async function sendHashInputFinalizeFullCmd(transport, p1, p2, data) {
  // FIXME split send.
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
    amountValueList, inputIndex, targetRedeemScript) {
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
    // if ('issuance' in dectx.vin[idx]) {
    //   vout[3] |= 0x80;
    // }
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
  }
  return errData.errorCode;
}

async function liquidFinalizeInputFull(transport, dectx) {
  let apdu = getVarIntBuffer(dectx.vout.length);
  let errData = await sendHashInputFinalizeFullCmd(transport, 0, 0, apdu);
  if (errData.errorCode != 0x9000) {
    console.log('fail sendHashInputStartCmd2', errData);
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
    transport, data, p1) {
  const CLA = 0xe0;
  const LIQUID_PROVIDE_ISSUANCE_INFORMATION = 0xe6;
  const apdu = Buffer.concat(
      [Buffer.from([CLA, LIQUID_PROVIDE_ISSUANCE_INFORMATION, p1, 0]),
        Buffer.from([data.length]), data]);
  debugSendLog('liquidProvideIssuanceInformation send -> ', apdu);
  const exchangeRet = await transport.exchange(apdu);
  const result = (exchangeRet.length <= 2) ? exchangeRet :
    exchangeRet.subarray(exchangeRet.length - 2);
  const ecode = convertErrorCode(result);
  if (ecode !== 0x9000) {
    console.log('sendProvideIssuanceInformationCmd Fail. ecode =', ecode);
  }
  return ecode;
}

async function liquidProvideIssuanceInformation(transport, dectx) {
  let isFind = false;
  for (let idx = 0; idx < dectx.vin.length; ++idx) {
    if ('issuance' in dectx.vin[idx]) {
      isFind = true;
      break;
    }
  }

  let ecode;
  let data;
  if (!isFind) {
    data = Buffer.alloc(dectx.vin.length);
    return await sendProvideIssuanceInformationCmd(transport, data, 0x80);
  }

  for (let idx = 0; idx < dectx.vin.length; ++idx) {
    const p1 = (idx === (dectx.vin.length - 1)) ? 0x80 : 0x00;
    if ('issuance' in dectx.vin[idx]) {
      const issuance = dectx.vin[idx].issuance;
      data = Buffer.concat([
        reverseBuffer(Buffer.from(issuance.assetBlindingNonce, 'hex')),
        reverseBuffer(Buffer.from(issuance.assetEntropy, 'hex')),
      ]);
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
      ecode = await sendProvideIssuanceInformationCmd(transport, data, p1);
    } else {
      data = Buffer.alloc(1);
      ecode = await sendProvideIssuanceInformationCmd(transport, data, p1);
    }
    if (ecode !== 0x9000) {
      break;
    }
  }
  return ecode;
}

const disconnectEcode = 0x6d00; // INS_NOT_SUPPORTED

async function checkConnect(transport) {
  // console.time('call getCoinVersion');
  const result = await getCoinVersion(transport);
  // console.timeEnd('call getCoinVersion');
  // console.log('getCoinVersion =', result);
  if (result.errorCode === 0x9000) {
    if ((result.prefixP2pkh === 0xeb) &&
        (result.prefixP2sh === 0x4b) &&
        (result.coinFamily === 0x01) &&
        (result.coinName === 'Bitcoin') &&
        (result.coinTicker === 'BTC')) {
      // liquid
    } else {
      return disconnectEcode;
    }
  }
  return result.errorCode;
}

function compressPubkey(publicKey) {
  if (!publicKey) return '';
  return cfdjs.GetCompressedPubkey({pubkey: publicKey}).pubkey;
}

const ledgerLiquidWrapper = class LedgerLiquidWrapper {
  constructor(networkType) {
    this.transport = undefined;
    if ((networkType !== 'liquidv1') && (networkType !== 'regtest')) {
      throw new Error('illegal network type.');
    }
    this.networkType = networkType;
    this.mainchainNetwork = (networkType === 'regtest') ?
        'regtest' : 'mainnet';
    this.waitForConnecting = false;
  }

  async getDeviceList() {
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
      errorMessage: errMsg,
      disconnect: false,
      deviceList: devList,
    };
  }

  async connect(maxWaitTime = undefined, devicePath = undefined) {
    const sleep = (msec) => new Promise(
        (resolve) => setTimeout(resolve, msec));

    if (this.transport) await this.transport.close();

    this.waitForConnecting = true;
    const waitLimit = (typeof maxWaitTime === 'number') ? maxWaitTime : 0xffffffff;
    const path = (typeof devicePath === 'string') ? devicePath : '';
    let transport = undefined;
    let count = (waitLimit <= 0) ? 0 : 1;
    let ecode = disconnectEcode;
    let errMsg = 'other error';
    while ((count <= waitLimit) && this.waitForConnecting) {
      try {
        transport = await TransportNodeHid.open(path);

        ecode = await checkConnect(transport);
        if (ecode === 0x9000) {
          this.transport = transport;
          break;
        } else if (ecode !== disconnectEcode) {
          console.log('illegal error. ', ecode);
          await transport.close();
          break;
        }
      } catch (e) {
        // console.log(`connection fail. count=${count}`, e);
        const errText = e.toString();
        if (errText.indexOf('DisconnectedDevice: Cannot write to HID device') >= 0) {
          // disconnect error
        } else if (errText.indexOf('TransportError: NoDevice') >= 0) {
          // device connect error
        } else if (errText.indexOf('cannot open device with path') >= 0) {
          // device connect error
        } else {
          console.log(`connection fail.(exception) count=${count}`, e);
          ecode = 0x6000;
          break;
        }
      }
      if (transport) await transport.close();
      transport = undefined;
      console.info(`connection fail. count=${count}`);
      ++count;
      if (count != waitLimit) await sleep(1000);
    }

    if (ecode === 0x9000) {
      errMsg = '';
    } else if (ecode === disconnectEcode) {
      if (this.waitForConnecting) {
        errMsg = 'connection fail.';
      } else {
        errMsg = 'connection cancel.';
      }
    }
    this.waitForConnecting = false;
    return {
      success: (ecode === 0x9000),
      errorCode: ecode,
      errorMessage: errMsg,
      disconnect: (ecode === disconnectEcode),
    };
  }

  cancelConnect() {
    this.waitForConnecting = false;
  }

  async isConnected() {
    let ecode = disconnectEcode;
    if (this.transport !== undefined) {
      try {
        ecode = await checkConnect(this.transport);
      } catch (e) {
        const errText = e.toString();
        if (errText.indexOf('DisconnectedDevice: Cannot write to HID device') >= 0) {
          // disconnect error
        } else if (errText.indexOf('TransportError: NoDevice') >= 0) {
          // device connect error
        } else {
          console.log(`connection fail.(exception) `, e);
          ecode = 0x8000;
        }
      }
      if (ecode !== 0x9000) this.disconnect();
    }
    let errMsg = 'other error';
    if (ecode === 0x9000) {
      errMsg = '';
    } else if (ecode === disconnectEcode) {
      errMsg = 'connection fail.';
    }
    return {
      success: (ecode === 0x9000),
      errorCode: ecode,
      errorMessage: errMsg,
      disconnect: (ecode === disconnectEcode),
    };
  }

  async disconnect() {
    if (this.transport !== undefined) {
      await this.transport.close();
      this.transport = undefined;
    }
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
    const connRet = await this.isConnected();
    let ecode = connRet.errorCode;
    let errMsg = connRet.errorMessage;
    if (connRet.success) {
      // TODO(k-matsuzawa): notfound liquid option(0x10, 0x11)
      const p2 = 1; // = 0x10;
      // console.time('call getWalletPublicKey');
      result = await getWalletPublicKey(
          this.transport, bip32Path, p2);
      // console.timeEnd('call getWalletPublicKey');
      // console.log('getWalletPublicKey result =', result);
      ecode = result.errorCode;
      errMsg = (ecode === 0x9000) ? '' : 'other error';
    }
    return {
      success: (ecode === 0x9000),
      errorCode: ecode,
      errorMessage: errMsg,
      disconnect: connRet.disconnect,
      publicKey: (!result) ? '' : compressPubkey(result.pubkey),
      chainCode: (!result) ? '' : result.chainCode,
    };
  }

  async getXpubKey(bip32Path) {
    let xpub = undefined;
    const connRet = await this.isConnected();
    let ecode = connRet.errorCode;
    let errMsg = connRet.errorMessage;
    if (connRet.success) {
      const p2 = 1; // = 0x10;
      const parent = await getWalletPublicKey(
          this.transport, bip32Path, p2, true);
      ecode = parent.errorCode;
      if (ecode !== 0x9000) {
        errMsg = 'other error';
      } else {
        const pubkey = await getWalletPublicKey(
            this.transport, bip32Path, p2);
        ecode = parent.errorCode;
        if (ecode !== 0x9000) {
          errMsg = 'other error';
        } else {
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
        }
      }
    }
    return {
      success: (ecode === 0x9000),
      errorCode: ecode,
      errorMessage: errMsg,
      disconnect: connRet.disconnect,
      xpubKey: (!xpub) ? '' : xpub,
    };
  }

  async getAddress(bip32Path, addressFormat) {
    let result = undefined;
    let addressRet = undefined;
    let pubkeyRet = undefined;
    const connRet = await this.isConnected();
    let ecode = connRet.errorCode;
    let errMsg = connRet.errorMessage;
    if (connRet.success) {
      pubkeyRet = await this.getWalletPublicKey(bip32Path);
      result = pubkeyRet;
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
        result = pubkeyRet;
      }
      ecode = result.errorCode;
      errMsg = (ecode === 0x9000) ? '' : 'other error';
    }
    return {
      success: (ecode === 0x9000),
      errorCode: ecode,
      errorMessage: errMsg,
      disconnect: connRet.disconnect,
      publicKey: (!pubkeyRet) ? '' : compressPubkey(pubkeyRet.pubkey),
      chainCode: (!pubkeyRet) ? '' : pubkeyRet.chainCode,
      address: (!addressRet) ? '' : addressRet.address,
    };
  }

  async setupHeadlessAuthorization(authorizationPublicKey) {
    const connRet = await this.isConnected();
    let ecode = connRet.errorCode;
    let errMsg = connRet.errorMessage;
    if (connRet.success) {
      ecode = await liquidSetupHeadless(this.transport,
          authorizationPublicKey);
      errMsg = (ecode === 0x9000) ? '' : 'other error.';
      if (ecode === 0x6985) {
        errMsg = 'CONDITIONS_OF_USE_NOT_SATISFIED';
      }
    }
    return {
      success: (ecode === 0x9000),
      errorCode: ecode,
      errorMessage: errMsg,
      disconnect: connRet.disconnect,
    };
  }

  async getSignature(proposalTransaction,
      walletUtxoList, authorizationSignature) {
    const signatureList = [];
    const connRet = await this.isConnected();
    if (!connRet.success) {
      return {
        success: connRet.success,
        errorCode: connRet.errorCode,
        errorMessage: connRet.errorMessage,
        disconnect: connRet.disconnect,
        signatureList: signatureList,
      };
    }
    const dectx = cfdjs.ElementsDecodeRawTransaction({
      hex: proposalTransaction, network: this.networkType,
      mainchainNetwork: this.mainchainNetwork});

    const amountValueList = [];

    const utxoList = walletUtxoList;
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
        // throw new Error('txin is not in the utxo list.');
        amountValueList.push(1); // dummy amount
      }
    }
    let ecode = 0x9000;

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
        }
      }

      if (!redeemScript) {
        const pubkeyRet = await this.getWalletPublicKey(utxo.bip32Path);
        ecode = pubkeyRet.errorCode;
        if (ecode !== 0x9000) {
          break;
        }
        redeemScript = this.getPublicKeyRedeemScript(pubkeyRet.publicKey);
      }
      utxoScriptList.push({
        redeemScript: redeemScript,
        targetIndex: targetIndex,
        utxo: utxo,
      });
    }

    // console.info('amountValueList =', amountValueList);
    if (ecode === 0x9000) {
      ecode = await startUntrustedTransaction(this.transport, dectx, false,
          amountValueList, -1, '');
    }
    if (ecode === 0x9000) {
      ecode = await liquidFinalizeInputFull(this.transport, dectx);
    }
    if (ecode === 0x9000) {
      ecode = await liquidProvideIssuanceInformation(this.transport, dectx);
    }

    if (ecode === 0x9000) {
      // sighashtype: 1=all only
      const sighashtype = 1;
      for (const utxoData of utxoScriptList) {
        ecode = await startUntrustedTransaction(this.transport, dectx,
            true, amountValueList, utxoData.targetIndex,
            utxoData.redeemScript);
        if (ecode !== 0x9000) {
          break;
        }
        const signatureRet = await untrustedHashSign(this.transport, dectx,
            utxoData.utxo.bip32Path, authorizationSignature, sighashtype);
        ecode = signatureRet.errorCode;
        if (ecode !== 0x9000) {
          break;
        }
        signatureList.push({
          utxoData: utxoData.utxo,
          signature: signatureRet.signature,
        });
      }
    }

    return {
      success: (ecode === 0x9000),
      errorCode: ecode,
      errorMessage: (ecode === 0x9000) ? '' : 'other error.',
      disconnect: false,
      signatureList: signatureList,
    };
  }
};

module.exports = ledgerLiquidWrapper;
module.exports.LedgerLiquidWrapper = ledgerLiquidWrapper;
