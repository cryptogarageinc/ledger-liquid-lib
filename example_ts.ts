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

  const authPubkey = '04b85b0e5f5b41f1a95bbf9a83edd95c741223c6d9dc5fe607de18f015684ff56ec359705fcf9bbeb1620fb458e15e3d99f23c6f5df5e91e016686371a65b16f0c';
  const setupRet = await liquidLib.setupHeadlessAuthorization(authPubkey);
  console.log('--HEADLESS LIQUID SEND AUTHORIZATION PUBLIC KEY --\n', setupRet);

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
      'keyData': {
        'hex': pubkey4,
        'type': 'pubkey',
      },
      'network': 'liquidv1',
      'isElements': true,
      'hashType': 'p2pkh',
    });
    const address4Segwit = cfdjs.CreateAddress({
      'keyData': {
        'hex': pubkey4,
        'type': 'pubkey',
      },
      'network': 'liquidv1',
      'isElements': true,
      'hashType': 'p2wpkh',
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
};
example();
