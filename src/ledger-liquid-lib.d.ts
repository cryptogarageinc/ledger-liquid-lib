/* eslint-disable require-jsdoc */
import TransportNodeHid from '@ledgerhq/hw-transport-node-hid';

export enum NetworkType {
  LiquidV1 = 'liquidv1',
  Regtest = 'regtest',
}

export interface UtxoData {
  txid: string; // key(outpoint)
  vout: number; // key(outpoint)
  amount: bigint;
  valueCommitment?: string;
}

export interface WalletUtxoData extends UtxoData {
  bip32Path: string; // key-1(bip32 path)
  // key-2(outpoint)
  descriptor?: string; // output descriptor. Only one of the redeemScript is set. pubkey-hash is unused.
  redeemScript?: string; // redeem script. Only one of the descriptor is set. pubkey-hash is unused.
}

export interface ResponseInfo {
  success: boolean;
  errorCode: number;
  errorMessage: string;
}

export interface GetPublicKeyResponse extends ResponseInfo {
  publicKey: string;
  chainCode: string;
}

export interface GetConfidentialAddressResponse extends ResponseInfo {
  confidentialAddress: string;
  confidentialKey: string;
}

export interface SignatureData {
  utxoData: WalletUtxoData;
  signature: string;
}

export interface GetSignatureAddressResponse extends ResponseInfo {
  signatureList: SignatureData[];
}

export class LedgerLiquidWrapper {
  constructor(transport: TransportNodeHid, network: NetworkType);

  /*
   * Get compressed public key.
   *
   * @param publicKey public key.
   * @return compressed public key.
   */
  // compressPubkey(publicKey: string): string;

  /**
   * Get redeem script for public key.
   *
   * @param publicKey public key.
   * @return redeem script.
   */
  getPublicKeyRedeemScript(publicKey: string): string;

  /**
   * Setup headless authorization.
   *
   * @param authorizationPublicKey authorization public key.
   * @returns ResponseInfo wrapped promise.
   */
  setupHeadlessAuthorization(
    authorizationPublicKey: string): Promise<ResponseInfo>;

  /**
   * Get public key with ledger wallet.
   *
   * @param bip32Path bip32 path.
   * @returns GetPublicKeyResponse wrapped promise.
   */
  getWalletPublicKey(bip32Path: string): Promise<GetPublicKeyResponse>;

  // TODO(k-matsuzawa): Does not yet support blindingTx.
  // function getWalletConfidentialAddress(address: string): Promise<GetConfidentialAddressResponse>;

  // TODO(k-matsuzawa): Does not yet support blindingTx.
  // function setProposalTransaction(
  //   proposalTransaction: string,
  //   walletUtxoList: UtxoData[]
  // ): Promise<ResponseInfo>;

  /**
   * Get signed signature.
   *
   * @param proposalTransaction         proposal transaction.
   * @param txinUtxoList                utxo list. (for amount or valueCommitment)
   * @param walletUtxoList              sign target utxo list.
   * @param authorizationSignature      authorization signature (from backend).
   * @param sigHashType                 signature hash type.
   * @returns GetSignatureAddressResponse wrapped promise.
   */
  getSignature(
    proposalTransaction: string, // proposal transaction.
    txinUtxoList: UtxoData[], // txin utxo list. (ignore walletUtxoList)
    walletUtxoList: WalletUtxoData[], // sign target utxo list.
    authorizationSignature: string, // authorization signature (from backend)
  ): Promise<GetSignatureAddressResponse>;
}
