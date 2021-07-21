/* eslint-disable require-jsdoc */

// import {Device} from 'usb-detection';
export interface Device {
  locationId: number;
  vendorId: number;
  productId: number;
  deviceName: string;
  manufacturer: string;
  serialNumber: string;
  deviceAddress: number;
}

export enum NetworkType {
  LiquidV1 = 'liquidv1',
  Regtest = 'regtest',
}

export enum ApplicationType {
  LiquidHeadless = 'Liquid Hless',
  LiquidTestHeadless = 'Liquid Test Hless',
  Empty = '',
}

export enum AddressType {
  Legacy = 'legacy',
  P2shSegwit = 'p2sh-segwit',
  Bech32 = 'bech32',
}

export enum GetSignatureState {
  AnalyzeUtxo = 'analyzeUtxo', // Preparation before 'input transaction'
  InputTx = 'inputTx', // input transaction to ledger
  GetSignature = 'getSignature', // request getSignature to ledger
}

export enum UsbDetectionType {
  Add = 'add', // add usb connection
  Remove = 'remove', // remove usb connection
}

export interface UtxoData {
  txid: string; // key(outpoint)
  vout: number; // key(outpoint)
  amount?: bigint | number;
  valueCommitment?: string;
}

export interface WalletUtxoData extends UtxoData {
  bip32Path: string; // key-1(bip32 path)
  // key-2(outpoint)
  descriptor?: string; // output descriptor. Only one of the redeemScript is set. pubkey-hash is unused.
  redeemScript?: string; // redeem script. Only one of the descriptor is set. pubkey-hash is unused.
}

export interface VersionInfo {
  major: number;
  minor: number;
  patch: number;
}

export interface ResponseInfo {
  success: boolean;
  errorCode: number;
  errorCodeHex: string;
  errorMessage: string;
  disconnect: boolean;
}

export interface ConnectionInfo {
  currentDevicePath: string;
  lastConnectTime: number;
}

export interface GetApplicationInfoResponse extends ResponseInfo {
  name: string;
  flag: number;
  architecture: number;
  version: VersionInfo;
  loaderVersion: VersionInfo;
}

export interface GetPublicKeyResponse extends ResponseInfo {
  publicKey: string;
  chainCode: string;
}

export interface GetXpubKeyResponse extends ResponseInfo {
  xpubKey: string;
}

export interface GetAddressResponse extends GetPublicKeyResponse {
  address: string;
}

export interface SignatureData {
  utxoData: WalletUtxoData;
  signature: string;
}

export interface GetSignatureAddressResponse extends ResponseInfo {
  signatureList: SignatureData[];
}

export interface GetDeviceListResponse extends ResponseInfo {
  deviceList: string[];
}

export interface ProgressInfo {
  current: number;
  total: number;
}

export interface CalculateSignatureProgress extends ResponseInfo {
  analyzeUtxo: ProgressInfo;
  inputTx: ProgressInfo;
  getSignature: ProgressInfo;
  total: ProgressInfo;
}

export interface GetSignatureProgress extends ResponseInfo {
  currentState: GetSignatureState;
  analyzeUtxo: ProgressInfo;
  inputTx: ProgressInfo;
  getSignature: ProgressInfo;
  total: ProgressInfo;
  lastAccessTime: number;
}

export class LedgerLiquidWrapper {
  /**
   * @constructor
   * @param network network type.
   * @param checkApplication application check flag.
   */
  constructor(network: NetworkType, checkApplication?: boolean);

  /**
   * start connection state change monitoring.
   */
  static startUsbDetectMonitoring(): void;

  /**
   * finish connection state change monitoring.
   */
  static finishUsbDetectMonitoring(): void;

  /**
   * register connection state changed listener.
   *
   * @param callback callback function.
   */
  static registerUsbDetectListener(
    callback: (state: UsbDetectionType, device: Device) => void): void

  /**
   * get usb device list.
   *
   * @return GetDeviceListResponse wrapped promise.
   */
  static getDeviceList(): Promise<GetDeviceListResponse>;

  /**
   * get application type.
   *
   * @return ApplicationType
   */
  getCurrentApplication(): ApplicationType;

  /**
   * Get last connection information.
   *
   * attention: using after connect or isConnected.
   * current API is only get last connection info.
   *
   * @return ConnectionInfo.
   */
  getLastConnectionInfo(): ConnectionInfo;

  /**
   * Check if it is accessing Ledger.
   *
   * @return true is accessing ledger(connect, getSignature, etc).
   */
  isAccessing(): boolean;

  /**
   * connect device.
   *
   * @param maxWaitTime maximum waiting time (sec).
   * @param devicePath target device path.
   * @return ResponseInfo wrapped promise.
   */
  connect(maxWaitTime: number | undefined, devicePath: string | undefined):
    Promise<ResponseInfo>;

  /**
   * cancel connecting wait.
   */
  cancelConnect(): void;

  /**
   * check device connection status.
   *
   * @return ResponseInfo wrapped promise.
   */
  isConnected(): Promise<ResponseInfo>;

  /**
   * disconnect current device.
   */
  disconnect(): Promise<void>;

  /**
   * Get application information.
   *
   * @returns GetApplicationInfoResponse wrapped promise.
   */
  getApplicationInfo(): Promise<GetApplicationInfoResponse>;

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

  /**
   * Get xpub key with ledger wallet.
   *
   * @param bip32Path bip32 path.
   * @returns GetXpubKeyResponse wrapped promise.
   */
  getXpubKey(bip32Path: string): Promise<GetXpubKeyResponse>;

  /**
   * Get address with ledger wallet.
   *
   * @param bip32Path bip32 path.
   * @param addressType address type.
   * @returns GetAddressResponse wrapped promise.
   */
  getAddress(bip32Path: string, addressType: AddressType):
    Promise<GetAddressResponse>;

  /**
   * Get signed signature.
   *
   * @param proposalTransaction         proposal transaction.
   * @param walletUtxoList              sign target utxo list.
   * @param authorizationSignature      authorization signature (from backend).
   * @returns GetSignatureAddressResponse wrapped promise.
   */
  getSignature(
    proposalTransaction: string, // proposal transaction.
    walletUtxoList: WalletUtxoData[], // sign target utxo list.
    authorizationSignature: string, // authorization signature (from backend)
  ): Promise<GetSignatureAddressResponse>;

  /**
   * Get state and progress of getSignature.
   *
   * @returns GetSignatureProgress.
   */
  getSignatureState(): GetSignatureProgress;

  /**
   * Calculate getSignature progress.
   *
   * @param proposalTransaction         proposal transaction.
   * @param walletUtxoList              sign target utxo list.
   * @returns CalculateSignatureProgress
   */
  calcSignatureProgress(
    proposalTransaction: string, // proposal transaction.
    walletUtxoList: WalletUtxoData[], // sign target utxo list.
  ): CalculateSignatureProgress;
}
