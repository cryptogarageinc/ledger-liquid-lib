/* eslint-disable require-jsdoc */
export default class TransportNodeHid {
  static open(path: string): Promise<TransportNodeHid>;
  open(path: string): Promise<TransportNodeHid>;
  setDebugMode(flag: boolean): void;
}
