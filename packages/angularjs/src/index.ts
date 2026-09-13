import type { CertificateProvider } from "@gostcrypto/core";
export interface AngularJsModule {constant(name:string,value:unknown):AngularJsModule;}
export interface AngularJsStatic {module(name:string,dependencies?:readonly string[]):AngularJsModule;}
/** Registers an AngularJS module exposing the provider as `gostCrypto`. */
export function registerGostCryptoModule(angular:AngularJsStatic,provider:CertificateProvider,moduleName="gostcrypto"):AngularJsModule{return angular.module(moduleName,[]).constant("gostCrypto",provider);}
