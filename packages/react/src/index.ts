import { createContext,createElement,useCallback,useContext,useEffect,useState,type ReactNode } from "react";
import type { Bytes,CertificateInfo,CertificateProvider,SignOptions } from "@gostcrypto/core";

const CertificateProviderContext=createContext<CertificateProvider|undefined>(undefined);
export interface GostCryptoProviderProps {readonly provider:CertificateProvider;readonly children?:ReactNode;}
export function GostCryptoProvider({provider,children}:GostCryptoProviderProps){return createElement(CertificateProviderContext.Provider,{value:provider},children);}
export function useCertificateProvider():CertificateProvider {const provider=useContext(CertificateProviderContext);if(provider===undefined)throw new Error("GostCryptoProvider is missing");return provider;}
export interface CertificatesState {readonly certificates:readonly CertificateInfo[];readonly loading:boolean;readonly error:unknown;readonly refresh:()=>Promise<void>;}
export function useCertificates():CertificatesState {const provider=useCertificateProvider(),[certificates,setCertificates]=useState<readonly CertificateInfo[]>([]),[loading,setLoading]=useState(true),[error,setError]=useState<unknown>();const refresh=useCallback(async()=>{setLoading(true);setError(undefined);try{setCertificates(await provider.listCertificates());}catch(reason){setError(reason);}finally{setLoading(false);}},[provider]);useEffect(()=>{void refresh();},[refresh]);return{certificates,loading,error,refresh};}
export function useGostSign() {const provider=useCertificateProvider();return useCallback((certificateId:string,data:Bytes,options:SignOptions)=>provider.sign(certificateId,data,options),[provider]);}
