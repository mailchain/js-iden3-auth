/* eslint-disable prettier/prettier */
import { Id } from '@iden3/js-iden3-core';
import { type IStateResolver, type ResolvedState, isGenesisStateId } from './resolver';
import type { DIDDocument, DIDResolutionResult, VerificationMethod } from 'did-resolver';

/**
 * Extended DID resolution result that includes additional information about Polygon ID resolution.
 */
type PolygonDidResolutionResult = DIDResolutionResult & {
  didDocument: DIDDocument & {
    verificationMethod: (VerificationMethod & {
      info: {
        id: string;
        state: string;
        replacedByState: string;
        createdAtTimestamp: string;
        replacedAtTimestamp: string;
        createdAtBlock: string;
        replacedAtBlock: string;
      };
      global: {
        root: string;
        replacedByRoot: string;
        createdAtTimestamp: string;
        replacedAtTimestamp: string;
        createdAtBlock: string;
        replacedAtBlock: string;
      };
    })[];
  };
};

/**
 * Implementation of {@link IStateResolver} that uses Vidos resolver service to resolve states.
 * It can serve as drop-in replacement for EthStateResolver.
 * 
 * - Vidos info: [https://vidos.id/](https://vidos.id/).
 * - Vidos Dashboard: [https://dashboard.vidos.id/](https://dashboard.vidos.id/).
 * - Vidos Docs: [https://vidos.id/docs/](https://vidos.id/docs/).
 * - Quick Start Guide - Create a resolver instance: [https://vidos.id/docs/services/resolver/guides/create-instance/](https://vidos.id/docs/services/resolver/guides/create-instance/)
 * 
 * @example
 * ```typescript
 * const resolver = new VidosResolver('https://my-resolver-123.resolver.service.eu.vidos.id', 'my-api-key');
 * 
 * const resolvers = {
 *   ["polygon:main"]: vidosResolver,
 * };
 * 
 * const verifier = await auth.Verifier.newVerifier({ stateResolver: resolvers, circuitsDir: path.join(__dirname, keyDIR), ipfsGatewayURL: "https://ipfs.io" });
 * ```
 */
export default class VidosResolver implements IStateResolver {
  
  /**
   * Create a new VidosResolver instance.
   * 
   * @param resolverUrl The URL of the Vidos resolver service to use.
   * @param apiKey The API key to use for authentication.
   * @param network The Polygon ID network to use. Default is 'main'.
   * 
   */
  constructor(private readonly resolverUrl: string, private readonly apiKey: string, private readonly network: 'main' | 'mumbai' | 'amoy' = 'main') {}

  // Note: implementation closely resembles EthStateResolver because Vidos resolver internally uses the same contract.
  // The only difference is the usage of regular HTTP requests instead of web3 calls.

  async rootResolve(state: bigint): Promise<ResolvedState> {
    const stateHex = state.toString(16);

    const zeroAddress = '11111111111111111111'; // 1 is 0 in base58
    const did = `did:polygonid:polygon:${this.network}:${zeroAddress}?gist=${stateHex}`;

    const response = await fetch(`${this.resolverUrl}/${encodeURIComponent(did)}`, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${this.apiKey}`
      }
    });
    const result = (await response.json()) as PolygonDidResolutionResult;
    if (result.didResolutionMetadata.error) {
      throw new Error(`error resolving DID: ${result.didResolutionMetadata.error}`);
    }

    const globalInfo = result.didDocument.verificationMethod[0].global;
    if (globalInfo == null) throw new Error('gist info not found');

    if (globalInfo.root !== stateHex) {
      throw new Error('gist info contains invalid state');
    }

    if (globalInfo.replacedByRoot !== '0') {
      if (globalInfo.replacedAtTimestamp === '0') {
        throw new Error('state was replaced, but replaced time unknown');
      }
      return {
        latest: false,
        state: state,
        transitionTimestamp: globalInfo.replacedAtTimestamp,
        genesis: false
      };
    }

    return {
      latest: true,
      state: state,
      transitionTimestamp: 0,
      genesis: false
    };
  }

  async resolve(id: bigint, state: bigint): Promise<ResolvedState> {
    const iden3Id = Id.fromBigInt(id);
    const stateHex = state.toString(16);

    const did = `did:polygonid:polygon:${this.network}:${iden3Id.string()}`;

    const didWithState = `${did}?state=${stateHex}`;
    const response = await fetch(`${this.resolverUrl}/${encodeURIComponent(didWithState)}`, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${this.apiKey}`
      }
    });
    const result = (await response.json()) as PolygonDidResolutionResult;
    if (result.didResolutionMetadata.error) {
      throw new Error(`error resolving DID: ${result.didResolutionMetadata.error}`);
    }

    const isGenesis = isGenesisStateId(id, state);

    const stateInfo = result.didDocument.verificationMethod[0].info;
    if (stateInfo == null) throw new Error('state info not found');

    if (stateInfo.id !== did) {
      throw new Error(`state was recorded for another identity`);
    }

    if (stateInfo.state !== stateHex) {
      if (stateInfo.replacedAtTimestamp === '0') {
        throw new Error(`no information about state transition`);
      }
      return {
        latest: false,
        genesis: false,
        state: state,
        transitionTimestamp: Number.parseInt(stateInfo.replacedAtTimestamp)
      };
    }

    return {
      latest: stateInfo.replacedAtTimestamp === '0',
      genesis: isGenesis,
      state,
      transitionTimestamp: Number.parseInt(stateInfo.replacedAtTimestamp)
    };
  }
}
