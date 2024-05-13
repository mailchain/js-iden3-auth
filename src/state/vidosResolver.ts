import { Id } from '@iden3/js-iden3-core';
import { type IStateResolver, type ResolvedState, isGenesisStateId } from './resolver';

type DidResolutionResult = {
  didResolutionMetadata: unknown;
  didDocumentMetadata: unknown;
  didDocument: {
    id: string;
    alsoKnownAs: string[];
    controller: string;
    verificationMethod: {
      id: string;
      type: string;
      controller: string;
      stateContractAddress: string;
      published: boolean;
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
    }[];
  };
};

/**
 * Implementation of {@link IStateResolver} that uses Vidos resolver service to resolve states.
 * It can serve as drop-in replacement for EthStateResolver.
 */
export default class VidosResolver implements IStateResolver {
  constructor(private readonly resolverUrl: string, private readonly apiKey: string) {}

  // Note: implementation closely resembles EthStateResolver because Vidos resolver internally uses the same contract. 
  // The only difference is the usage of regular HTTP requests instead of web3 calls.

  async rootResolve(state: bigint): Promise<ResolvedState> {
    const stateHex = state.toString(16);

    const zeroAddress = '11111111111111111111'; // 1 is 0 in base58
    const did = `did:polygonid:polygon:amoy:${zeroAddress}?gist=${stateHex}`;

    const response = await fetch(`${this.resolverUrl}/${encodeURIComponent(did)}`, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${this.apiKey}`
      }
    });
    const result = (await response.json()) as DidResolutionResult;

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

    const did = `did:polygonid:polygon:amoy:${iden3Id.string()}`;

    const didWithState = `${did}?state=${stateHex}`;
    const response = await fetch(`${this.resolverUrl}/${encodeURIComponent(didWithState)}`, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${this.apiKey}`
      }
    });
    const result = await response.json();
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
