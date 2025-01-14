import { cacheLoader } from '@0xpolygonid/js-sdk';
import { DocumentLoader } from '@iden3/js-jsonld-merklization';
import { VerifyOpts } from '@lib/circuits';
import { IStateResolver, ResolvedState, Resolvers } from '@lib/state/resolver';
import { DIDResolutionResult } from 'did-resolver';

class MockResolver implements IStateResolver {
  resolve(): Promise<ResolvedState> {
    const t: ResolvedState = {
      latest: true,
      state: null,
      genesis: false,
      transitionTimestamp: 0
    };
    return Promise.resolve(t);
  }
  rootResolve(): Promise<ResolvedState> {
    const t: ResolvedState = {
      latest: true,
      state: null,
      genesis: false,
      transitionTimestamp: 0
    };
    return Promise.resolve(t);
  }
}

class MockResolverWithNoStateInContract implements IStateResolver {
  resolve(): Promise<ResolvedState> {
    throw new Error('State is not genesis and not registered in the smart contract');
  }
  rootResolve(): Promise<ResolvedState> {
    throw new Error('GIST root does not exist in the smart contract');
  }
}

class MockResolverWithNotLatesState implements IStateResolver {
  resolve(): Promise<ResolvedState> {
    const t: ResolvedState = {
      latest: false,
      state: null,
      genesis: false,
      transitionTimestamp: 1712653265
    };
    return Promise.resolve(t);
  }
  rootResolve(): Promise<ResolvedState> {
    const t: ResolvedState = {
      latest: false,
      state: null,
      genesis: false,
      transitionTimestamp: 1712653265
    };
    return Promise.resolve(t);
  }
}

export const exampleDidDoc = {
  '@context': [
    'https://www.w3.org/ns/did/v1',
    {
      EcdsaSecp256k1RecoveryMethod2020:
        'https://identity.foundation/EcdsaSecp256k1RecoverySignature2020#EcdsaSecp256k1RecoveryMethod2020',
      blockchainAccountId: 'https://w3id.org/security#blockchainAccountId'
    }
  ],
  id: 'did:pkh:poly:0x7141E4d20F7644DC8c0AdCA8a520EC83C6cABD65',
  verificationMethod: [
    {
      id: 'did:pkh:poly:0x7141E4d20F7644DC8c0AdCA8a520EC83C6cABD65#Recovery2020',
      type: 'EcdsaSecp256k1RecoveryMethod2020',
      controller: 'did:pkh:poly:0x7141E4d20F7644DC8c0AdCA8a520EC83C6cABD65',
      blockchainAccountId: 'eip155:137:0x7141E4d20F7644DC8c0AdCA8a520EC83C6cABD65'
    }
  ],
  authentication: ['did:pkh:poly:0x7141E4d20F7644DC8c0AdCA8a520EC83C6cABD65#Recovery2020'],
  assertionMethod: ['did:pkh:poly:0x7141E4d20F7644DC8c0AdCA8a520EC83C6cABD65#Recovery2020']
};

export const testOpts: VerifyOpts = {
  acceptedStateTransitionDelay: 5 * 60 * 1000, // 5 minutes
  acceptedProofGenerationDelay: 10 * 365 * 24 * 60 * 60 * 1000 // 10 years
};

const mockStateResolver: MockResolver = new MockResolver();
export const mockResolverWithNoStateInContract: MockResolver =
  new MockResolverWithNoStateInContract();
export const mockResolverWithNotLatesState: MockResolver = new MockResolverWithNotLatesState();
export const resolvers: Resolvers = {
  'polygon:amoy': mockStateResolver,
  'polygon:mumbai': mockStateResolver
};
export const resolveDIDDocument = {
  resolve: () => Promise.resolve({ didDocument: exampleDidDoc } as DIDResolutionResult)
};

export const schemaLoader: DocumentLoader = cacheLoader({
  ipfsNodeURL: process.env.IPFS_URL ?? 'https://ipfs.io'
});
