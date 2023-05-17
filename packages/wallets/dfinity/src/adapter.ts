import type { WalletName } from '@solana/wallet-adapter-base';
import {
    BaseSignerWalletAdapter,
    isVersionedTransaction,
    WalletNotConnectedError,
    WalletReadyState,
} from '@solana/wallet-adapter-base';
import type { Message, TransactionVersion } from '@solana/web3.js';
import { Transaction, VersionedTransaction } from '@solana/web3.js';
import { Keypair, PublicKey } from '@solana/web3.js';
import type { Ed25519KeyIdentity, Ed25519PublicKey } from '@dfinity/identity';

export const IIWalletName = 'Internet Identity Solana Wallet' as WalletName<'Internet Identity Solana Wallet'>;

/**
 * Wallet Adapter without using a third-party wallet.
 */
export class IIWalletAdapter extends BaseSignerWalletAdapter {
    name = IIWalletName;
    url = 'https://github.com/solana-labs/wallet-adapter#usage';
    icon =
        'data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMzQiIGhlaWdodD0iMzAiIGZpbGw9Im5vbmUiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+PHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9Ik0zNCAxMC42djIuN2wtOS41IDE2LjVoLTQuNmw2LTEwLjVhMi4xIDIuMSAwIDEgMCAyLTMuNGw0LjgtOC4zYTQgNCAwIDAgMSAxLjMgM1ptLTQuMyAxOS4xaC0uNmw0LjktOC40djQuMmMwIDIuMy0yIDQuMy00LjMgNC4zWm0yLTI4LjRjLS4zLS44LTEtMS4zLTItMS4zaC0xLjlsLTIuNCA0LjNIMzBsMS43LTNabS0zIDVoLTQuNkwxMC42IDI5LjhoNC43TDI4LjggNi40Wk0xOC43IDBoNC42bC0yLjUgNC4zaC00LjZMMTguNiAwWk0xNSA2LjRoNC42TDYgMjkuOEg0LjJjLS44IDAtMS43LS4zLTIuNC0uOEwxNSA2LjRaTTE0IDBIOS40TDcgNC4zaDQuNkwxNCAwWm0tMy42IDYuNEg1LjdMMCAxNi4ydjhMMTAuMyA2LjRaTTQuMyAwaC40TDAgOC4ydi00QzAgMiAxLjkgMCA0LjMgMFoiIGZpbGw9IiM5OTQ1RkYiLz48L3N2Zz4=';
    supportedTransactionVersions: ReadonlySet<TransactionVersion> = new Set(['legacy', 0]);

    #identity: Ed25519KeyIdentity | null = null;

    constructor(identity: Ed25519KeyIdentity) {
        super();
        this.#identity = identity;
    }

    get connecting() {
        return false;
    }

    get publicKey() {
        return this.#identity && new PublicKey((this.#identity.getPublicKey() as Ed25519PublicKey).toRaw());
    }

    get readyState() {
        return WalletReadyState.Loadable;
    }

    async connect(): Promise<void> {
        if (!this.#identity) {
            throw new WalletNotConnectedError();
        } else {
            this.emit('connect', this.publicKey as PublicKey);
        }
    }

    async disconnect(): Promise<void> {
        // this.#identity = null;
        this.emit('disconnect');
    }

    async signTransaction<T extends Transaction | VersionedTransaction>(transaction: T): Promise<T> {
        if (!this.#identity) throw new WalletNotConnectedError();

        if (isVersionedTransaction(transaction)) {
            await transaction.sign_with_identity([this.#identity]);
        } else {
            await transaction.partial_sign_with_identity(this.#identity);
        }
        return transaction;
    }
}

declare module '@solana/web3.js' {
    interface VersionedTransaction {
        sign_with_identity(identities: Array<Ed25519KeyIdentity>): Promise<void>;
    }
    interface Transaction {
        partial_sign_with_identity(...identities: Array<Ed25519KeyIdentity>): Promise<void>;
        _compile(): Message;
        _partialSignWithIdentity(message: Message, ...identities: Ed25519KeyIdentity[]): Promise<void>;
        _addSignature(pubkey: PublicKey, signature: Buffer): void;
    }
}

VersionedTransaction.prototype.sign_with_identity = async function sign_with_identity(
    identities: Array<Ed25519KeyIdentity>
): Promise<void> {
    const messageData = this.message.serialize();
    const signerPubkeys = this.message.staticAccountKeys.slice(0, this.message.header.numRequiredSignatures);
    for (const identity of identities) {
        const identity_pubkey = new PublicKey((identity.getPublicKey() as Ed25519PublicKey).toRaw());
        const signerIndex = signerPubkeys.findIndex((pubkey) => pubkey.equals(identity_pubkey));
        if (!(signerIndex >= 0)) {
            throw new Error(`Cannot sign with non signer key ${identity_pubkey.toBase58()}`);
        }
        this.signatures[signerIndex] = new Uint8Array(await identity.sign(messageData));
    }
};

Transaction.prototype.partial_sign_with_identity = async function partial_sign_with_identity(
    ...identities: Array<Ed25519KeyIdentity>
): Promise<void> {
    if (identities.length === 0) {
        throw new Error('No signers');
    }

    // Dedupe signers
    const seen = new Set();
    const uniqueSigners = [];
    for (const identity of identities) {
        const key = new PublicKey((identity.getPublicKey() as Ed25519PublicKey).toRaw()).toString();
        if (seen.has(key)) {
            continue;
        } else {
            seen.add(key);
            uniqueSigners.push(identity);
        }
    }

    const message = this._compile();
    this._partialSignWithIdentity(message, ...uniqueSigners);
};

Transaction.prototype._compile = function _compile(): Message {
    const message = this.compileMessage();
    const signedKeys = message.accountKeys.slice(0, message.header.numRequiredSignatures);

    if (this.signatures.length === signedKeys.length) {
        const valid = this.signatures.every((pair, index) => {
            return signedKeys[index].equals(pair.publicKey);
        });

        if (valid) return message;
    }

    this.signatures = signedKeys.map((publicKey) => ({
        signature: null,
        publicKey,
    }));

    return message;
};

Transaction.prototype._partialSignWithIdentity = async function _partialSignWithIdentity(
    message: Message,
    ...identities: Array<Ed25519KeyIdentity>
) {
    const signData = message.serialize();
    identities.forEach(async (identity) => {
        const signature = new Uint8Array(await identity.sign(signData));
        this._addSignature(
            new PublicKey((identity.getPublicKey() as Ed25519PublicKey).toRaw()),
            Buffer.from(signature.buffer, signature.byteOffset, signature.byteLength)
        );
    });
};

Transaction.prototype._addSignature = function _addSignature(pubkey: PublicKey, signature: Buffer) {
    if (signature.length !== 64) {
        throw new Error('Assertion failed.');
    }

    const index = this.signatures.findIndex((sigpair) => pubkey.equals(sigpair.publicKey));
    if (index < 0) {
        throw new Error(`unknown signer: ${pubkey.toString()}`);
    }

    this.signatures[index].signature = Buffer.from(signature);
};
