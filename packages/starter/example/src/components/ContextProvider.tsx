import { createTheme, StyledEngineProvider, ThemeProvider } from '@mui/material';
import { deepPurple, pink } from '@mui/material/colors';
import { WalletModalProvider as AntDesignWalletModalProvider } from '@solana/wallet-adapter-ant-design';
import type { Adapter, WalletError } from '@solana/wallet-adapter-base';
import { WalletAdapterNetwork } from '@solana/wallet-adapter-base';
import { WalletDialogProvider as MaterialUIWalletDialogProvider } from '@solana/wallet-adapter-material-ui';
import { ConnectionProvider, WalletProvider } from '@solana/wallet-adapter-react';
import { WalletModalProvider as ReactUIWalletModalProvider } from '@solana/wallet-adapter-react-ui';
import { IIWalletAdapter } from '@solana/wallet-adapter-wallets';
import { clusterApiUrl } from '@solana/web3.js';
import { SnackbarProvider, useSnackbar } from 'notistack';
import type { FC, ReactNode } from 'react';
import React, { useCallback, useMemo } from 'react';
import { AutoConnectProvider, useAutoConnect } from './AutoConnectProvider';
import { Ed25519KeyIdentity } from '@dfinity/identity';

const theme = createTheme({
    palette: {
        mode: 'dark',
        primary: {
            main: deepPurple[700],
        },
        secondary: {
            main: pink[700],
        },
    },
    components: {
        MuiButtonBase: {
            styleOverrides: {
                root: {
                    justifyContent: 'flex-start',
                },
            },
        },
        MuiButton: {
            styleOverrides: {
                root: {
                    textTransform: 'none',
                    padding: '12px 16px',
                },
                startIcon: {
                    marginRight: 8,
                },
                endIcon: {
                    marginLeft: 8,
                },
            },
        },
    },
});

const WalletContextProvider: FC<{ children: ReactNode }> = ({ children }) => {
    const { autoConnect } = useAutoConnect();

    // Can be set to 'devnet', 'testnet', or 'mainnet-beta'
    const network = WalletAdapterNetwork.Devnet;

    // You can also provide a custom RPC endpoint
    const endpoint = useMemo(() => clusterApiUrl(network), [network]);

    const wallets = useMemo(
        () => [
            /**
             * Wallets that implement either of these standards will be available automatically.
             *
             *   - Solana Mobile Stack Mobile Wallet Adapter Protocol
             *     (https://github.com/solana-mobile/mobile-wallet-adapter)
             *   - Solana Wallet Standard
             *     (https://github.com/solana-labs/wallet-standard)
             *
             * If you wish to support a wallet that supports neither of those standards,
             * instantiate its legacy wallet adapter here. Common legacy adapters can be found
             * in the npm package `@solana/wallet-adapter-wallets`.
             */
            new IIWalletAdapter(Ed25519KeyIdentity.generate()),
        ],
        // eslint-disable-next-line react-hooks/exhaustive-deps
        [network]
    );

    const { enqueueSnackbar } = useSnackbar();
    const onError = useCallback(
        (error: WalletError, adapter?: Adapter) => {
            enqueueSnackbar(error.message ? `${error.name}: ${error.message}` : error.name, { variant: 'error' });
            console.error(error, adapter);
        },
        [enqueueSnackbar]
    );

    return (
        <ConnectionProvider endpoint={endpoint}>
            <WalletProvider wallets={wallets} onError={onError} autoConnect={autoConnect}>
                <MaterialUIWalletDialogProvider>
                    <AntDesignWalletModalProvider>
                        <ReactUIWalletModalProvider>{children}</ReactUIWalletModalProvider>
                    </AntDesignWalletModalProvider>
                </MaterialUIWalletDialogProvider>
            </WalletProvider>
        </ConnectionProvider>
    );
};

export const ContextProvider: FC<{ children: ReactNode }> = ({ children }) => {
    return (
        <StyledEngineProvider injectFirst>
            <ThemeProvider theme={theme}>
                <SnackbarProvider>
                    <AutoConnectProvider>
                        <WalletContextProvider>{children}</WalletContextProvider>
                    </AutoConnectProvider>
                </SnackbarProvider>
            </ThemeProvider>
        </StyledEngineProvider>
    );
};
