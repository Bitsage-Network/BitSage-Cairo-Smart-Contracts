import { RpcProvider } from 'starknet';

async function main() {
    const provider = new RpcProvider({ nodeUrl: 'https://rpc.starknet-testnet.lava.build' });
    const otc = '0x7b2b59d93764ccf1ea85edca2720c37bba7742d05a2791175982eaa59cedef0';
    
    for (let i = 0; i < 3; i++) {
        try {
            const result = await provider.callContract({
                contractAddress: otc,
                entrypoint: 'get_pair_info',
                calldata: [i.toString()],
            });
            console.log('Pair ' + i + ':');
            console.log('  base_token:', result[0]);
            console.log('  quote_token:', result[1]);
            console.log('  is_active:', result[6]);
        } catch (e) {
            console.log('Pair ' + i + ': error -', e.message?.slice(0, 150) || e);
        }
    }
}

main().catch(console.error);
