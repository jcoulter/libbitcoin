#include <bitcoin/bitcoin.hpp>
#include <bitcoin/client.hpp>
#include <string.h>
#include <bitcoin/bitcoin/chain/script.hpp>


using namespace bc;
using namespace bc::wallet;
using namespace bc::machine;
using namespace bc::chain;



class derivation_path {

public:
    derivation_path(int purpose);

    derivation_path(int purpose, int coin, int account, int change, int index);

    bool hasPurpose() {
        return coin >= 0;
    }

    bool hasCoin() {
        return coin >= 0;
    }

    bool hasAccount() {
        return coin >= 0;
    }

    bool hasChange() {
        return coin >= 0;
    }

    bool hasindex() {
        return coin >= 0;
    }

    int getPurpose() {
        return purpose;
    }

    int getCoin() {
        return coin;
    }

    int getAccount() {
        return account;
    }

    int getChange() {
        return change;
    }

    int getIndex() {
        return index;
    }

    int getHardenedPurpose() {
        return purpose + hardenedOffset;
    }

    int getHardenedCoin() {
        return coin + hardenedOffset;
    }

    int getHardenedAccount() {
        return account + hardenedOffset;
    }


private:
    uint32_t hardenedOffset = bc::wallet::hd_first_hardened_key;
    int purpose = -1;
    int coin = -1;
    int account = -1;
    int change = -1;
    int index = -1;
};

derivation_path::derivation_path(int purpose) {
    this->purpose = purpose;
}

derivation_path::derivation_path(int purpose, int coin, int account, int change, int index) {
    this->purpose = purpose;
    this->coin = coin;
    this->account = account;
    this->change = change;
    this->index = index;
}



points_value getUTXOs(payment_address Addy, uint64_t amount) {
    client::connection_type connection = {};
    connection.retries = 3;
    connection.timeout_seconds = 8;
    connection.server = config::endpoint("tcp://testnet1.libbitcoin.net:19091");
    client::obelisk_client client(connection);

    points_value val1;
    static const auto on_done = [&val1](const points_value &vals) {

        std::cout << "Success: " << vals.value() << std::endl;
        val1 = vals;
    };

    static const auto on_error = [](const code &ec) {
        std::cout << "Error Code: " << ec.message() << std::endl;
    };

    if (!client.connect(connection)) {
        std::cout << "Fail" << std::endl;
    } else {
        std::cout << "Connection Succeeded" << std::endl;
    }

    client.blockchain_fetch_unspent_outputs(on_error, on_done, Addy, amount, select_outputs::algorithm::greedy);

    client.wait();


    //return allPoints;
    return val1;


}


void broadcastTX(transaction tx) {
    client::connection_type connection = {};
    connection.retries = 3;
    connection.timeout_seconds = 8;
    connection.server = config::endpoint("tcp://testnet3.libbitcoin.net:19091");
    client::obelisk_client client(connection);

    if (!client.connect(connection)) {
        std::cout << "Fail" << std::endl;
    } else {
        std::cout << "Connection Succeeded" << std::endl;
    }

    static const auto on_done = [](const code &ec) {

        std::cout << "Success: " << ec.message() << std::endl;

    };

    static const auto on_error2 = [](const code &ec) {

        std::cout << "Error Code: " << ec.message() << std::endl;

    };

    client.transaction_pool_broadcast(on_error2, on_done, tx);
    client.wait();
}

hd_private getPrivateKey(std::string walletMnemonic) {
    std::string mnemonic = walletMnemonic;
    data_chunk seed = to_chunk(decode_mnemonic(split(mnemonic)));
    return hd_private(seed, hd_private::testnet);
}

operation::list witnessProgram(ec_compressed publicKey) {
    //TODO: My example
    short_hash KeyHash = bitcoin_short_hash(publicKey);
    return {operation(opcode(0)), operation(to_chunk(KeyHash))};
    //TODO: their example - same output

//    short_hash keyhash_dest = bitcoin_short_hash(publicKey);
//    operation::list p2wpkh_operations;
//    p2wpkh_operations.push_back(operation(opcode::push_size_0));
//    p2wpkh_operations.push_back(operation(to_chunk(keyhash_dest)));
//
//    return p2wpkh_operations;


}

bc::wallet::hd_private childPrivateKey(bc::wallet::hd_private privKey, int index) {
    return privKey.derive_private(index);
}


bc::wallet::hd_private indexPrivateKeyForHardenedDerivationPath(hd_private privateKey, derivation_path path) {

    bc::wallet::hd_private purposePrivateKey = childPrivateKey(privateKey, path.getHardenedPurpose());
    bc::wallet::hd_private coinPrivateKey = childPrivateKey(purposePrivateKey, path.getHardenedCoin());
    bc::wallet::hd_private accountPrivateKey = childPrivateKey(coinPrivateKey, path.getHardenedAccount());
    bc::wallet::hd_private changePrivateKey = childPrivateKey(accountPrivateKey, path.getChange());
    return childPrivateKey(changePrivateKey, path.getIndex());
}


//TODO: what is going on here between the p2wpkh and the p2sh?
payment_address paymentAddressForCompressedPubKey(ec_compressed compressedPublicKey, script P2WPKH) {
    short_hash WitnessProgramHash = bitcoin_short_hash(P2WPKH.to_data(0));
    return payment_address(P2WPKH, payment_address::testnet_p2sh);
}

ec_compressed compressedPublicKeyForHardenedDerivationPath(hd_private privateKey, derivation_path path) {
    bc::wallet::hd_private indexPrivateKey = indexPrivateKeyForHardenedDerivationPath(privateKey, path);
    bc::wallet::hd_public indexPublicKey = indexPrivateKey.to_public();
    return indexPublicKey.point();
}

payment_address paymentAddressForHardenedDerivationPath(hd_private privateKey, derivation_path path) {
    ec_compressed compressedPublicKey = compressedPublicKeyForHardenedDerivationPath(privateKey, path);

    script P2WPKH = script(witnessProgram(compressedPublicKey));
    // short_hash WitnessProgramHash = bitcoin_short_hash(P2WPKH.to_data(0));
    // payment_address fromAddress = payment_address(P2WPKH, payment_address::testnet_p2sh);
    return paymentAddressForCompressedPubKey(compressedPublicKey, P2WPKH);
}


script P2WPKHForHardenedDerivationPath(hd_private privateKey, derivation_path path) {
    return script(witnessProgram((compressedPublicKeyForHardenedDerivationPath(privateKey, path))));
}



class usable_address {
public:
    usable_address(hd_private privateKey, derivation_path path);
    payment_address buildPaymentAddress(){
        return paymentAddressForHardenedDerivationPath(privateKey, path);
    }
    ec_compressed buildCompressedPublicKey(){
        return compressedPublicKeyForHardenedDerivationPath(privateKey, path);
    }
    script buildP2WPKH(){
        return P2WPKHForHardenedDerivationPath(privateKey, path);
    }
    bc::wallet::hd_private buildPrivateKey(){
        return indexPrivateKeyForHardenedDerivationPath(privateKey, path);
    }
private:
    hd_private privateKey;
    derivation_path path = 0;
};

usable_address::usable_address(hd_private privateKey, derivation_path path) {
    this->privateKey = privateKey;
    this->path = path;
}



void createInputFrom(transaction &tx, int input_index, chain::point_value utxo, usable_address usableAddress) {
    cout << "Making input" << input_index << " \n";


    //Make Input
    input workingInput = input();
    workingInput.set_previous_output(output_point(utxo));
    workingInput.set_sequence(max_input_sequence);
    tx.inputs().push_back(workingInput);
    uint64_t previous_amount = utxo.value();


    cout << "Making signature" << input_index << " \n";

//    todo: this matches example
    //Make Signature
    script script_code = script::to_pay_key_hash_pattern(bitcoin_short_hash(usableAddress.buildCompressedPublicKey()));
    endorsement sig;

    cout << "tx.inputs()[input_index].previous_output().index() " << tx.inputs()[input_index].previous_output().index() << "\n";
    script().create_endorsement(sig, usableAddress.buildPrivateKey().secret(), script_code, tx,
                                tx.inputs()[input_index].previous_output().index(), sighash_algorithm::all,
                                script_version::zero, previous_amount);

    cout << "Making input script" << input_index << " \n";

    //set input script
    data_chunk scriptChunk = to_chunk(usableAddress.buildP2WPKH().to_data(true));
    tx.inputs()[input_index].set_script(script(scriptChunk, false));

    std::cout << "input [" << input_index << "] P2SH Script: " << tx.inputs()[input_index].script().to_string(0)
              << std::endl;


    cout << "Making Witness" << input_index << " \n";

    //Make Witness
    data_stack witness_data{sig, to_chunk(usableAddress.buildCompressedPublicKey())};
//    data_stack witness_data{to_chunk(sig), to_chunk(usableAddress.buildCompressedPublicKey())};
    tx.inputs()[input_index].set_witness(witness(witness_data));

}

void createPayToScriptOutputFrom(transaction &tx, payment_address address, uint64_t amount) {
    tx.outputs().push_back(output(amount, script(script().to_pay_script_hash_pattern(address.hash()))));
}

void createPayToKeyOutputFrom(transaction &tx, payment_address address, uint64_t amount) {
    tx.outputs().push_back(output(amount, script(script().to_pay_key_hash_pattern(address.hash()))));
}


//payment_address
//ec_compressed public
//p2wpkh
//hd_private



int main() {

    // hd_private privateKey = getPrivateKey("retire detect ceiling lab labor approve busy easy swing adjust dumb north");
//    hd_private privateKey = getPrivateKey("sad post like task render prefer attitude advice hazard cruel guitar coral");
	hd_private privateKey = getPrivateKey("company rail code drop garlic weird enable month lyrics faint educate pilot marine orphan boat");


    usable_address input1(privateKey, derivation_path(49, 1, 0, 0, 4));

    usable_address change(privateKey, derivation_path(49, 1, 0, 1, 2));



//	payment_address input2 = paymentAddressForHardenedDerivationPath(privateKey, 49, 1, 0, 0, 3);
//    ec_compressed input2_CompressedPublicKey = compressedPublicKeyForHardenedDerivationPath(privateKey, 49, 1, 0, 0, 3);
//    script input2_P2WPKH = P2WPKHForHardenedDerivationPath(privateKey, 49, 1, 0, 1, 0);
//    bc::wallet::hd_private input2_privateKey = indexPrivateKeyForHardenedDerivationPath(privateKey, 49, 1, 0, 0, 3);


    cout << "Payment Address (input1): " << input1.buildPaymentAddress() << "\n";
//	cout << "Payment Address (input2): " << input2 << "\n";
    cout << "Payment Address (changeAddress): " << change.buildPaymentAddress() << "\n";

    cout << "ec_private::testnet: " << ec_private::testnet << "\n";



    //Start Building Transanction
    transaction tx;
    tx.set_version(1u);
    //Make Output

    payment_address toAddress = wallet::payment_address("2MtCTasDMj8AADvGvviACU38B2Xw3sR4QVP");
    cout << "Payment Address (toAddress): " << toAddress << "\n";
    uint64_t amount = 4900000;
//    btc_to_satoshi(amount, "0.0001");
//    tx.outputs().push_back(output(amount, script(script().to_pay_script_hash_pattern(toAddress.hash()))));

    createPayToScriptOutputFrom(tx, toAddress, amount);

    std::cout << "output [0] P2SH Script: " << tx.outputs()[0].script().to_string(0) << std::endl;



    chain::point_value utxo1(chain::point
     {
             hash_literal(
                     "d4e29323e8c720bf12bd11ea9e73ed3eef22c79efe9cd1e43f4b52311e87429f"),
             0u
     }, 4900000);

//    if(retrieved_utxo == utxo1){
//        cout << "They are the same!\n";
//    }

//    cout << "UTXO:  " << " Index: " << utxo1.index() << "\n";

    chain::point_value utxo2(chain::point
    {
        hash_literal("74a90934eff36e34da015b567d7995f0834866d7da4c9149ff65b1d5857f6a92"),
                0u
    }, 59000000);






//    uint64_t change_amount = utxo1.value() - amount - 10000;
//	uint64_t change_amount = utxo2.value()  - amount - 10000;
	uint64_t change_amount = utxo1.value() + utxo2.value() - amount - 10000;

    cout << "Change: " << change_amount << "\n";

//	script outScript = script(script().to_pay_script_hash_pattern(changeAddress.hash()));
//	tx.outputs().push_back(output(change, outScript));

    createPayToScriptOutputFrom(tx, change.buildPaymentAddress(), change_amount);

    std::cout << "output [1] P2SH Script: " << tx.outputs()[1].script().to_string(0) << std::endl;


    cout << "about to create inputs from utxo's\n";


    createInputFrom(tx, 0, utxo1, input1);
    createInputFrom(tx, 1, utxo2, input1);

//    createInputFrom(tx, 1, utxo2, input2_CompressedPublicKey, input2_P2WPKH, input2_privateKey);

    if (tx.is_valid()) {
        cout << "TX IS VALID!!!!!!!!!!!\n";
    }

    std::cout << encode_base16(tx.to_data(true, true)) << std::endl;




//	broadcastTX(tx);
//
//	build
// g++ -std=c++11 -o spend_simple segwit_simple_spend.cpp $(pkg-config --cflags libbitcoin --libs libbitcoin libbitcoin-client)

}






// 01000000000101ecddf17b2360559376c8e1fa1d0957fb73a22c3c4ea13d69fb0f69f31a7e97c100000000171600147cbe2f2fb7ba9cee0f58f44a43788b3da9cdd88effffffff02008793030000000017a9140a723a3bfd9d93b5831d05b5d5cf02b7c5683d128730244c000000000017a914c8b03ea47156babe180d5e7c319867cb4ad68c39870247304402205f5aef7ccbe7c375e7262e35d7651400d74297b15e202bae415b91627a1ecdca02206b770ad5273a8ae046b7165f392e908eb8d33fe50a4fd7a5d9c32dd9659183ea0121031f00162786f395fe02bb443934edac236f4b6570ba5129b4acd684cb7208f39600000000
// 01000000000101ecddf17b2360559376c8e1fa1d0957fb73a22c3c4ea13d69fb0f69f31a7e97c100000000171600147cbe2f2fb7ba9cee0f58f44a43788b3da9cdd88effffffff02008793030000000017a9140a723a3bfd9d93b5831d05b5d5cf02b7c5683d128730244c000000000017a914c8b03ea47156babe180d5e7c319867cb4ad68c39870247304402205f5aef7ccbe7c375e7262e35d7651400d74297b15e202bae415b91627a1ecdca02206b770ad5273a8ae046b7165f392e908eb8d33fe50a4fd7a5d9c32dd9659183ea0121031f00162786f395fe02bb443934edac236f4b6570ba5129b4acd684cb7208f39600000000
// 01000000000101ecddf17b2360559376c8e1fa1d0957fb73a22c3c4ea13d69fb0f69f31a7e97c100000000171600147cbe2f2fb7ba9cee0f58f44a43788b3da9cdd88effffffff02008793030000000017a9140a723a3bfd9d93b5831d05b5d5cf02b7c5683d128730244c000000000017a914c8b03ea47156babe180d5e7c319867cb4ad68c39870247304402205f5aef7ccbe7c375e7262e35d7651400d74297b15e202bae415b91627a1ecdca02206b770ad5273a8ae046b7165f392e908eb8d33fe50a4fd7a5d9c32dd9659183ea0121031f00162786f395fe02bb443934edac236f4b6570ba5129b4acd684cb7208f39600000000


// 01000000000101a39ed2ca5c2bfa9e7afd9d9e420bf6fa8b59fa8715f1219320eee772502619650000000017160014232b0a07cb7d6f7ed8ad58eb75a948a7bb884780ffffffff02c04484030000000017a9143361fabb3a1d7367d5664e41870bf86aa074e22d87301b0f000000000017a9146378fa401dd34160e17021989bd913d940f26ffc870247304402202f7b320df875b3206d431e4e7b4edecb5fcc64b75a4b97183cf6591d9b56a86a02201291917f9225ee0670c52916a8cff17fcdc97904ed4f7f12ead73db50565f26e0121035829a0fbcfbf02a179cdce0b5544ab8166337e0b96d963bb3bd14c0f4ceb1a6a00000000

//failed send from change
// 01000000000101a39ed2ca5c2bfa9e7afd9d9e420bf6fa8b59fa8715f1219320eee7725026196501000000171600142154370d86a72201646e04fc1d4747bf8bb695c8ffffffff02a0c44a000000000017a9143361fabb3a1d7367d5664e41870bf86aa074e22d87803801000000000017a9146378fa401dd34160e17021989bd913d940f26ffc8702483045022100fdfe4f97efa6df3cfdf044997bca62f96fc00b780652759b5da4d8255998877902205149c9a8752a25def2f08286ec284e1c5020dd1a69512840c85b6898ab3ca279012103d91c31cd2bd7dd1fbc848af892f1df0fae15552788873a2d00b069abc200c4b900000000

// attempt to send funds from faucet -> change address - sent successfully
// 01000000000101426266571137c48342f25cfbe5563f8a27958d4c3e7064450964c8c03e8ff0dd00000000171600142154370d86a72201646e04fc1d4747bf8bb695c8ffffffff02a0c44a000000000017a9143361fabb3a1d7367d5664e41870bf86aa074e22d8790e694030000000017a9146378fa401dd34160e17021989bd913d940f26ffc870247304402205659f1a684023aeb24954033963bdebec0683786e1be6e30758705b1f944a40102200a28010fe57ca9b61cccd446959d0333f00982757e9eabfc179f171dbb9728d7012103d91c31cd2bd7dd1fbc848af892f1df0fae15552788873a2d00b069abc200c4b900000000

// attempt to spend from 2 0-indexed utxos from the same receive address
// 010000000001029f42871e31524b3fe4d19cfe9ec722ef3eed739eea11bd12bf20c7e82393e2d40000000017160014cd09965a3a206c1c0ffad854bc47f0e32071f941ffffffff926a7f85d5b165ff49914cdad7664883f095797d565b01da346ef3ef3409a9740000000017160014cd09965a3a206c1c0ffad854bc47f0e32071f941ffffffff02a0c44a000000000017a9140a723a3bfd9d93b5831d05b5d5cf02b7c5683d1287b01d84030000000017a9146378fa401dd34160e17021989bd913d940f26ffc8702483045022100f66d7e0a2be57ef7071a930ec8208fec0841c741c6ec0b96039d21e11427aca202206d79223d6900ba6703081633ede5c65ad7caee43fc6a0cd83838bcc7b3d115c90121022cbcc7095b46aeb979b8770a12725c5fbb209c97e8f1f66b6681b6ded38d094b0247304402204abf1db57e657860d565552939f4d638e2e25b0be002d7a6718ac8c35453e753022038447edd64c87a7ff919837871d3392a28fc5e20f1d60ac97724f658d67c288f0121022cbcc7095b46aeb979b8770a12725c5fbb209c97e8f1f66b6681b6ded38d094b00000000
