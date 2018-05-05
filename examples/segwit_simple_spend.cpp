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
    short_hash KeyHash = bitcoin_short_hash(publicKey);
    return {operation(opcode(0)), operation(to_chunk(KeyHash))};
}

bc::wallet::hd_private childPrivateKey(bc::wallet::hd_private privKey, int index) {
    return privKey.derive_private(index);
}


bc::wallet::hd_private
indexPrivateKeyForHardenedDerivationPath(hd_private privateKey, derivation_path path) {
//
//    auto hardenedOffset = bc::wallet::hd_first_hardened_key;
//    int hardenedPurposeIndex = (int) (purpose + hardenedOffset);
//    int hardenedCoinIndex = (int) (coin + hardenedOffset);
//    int hardenedAccountIndex = (int) (account + hardenedOffset);
//    int changeIndex = (int) (change);
//    int indexIndex = (int) (index);

    // 2. generate keys
    bc::wallet::hd_private purposePrivateKey = childPrivateKey(privateKey, path.getHardenedPurpose());

    bc::wallet::hd_private coinPrivateKey = childPrivateKey(purposePrivateKey, path.getHardenedCoin());

    bc::wallet::hd_private accountPrivateKey = childPrivateKey(coinPrivateKey, path.getHardenedAccount());

    bc::wallet::hd_private changePrivateKey = childPrivateKey(accountPrivateKey, path.getChange());

    return childPrivateKey(changePrivateKey, path.getIndex());
}

payment_address paymentAddressForCompressedPubKey(ec_compressed compressedPublicKey, script P2WPKH) {
    // script P2WPKH = script(witnessProgram(compressedPublicKey));
    short_hash WitnessProgramHash = bitcoin_short_hash(P2WPKH.to_data(0));
    payment_address fromAddress = payment_address(P2WPKH, payment_address::testnet_p2sh);
    return fromAddress;
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


script
P2WPKHForHardenedDerivationPath(hd_private privateKey, derivation_path path) {
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

    //Make Signature
    script script_code = script::to_pay_key_hash_pattern(bitcoin_short_hash(usableAddress.buildCompressedPublicKey()));
    endorsement sig;
    script().create_endorsement(sig, usableAddress.buildPrivateKey().secret(), script_code, tx,
                                tx.inputs()[input_index].previous_output().index(), sighash_algorithm::all,
                                script_version::zero, previous_amount);

    cout << "Making Witness" << input_index << " \n";

    //Make Witness
    data_stack witness_data{to_chunk(sig), to_chunk(usableAddress.buildCompressedPublicKey())};
    tx.inputs()[input_index].set_witness(witness(witness_data));

    cout << "Making input script" << input_index << " \n";

    //set input script
    data_chunk scriptChunk = to_chunk(usableAddress.buildP2WPKH().to_data(1));
    tx.inputs()[input_index].set_script(script(scriptChunk, false));

    std::cout << "input [" << input_index << "] P2SH Script: " << tx.inputs()[input_index].script().to_string(0)
              << std::endl;

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
    hd_private privateKey = getPrivateKey("sad post like task render prefer attitude advice hazard cruel guitar coral");
//	hd_private privateKey = getPrivateKey("company rail code drop garlic weird enable month lyrics faint educate pilot marine orphan boat");

    derivation_path input1_path(49, 1, 0, 0, 0);
    derivation_path change_path(49, 1, 0, 1, 0);


    usable_address input1(privateKey, input1_path);
    usable_address change(privateKey, change_path);

//    ec_compressed input1_CompressedPublicKey = input1.buildCompressedPublicKey();
//    script input1_P2WPKH = input1.buildP2WPKH();
//    bc::wallet::hd_private input1_privateKey = input1.buildPrivateKey();

//	payment_address input2 = paymentAddressForHardenedDerivationPath(privateKey, 49, 1, 0, 0, 3);
//    ec_compressed input2_CompressedPublicKey = compressedPublicKeyForHardenedDerivationPath(privateKey, 49, 1, 0, 0, 3);
//    script input2_P2WPKH = P2WPKHForHardenedDerivationPath(privateKey, 49, 1, 0, 1, 0);
//    bc::wallet::hd_private input2_privateKey = indexPrivateKeyForHardenedDerivationPath(privateKey, 49, 1, 0, 0, 3);

    payment_address changeAddress = paymentAddressForHardenedDerivationPath(privateKey, change_path);


    cout << "Payment Address (input1): " << input1.buildPaymentAddress() << "\n";
//	cout << "Payment Address (input2): " << input2 << "\n";
    cout << "Payment Address (changeAddress): " << change.buildPaymentAddress() << "\n";

    cout << "ec_private::testnet: " << ec_private::testnet << "\n";



    //Start Building Transanction
    transaction tx;
    tx.set_version(1u);
    //Make Output

    payment_address toAddress = wallet::payment_address("2N7WQkFtJcdvfMp4HwkoiJonvYDYjh2rAFK");
    cout << "Payment Address (toAddress): " << toAddress << "\n";
    uint64_t amount = 10000;
//    btc_to_satoshi(amount, "0.0001");
//    tx.outputs().push_back(output(amount, script(script().to_pay_script_hash_pattern(toAddress.hash()))));

    createPayToScriptOutputFrom(tx, toAddress, amount);

    std::cout << "output [0] P2SH Script: " << tx.outputs()[0].script().to_string(0) << std::endl;

    //Make Change
//  std::cout << "from address: " << fromAddress.encoded() << std::endl;
//  hd_private nextIndexPrivateKey = childPrivateKey(receiveChangePrivateKey, 0);
//  ec_compressed compressedChangePublicKey = nextIndexPrivateKey.to_public().point();
//  script changeP2WPKH = script(witnessProgram(compressedChangePublicKey));
//  payment_address changeAddress = paymentAddressForCompressedPubKey(compressedChangePublicKey, changeP2WPKH);
//  std::cout << "change address: " << changeAddress.encoded() << std::endl;



//    points_value UTXOs = getUTXOs(input1, amount);

//    cout << "UTXOs value: " << UTXOs.value() << "\n";
//    cout << "UTXOs points[0].value: " << UTXOs.points[0].value() << "\n";
//    cout << "UTXOs points[0].index : " << UTXOs.points[0].index() << "\n";
//    cout << "UTXOs points[0].hash: " << UTXOs.points[0].hash() << "\n";



//    chain::point_value retrieved_utxo = UTXOs.points[0];



    chain::point_value utxo1(chain::point
                                     {
                                             hash_literal(
                                                     "5f36bff2d7492dfc9e091468f930fccb7f14417e3daee9254fc32b92578e0440"),
                                             0u
                                     }, 100000);

//    if(retrieved_utxo == utxo1){
//        cout << "They are the same!\n";
//    }

//    cout << "UTXO:  " << " Index: " << utxo1.index() << "\n";

//    chain::point_value utxo2(chain::point
//    {
//        hash_literal("c7c0d4e3ed1fdb0a05b622a7fe16d1067a51190a88823c70df107c678d8deba8"),
//                0u
//    }, 16250000);






    uint64_t change_amount = utxo1.value() - amount - 10000;
//	uint64_t change_amount = utxo2.value()  - amount - 10000;
//	uint64_t change_amount = utxo1.value() + utxo2.value() - amount - 10000;

    cout << "Change: " << change_amount << "\n";

//	script outScript = script(script().to_pay_script_hash_pattern(changeAddress.hash()));
//	tx.outputs().push_back(output(change, outScript));

    createPayToScriptOutputFrom(tx, change.buildPaymentAddress(), change_amount);

    std::cout << "output [1] P2SH Script: " << tx.outputs()[1].script().to_string(0) << std::endl;


    cout << "about to create inputs from utxo's\n";


    createInputFrom(tx, 0, utxo1, input1);







//    createInputFrom(tx, 1, utxo2, input2_CompressedPublicKey, input2_P2WPKH, input2_privateKey);

    if (tx.is_valid()) {
        cout << "TX IS VALID!!!\n";
    }

    std::cout << encode_base16(tx.to_data(true, true)) << std::endl;




//	broadcastTX(tx);
//
//	build
// g++ -std=c++11 -o spend_simple segwit_simple_spend.cpp $(pkg-config --cflags libbitcoin --libs libbitcoin libbitcoin-client)

}







//0100000000010140048e57922bc34f25e9ae3d7e41147fcbfc30f96814099efc2d49d7f2bf365f0000000017160014511ee69b10c17b0ab130a5d628378dff7cf37ba5ffffffff02102700000000000017a9149c70fb19ce7e2de4a07c716842e9bc1090a455d187803801000000000017a9148f6fcbf767432269c0145ac75f9c1fe701f099d38702483045022100ac74070ff41a834e5ca407f731c0ed19ea39356c07fd4bc4944c3dad9992b32d022043324d1fd93861258ab561f8f9e5354feb1a44507ab5d52e9715f55a742ce0530121022713623696fe288e30098bf9098bf55922e15413680b77266466dbad907ae22500000000


//0100000000010140048e57922bc34f25e9ae3d7e41147fcbfc30f96814099efc2d49d7f2bf365f0000000017160014511ee69b10c17b0ab130a5d628378dff7cf37ba5ffffffff02102700000000000017a9149c70fb19ce7e2de4a07c716842e9bc1090a455d187803801000000000017a9148f6fcbf767432269c0145ac75f9c1fe701f099d38702483045022100ac74070ff41a834e5ca407f731c0ed19ea39356c07fd4bc4944c3dad9992b32d022043324d1fd93861258ab561f8f9e5354feb1a44507ab5d52e9715f55a742ce0530121022713623696fe288e30098bf9098bf55922e15413680b77266466dbad907ae22500000000
