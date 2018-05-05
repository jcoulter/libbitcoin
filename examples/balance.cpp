#include <bitcoin/bitcoin.hpp>
#include <bitcoin/client.hpp>
#include <string.h>
#include <iostream>

using namespace bc;

uint64_t balancer(const chain::history::list& rows) {
  uint64_t unspent_balance = 0;
  for (const auto& row: rows) {
    // spend unconfirmed (or no spend attempted)
    if (row.spend.hash() == null_hash) {
      unspent_balance += row.value;
    }
  }
  return unspent_balance;
}

void getBalance(wallet::payment_address address) {
  cout << "address: " << address << "\n";
  client::connection_type connection = {};
  connection.retries = 3;
  connection.timeout_seconds = 8;
  connection.server = config::endpoint("tcp://testnet1.libbitcoin.net:19091");

  client::obelisk_client client(connection);

  static const auto on_done = [](const chain::history::list& rows) {
    uint64_t balance = balancer(rows);
    std::cout << encode_base10(balance, 8) << std::endl;
  };

  static const auto on_error2 = [](const code ec) {
    std::cout << "Error Code: " << ec.message() << std::endl;
  };

  if (!client.connect(connection)) {
    std::cout << "!!! Failed to connect !!!" << std::endl;
  } else {
    std::cout << "Connection sucessful." << std::endl;
  }

  client.blockchain_fetch_history3(on_error2, on_done, address);
  client.wait();


}

int main(int argc, char** argv)
{

  cout << "You have entered " << argc
       << " arguments:" << "\n";

  for (int i = 0; i < argc; ++i)
    cout << argv[i] << "\n";

  wallet::payment_address address(argv[1]);
  getBalance(address);
}