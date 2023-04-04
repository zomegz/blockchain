#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <chrono>
#include <ctime>
#include <openssl/ripemd.h>
#include <thread>
#include <unordered_set>
#include <iomanip>
#include <keccak/keccak.h>
#include <random>
#include <sstream>
#include <map>

using namespace std;

string keccak256(const string str) {
    keccak::sha3_256 hash;
    hash.update(str.c_str(), str.size());
    return hash.digest();
}

struct address {
    string street;
    string city;
    string state;
    string zip;
};

class Block {
public:
    std::string hash;
    std::string prevHash;
    int index;
    long long timestamp;
    std::string data;
    std::string signer;

    Block(std::string prevHash, int index, long long timestamp, std::string data, std::string signer) {
        this->prevHash = prevHash;
        this->index = index;
        this->timestamp = timestamp;
        this->data = data;
        this->signer = signer;
        this->hash = calculateHash();
    }

    std::string calculateHash() {
        std::string hashData = prevHash + std::to_string(index) + std::to_string(timestamp) + data + signer;
        std::string hash = keccak256(hashData);
        return hash;
    }

    void setTimestamp() {
        // Use current time and a random number to set the timestamp
        auto now = chrono::system_clock::now();
        auto now_ms = chrono::time_point_cast<chrono::milliseconds>(now);
        auto epoch = now_ms.time_since_epoch();
        auto rand_num = rand();
        long long rand_ms = static_cast<long long>(rand_num) % 1000;
        timestamp = static_cast<long long>(epoch.count()) + rand_ms;
    }
};

class SmartContract {
public:
    virtual bool execute(Block& block) = 0;
    virtual ~SmartContract() {}
};

class PaymentContract : public SmartContract {
public:
    struct Payment {
        address recipient;
        uint amount;
    };

    PaymentContract() {}

    void addPayment(address recipient, uint amount) {
        // check if the address is valid before adding it to the list of payments
        if (isAddressValid(recipient)) {
            payments.push_back({recipient, amount});
        }
    }

    void executePayments() {
        for (Payment payment : payments) {
            // execute payment
            std::cout << "Pay " << payment.amount << " to " << payment.recipient.street << ", " << payment.recipient.city << ", " << payment.recipient.state << " " << payment.recipient.zip << "\n";
        }
    }

    bool execute(Block& block) override {
        executePayments();
        return true;
    }

private:
    vector<Payment> payments;

    bool isAddressValid(address recipient) {
        // implement address validation logic here
        return true;
    }
};

class PoA_Blockchain {
private:
    std::vector<Block> chain;
    int difficulty;
    std::string genesisHash;
    int blockCapacity;
    std::vector<std::string> authorizedSigners;
    std::vector<SmartContract*> contracts;
    std::unordered_set<std::string> validators;
    std::string currentValidator;
    std::map<std::string, std::vector<Block*>> signerToBlocks;
    std::mutex chainMutex; // Mutex to ensure thread safety when modifying the blockchain

public:
PoA_Blockchain(int difficulty, int blockCapacity, std::vectorstd::string authorizedSigners) {
this->difficulty = difficulty;
this->blockCapacity = blockCapacity;
genesisHash = "0000000000000000000000000000000000000000000000000000000000000000";
chain.emplace_back(genesisHash, 0, time(0), "Genesis Block", "Admin");
this->authorizedSigners = authorizedSigners;
this->validators.insert(authorizedSigners.begin(), authorizedSigners.end());
currentValidator = *validators.begin();
}

Block get(int index) {
    std::lock_guard<std::mutex> lock(chainMutex);
    if (index < chain.size()) {
        return chain[index];
    }
    throw std::out_of_range("Block index out of range");
}

std::vector<std::string> getAuthorizedSigners() {
    std::lock_guard<std::mutex> lock(chainMutex);
    return authorizedSigners;
}

bool addBlock(Block block) {
    std::lock_guard<std::mutex> lock(chainMutex);
    if (isValidBlock(block) && chain.size() < blockCapacity) {
        for (SmartContract* contract : contracts) {
            if (!contract->execute(block)) {
                std::cerr << "Block rejected by contract\n";
                return false;
            }
        }
        chain.push_back(block);
        signerToBlocks[block.signer].push_back(&chain.back());
        return true;
    }
    return false;
}

bool isValidBlock(Block block) {
    std::lock_guard<std::mutex> lock(chainMutex);
    if (block.index != chain.size()) {
        return false;
    }
    if (block.prevHash != getLastBlock().hash) {
        return false;
    }
    if (!isAuthorized(block.signer)) {
        return false;
    }
    if (block.calculateHash().substr(0, difficulty) != std::string(difficulty, '0')) {
        return false;
    }
    if (getSigners(block).size() < authorizedSigners.size()) {
        return false;
    }
    return true;
}

bool isAuthorized(std::string signer) {
    std::lock_guard<std::mutex> lock(chainMutex);
    return authorizedSigners.count(signer) > 0;
}

Block getLastBlock() {
    std::lock_guard<std::mutex> lock(chainMutex);
    return chain.back();
}

std::vector<std::string> getSigners(Block block) {
    std::vector<std::string> signers;
    for (int i = 0; i < block.data.size(); i++) {
        if (isAuthorized(block.data[i].signer) && find(signers.begin(), signers.end(), block.data[i].signer) == signers.end()) {
            signers.push_back(block.data[i].signer);
        }
    }
    return signers;
}

bool isValidChain() {
    std::lock_guard<std::mutex> lock(chainMutex);
    for (int i = 1; i < chain.size(); i++) {
        if (!isValidBlock(chain[i])) {
            return false;
        }
        if (getSigners(chain[i]).size() < authorizedSigners.size()) {
            return false;
        }
    }
    return true;
}

void addAuthority(const std::string& signer) {
    std::lock_guard<std::mutex> lock(chainMutex);
    authorizedSigners.insert(signer);
    validators.insert(signer);
}

void removeAuthority(const std::string& signer) {
    std::lock_guard<std::mutex> lock(chainMutex);
    authorizedSigners.erase(signer);
    validators.erase(signer);
    signerToBlocks.erase(signer);
}

void addContract(SmartContract* contract) {
    std::lock_guard<std::mutex> lock(chainMutex);
    contracts.push_back(contract);
}


bool isValidBlock(const Block& block) {
    std::lock_guard<std::mutex> lock(chainMutex);
    if (block.index != chain.size()) {
        return false;
    }
    if (block.prevHash != getLastBlock().hash) {
        return false;
    }
    if (!isAuthorized(block.signer)) {
        return false;
    }
    if (block.calculateHash().substr(0, difficulty) != std::string(difficulty, '0')) {
        return false;
    }
    if (getSigners(block).size() < authorizedSigners.size()) {
        return false;
    }
    return true;
}

bool setValidator(const std::string& validator) {
    std::lock_guard<std::mutex> lock(chainMutex);
    if (validators.find(validator) == validators.end()) {
        return false;
    }
    currentValidator = validator;
    return true;
}

bool executePayments() {
    std::lock_guard<std::mutex> lock(chainMutex);
    if (!isAuthorized(currentValidator)) {
        std::cerr << "Current validator is not authorized to execute payments\n";
        return false;
    }
    if (!paymentContract.execute(getLastBlock())) {
        std::cerr << "Payment execution failed\n";
        return false;
    }
    return true;
}


bool isValidAddress(const address& recipient) {
    // implement address validation logic here
    return true;
}

void addPayment(const address& recipient, uint amount) {
    std::lock_guard<std::mutex> lock(chainMutex);
    if (amount <= 0) {
        std::cerr << "Payment amount must be greater than zero\n";
        return;
    }
    if (isValidAddress(recipient)) {
        PaymentContract::Payment payment = {recipient, amount};
        paymentContract.addPayment(payment);
    } else {
        std::cerr << "Invalid address\n";
    }
}
int main() {
    srand(time(NULL)); // Seed the random number generator with the current time
    std::vector<std::string> authorizedSigners = {"Alice", "Bob", "Charlie"};
    PoA_Blockchain blockchain(4, 10, authorizedSigners);
    Block block("0000000000000000000000000000000000000000000000000000000000000000", 0, 0, "Genesis Block", "Admin");
    block.setTimestamp();
    std::cout << "Block timestamp: " << block.timestamp << std::endl;
    PaymentContract paymentContract;
    paymentContract.addPayment({"123 Main St", "Anytown", "CA", "12345"}, 100);
    SmartContract* contract = &paymentContract;
    blockchain.addContract(contract);

    // Add test data
    address recipient1 = {"456 Oak St", "Anycity", "NY", "67890"};
    address recipient2 = {"789 Maple Ave", "Anyville", "TX", "54321"};
    address recipient3 = {"321 Pine St", "Anystate", "FL", "98765"};
    blockchain.addPayment(recipient1, 200);
    blockchain.addPayment(recipient2, 300);
    blockchain.addPayment(recipient3, 400);

    // Execute payments
    blockchain.executePayments();

    std::cout << "Blockchain is valid: " << std::boolalpha << blockchain.isValidChain() << std::endl;

    return 0;
}


