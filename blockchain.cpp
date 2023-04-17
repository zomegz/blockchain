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
#include <memory>
#include <mutex>
#include <regex>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

using namespace std;

string keccak256(const string& str) {
    keccak::sha3_256 hash;
    hash.update(str.c_str(), str.size());
    return hash.digest();
}

struct Address {
    string street;
    string city;
    string state;
    string zip;

    bool isValid() const {
        // Implement address validation logic here
        regex street_regex("^[0-9]+\\s+([a-zA-Z]+|[a-zA-Z]+\\s[a-zA-Z]+)$");
        regex city_regex("^[a-zA-Z]+(?:[\\s-][a-zA-Z]+)*$");
        regex state_regex("^[A-Z]{2}$");
        regex zip_regex("^\\d{5}(?:[-\\s]\\d{4})?$");

        return regex_match(street, street_regex) &&
               regex_match(city, city_regex) &&
               regex_match(state, state_regex) &&
               regex_match(zip, zip_regex);
    }
};

class Block {
public:
    string hash;
    string prevHash;
    int index;
    long long timestamp;
    string data;
    string signer;
    string signature;

    Block(const string& prevHash, int index, long long timestamp, const string& data, const string& signer, const string& signature) :
        prevHash(prevHash), index(index), timestamp(timestamp), data(data), signer(signer), signature(signature) {
            this->hash = calculateHash();
    }

    string calculateHash() const {
        string hashData = prevHash + to_string(index) + to_string(timestamp) + data + signer + signature;
        string hash = keccak256(hashData);
        return hash;
    }

    void setTimestamp() {
        // Use current time as the timestamp
        auto now = chrono::system_clock::now();
        auto now_ms = chrono::time_point_cast<chrono::milliseconds>(now);
        auto epoch = now_ms.time_since_epoch();
        timestamp = static_cast<long long>(epoch.count());
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
        Address recipient;
        uint amount;
    };

    PaymentContract() {}

    void addPayment(const Address& recipient, uint amount) {
        // Check if the address is valid before adding it to the list of payments
        if (recipient.isValid() && amount > 0) {
            payments.push_back({recipient, amount});
        }
    }

    void executePayments() {
        for (Payment payment : payments) {
            // Execute payment
            cout << "Pay " << payment.amount << " to " << payment.recipient.street << ", " << payment.recipient.city << ", " << payment.recipient.state << " " << payment.recipient.zip << "\n";
        }
    }

       bool execute(Block& block) override {
        executePayments();
        return true;
    }

private:
    vector<Payment> payments;
};

class PBFT {
public:
    static const int f = 1; // Maximum number of Byzantine failures that the consensus algorithm can tolerate

    bool validate(Block& block, const unordered_set<string>& authorizedSigners) {
        // Check that the block is signed by at least 2f+1 authorized signers
        int numSignatures = 0;
        for (const auto& signer : authorizedSigners) {
            if (block.signer == signer) {
                numSignatures++;
            }
            if (numSignatures >= 2 * f + 1) {
                return true;
            }
        }
        return false;
    }
};

string sign(const string& privateKeyPem, const string& data) {
    BIO* bio = BIO_new_mem_buf(privateKeyPem.c_str(), -1);
    EVP_PKEY* privateKey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, privateKey);

    const unsigned char* dataToSign = reinterpret_cast<const unsigned char*>(data.c_str());
    size_t dataToSignLen = data.size();

    size_t signatureLen;
    EVP_DigestSign(mdctx, NULL, &signatureLen, dataToSign, dataToSignLen);

    unsigned char* signature = new unsigned char[signatureLen];
    EVP_DigestSign(mdctx, signature, &signatureLen, dataToSign, dataToSignLen);

    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(privateKey);

    string result(reinterpret_cast<char*>(signature), signatureLen);
    delete[] signature;

    return result;
}

bool verify(const string& publicKeyPem, const string& data, const string& signature) {
    BIO* bio = BIO_new_mem_buf(publicKeyPem.c_str(), -1);
    EVP_PKEY* publicKey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, publicKey);

    const unsigned char* dataToVerify = reinterpret_cast<const unsigned char*>(data.c_str());
    size_t dataToVerifyLen = data.size();

    const unsigned char* signatureToVerify = reinterpret_cast<const unsigned char*>(signature.c_str());
    size_t signatureToVerifyLen = signature.size();

    int result = EVP_DigestVerify(mdctx, signatureToVerify, signatureToVerifyLen, dataToVerify, dataToVerifyLen);

    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(publicKey);

    return result == 1;
}

class Blockchain {
public:
    Blockchain() {
        // Create genesis block
        Block genesisBlock("0", 0, 0, "Genesis Block", "", "");
        chain.push_back(genesisBlock);
        authorizedSigners.insert("authorized_signer_1_public_key");
        authorizedSigners.insert("authorized_signer_2_public_key");
        authorizedSigners.insert("authorized_signer_3_public_key");
    }

    void addBlock(const string& data, const string& signer, const string& signature) {
        lock_guard<mutex> lock(chainMutex);

        if (authorizedSigners.find(signer) == authorizedSigners.end()) {
            cout << "Unauthorized signer." << endl;
            return;
        }

        Block newBlock(chain.back().hash, chain.size(), 0, data, signer, signature);
        newBlock.setTimestamp();

        // Verify the signature of the block
        string hashData = newBlock.prevHash + to_string(newBlock.index) + to_string(newBlock.timestamp) + newBlock.data + newBlock.signer;
        if (!verify(signer, hashData, signature)) {
            cout << "Invalid signature." << endl;
            return;
        }

        if (pbft.validate(newBlock, authorizedSigners)) {
            chain.push_back(newBlock);
            cout << "Block added: " << newBlock.hash << endl;
        } else {
            cout << "Block not added: Invalid signer." << endl;
        }
    }

    void addSmartContract(unique_ptr<SmartContract> smartContract) {
        lock_guard<mutex> lock(contractMutex);
        smartContracts.push_back(move(smartContract));
    }

    void executeSmartContracts() {
        lock_guard<mutex> lock(contractMutex);

        for (auto& contract : smartContracts) {
            contract->execute(chain.back());
        }
    }

private:
    vector<Block> chain;
    vector<unique_ptr<SmartContract>> smartContracts;
    unordered_set<string> authorizedSigners;
    PBFT pbft;
    mutex chainMutex;
    mutex contractMutex;
};

int main() {
    Blockchain blockchain;
    // Create a payment contract
    auto paymentContract = make_unique<PaymentContract>();
    Address recipient1{"123 Main St", "New York", "NY", "10001"};
    paymentContract->addPayment(recipient1, 100);
    Address recipient2{"456 Broadway", "New York", "NY", "10002"};
    paymentContract->addPayment(recipient2, 200);

    // Add the payment contract to the blockchain
    blockchain.addSmartContract(move(paymentContract));

    // Add a block
    string data = "Block 1";
    string signer = "authorized_signer_1_public_key";
    string privateKey = "authorized_signer_1_private_key";
    string signature = sign(privateKey, data);
    blockchain.addBlock(data, signer, signature);

    // Execute smart contracts
    blockchain.executeSmartContracts();

    return 0;
}

// Test suite for Address validation
void testAddressValidation() {
    // Valid Addresses
    EXPECT_TRUE(isValidAddress("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"));
    EXPECT_TRUE(isValidAddress("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"));
    EXPECT_TRUE(isValidAddress("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"));

    // Invalid Addresses
    EXPECT_FALSE(isValidAddress("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN3"));  // Invalid checksum
    EXPECT_FALSE(isValidAddress("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLz"));  // Invalid checksum
    EXPECT_FALSE(isValidAddress("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdr"));  // Invalid checksum
    EXPECT_FALSE(isValidAddress("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq1"));  // Too long
    EXPECT_FALSE(isValidAddress("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5md"));  // Too short
    EXPECT_FALSE(isValidAddress("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5md0"));  // Invalid witness version
}

int main() {
    testAddressValidation();
    return 0;
}