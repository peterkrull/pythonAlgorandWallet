# Algorand Wallet written in Python (CLI only)

Algorand Wallet written in Python, to allow for signing of transactions and interacting with the Algorand blockchain. This wallet does not contain a graphical user interfaces, but the included functions make it easy to manage an account as well as send various transaction. The aim is to simplify the usage of the Algorand SDK for python, by combining the various methods into a package that allows for higher-level functionality.

The AlgoExplorer API class inherits all methods from the AlgodClient class of the Algorand SDK, meaning `algorandWallet.py` is compatible with regular private nodes when using AlgodClient.

_More functionality will be added in the future._

## Contents

The two files `algorandWallet.py` and `AlgoExplorerAPI.py` provide the functionality you need manage a simple account, encrypt and decrypt priavte keys, add and remove contacts as well as make simple transaction on the blockchain without having to set up and maintain a personal Algorand node.

## Creating a new wallet and adding contacts

```python
import algorandWallet as aw

# Creates wallet object (if file does not already exist)
wallet = aw.algoWallet("algorandWallet")

# Generates an account and encrypts it using a password
wallet.genAccount("primary_account","myPassword1234!")

# OR

# Import account from existing mnemonic or private key and encrypt it
wallet.importAccount("primary_account2","25 words in a row","myPassphrase78")

# Adds a contact and gives it easy to type name
wallet.addContact("Algorand8","APDO5T76FB57LNURPHTLAGLQOHUQZXYHH2ZKR4DPQRKK76FB4IAOBVBXHQ")

# Exports wallet to a file (in this case to "algorandWallet")
wallet.exportWallet()
```

## Using wallet to make transaction
```python
import AlgoExplorerAPI as ae
import algorandWallet as aw

# Opens wallet file if it exists
wallet = aw.algoWallet("algorandWallet")

# Creates a connection to the AlgoExplorer API and get suggested parameters
node = ae.node("mainnet")
params = node.suggested_params()

# Sends 0.1337 Algos to Algorand8 on testnet, and decrypts the wallet for signing
tx = wallet.makeSendAlgoTx("primary_account","Algorand8",0.1337,params,"myPassword1234!")

# Sends transaction and catches transaction ID
txnote = node.send_transaction(tx) # Posts money transfer transaction to blockchain

# Prints link to AlgoExplorer transaction page 
# !!This will only work for the AlgoExplorerAPI node!!
print( node.explorer_tx(txA) ) 
```
## Participating in consensus

```python
import AlgoExplorerAPI as ae
import algorandWallet as aw

# Creates wallet object
wallet = aw.algoWallet("algorandWallet")

# Creates a connection to the AlgoExplorer API
node = ae.node("mainnet")
params = node.suggested_params()

# https://developer.algorand.org/docs/run-a-node/participate/generate_keys/
partkeyinfo = {'!! Your partkey dictionary should go here !!'}

# Registers as online for participation in consensus
tx = wallet.participateConsensus("primary_account",params,partkeyinfo,"myPassword1234!")

# Sends transaction and catches transaction ID
txnote = node.send_transaction(tx) # Posts consensus participation transaction to blockchain

# Prints link to AlgoExplorer transaction page 
# !!This will only work for the AlgoExplorerAPI node!!
print( node.explorer_tx(tx) )
```