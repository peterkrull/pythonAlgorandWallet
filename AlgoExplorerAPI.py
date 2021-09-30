import algosdk

# AlgoExplorer API compatability class
class node:

    # 'requests' library to interact with API
    req = __import__('requests')

    # class constructor, sets base url to chosen net type
    def __init__(self,net = "mainnet"):
        self.net = net.lower()
        if net.lower() == "mainnet":
            self.base_url = "https://algoexplorerapi.io/"
        elif net.lower() == "testnet":
            self.base_url = "https://testnet.algoexplorerapi.io/"
        elif net.lower() == "betanet":
            self.base_url = "https://betanet.algoexplorerapi.io/"
        else:
            print("Invalid net type : " + str(net) + " ; defaulting to testnet.")
            self.base_url = "https://testnet.algoexplorerapi.io/"
            self.net = "testnet"
    
    # returns relevant explorer URL
    def explorer(self):
        if self.net == "mainnet":
            return "https://algoexplorer.io/"
        elif self.net == "testnet":
            return "https://testnet.algoexplorer.io/"
        elif self.net == "betanet":
            return "https://betanet.algoexplorer.io/"

    # Returns true if the API is healthy    
    def health(self):
        temp_url = self.base_url + str("health")
        return self.req.get(temp_url).ok

    # Gets parameters for new transactions
    def suggested_params(self):
        temp_url = self.base_url + str("v2/transactions/params")
        response = self.req.get(temp_url)
        
        if response.ok:
            import ast
            raw =  ast.literal_eval(bytes.decode(response.content))
            return {
                "first":raw["last-round"],
                "last":raw["last-round"]+1000,
                "gh":raw["genesis-hash"],
                "gen":raw["genesis-id"],
                "fee":raw["fee"],
                "flat_fee":False,
                "consensus_version":raw["consensus-version"],
                "min_fee":raw["min-fee"]
            }
        else:
            raise Exception("Can't connect to API. URL might be incorrect.")

    # Gets the info related to a public address
    def account_info(self,public_addr):
        temp_url = self.base_url + str("v2/accounts/" + str(public_addr))
        response = self.req.get(temp_url)
        if response.ok:
            import ast
            return ast.literal_eval(bytes.decode(response.content))
        else:
            raise Exception("API call failed :{}".format(response.content))
    
    # make post transaction to the blockchain using API
    def send_transaction(self,signed_txn):
        import base64
        # Turn a Algorand MSGpack into a binary that is compatible with the API
        signed_txn = base64.b64decode(algosdk.encoding.msgpack_encode(signed_txn))
        return self.req.post(self.base_url + "v2/transactions",signed_txn)
