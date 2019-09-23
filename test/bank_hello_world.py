from CipherUtil import loadCertFromFile
from BankCore import LedgerLineStorage, LedgerLine
from OnlineBank import BankClientProtocol, OnlineBankConfig
import asyncio

bankconfig = OnlineBankConfig()
bank_addr =     bankconfig.get_parameter("CLIENT", "bank_addr")
bank_port = int(bankconfig.get_parameter("CLIENT", "bank_port"))
bank_stack     =     bankconfig.get_parameter("CLIENT", "stack","default")
bank_username  =     self._bankconfig.get_parameter("CLIENT", "username")

certPath = os.path.join(bankconfig.path(), "bank.cert")
bank_cert = loadCertFromFile(certPath)


async def example_transfer(username, password, src, dst, amount, memo):
    transport, bank_client = await playground.create_connection(
            lambda: BankClientProtocol(bank_cert, username, password),
            bank_addr,
            bank_port,
            family='default'
        )
    print("Connected. Logging in.")
        
    try:
        await bank_client.loginToServer()
    except Exception as e:
        print("Login error. {}".format(e))
        return False

    try:
        await bank_client.switchAccount(switchToAccount)
    except Exception as e:
        print("Could not set source account as {} because {}".format(
            src,
            e))
        return False
    
    try:
        result = await bank_client.transfer(dst, amount, memo)
    except Exception as e:
        print("Could not transfer because {}".format(e))
        return False
        
    return result
    
def example_verify(receipt_bytes, signature_bytes, dst, amount, memo):
    if not self.__bankClient.verify(receiptBytes, sigBytes):
        raise Exception("Bad receipt. Not correctly signed by bank")
    ledger_line = LedgerLineStorage.deserialize(receipt_bytes)
    if ledger_line.getTransactionAmount(dst) != amount:
        raise Exception("Invalid amount. Expected {} got {}".format(amount, ledger_line.getTransactionAmount(dst)))
    elif ledger_line.memo() != memo:
        raise Exception("Invalid memo. Expected {} got {}".format(memo, ledger_line.memo()))
    return True
    
if __name__=="__main__":
    src, dst, amount, memo = sys.argv[1:5]
    username = bank_username # could override at the command line
    password = input("Enter password for {}: ".format(username))
    loop = asyncio.get_event_loop()
    result = loop.run_until_complete(
        example_transfer(username, password, src, dst, amount, memo))
    example_verify(result.Receipt, result.ReceiptSignature, dst, amount, memo)
    print("Receipt verified.")