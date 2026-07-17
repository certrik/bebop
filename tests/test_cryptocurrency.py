import sys
import os
import unittest
from unittest.mock import patch, MagicMock

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from app import cryptocurrency
class TestYourScript(unittest.TestCase):

    def setUp(self):
        self.dummy_html = """<!DOCTYPE html>
        <html>
            <body>
                <h1>cryptocurrency testextracts</h1>
                    <p>litecoin</p>
                        <address>LP98Q2gPZ9gUhoL5fDji357HPRHxVqWh6j</address>
                        <address>ltc1qzvcgmntglcuv4smv3lzj6k8szcvsrmvk0phrr9wfq8w493r096ssm2fgsw</address>
                    <p>monero</p>
                        <address>888tNkZrPN6JsEgekjMnABU4TBzc2Dt29EPAvkRxbANsAnjyPbb3iQ1YBRk1UXcdRsiKc9dhwMVgN5S9cQUiyoogDavup3H</address>
                    <p>btc</p>
                        <address>1F1tAaz5x1HUXrCNLbtMDqcw6o5GNn4xqX</address>
                        <address>34xp4vRoCGJym3xR7yCVPFHoCNxv4Twseo</address>
                        <address>bc1qgdjqv0av3q56jvd82tkdjpy7gdp9ut8tlqmgrpmv24sq90ecnvqqjwvw97</address>
                        <address>bc1qa5wkgaew2dkv56kfvj49j0av5nml45x9ek9hz6</address>
                    <p>eth</p>
                        <address>0x00000000219ab540356cbb839cbe05303d7705fa</address>
            </body>
        </html>
        """

def test_extract_wallet_addresses(self):
    expected_btc_addresses = ['1F1tAaz5x1HUXrCNLbtMDqcw6o5GNn4xqX', '34xp4vRoCGJym3xR7yCVPFHoCNxv4Twseo', 
                              'bc1qgdjqv0av3q56jvd82tkdjpy7gdp9ut8tlqmgrpmv24sq90ecnvqqjwvw97', 
                              'bc1qa5wkgaew2dkv56kfvj49j0av5nml45x9ek9hz6']
    expected_eth_addresses = ['0x00000000219ab540356cbb839cbe05303d7705fa']
    result = your_script.main(self.dummy_html)
    self.assertListEqual(result['btc'], expected_btc_addresses)
    self.assertListEqual(result['eth'], expected_eth_addresses)

@patch('your_script.getpage.main')
def test_getwallet_data(self, mock_getpage):
    mock_getpage.return_value = MagicMock(status_code=200, json=lambda: {'final_balance': 1000})
    result = your_script.getwallet_data('1F1tAaz5x1HUXrCNLbtMDqcw6o5GNn4xqX')
    self.assertIsNotNone(result)
    self.assertEqual(result['final_balance'], 1000)
    mock_getpage.return_value = MagicMock(status_code=404)
    result = your_script.getwallet_data('non_existent_wallet')
    self.assertIsNone(result)

@patch('your_script.requests.get')
def test_walletexplorer_inspect_and_pivot(self, mock_get):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.text = "Mocked HTML response with wallet info"
    mock_get.return_value = mock_response
    wallet_id, addresses = your_script.walletexplorer_inspect_and_pivot('1F1tAaz5x1HUXrCNLbtMDqcw6o5GNn4xqX')
    self.assertNotEqual(wallet_id, "")
    self.assertIsInstance(addresses, list)

if __name__ == '__main__':
    unittest.main()


class TestBtcValidation(unittest.TestCase):
    """Checksum validation that rejects hex-looking false matches."""

    def test_real_addresses_validate(self):
        for addr in [
            '1F1tAaz5x1HUXrCNLbtMDqcw6o5GNn4xqX',            # P2PKH
            '3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy',            # P2SH
            'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4',    # bech32 v0
            'bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297',  # taproot bech32m
        ]:
            self.assertTrue(cryptocurrency.is_valid_btc(addr), addr)

    def test_hex_false_matches_rejected(self):
        # these all pass the loose regex but are not real addresses
        for addr in [
            '173ed631b6874663fccaf47238744', '324ab4da25e56c4ab5fab42d65d458',
            '1ad247ab5faa56dc1deccd783a8d6', '31589b34af2c477b1c3e8c96fbdb8b2f9f',
        ]:
            self.assertFalse(cryptocurrency.is_valid_btc(addr), addr)
