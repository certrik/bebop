import sys
import os
import unittest
from unittest.mock import patch, MagicMock

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from app import cryptocurrency


class TestWalletExtraction(unittest.TestCase):

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

    # patch getwallet_data so main() doesn't hit blockcypher during extraction
    @patch('app.cryptocurrency.getwallet_data')
    def test_extract_wallet_addresses(self, _mock_balance):
        expected_btc = {
            '1F1tAaz5x1HUXrCNLbtMDqcw6o5GNn4xqX',
            '34xp4vRoCGJym3xR7yCVPFHoCNxv4Twseo',
            'bc1qgdjqv0av3q56jvd82tkdjpy7gdp9ut8tlqmgrpmv24sq90ecnvqqjwvw97',
            'bc1qa5wkgaew2dkv56kfvj49j0av5nml45x9ek9hz6',
        }
        expected_eth = {'0x00000000219ab540356cbb839cbe05303d7705fa'}
        result = cryptocurrency.main(self.dummy_html)
        self.assertEqual(set(result['btc']), expected_btc)
        self.assertEqual(set(result['eth']), expected_eth)

    @patch('app.cryptocurrency.requests.get')
    def test_getwallet_data(self, mock_get):
        mock_get.return_value = MagicMock(status_code=200,
                                          json=lambda: {'final_balance': 1000})
        result = cryptocurrency.getwallet_data('1F1tAaz5x1HUXrCNLbtMDqcw6o5GNn4xqX')
        self.assertIsNotNone(result)
        self.assertEqual(result['final_balance'], 1000)

        mock_get.return_value = MagicMock(status_code=404)
        self.assertIsNone(cryptocurrency.getwallet_data('non_existent_wallet'))

    @patch('app.cryptocurrency.requests.get')
    def test_walletexplorer_inspect_and_pivot(self, mock_get):
        addr = '1F1tAaz5x1HUXrCNLbtMDqcw6o5GNn4xqX'
        page1 = MagicMock(status_code=200,
                          text='<div class="walletnote"><a href="/wallet/W1">w</a></div>')
        page2 = MagicMock(status_code=200, text=(
            '<table><tr><th>addr</th></tr>'
            '<tr><td><a href="/address/AAA">AAA</a></td></tr>'
            f'<tr><td><a href="/address/{addr}">self</a></td></tr></table>'))
        mock_get.side_effect = [page1, page2]

        wallet_id, addresses = cryptocurrency.walletexplorer_inspect_and_pivot(addr)
        self.assertEqual(wallet_id[2], 'W1')
        self.assertIn('AAA', addresses)          # pivot address kept
        self.assertNotIn(addr, addresses)        # the queried address itself dropped


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
