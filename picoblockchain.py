# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
import random
import hashlib
import threading
import sys
import readline
import simplejson as json
import math
from collections import namedtuple
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS
from twisted.internet import reactor, protocol
from twisted.protocols import basic


DIFFICULTY = 16


def blocktuple(typename, field_names):
    class typename(namedtuple(typename, field_names)):
        def serialize(self):
            return json.dumps(self._asdict(), sort_keys=True)

        def hash(self):
            return hashlib.sha256(self.serialize().encode()).digest().hex()
    return typename


TxPart = blocktuple('TxPart', ['amount', 'address'])
Outpoint = blocktuple('Outpoint', ['tx_hash', 'outs_index'])
BlockHeader = blocktuple('BlockHeader', ['merkle_root', 'previous', 'nonce'])


# ins = Outpoint, outs = TxPart
class Transaction(blocktuple('Transaction', ['ins', 'outs'])):
    def sign(self, private_key, public_key):
        return PKCS1_PSS.new(RSA.importKey(private_key)).sign(
                SHA256.new(self.serialize().encode()))


class Payment(blocktuple('Payment', ['transaction', 'public_key',
                                     'signature'])):
    def verify(self):
        return PKCS1_PSS.new(RSA.importKey(
            bytes.fromhex(self.public_key))).verify(SHA256.new(
                self.transaction.serialize().encode()),
                bytes.fromhex(self.signature))


# Transactions: start with coinbase (1st), then all others.
class Block(blocktuple('Block', ['header', 'transactions'])):
    def hash(self):
        # Use the header hash
        return self.header.hash()


class UTXO(dict):
    def __delitem__(self, item):
        self.pop(item, None)

    def add_block(self, block):
        for transaction in block.transactions:
            for i, output in enumerate(transaction.outs):
                self[Outpoint(transaction.hash(), i)] = output
        for transaction in block.transactions:
            for outpoint in transaction.ins:
                del self[outpoint]


class WalletUTXO(UTXO):
    def __init__(self, address):
        super().__init__()
        self.address = address

    def __setitem__(self, outpoint, tx_part):
        # Ignore outpoints that were not for my address
        if tx_part.address == self.address:
            super().__setitem__(outpoint, tx_part)

    def balance(self):
        return sum(tx_part.amount for tx_part in self.values())

    def find_to_spend(self, amount):
        spending = []
        total = 0
        for outpoint, tx_part in self.items():
            if total >= amount:
                break
            spending.append(outpoint)
            total += tx_part.amount
        return spending, total - amount

    def spend(self, outpoints):
        for outpoint in outpoints:
            del self[outpoint]


class BlockTree(dict):
    GENESIS = Block(BlockHeader('0'*64, '0'*64, 0), [])

    def __init__(self):
        super().__init__()
        # Header Hash -> Block
        self[self.GENESIS.hash()] = self.GENESIS

    def add(self, block):
        self[block.hash()] = block

    def __contains__(self, key):
        return key.hash() in self.keys()

    # Length from block to GENESIS, or None if no path exists (then block is
    # invalid)
    def chainlength(self, block):
        # TODO: maybe only verify until known depth
        return sum(1 for _ in self.chain(block))

    def chain(self, block):
        current = block
        while current != self.GENESIS:
            yield current
            try:
                current = self[current.header.previous]
            except KeyError:
                return None
        yield self.GENESIS

    def build_utxo(self, active_block):
        new_utxo = UTXO()
        for block in reversed(list(self.chain(active_block))):
            new_utxo.add_block(block)
        return new_utxo


class Event:
    def __init__(self):
        self.handlers = []

    def __call__(self, *args, **kwargs):
        for handler in self.handlers:
            handler(*args, **kwargs)

    def __iadd__(self, handler):
        self.handlers.append(handler)
        return self


class Node:
    def __init__(self):
        self.log = Event()

        # Events for unverified objects
        self.new_payment = Event()
        self.new_payment += self._handle_payment
        self.new_block = Event()
        self.new_block += self._handle_block

        # Events for verified objects
        self.payment = Event()
        self.block = Event()
        self.transaction = Event()
        self.reorganization = Event()

        self.utxo = UTXO()

        self.block_tree = BlockTree()
        # Currently active chain
        self.active_block = self.block_tree.GENESIS

        self.pending_transactions = set()

    def recalculate_utxo(self):
        self._reorganize(self.active_block)

    def valid_block(self, block):
        # Verify that there is a path to Genesis
        if self.block_tree.chainlength(block) is None:
            self.log('Block rejected: no path to genesis')
            return False
        # Verify proof of work
        if not self._valid_block_difficulty(block, DIFFICULTY):
            self.log('Block rejected due to insufficient work')
            return False
        # Verify coinbase transaction
        if not self._valid_block_coinbase(block):
            self.log('Block rejected due to invalid coinbase transaction')
            return False
        # Verify all transactions
        if not self._valid_block_transactions(block):
            self.log('Block rejected due to one or more invalid' +
                     'transactions')
            return False
        return True

    def valid_payment(self, payment):
        transaction = payment.transaction
        # Verify signature is from public key
        if not payment.verify():
            self.log('Rejected payment due to incorrect signature')
            return False
        # Verify spending own money
        for outpoint in transaction.ins:
            input_ = self.utxo[outpoint]
            if input_.address != hashlib.sha256(
                    bytes.fromhex(payment.public_key)).hexdigest():
                self.log('Rejected payment because money spent is not from' +
                         ' signer')
                return False
        # Transaction validation rules
        if not self.valid_transaction(transaction):
            self.log('Rejected payment because transaction was invalid')
            return False
        return True

    def valid_transaction(self, transaction):
        # Verify money is unspent
        for outpoint in transaction.ins:
            if outpoint not in self.utxo:
                self.log('Rejected payment because money was already spent')
                return False
        # Verify tx in >= tx out
        in_ = sum(self.utxo[outpoint].amount for outpoint in transaction.ins)
        out = sum(x.amount for x in transaction.outs)
        if in_ < out:
            self.log('Rejected payment because in < out. in', in_, 'out',
                     out)
            return False
        return True

    def _handle_block(self, block):
        if block in self.block_tree:
            # Already added. Do not add again.
            return
        if not self.valid_block(block):
            self.log('Invalid block', block.hash(),
                     'received. Rejected.')
            return

        # Add to the block tree
        self.block_tree.add(block)

        # Events
        self.block(block)

        self.log('Added block', block.hash(), block)

        if block.header.previous == self.active_block.hash():
            # Block is next in the active chain. Easy.
            self.active_block = block
            # Own handling
            self.utxo.add_block(block)
        elif self.block_tree.chainlength(block) > \
                self.block_tree.chainlength(self.active_block):
            # Block is in a longer chain. Reorganize.
            self._reorganize(self.active_block)
        else:
            # Block is not in longest chain. Abort.
            return

        # Transactions are not pending anymore
        self.pending_transactions -= set(block.transactions)

    def _handle_payment(self, payment):
        if payment.transaction in self.pending_transactions:
            # Already added. Do not add again.
            return
        if not self.valid_payment(payment):
            self.log('Invalid payment with transaction',
                     payment.transaction.hash(), 'received. Rejected.')
            return

        self.log('Received payment with transaction',
                 payment.transaction.hash())

        transaction = payment.transaction

        self.pending_transactions |= {transaction}

        # Events
        self.payment(payment)
        self.transaction(transaction)

    def _reorganize(self, new_block):
        self.utxo = self.block_tree.build_utxo(new_block)
        self.active_block = new_block

        # Events
        self.reorganization(self.utxo)

    def _valid_block_difficulty(self, block, difficulty):
        return bin(int(block.hash(), 16))[2:].zfill(256)[0:difficulty] \
                == '0'*difficulty

    def _valid_block_coinbase(self, block):
        coinbase = block.transactions[0]
        other_transactions = block.transactions[1:]
        # Balance = Total coins spent in transaction
        balance = sum(self._transaction_balance(tx)
                      for tx in other_transactions)
        # Exactly 1 "new money" allowed
        return balance + coinbase.outs[0].amount == 1

    def _valid_block_transactions(self, block):
        for transaction in block.transactions[1:]:
            if not self.valid_transaction(transaction):
                return False
        return True

    def _transaction_balance(self, transaction):
        return sum(out.amount for out in transaction.outs) - \
                sum(self.utxo[outpoint].amount for outpoint in transaction.ins)


class WalletMixIn:
    def __init__(self):
        self.block += self._handle_block_wallet
        self.reorganization += self._handle_reorganization_wallet
        self.transaction += self._handle_transaction_wallet

        # Create keys
        key = RSA.generate(2048)
        self.private_key = key.exportKey()
        self.public_key = key.publickey().exportKey()
        self.address = hashlib.sha256(self.public_key).hexdigest()

        self.my_utxo = WalletUTXO(self.address)

    def balance(self):
        return self.my_utxo.balance()

    def send(self, amount, to_address):
        # Make the transaction
        # Unspent outpoints to spend
        spending, change = self.my_utxo.find_to_spend(amount)
        outs = [TxPart(amount, to_address)]
        if change > 0:
            # Give change back to self
            outs.append(TxPart(change, self.address))

        transaction = Transaction(tuple(spending), tuple(outs))
        # Create the payment
        signature = transaction.sign(self.private_key, self.public_key)
        payment = Payment(transaction, self.public_key.hex(), signature.hex())

        # Event
        self.new_payment(payment)

    def _handle_transaction_wallet(self, transaction):
        self.my_utxo.spend(transaction.ins)

    def _handle_block_wallet(self, block):
        self.my_utxo.add_block(block)

    def _handle_reorganization_wallet(self, utxo):
        new_utxo = WalletUTXO(self.address)
        for outpoint, output in utxo.items():
            new_utxo[outpoint] = output
        self.my_utxo = new_utxo


class MinerMixIn:
    def __init__(self, to_address):
        self.to_address = to_address

    def start_miner(self):
        miner_thread = threading.Thread(target=self._miner)
        miner_thread.daemon = True
        miner_thread.start()

    def _miner(self):
        while True:
            # All pending transactions + constant fee
            normal_transactions_set = self.pending_transactions.copy()
            normal_transactions = list(normal_transactions_set)
            # TODO: Miner fees
            # The coinbase transaction + the normal transactions
            block_transactions = [Transaction((Outpoint(
                hex(random.getrandbits(256))[2:], 0),),
                (TxPart(1, self.to_address),)
                )] + normal_transactions
            merkle_root = MinerMixIn._merkle_root(block_transactions)

            active_block_hash = self.active_block.hash()
            block_header = BlockHeader(merkle_root,
                                       self.active_block.hash(),
                                       None)
            while normal_transactions_set == self.pending_transactions and \
                    active_block_hash == self.active_block.hash():
                # TODO: self-adjusting difficulty
                block_header = MinerMixIn._find_nonce(block_header, DIFFICULTY)
                if block_header.nonce is not None:
                    block = Block(block_header, tuple(block_transactions))
                    self.new_block(block)

    @staticmethod
    def _merkle_root(transactions):
        def tuple_hash(x, y):
            h = hashlib.sha256()
            h.update(x)
            h.update(y)
            return h.digest()
        # Pad list until power of two
        leaf_transactions = transactions + \
            [transactions[-1]] * \
            (2**math.ceil(math.log(len(transactions), 2)) -
                len(transactions))
        merkle_leafs = list(map(lambda tx: bytes.fromhex(tx.hash()),
                                leaf_transactions))
        while len(merkle_leafs) != 1:
            merkle_leafs = list(map(lambda txs: tuple_hash(*txs),
                                    zip(merkle_leafs[::2],
                                        merkle_leafs[1::2])))
        return merkle_leafs[0].hex()

    @staticmethod
    def _find_nonce(block_header, difficulty):
        nonce = random.getrandbits(32)
        new_block_header = block_header._replace(nonce=nonce)
        found_hash = bin(int(new_block_header.hash(), 16))[2:].zfill(256)
        if found_hash[0:difficulty] == '0'*difficulty:
            return new_block_header
        return block_header


class NetworkingMixIn:
    class Message(namedtuple('Message', ['type', 'payload'])):
        def serialize(self):
            return json.dumps(self, sort_keys=True)

    class PubProtocol(basic.LineReceiver):
        def __init__(self, factory):
            self.factory = factory

        def connectionMade(self):
            self.factory.clients.add(self)
            self.factory.new_peer_handler(self)

        def connectionLost(self, reason):
            self.factory.clients.remove(self)

        def lineReceived(self, line):
            self.factory.line_handler(line)

    class PubFactory(protocol.ClientFactory):
        def __init__(self, line_handler, new_peer_handler):
            self.clients = set()
            # Base on handler instead of storing received here
            self.received = set()
            self.line_handler = line_handler
            self.new_peer_handler = new_peer_handler

        def buildProtocol(self, addr):
            return NetworkingMixIn.PubProtocol(self)

    def __init__(self):
        self.factory = NetworkingMixIn.PubFactory(self._handle_line,
                                                  self._handle_new_peer)
        self.block += self._handle_block_networker
        self.payment += self._handle_payment_networker

    def start_networking(self, port, peers):
        networker_thread = threading.Thread(target=self._start_networking,
                                            args=(port, peers))
        networker_thread.daemon = True
        networker_thread.start()

    def _start_networking(self, port, peers):
        reactor.listenTCP(port, self.factory)
        for addr, port in peers:
            reactor.connectTCP(addr, port, self.factory)
        reactor.run(installSignalHandlers=False)

    def _handle_block_networker(self, block):
        msg = NetworkingMixIn.Message('block', block).serialize()
        for client in self.factory.clients:
            client.sendLine(msg.encode())

    def _handle_payment_networker(self, payment):
        msg = NetworkingMixIn.Message('payment', payment).serialize()
        for client in self.factory.clients:
            client.sendLine(msg.encode())

    def _handle_line(self, msg):
        def to_object(dct):
            # Convert lists to tuples
            for k, v in dct.items():
                if type(v) == list:
                    dct[k] = tuple(v)
            types = [NetworkingMixIn.Message, TxPart, Outpoint, Transaction,
                     Payment, BlockHeader, Block]
            for type_ in types:
                try:
                    return type_(**dct)
                except TypeError:
                    pass
        msg = json.loads(msg.decode(), object_hook=to_object)
        if msg.type == 'block':
            self.new_block(msg.payload)
        elif msg.type == 'payment':
            self.new_payment(msg.payload)
        elif msg.type == 'blocks':
            self._add_blocks(msg.payload)

    def _handle_new_peer(self, peer):
        # Send new peer all the blocks I know of
        msg = NetworkingMixIn.Message(
            'blocks', tuple(self.block_tree.values())).serialize()
        peer.sendLine(msg.encode())

    def _add_blocks(self, blocks):
        # Add all blocks in BFS order
        blockset = set(filter(lambda block: block.header.previous ==
                              self.block_tree.GENESIS.hash(), blocks))
        while blockset:
            added_hashes = set()
            for block in blockset:
                self.new_block(block)
                added_hashes.add(block.hash())
            blockset = set(filter(lambda block: block.header.previous
                                  in added_hashes, blocks))


if __name__ == '__main__':
    def safe_print(*args):
        print()
        print(*args)
        sys.stdout.write('> ' + readline.get_line_buffer())
        sys.stdout.flush()

    class Peer(Node, WalletMixIn, MinerMixIn, NetworkingMixIn):
        def __init__(self):
            Node.__init__(self)
            WalletMixIn.__init__(self)
            MinerMixIn.__init__(self, self.address)
            NetworkingMixIn.__init__(self)
    peer = Peer()
    peer.log += safe_print
    print('Wallet setup. Address ', peer.address)
    peer.start_miner()
    print('Miner started.')
    other_peers = list(map(lambda l: (l[0], int(l[1])),
                           (a.split(':') for a in sys.argv[2:])))
    peer.start_networking(int(sys.argv[1]), other_peers)
    # Prompt
    while True:
        command = input('> ').split(' ')
        if command[0] == 'send':
            peer.send(int(command[1]), command[2])
        elif command[0] == 'address':
            print(peer.address)
        elif command[0] == 'balance':
            print(peer.balance())
        elif command[0] == 'reorg':
            peer.recalculate_utxo()
        elif command[0] == 'quit':
            sys.exit(0)
