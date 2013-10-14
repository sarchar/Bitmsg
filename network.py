from collections import deque
import os
import pickle
import random
import socket
import struct
import sys
import threading
import time
import traceback

from bitcoin import Bitcoin
from transaction import Transaction

class BadCommand(Exception):
    pass

class BitcoinNetwork(threading.Thread):
    PEER_SOURCES = [
        'seed.bitcoin.sipa.be',
        'dnsseed.bluematt.me',
        'dnsseed.bitcoin.dashjr.org',
        'bitseed.xf2.org',
    ]

    # Number of peer addresses to keep, even if they have timeouts that have exceeded
    MINIMUM_PEER_ADDRESS_COUNT = 200

    ADDRESS_FILE = 'addresses.dat'
    DEFAULT_NUM_PEERS = int(sys.argv[sys.argv.index('-numpeers')+1]) if '-numpeers' in sys.argv else 10
    DEFAULT_PORT = 8333
    DEFAULT_USER_AGENT = '/Satoshi:0.7.2/'
    DEFAULT_SEED_ADDR_TIMEOUT = 3*60*60
    DEFAULT_PEER_TIMEOUT = 7*24*60*60
    REQUIRED_PEER_TIME = 1*24*60*60 # We only care about peers who have at least a day left to live
    ADDRESSES_CHECK_TIME = 15*60 # Every 15 minutes..

    MSG_ERROR = 0
    MSG_TX = 1
    MSG_BLOCK = 2

    TRANSACTION_VERSION = 2

    REQUEST_GO      = 1
    REQUEST_WAIT    = 2
    REQUEST_DONT    = 3
    REQUEST_TIMEOUT = 4

    def __init__(self, callbacks, num_peer_goal=DEFAULT_NUM_PEERS, client_version=60002, user_agent=DEFAULT_USER_AGENT):
        threading.Thread.__init__(self)
        self.num_peer_goal = num_peer_goal
        self.client_version = client_version
        self.available_services = 1
        self.user_agent = user_agent
        self.running = False
        self.callbacks = callbacks

    def start(self):
        self.running = True
        threading.Thread.start(self)

    def stop(self):
        self.running = False

    def run(self):
        print("Network thread starting...")
        try:
            self._run()
        except:
            traceback.print_exc()

        for peer in self.peer_connections.values():
            peer.stop()
            peer.join()

        try:
            print("Saving peer addresses...")
            self.save_addresses()
        except:
            traceback.print_exc()

        print("Network thread exiting...")

    def _run(self):
        self.start_time = time.time()

        self.peer_addresses = {}
        self.peer_connections = {}
        self.peer_address_changes_since_last_save = 0
        self.last_addresses_save_time = self.start_time

        self.transaction_request_pool_lock = threading.Lock()
        self.transaction_request_pool = {}

        if not self.load_addresses():
            print("Fetching new addresses...")
            self.fetch_new_addresses()
            self.save_addresses()

        while self.running:
            self.step()
            time.sleep(0.3)

    def step(self):
        now = time.time()

        self.check_for_dead_peer_connections()
        if len(self.peer_connections) < self.num_peer_goal:
            self.try_new_peer()

        if self.peer_address_changes_since_last_save >= 100 or (now - self.last_addresses_save_time) > BitcoinNetwork.ADDRESSES_CHECK_TIME:
            self.filter_timed_out_peers()
            self.save_addresses()
            self.last_addresses_save_time = now

    def filter_timed_out_peers(self):
        if len(self.peer_addresses) <= BitcoinNetwork.MINIMUM_PEER_ADDRESS_COUNT:
            return

        peers = {}
        now = time.time()
        for key in self.peer_addresses:
            peer = self.peer_addresses[key]
            if key in self.peer_connections or peer['timeout'] > now:
                peers[key] = peer

        if len(peers) < BitcoinNetwork.MINIMUM_PEER_ADDRESS_COUNT:
            peers = {}
            for _ in range(BitcoinNetwork.MINIMUM_PEER_ADDRESS_COUNT):
                while True:
                    key = random.choice(list(self.peer_addresses.keys()))
                    if key not in peers:
                        peer = self.peer_addresses.get(key, None)
                        peers[key] = peer
                        break

        self.peer_addresses = peers

    def load_addresses(self):
        addresses_file = os.sep.join([os.getcwd(), "{}".format(BitcoinNetwork.ADDRESS_FILE)])
        try:
            self.peer_addresses = pickle.load(open(addresses_file, "rb"))
            self.filter_timed_out_peers()
            print("Loaded {} peer addresses.".format(len(self.peer_addresses)))
            return True
        except FileNotFoundError:
            pass
        except:
            traceback.print_exc()
        return False

    def save_addresses(self):
        addresses_file = os.sep.join([os.getcwd(), "{}".format(BitcoinNetwork.ADDRESS_FILE)])
        pickle.dump(self.peer_addresses, open(addresses_file, "wb"))
        self.peer_address_changes_since_last_save = 0

    def fetch_new_addresses(self):
        for src in BitcoinNetwork.PEER_SOURCES:
            for _, _, _, _, ipport in socket.getaddrinfo(src, None):
                ip, _ = ipport
                self.add_peer_address(ip + ":{}".format(BitcoinNetwork.DEFAULT_PORT), BitcoinNetwork.DEFAULT_SEED_ADDR_TIMEOUT)

    def add_peer_address(self, address, timeout):
        if address not in self.peer_addresses:
            self.peer_addresses[address] = {'timeout': time.time() + timeout, 'last_connect_time': 0, 'failed_attempts': 0}
            self.peer_address_changes_since_last_save += 1
            return True
        return False

    def discovered_peer_address(self, address, last, services):
        # Truncate last to our clock...
        now = time.time()
        last = min(now, last)
        if (now - last) < BitcoinNetwork.DEFAULT_PEER_TIMEOUT:
            timeLeft = BitcoinNetwork.DEFAULT_PEER_TIMEOUT - (now - last)
            if timeLeft >= BitcoinNetwork.REQUIRED_PEER_TIME:
                self.add_peer_address(address, timeLeft)

    def check_for_dead_peer_connections(self):
        for peer_address in list(self.peer_connections):
            assert peer_address in list(self.peer_addresses)
            if not self.peer_connections[peer_address].is_alive():
                self.peer_connections[peer_address].join()
                dead_peer = self.peer_connections.pop(peer_address)

                if dead_peer.bad_peer:
                    self.peer_addresses[peer_address]['failed_attempts'] += 1

                    if self.peer_addresses[peer_address]['failed_attempts'] >= 20:
                        self.peer_addresses.pop(peer_address)
            else:
                if self.peer_addresses[peer_address]['failed_attempts'] != 0:
                    # Restart counter if we've been connected for a while and the peer looks good
                    if (time.time() - self.peer_connections[peer_address].connection_time) > 5*60:
                        self.peer_addresses[peer_address]['failed_attempts'] = 0

    def try_new_peer(self):
        now = time.time()

        peers = list(self.peer_addresses.keys())
        random.shuffle(peers)

        for address in peers:
            if address in self.peer_connections:
                continue
            if ':' not in address:
                continue
            p = self.peer_addresses[address]

            # Wait between connection attempts
            if (now - p['last_connect_time']) < 10*60:
                continue

            p['last_connect_time'] = now

            peer = BitcoinNetworkPeer(self, address)
            peer.start()

            assert address in list(self.peer_addresses)
            self.peer_connections[address] = peer
            break
        else:
            # We didn't have any addresses to connect to.. wat do?
            print("WARNING! We're out of peers!")

    def will_request_transaction(self, txhash):
        with self.transaction_request_pool_lock:
            if not self.callbacks.will_request_transaction(txhash):
                return BitcoinNetwork.REQUEST_DONT

            if txhash not in self.transaction_request_pool:
                self.transaction_request_pool[txhash] = { "req": False }

            if self.transaction_request_pool[txhash]['req']:
                return BitcoinNetwork.REQUEST_WAIT

            self.transaction_request_pool[txhash]['req'] = True
            self.transaction_request_pool[txhash]['at'] = time.time()
            return BitcoinNetwork.REQUEST_GO

    def transaction_request_abort(self, txhash):
        with self.transaction_request_pool_lock:
            if txhash not in self.transaction_request_pool:
                return
            self.transaction_request_pool.pop(txhash)

    def got_transaction(self, tx):
        txhash = tx.hash()
        with self.transaction_request_pool_lock:
            #print('got tx {}'.format(Bitcoin.bytes_to_hexstring(txhash)))

            if txhash in self.transaction_request_pool:
                self.transaction_request_pool.pop(txhash)

            try:
                self.callbacks.got_transaction(tx)
            except:
                print('error processing transaction:')
                traceback.print_exc()

class BitcoinNetworkPeer(threading.Thread):
    STATE_DEAD = -1
    STATE_INIT = 1
    STATE_CONNECTED = 2
    STATE_READY = 3

    def __init__(self, bitcoin_network, peer_address):
        threading.Thread.__init__(self)
        self.bitcoin_network = bitcoin_network
        self.peer_address    = peer_address
        self.state           = BitcoinNetworkPeer.STATE_DEAD
        self.running         = False
        self.connection_time = 0

        self.COMMAND_TABLE = {}
        for v in dir(self):
            if v.startswith('handle_'):
                name = v[7:].lower()
                self.COMMAND_TABLE[name] = getattr(self, v)

    def start(self):
        self.running = True
        threading.Thread.start(self)

    def stop(self):
        self.running = False

    def run(self):
        #print("Connection to peer {} starting.".format(self.peer_address))
        try:
            self._run()
        except:
            traceback.print_exc()
        #print("Connection to peer {} exiting.".format(self.peer_address))

    def _run(self):
        self.state = BitcoinNetworkPeer.STATE_INIT
        self.bad_peer = False # Set to True to tell the manager that the peer is someone we should wait some time before reconnecting again
        self.socket = None
        self.version_ack = False
        self.known_transactions = set()
        self.transaction_requests_in_progress = {}
        self.peer_last_block = 0
        self.recv_bytes = 0
        self.sent_bytes = 0
        self.send_queue = deque()

        while self.running:
            try:
                self.step()
                time.sleep(0.06)
            except:
                print("Exception is causing connection abort...")

                for txhash in self.transaction_requests_in_progress.keys():
                    self.bitcoin_network.transaction_request_abort(txhash)

                self.bad_peer = True
                raise

        self.close_connection()

    def close_connection(self):
        if self.socket is not None:
            try:
                self.socket.shutdown(socket.SHUT_RDWR)
            except OSError as e:
                if e.errno != 10057: # Socket is already closed
                    raise
        self.socket = None

    def step(self):
        if self.state == BitcoinNetworkPeer.STATE_INIT:
            self.try_connect()
        elif self.state == BitcoinNetworkPeer.STATE_CONNECTED:
            self.send_version()
            self.state = BitcoinNetworkPeer.STATE_READY
            self.socket.settimeout(0.1)
        elif self.state == BitcoinNetworkPeer.STATE_READY:
            self.check_for_messages()
            self.check_for_idle_behavior()
        elif self.state == BitcoinNetworkPeer.STATE_DEAD:
            self.running = False
        else:
            print("unknown state {}".format(self.state))
        self.__send()

    def try_connect(self):
        address, port = self.peer_address.split(":")
        port = int(port)

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.settimeout(5)

        try:
            self.socket.connect((address, port))
            self.state = BitcoinNetworkPeer.STATE_CONNECTED
            self.data_buffer = bytes()
            #print("Connected to peer {}.".format(self.peer_address))
        except:
            self.state = BitcoinNetworkPeer.STATE_DEAD
            self.bad_peer = True
            #print("Could not connect to peer {}.".format(self.peer_address))

    def check_for_messages(self):
        try:
            data = self.socket.recv(4096)
        except ConnectionResetError:
            self.state = BitcoinNetworkPeer.STATE_DEAD
            return
        except socket.timeout:
            return

        if len(data) == 0:  # Have we lost connection?
            self.state = BitcoinNetworkPeer.STATE_DEAD
            return

        # TODO - unwrap_message should return a "required" length for the message to be successful
        # and we should wait until that length becomes available before calling unwrap_message again
        current_buffer = self.data_buffer + data
        self.recv_bytes += len(data)

        while True:
            command, payload, leftover_data = Bitcoin.unwrap_message(current_buffer, Bitcoin.NETWORK_DELIVERY)
            self.data_buffer = leftover_data

            if command is None:
                break

            self.got_peer_message(command, payload)
            current_buffer = self.data_buffer

    def got_peer_message(self, command, payload):
        self.COMMAND_TABLE.get(command, lambda p: self.invalid_command(command, p))(payload)

    def invalid_command(self, command, payload):
        print("({}) GOT: {} (payload {} bytes)".format(self.peer_address, command, len(payload)))

    def send(self, message):
        self.send_queue.append(message)

    def __send(self):
        while len(self.send_queue):
            q = self.send_queue.popleft()
            try:
                self.socket.send(q)
                self.sent_bytes += len(q)
            except (ConnectionAbortedError, OSError):
                # Socket issue?
                traceback.print_exc()
                self.state = BitcoinNetworkPeer.STATE_DEAD
                break

    def check_for_idle_behavior(self):
        self.check_for_idle_transactions()

    def check_for_idle_transactions(self):
        now = time.time()

        for txhash in list(self.transaction_requests_in_progress.keys()):
            if (now - self.transaction_requests_in_progress[txhash]) >= 10:
                # Transaction timed out. Try again in 15 seconds?
                self.known_transactions.add((txhash, now+2))
                self.transaction_requests_in_progress.pop(txhash)
                self.bitcoin_network.transaction_request_abort(txhash)

        request_txns = []
        for txhash, when in list(self.known_transactions):
            if (len(self.transaction_requests_in_progress) + len(request_txns)) >= 5:
                break

            if when > now: # wait on some txns
                continue

            c = self.bitcoin_network.will_request_transaction(txhash)
            self.known_transactions.remove((txhash, when))
            if c == BitcoinNetwork.REQUEST_GO:
                request_txns.append(txhash)
                break
            elif c == BitcoinNetwork.REQUEST_DONT:
                # Boss said don't get it...
                continue
            elif c == BitcoinNetwork.REQUEST_WAIT:
                # Let's recheck this tx later
                self.known_transactions.add((txhash, now + 5))

        if len(request_txns):
            self.request_transactions(request_txns)

    def handle_version(self, payload):
        if len(payload) < 20:
            raise BadCommand()

        try:
            self.peer_version, self.peer_services, when = struct.unpack("<LQQ", payload[:20])
            recipient_address, services, payload = Bitcoin.unserialize_network_address(payload[20:], with_timestamp=False)
            sender_address, services, payload = Bitcoin.unserialize_network_address(payload, with_timestamp=False)
            nonce = struct.unpack("<Q", payload[:8])[0]
            self.peer_user_agent, payload = Bitcoin.unserialize_string(payload[8:])
            self.peer_last_block = struct.unpack("<L", payload)[0]
        except:
            self.state = BitcoinNetworkPeer.STATE_DEAD
            return

        #print("({}) PEER: version {} (User-agent {}, last block {})".format(self.peer_address, self.peer_version, self.peer_user_agent, self.peer_last_block))
        
        self.send_verack()

    def handle_verack(self, payload):
        self.version_ack = True
        self.connection_time = time.time()

    def handle_addr(self, payload):
        count, payload = Bitcoin.unserialize_variable_int(payload)

        for i in range(min(count, 100)):
            addr, services, when, payload = Bitcoin.unserialize_network_address(payload, with_timestamp=self.peer_version >= 31402)
            self.bitcoin_network.discovered_peer_address('{}:{}'.format(*addr), when, services)

    def handle_inv(self, payload):
        count, payload = Bitcoin.unserialize_variable_int(payload)

        for i in range(count):
            inv, payload = Bitcoin.unserialize_inv(payload)

            if inv['type'] == BitcoinNetwork.MSG_ERROR:
                continue

            elif inv['type'] == BitcoinNetwork.MSG_TX:
                #print('got inv for tx {}'.format(Bitcoin.bytes_to_hexstring(inv['hash'])))
                self.known_transactions.add((inv['hash'], time.time()))

            elif inv['type'] == BitcoinNetwork.MSG_BLOCK:
                #print('got inv for block {}'.format(Bitcoin.bytes_to_hexstring(inv['hash'])))
                pass

    def handle_tx(self, payload):
        tx, _ = Transaction.unserialize(payload)
        txhash = tx.hash()
        if txhash in self.transaction_requests_in_progress:
            self.bitcoin_network.got_transaction(tx)
            self.transaction_requests_in_progress.pop(txhash)

    def handle_notfound(self, payload):
        print('got notfound')
        pass

    def send_version(self):
        version  = self.bitcoin_network.client_version
        services = self.bitcoin_network.available_services
        now      = int(time.time())

        recipient_address = Bitcoin.serialize_network_address(None, self.bitcoin_network.available_services, with_timestamp=False)
        sender_address    = Bitcoin.serialize_network_address(None, self.bitcoin_network.available_services, with_timestamp=False)
        
        nonce      = random.randrange(0, 1 << 64)
        user_agent = Bitcoin.serialize_string(self.bitcoin_network.user_agent)
        lastBlock  = random.randrange(1024, 102400*2) # TODO - is it OK to just say '0' on every connect?

        payload = struct.pack("<LQQ", version, services, now) + recipient_address + sender_address + struct.pack("<Q", nonce) + user_agent + struct.pack("<L", lastBlock)
        message = Bitcoin.wrap_message("version", payload, Bitcoin.NETWORK_DELIVERY)

        self.send(message)

    def send_verack(self):
        self.send(Bitcoin.wrap_message("verack", b'', Bitcoin.NETWORK_DELIVERY))

    def sendGetData(self, items):
        data = []
        for item in items:
            data.append(Bitcoin.serialize_inv(item[0], item[1]))

        payload = Bitcoin.serialize_variable_int(len(data)) + b''.join(data)
        message = Bitcoin.wrap_message("getdata", payload, Bitcoin.NETWORK_DELIVERY)
        self.send(message)
        #print("sent getdata for {} items".format(len(items)))

    def request_transactions(self, txhashes):
        now = time.time()
        for txhash in txhashes:
            self.transaction_requests_in_progress[txhash] = now
        self.sendGetData([(BitcoinNetwork.MSG_TX, txhash) for txhash in txhashes])
        return True

