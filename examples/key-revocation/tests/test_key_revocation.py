from coapthon.client.helperclient import HelperClient
from coapthon import defines
from base64 import b16decode
from crypto import *
import pytest
import time
import threading
import random
import math

import logging
logging.basicConfig()

NUMBER_OF_COOJA_MOTES = 100

mac_1 = "00124b000430533b"
mac_2 = "00124b000430531a"
mac_3 = "00124b00043053c6"
mac_4 = "00124b000430535d"
mac_5 = "00124b000430546f"
mac_6 = "00124b00043052e8"
mac_7 = "00124b0004305329"
mac_8 = "00124b0004305366"

cooja_macs = []
for i in xrange(NUMBER_OF_COOJA_MOTES):
	ide = i + 2
	cooja_macs.append(("000" + hex(ide)[2:])[-4:] * 4)

mac = cooja_macs[27]
# mac = mac_5

invalid_mac = "1337133713371337"

host_1 = "fd00::212:4b00:430:533b"
host_2 = "fd00::212:4b00:430:535d"
host_3 = "fd00::212:4b00:430:531a"
host_4 = "fd00::212:4b00:430:53c6"
host_5 = "fd00::212:4b00:430:53c1"
host_6 = "fd00::212:4b00:430:53d9"
host_7 = "fd00::212:4b00:430:52e8"
host_8 = "fd00::212:4b00:430:546f"
host_9 = "fd00::212:4b00:430:5403"
host_10 = "fd00::212:4b00:430:52f1"
host_11 = "fd00::212:4b00:430:5329"
host_12 = "fd00::212:4b00:430:531a"
host_13 = "fd00::212:4b00:430:5395"


cooja_hosts = []
for i in xrange(NUMBER_OF_COOJA_MOTES):
	ide = i + 2
	idStr = hex(ide)[2:]
	cooja_hosts.append("fd00::2" + ("0" + idStr)[-2:] + (":" + idStr) * 3)

available_hosts = cooja_hosts[:27] + cooja_hosts[27:]
# available_hosts = [host_7, host_12, host_13]

port = 5683

BROADCAST_KEY_PATH = "akes/key-revocation"

# Save the current CoAP Message ID per node
current_mid = {}
for host in available_hosts:
	current_mid[host] = 1530

debugMarker = pytest.mark.debugMarker


@pytest.fixture(scope="module", autouse=True)
def client():
	client = HelperClient(server=(available_hosts[0], port))
	yield client
	# Teardown
	try:
		client.stop()
	except:
		pass

@pytest.fixture(scope="module", autouse=True)
def clients():
	clients = []
	for host in available_hosts:
		clients.append(HelperClient(server=(host, port)))
	yield clients
	# Teardown
	for client in clients:
		try:
			client.stop()
		except:
			pass



# HELPER FUNCTIONS

def getDebugValue(client, param):
	# request = client.mk_request(defines.Codes.GET, BROADCAST_KEY_PATH + "?debug=" + param)
	# request.mid = 5
	# response = client.send_request(request, None, None)
	response = client.get(BROADCAST_KEY_PATH + "?debug=" + param)
	# print response.pretty_print()
	return response.payload.strip('\0')


def revokeNode(client, nodeId, mid=None):
	global current_mid
	if not mid:
		mid = current_mid[client.server[0]]
	newSecret = "newsecnewsecnewsec";
	message = nodeId + newSecret
	nonce = str(mid) + str(defines.Types["CON"])
	payload = encrypt(message, nonce);

	request = client.mk_request(defines.Codes.POST, BROADCAST_KEY_PATH)
	request.mid = mid
	request.type = defines.Types["CON"]
	request.payload = payload
	response = client.send_request(request, None, None)
	# response = client.post(BROADCAST_KEY_PATH, payload)

	print "Got response for node", client.server
	nonce = str(response.mid) + str(response.type)
	code = 2
	if (response.payload):
		responsePayload = decrypt(response.payload, nonce)
		code = int(responsePayload)
	# assert response.mid == request.mid

	current_mid[client.server[0]] += 1
	return response.code, code


def revokeNodes(clients, nodeId):
	return map(lambda client: revokeNode(client, nodeId), clients)


def worker(clients, nodeId, results):
	while len(clients):
		client = clients.pop()
		results.append(revokeNode(client, nodeId))


def revokeNodesParallel(clients, nodeId):
	results = []
	for i in range(1):
		t = threading.Thread(target=worker, args=(clients, nodeId, results))
		t.start()

	main_thread = threading.currentThread()
	for t in threading.enumerate():
		if t is not main_thread:
			t.join()

	return results


# TESTCASES

def test_getBroadcastKey(client):
	broadcastKey = getDebugValue(client, "broadcastKey");
	print "Broadcast key is", broadcastKey
	assert len(broadcastKey) == 16

def test_getNeighborCount(client):
	neighborCount = getDebugValue(client, "neighborCount");
	print "Neighbor count is", neighborCount
	assert neighborCount >= 0

def test_revokeNode(client):
	oldKey = getDebugValue(client, "broadcastKey");
	oldNeighborCount = int(getDebugValue(client, "neighborCount"));
	restCode, statusCode = revokeNode(client, mac.decode("hex"));
	print "Revoke node return code:", restCode, statusCode
	newKey = getDebugValue(client, "broadcastKey");
	newNeighborCount = int(getDebugValue(client, "neighborCount"));
	assert oldKey != newKey
	assert newNeighborCount == oldNeighborCount - 1

# @debugMarker
def test_revokeInvalidNode(client):
	oldKey = getDebugValue(client, "broadcastKey");
	oldNeighborCount = int(getDebugValue(client, "neighborCount"));
	restCode, statusCode = revokeNode(client, invalid_mac.decode("hex"));
	print "Revoke node return code:", restCode, statusCode
	newKey = getDebugValue(client, "broadcastKey");
	newNeighborCount = int(getDebugValue(client, "neighborCount"));
	assert oldKey == newKey
	assert newNeighborCount == oldNeighborCount
	assert statusCode == 0

@debugMarker
def test_revokeNodeInWholeNetwork(clients):
	# oldKey = getDebugValue(client, "broadcastKey");
	# oldNeighborCount = int(getDebugValue(client, "neighborCount"));
	responses = revokeNodesParallel(clients, mac.decode("hex"));
	print "Revoke nodes return codes:", responses
	# newKey = getDebugValue(client, "broadcastKey");
	# newNeighborCount = int(getDebugValue(client, "neighborCount"));
	# assert oldKey != newKey
	# assert newNeighborCount == oldNeighborCount - 1
	for (restCode, statusCode) in responses:
		assert statusCode == 0

def test_revokeNodeInWholeNetworkInterval(clients):
	# oldKey = getDebugValue(client, "broadcastKey");
	# oldNeighborCount = int(getDebugValue(client, "neighborCount"));
	interval = 5 * 60
	backoff = 30
	for i in range(12):
		stime = time.time()
		print "sleep for init", backoff
		time.sleep(backoff)
		ran = random.random() * (interval - backoff)
		print "sleep random", ran
		time.sleep(ran)
		responses = revokeNodes(clients, mac.decode("hex"));
		print "Revoke nodes return codes:", responses
		remaining = interval - (time.time() - stime)
		if remaining > 0:
			print "sleep remaining", remaining
			time.sleep(remaining)
	# newKey = getDebugValue(client, "broadcastKey");
	# newNeighborCount = int(getDebugValue(client, "neighborCount"));
	# assert oldKey != newKey
	# assert newNeighborCount == oldNeighborCount - 1
	for (restCode, statusCode) in responses:
		assert statusCode == 0

# @debugMarker
def test_revokeNodeReplayed(client):
	constant_mid = 2000
	restCode, statusCode = revokeNode(client, invalid_mac.decode("hex"), constant_mid);
	print "Revoke node return code:", restCode, statusCode
	assert statusCode == 0
	# Do not increase current_mid -> should be detected as replayed and fail
	restCode, statusCode = revokeNode(client, invalid_mac.decode("hex"), constant_mid);
	print "Revoke node return code for replayed message:", restCode, statusCode
	assert statusCode != 0