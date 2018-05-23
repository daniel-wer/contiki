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

TEST_MOTE = 0

PORT = 5683
BROADCAST_KEY_PATH = "akes/key-revocation"

invalid_mac = "1337133713371337"
mac_to_revoke = ""
available_hosts = []

if TEST_MOTE:

	mac_1 = "00124b000430533b"
	mac_2 = "00124b000430531a"
	mac_3 = "00124b00043053c6"
	mac_4 = "00124b000430535d"
	mac_5 = "00124b000430546f"
	mac_6 = "00124b00043052e8"
	mac_7 = "00124b0004305329"
	mac_8 = "00124b0004305366"

	mac_to_revoke = mac_5

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

	available_hosts = [host_7, host_12, host_13]

else:

	NUMBER_OF_COOJA_MOTES = 4

	cooja_macs = []
	for i in xrange(NUMBER_OF_COOJA_MOTES):
		ide = i + 2
		cooja_macs.append(("000" + hex(ide)[2:])[-4:] * 4)

	revoked_node_index = 3
	mac_to_revoke = cooja_macs[revoked_node_index]


	cooja_hosts = []
	for i in xrange(NUMBER_OF_COOJA_MOTES):
		ide = i + 2
		idStr = hex(ide)[2:]
		cooja_hosts.append("fd00::2" + ("0" + idStr)[-2:] + (":" + idStr) * 3)

	available_hosts = cooja_hosts[:revoked_node_index] + cooja_hosts[revoked_node_index+1:]

	print available_hosts



# Save the current CoAP Message ID per node
current_mid = {}
for host in available_hosts:
	current_mid[host] = 1530


@pytest.fixture(scope="module", autouse=True)
def client():
	client = HelperClient(server=(available_hosts[0], PORT))
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
		clients.append(HelperClient(server=(host, PORT)))
	yield clients
	# Teardown
	for client in clients:
		try:
			client.stop()
		except:
			pass



# HELPER FUNCTIONS

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


# TESTCASES

def test_revokeNodeInWholeNetwork(clients):
	responses = revokeNodes(clients, mac_to_revoke.decode("hex"));
	print "Revoke nodes return codes:", responses
	for (restCode, statusCode) in responses:
		assert statusCode == 0


def test_revokeNodeReplayed(client):
	constant_mid = 2000
	restCode, statusCode = revokeNode(client, invalid_mac.decode("hex"), constant_mid);
	print "Revoke node return code:", restCode, statusCode
	assert statusCode == 0
	# Do not increase current_mid -> should be detected as replayed and fail
	restCode, statusCode = revokeNode(client, invalid_mac.decode("hex"), constant_mid);
	print "Revoke node return code for replayed message:", restCode, statusCode
	assert statusCode != 0