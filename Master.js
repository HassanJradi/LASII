const Net = require('net')
const crypto = require('crypto')
const asy_crypto = require('asymmetric-crypto')
const iota = require('iota.lib.js')
const Mam = require('./mam.node.js')
const rand = require('random-key')
const sleep = require('thread-sleep')
const STANDARD_INPUT = process.stdin

const JOIN_REQUEST_C = 'a'
const CLIENT_ID_C = 'b'
const EXECLUSIVE_KEY_C = 'c'
const JOIN_NB_C = 'd'
const CURRENT_CLIENT_CH_SIDE_KEY_C = 'e'
const CLIENT_CH_MAIN_ROOT_C = 'f'
const RETRIEVE_EXECLUSIVE_KEY_C = 'g'
const ZONE_ID_C = 'h'
const EXTEND_ZONE_REQUEST_C = 'i'
const CH1_MAIN_ROOT_C = 'j'
const CH2_SHARED_ROOT_C = 'k'
const CH2_SIDE_KEY_C = 'l'

const ADD_CLIENT = 1
const ADD_MASTER = 2
const EXTEND_ZONE = 3
const REVOKE_CLIENT = 4
const REVOKE_MASTER = 5
const SHOW_INFO = 6

const IOTA = new iota({ provider: `http://192.168.1.70:10101` })
const CLIENT_MASTER_SOCKET_PORT = Math.ceil(Math.random() * 1000 + 7000)
const MASTER_MASTER_SOCKET_PORT = Math.ceil(Math.random() * 1000 + 8000)
const CLIENT_MASTER_SOCKET = new Net.Server()
const MASTER_MASTER_SOCKET = new Net.Server()
const MASTER_KEY_PAIR = asy_crypto.keyPair()
const SEED_1 = randomSeedGenerator()
const SEED_2 = randomSeedGenerator()
const ZONE_ID = rand.generate(60)
const SLEEP_DURATION = 100
const ALGORTIHM = 'aes-192-cbc'
const IV = Buffer.alloc(16, 0)

var current_Join_Nb = 1
var current_Execlusive_Key_Nb = 1
var current_Execlusive_Key = rand.generate(128)
var execlusive_Keys = [current_Execlusive_Key]
var current_Client_Ch_Side_Key = rand.generate(128)
var client_Ch_Side_Keys = [current_Client_Ch_Side_Key]
var master_Socket
var trusted_Masters = []
var trusted_Clients = []

var trust_New_Client = false
var trust_New_Master = false

var Ch1_Current_State = Mam.init(IOTA, SEED_1, 1, 0, 'private')
publishOnTheTangle('Starting Master of Zone ' + ZONE_ID + ' Channel 1', Ch1_Current_State)
const CH1_MAIN_ROOT = Ch1_Current_State.channel.next_root

var Ch2_Side_Key = rand.generate(128)
var Ch2_Current_State = Mam.init(IOTA, SEED_2, 1, 0, 'restriceted', IOTA.utils.toTrytes(Ch2_Side_Key))
publishOnTheTangle('Starting Master of Zone ' + ZONE_ID + ' Channel 2', Ch2_Current_State)
var Ch2_Shared_Root = Ch2_Current_State.channel.next_root
publishOnTheTangle(client_Ch_Side_Keys[0], Ch2_Current_State)

var action = null
STANDARD_INPUT.on('data', data => {
	if (action == null) {
		data = Number(data)
		switch (data) {
			case ADD_CLIENT: {
				trust_New_Client = true
				console.log('[+] You can add a new CLIENT now on PORT: ' + CLIENT_MASTER_SOCKET_PORT)
				break
			}
			case ADD_MASTER: {
				trust_New_Master = true
				console.log('[+] You can add a new MASTER now on PORT: ' + MASTER_MASTER_SOCKET_PORT)
				break
			}
			case EXTEND_ZONE: {
				action = EXTEND_ZONE
				start = true
				console.log('[+] Enter Peer Master IP:PORT')
				break
			}
			case REVOKE_CLIENT: {
				action = REVOKE_CLIENT
				let i = 1
				trusted_Clients.forEach(trusted_Client => {
					console.log('*************')
					console.log(i++ + ' ' + trusted_Client.clientID)
				})
				console.log('*************')
				console.log('[+] Enter client number')
				break
			}
			case REVOKE_MASTER: {
				action = REVOKE_MASTER
				let i = 1
				trusted_Masters.forEach(trusted_Master => {
					console.log('****************************************************************')
					console.log(i++ + ' ' + trusted_Master.zoneID)
				})
				console.log('****************************************************************')
				console.log('[+] Enter zone number')
				break
			}
			case SHOW_INFO: {
				console.log('\n***********************************************************************************************************************************************************************\n')
				console.log('1- Zone ID: ' + ZONE_ID)
				console.log('2- Seed 1: ' + SEED_1)
				console.log('3- Seed 2: ' + SEED_2)
				console.log('4- Execlusive Key: ' + current_Execlusive_Key)
				console.log('5- Current Client Channel Side Key: ' + current_Client_Ch_Side_Key)
				console.log('6- Channel 1 Main Root: ' + CH1_MAIN_ROOT)
				console.log('7- Channel 2 Shared Root: ' + Ch2_Shared_Root)
				console.log('8- Channel 2 Side Key: ' + Ch2_Side_Key)
				console.log()

				i = 1
				console.log('10- Trusted Zone IDs: ')
				trusted_Masters.forEach(trusted_Master => console.log('\t' + i++ + '- ' + trusted_Master.zoneID))
				console.log()

				i = 1
				console.log('11- Client IDs: ')
				trusted_Clients.forEach(trusted_Client => console.log('\t' + i++ + '- ' + trusted_Client.clientID))

				console.log('\n***********************************************************************************************************************************************************************\n')
				break
			}
			default: {
				print()
			}
		}
	}
	else {
		data = data.toString()
		switch (action) {
			case EXTEND_ZONE: {
				let master_Peer_IP = data.substr(0, data.indexOf(':'))
				let master_Peer_Port = data.substr(data.indexOf(':') + 1)

				try {
					master_Socket = new Net.Socket()
					master_Socket.on('error', err => console.log(`[-] ${err}`))
					master_Socket.on('end', () => console.log('[*] I am not trusted'))
					master_Socket.connect({ port: master_Peer_Port, host: master_Peer_IP }, function () {
						var peer_Zone_ID
						var peer_Ch1_Main_Root
						var peer_Ch2_Shared_Root
						var peer_Ch2_Side_Key

						console.log('[+] Peer Master Found')

						master_Socket.write(`Public Key:${MASTER_KEY_PAIR.publicKey}`)

						master_Socket.on('data', chunk => {
							chunk = chunk.toString()
							if (chunk.search('Public Key') == 0) {
								master_Peer_Public_Key = chunk.substr(chunk.indexOf(':') + 1)
								sendExtendZoneRequest(master_Peer_Public_Key)
							}
							else {
								try {
									let encryptedData = chunk.substr(0, chunk.indexOf(' '))
									let encryptedNonce = chunk.substr(chunk.indexOf(' ') + 1)
									let decrypted = asy_crypto.decrypt(encryptedData, encryptedNonce, master_Peer_Public_Key, MASTER_KEY_PAIR.secretKey)
									decrypted = decrypted.toString()

									switch (decrypted[0]) {
										case ZONE_ID_C: {
											peer_Zone_ID = decrypted.substr(1)
											break
										}
										case CH1_MAIN_ROOT_C: {
											peer_Ch1_Main_Root = decrypted.substr(1)
											break
										}
										case CH2_SHARED_ROOT_C: {
											peer_Ch2_Shared_Root = decrypted.substr(1)
											break
										}
										case CH2_SIDE_KEY_C: {
											peer_Ch2_Side_Key = decrypted.substr(1)

											let key = crypto.scryptSync(current_Execlusive_Key, 'salt', 24)
											let cipher = crypto.createCipheriv(ALGORTIHM, key, IV)

											let toPublish = 'Peer Channel 1 Main Root: ' + peer_Ch1_Main_Root + '\n' +
												'Peer Channel 2 Shared Root: ' + peer_Ch2_Shared_Root + '\n' +
												'Peer Channel 2 Side Key: ' + peer_Ch2_Side_Key

											let encrypted = cipher.update(toPublish, 'utf8', 'hex');
											encrypted += cipher.final('hex');

											publishOnTheTangle('Extended ZoneID: ' + peer_Zone_ID + '\n' + 'Execlusive Key Number: ' + current_Execlusive_Key_Nb + '\n' + 'Encrypted : ' + encrypted, Ch1_Current_State)
											console.log('[+] I am trusted now')
											break
										}
									}
								} catch (err) {
									console.log(`[-] ${err}`)
								}
							}
						})
					})
				}
				catch (err) {
					console.log(`[-] ${err}`)
				}
				finally {
					break
				}

			}
			case REVOKE_CLIENT: {
				try {
					let revoked_Client_ID = trusted_Clients[data - 1].clientID
					trusted_Clients[data - 1].socket.end()
					trusted_Clients = trusted_Clients.filter(trusted_Client => trusted_Client.clientID != revoked_Client_ID)

					current_Execlusive_Key = rand.generate(128)
					execlusive_Keys.push(current_Execlusive_Key)

					trusted_Clients.forEach(trusted_Client => {
						let msg = asy_crypto.encrypt(EXECLUSIVE_KEY_C + current_Execlusive_Key, trusted_Client.publicKey, MASTER_KEY_PAIR.secretKey)
						trusted_Client.socket.write(msg.data + ' ' + msg.nonce)
					})

					current_Client_Ch_Side_Key = rand.generate(128)
					client_Ch_Side_Keys.push(current_Client_Ch_Side_Key)

					Ch2_Side_Key = rand.generate(128)
					Ch2_Shared_Root = Ch2_Current_State.channel.next_root
					Ch2_Current_State = Mam.changeMode(Ch2_Current_State, 'restricted', IOTA.utils.toTrytes(Ch2_Side_Key))

					let toPublish = 'Current Client Channel Side Key: ' + current_Client_Ch_Side_Key + '\n' +
						'Channel 2 Shared Root: ' + Ch2_Shared_Root + '\n' +
						'Channel 2 Side Key: ' + Ch2_Side_Key

					let key = crypto.scryptSync(current_Execlusive_Key, 'salt', 24)
					let cipher = crypto.createCipheriv(ALGORTIHM, key, IV)
					let encrypted = cipher.update(toPublish, 'utf8', 'hex')
					encrypted += cipher.final('hex')

					let revoke_Notification = 'Revoke Notification, New Channel Info:\n' + encrypted
					publishOnTheTangle(revoke_Notification, Ch1_Current_State)

					client_Ch_Side_Keys.forEach(client_Ch_side_key => publishOnTheTangle(client_Ch_side_key, Ch2_Current_State))

					trusted_Masters.forEach(trusted_Master_Socket => sendTrustInformation(trusted_Master_Socket.publicKey, trusted_Master_Socket.socket))
					current_Join_Nb++
					console.log('[+] Client Revoked Successfully')
				}
				catch (err) {
					console.log('[-] Check Client Number')
				}
				finally {
					break
				}
			}
			case REVOKE_MASTER: {
				try {
					let revoked_Zone_ID = trusted_Masters[data - 1].zoneID
					trusted_Masters[data - 1].socket.end()
					trusted_Masters = trusted_Masters.filter(trusted_Master_Socket => trusted_Master_Socket.zoneID != revoked_Zone_ID)

					current_Client_Ch_Side_Key = rand.generate(128)
					client_Ch_Side_Keys.push(current_Client_Ch_Side_Key)

					Ch2_Side_Key = rand.generate(128)
					Ch2_Current_State = Mam.changeMode(Ch2_Current_State, 'restricted', IOTA.utils.toTrytes(Ch2_Side_Key))
					Ch2_Shared_Root = Ch2_Current_State.channel.next_root

					let toPublish = 'Current Client Channel Side Key: ' + current_Client_Ch_Side_Key + '\n' +
						'Channel 2 Shared Root: ' + Ch2_Shared_Root + '\n' +
						'Channel 2 Side Key: ' + Ch2_Side_Key

					let key = crypto.scryptSync(current_Execlusive_Key, 'salt', 24)
					let cipher = crypto.createCipheriv(ALGORTIHM, key, IV)
					let encrypted = cipher.update(toPublish, 'utf8', 'hex')
					encrypted += cipher.final('hex')

					let revoke_Notification = 'Revoke Notification, New Channel Info:\n' + encrypted
					publishOnTheTangle(revoke_Notification, Ch1_Current_State)

					client_Ch_Side_Keys.forEach(client_Ch_side_key => publishOnTheTangle(client_Ch_side_key, Ch2_Current_State))
									
					trusted_Masters.forEach(trusted_Master_Socket => sendTrustInformation(trusted_Master_Socket.publicKey, trusted_Master_Socket.socket))
					current_Join_Nb++
					console.log('[+] Zone Revoked Successfully')
				}
				catch (err) {
					console.log('[-] Check Zone Number')
				}
				finally {
					break
				}
			}
		}
		action = null
	}
})

CLIENT_MASTER_SOCKET.listen(CLIENT_MASTER_SOCKET_PORT, () => {
	console.log(`\n[+] Master listening for CLIENT connection requests on socket localhost:${CLIENT_MASTER_SOCKET_PORT}`)
})

MASTER_MASTER_SOCKET.listen(MASTER_MASTER_SOCKET_PORT, () => {
	console.log(`\n[+] Master listening for MASTER connection requests on socket localhost:${MASTER_MASTER_SOCKET_PORT}`)
	print()
})

CLIENT_MASTER_SOCKET.on('connection', socket => {
	//if (trust_New_Client) {
	if (true) {
		var client_ID = rand.generate(10)
		var client_Details
		var client_Public_Key
		var client_Ch_Main_Root

		console.log('[+] A client here')
		socket.write(`Public Key:${MASTER_KEY_PAIR.publicKey}`)

		socket.on('data', chunk => {
			chunk = chunk.toString()
			if (chunk.search('Public Key') == 0) client_Public_Key = chunk.substr(chunk.indexOf(':') + 1)
			else {
				try {
					let encryptedData = chunk.substr(0, chunk.indexOf(' '))
					let encryptedNonce = chunk.substr(chunk.indexOf(' ') + 1)
					let decrypted = asy_crypto.decrypt(encryptedData, encryptedNonce, client_Public_Key, MASTER_KEY_PAIR.secretKey)
					decrypted = decrypted.toString()

					switch (decrypted[0]) {
						case JOIN_REQUEST_C:
							{
								client_Details = decrypted.substr(1)
								sendZoneInformation(client_ID, client_Public_Key, socket)
								break
							}
						case CLIENT_CH_MAIN_ROOT_C:
							{
								client_Ch_Main_Root = decrypted.substr(1)
								let toPublish = 'Client ID: ' + client_ID + '\n' + 'Client Details: ' + client_Details + '\n' + 'Public Key: ' + client_Public_Key + '\n' + 'Merkle Root: ' + client_Ch_Main_Root + '\n' + 'Join Number: ' + current_Join_Nb
								publishOnTheTangle(toPublish, Ch1_Current_State)
								trust_New_Client = false
								trusted_Clients.push({ 'clientID': client_ID, 'publicKey': client_Public_Key, 'socket': socket })
								console.log('[+] Client Added Successfully')
								break
							}
						case RETRIEVE_EXECLUSIVE_KEY_C:
							{
								let requested_Execlusive_Key_Index = Number(decrypted.substr(1)) - 1
								let msg = asy_crypto.encrypt(RETRIEVE_EXECLUSIVE_KEY_C + execlusive_Keys[requested_Execlusive_Key_Index], client_Public_Key, MASTER_KEY_PAIR.secretKey)
								socket.write(msg.data + ' ' + msg.nonce)
								break
							}
					}
				} catch (err) {
					console.log(`[-] ${err}`)
					trust_New_Client = false
				}
			}
		})

		socket.on('error', err => {
			console.log(`[-] ${err}`)
			trusted_Clients = trusted_Clients.filter(trusted_Client => trusted_Client.socket != socket)
			trust_New_Client = false
		})

		socket.on('end', err => {
			trusted_Clients = trusted_Clients.filter(trusted_Client => trusted_Client.clientID != client_ID)
			console.log('[*] The Client ' + client_ID + ' quit the zone')
		})
	}
	else socket.end()
})

MASTER_MASTER_SOCKET.on('connection', socket => {
	//if (trust_New_Master) {
	if (true) {
		var master_Peer_Public_Key

		console.log('[+] Peer Master found')
		socket.write(`Public Key:${MASTER_KEY_PAIR.publicKey}`)

		socket.on('data', chunk => {
			chunk = chunk.toString()
			if (chunk.search('Public Key') == 0) master_Peer_Public_Key = chunk.substr(chunk.indexOf(':') + 1)
			else {
				try {
					let encryptedData = chunk.substr(0, chunk.indexOf(' '))
					let encryptedNonce = chunk.substr(chunk.indexOf(' ') + 1)
					let decrypted = asy_crypto.decrypt(encryptedData, encryptedNonce, master_Peer_Public_Key, MASTER_KEY_PAIR.secretKey)
					decrypted = decrypted.toString()

					switch (decrypted[0]) {
						case EXTEND_ZONE_REQUEST_C: {
							sendTrustInformation(master_Peer_Public_Key, socket)
							break
						}
						case ZONE_ID_C: {
							let peer_Zone_ID = decrypted.substr(1)
							trust_New_Master = false
							trusted_Masters.push({ 'zoneID': peer_Zone_ID, 'publicKey': master_Peer_Public_Key, 'socket': socket })
							console.log('[+] Master Trusted Successfully')
							break
						}
					}
				} catch (err) {
					console.log(`[-] ${err}`)
					trusted_Masters = trusted_Masters.filter(trusted_Master => trusted_Master.socket != socket)
					trust_New_Master = false
				}
			}
		})

		socket.on('error', function (err) {
			console.log(`[-] ${err}`)
			trusted_Masters = trusted_Masters.filter(trusted_Master => trusted_Master.socket != socket)
			trust_New_Master = false
		})
	}
	else socket.end()
})

function sendZoneInformation(client_ID, client_Public_Key, socket) {
	let msg

	msg = asy_crypto.encrypt(CLIENT_ID_C + client_ID, client_Public_Key, MASTER_KEY_PAIR.secretKey)
	socket.write(msg.data + ' ' + msg.nonce)
	sleep(SLEEP_DURATION)

	msg = asy_crypto.encrypt(ZONE_ID_C + ZONE_ID, client_Public_Key, MASTER_KEY_PAIR.secretKey)
	socket.write(msg.data + ' ' + msg.nonce)
	sleep(SLEEP_DURATION)

	msg = asy_crypto.encrypt(CH1_MAIN_ROOT_C + CH1_MAIN_ROOT, client_Public_Key, MASTER_KEY_PAIR.secretKey)
	socket.write(msg.data + ' ' + msg.nonce)
	sleep(SLEEP_DURATION)

	msg = asy_crypto.encrypt(CH2_SHARED_ROOT_C + Ch2_Shared_Root, client_Public_Key, MASTER_KEY_PAIR.secretKey)
	socket.write(msg.data + ' ' + msg.nonce)
	sleep(SLEEP_DURATION)

	msg = asy_crypto.encrypt(CH2_SIDE_KEY_C + Ch2_Side_Key, client_Public_Key, MASTER_KEY_PAIR.secretKey)
	socket.write(msg.data + ' ' + msg.nonce)
	sleep(SLEEP_DURATION)

	msg = asy_crypto.encrypt(EXECLUSIVE_KEY_C + current_Execlusive_Key, client_Public_Key, MASTER_KEY_PAIR.secretKey)
	socket.write(msg.data + ' ' + msg.nonce)
	sleep(SLEEP_DURATION)

	msg = asy_crypto.encrypt(JOIN_NB_C + current_Join_Nb, client_Public_Key, MASTER_KEY_PAIR.secretKey)
	socket.write(msg.data + ' ' + msg.nonce)
	sleep(SLEEP_DURATION)

	msg = asy_crypto.encrypt(CURRENT_CLIENT_CH_SIDE_KEY_C + current_Client_Ch_Side_Key, client_Public_Key, MASTER_KEY_PAIR.secretKey)
	socket.write(msg.data + ' ' + msg.nonce)
	sleep(SLEEP_DURATION)
}

function sendTrustInformation(master_Peer_Public_Key, socket) {
	let msg

	msg = asy_crypto.encrypt(ZONE_ID_C + ZONE_ID, master_Peer_Public_Key, MASTER_KEY_PAIR.secretKey)
	socket.write(msg.data + ' ' + msg.nonce)
	sleep(SLEEP_DURATION)

	msg = asy_crypto.encrypt(CH1_MAIN_ROOT_C + CH1_MAIN_ROOT, master_Peer_Public_Key, MASTER_KEY_PAIR.secretKey)
	socket.write(msg.data + ' ' + msg.nonce)
	sleep(SLEEP_DURATION)

	msg = asy_crypto.encrypt(CH2_SHARED_ROOT_C + Ch2_Shared_Root, master_Peer_Public_Key, MASTER_KEY_PAIR.secretKey)
	socket.write(msg.data + ' ' + msg.nonce)
	sleep(SLEEP_DURATION)

	msg = asy_crypto.encrypt(CH2_SIDE_KEY_C + Ch2_Side_Key, master_Peer_Public_Key, MASTER_KEY_PAIR.secretKey)
	socket.write(msg.data + ' ' + msg.nonce)
}

function sendExtendZoneRequest(master_Peer_Public_Key) {
	let msg

	console.log('[+] Sending Extend Zone Request')

	msg = asy_crypto.encrypt(EXTEND_ZONE_REQUEST_C, master_Peer_Public_Key, MASTER_KEY_PAIR.secretKey)
	master_Socket.write(msg.data + ' ' + msg.nonce)
	sleep(SLEEP_DURATION)

	msg = asy_crypto.encrypt(ZONE_ID_C + ZONE_ID, master_Peer_Public_Key, MASTER_KEY_PAIR.secretKey)
	master_Socket.write(msg.data + ' ' + msg.nonce)
}

async function publishOnTheTangle(toPublish, Ch_State) {
	try {
		let message = Mam.create(Ch_State, IOTA.utils.toTrytes(JSON.stringify(toPublish)))
		return await Mam.attach(message.payload, message.address)
	}
	catch (err) { console.log('[-] IOTA Network Error') }
}

function randomSeedGenerator() {
	let charSet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ9'
	let randomSEED = ''
	for (let i = 0; i < 81; i++) {
		let randomPoz = Math.floor(Math.random() * charSet.length)
		randomSEED += charSet.substring(randomPoz, randomPoz + 1)
	}
	return randomSEED
}

function print() {
	console.log()
	console.log('***************************')
	console.log('Choose Your Option: 1 -> 6')
	console.log('***************************')
	console.log('1- Add Client')
	console.log('2- Add Master')
	console.log('3- Extend the Zone')
	console.log('4- Revoke Client')
	console.log('5- Revoke Master')
	console.log('6- Show Master Information')
	console.log('***************************')
	console.log()
}