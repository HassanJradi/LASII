const Net = require('net')
const crypto = require('crypto')
const asy_crypto = require('asymmetric-crypto')
const iota = require('iota.lib.js')
const Mam = require('./mam.node.js')
const STANDARD_INPUT = process.stdin

const JOIN_REQUEST_C = 'a'
const CLIENT_ID_C = 'b'
const EXECLUSIVE_KEY_C = 'c'
const JOIN_NB_C = 'd'
const CURRENT_CLIENT_CH_SIDE_KEY_C = 'e'
const CLIENT_CH_MAIN_ROOT_C = 'f'
const RETRIEVE_EXECLUSIVE_KEY_C = 'g'
const ZONE_ID_C = 'h'
const CH1_MAIN_ROOT_C = 'j'
const CH2_SHARED_ROOT_C = 'k'
const CH2_SIDE_KEY_C = 'l'

const JOIN_ZONE = 1
const SHARE_RANDOM_DATA = 2
const SHOW_ZONE_CLIENTS = 3
const GET_MY_ZONE_CLIENT_DATA = 4
const FIND_EXTENDED_ZONE_CLIENT_DATA = 5
const SHOW_INFO = 6
const QUIT_ZONE = 7
const GET_EXTENDED_ZONE_CLIENT_DATA = 8

const IOTA = new iota({ provider: `http://192.168.1.70:10101` })
const SEED = randomSeedGenerator()
const CLIENT_KEY_PAIR = asy_crypto.keyPair()
const ALGORTIHM = 'aes-192-cbc'
const IV = Buffer.alloc(16, 0)

let ZONE_ID
let CLIENT_ID
let CH1_MAIN_ROOT
let JOIN_NB = 0

var PEER_CH1_MAIN_ROOT
var PEER_CH2_SHARED_ROOT
var PEER_CH2_SIDE_KEY

var client_Socket
var Ch_Current_State
var master_Public_Key
var current_Client_Ch_Side_Key
var last_Ch1_Checked_Root
var Ch2_Shared_Root
var Ch2_Side_Key
var execlusive_Key
var encrypted_Zone_Data

print()

var action = null
STANDARD_INPUT.on('data', data => {
	if (action == null) {
		data = Number(data)
		switch (data) {
			case JOIN_ZONE: {
				if (JOIN_NB == 0) {
					action = JOIN_ZONE
					console.log('[+] Enter Master IP:PORT')
				}
				else {
					console.log('[*] You are already joined')
				}
				break
			}
			case SHOW_ZONE_CLIENTS: {
				getZoneClients(CH1_MAIN_ROOT).then(zoneClients => {
					console.log('************ Zone Client IDs ************')
					for (let i = 1; i <= zoneClients.length; i++) {
						console.log(i + '- ' + zoneClients[i - 1])
					}
					console.log('*****************************************')
				}).catch(err => {
					console.log('[-] You are not joined yet')
				})
				break
			}
			case GET_MY_ZONE_CLIENT_DATA: {
				getZoneClients(CH1_MAIN_ROOT).then(zoneClients => {
					console.log('************ Zone Client IDs ************')
					for (let i = 1; i <= zoneClients.length; i++) {
						console.log(i + '- ' + zoneClients[i - 1])
					}
					console.log('*****************************************')
					action = GET_MY_ZONE_CLIENT_DATA
					console.log('[+] Enter client number')
				}).catch(err => {
					console.log('[-] You are not joined yet')
				})
				break
			}
			case FIND_EXTENDED_ZONE_CLIENT_DATA: {
				action = FIND_EXTENDED_ZONE_CLIENT_DATA
				console.log('[+] Enter zone ID')
				break
			}
			case SHOW_INFO: {
				console.log('\n***********************************************************************************************************************************************************************\n')
				console.log('1- Seed: ' + SEED)

				if (JOIN_NB > 0) {
					console.log('2- Client ID: ' + CLIENT_ID)
					console.log('3- Join Nb: ' + JOIN_NB)
					console.log('4- Zone ID: ' + ZONE_ID)
					console.log('5- Channel 1 Main Root: ' + CH1_MAIN_ROOT)
					console.log('6- Channel 2 Shared Root: ' + Ch2_Shared_Root)
					console.log('7- Channel 2 Side Key: ' + Ch2_Side_Key)
					console.log('8- Execlusive Key: ' + execlusive_Key)
					console.log('9- Current Client Channel Side Key: ' + current_Client_Ch_Side_Key)
					console.log('10- Client Channel Main Root: ' + Ch_Main_Root)
				}
				else {
					console.log('[*] Not Joined Yet')
				}
				console.log('\n***********************************************************************************************************************************************************************\n')
				break
			}
			case SHARE_RANDOM_DATA: {
				checkChannelInformation().then(() => {
					publishOnTheTangle((Math.random() * 100).toString().substr(3, 10), Ch_Current_State).then(promise => {
						if (promise != undefined)
							console.log('[+] Shared Successfully')
					})
				})
				break
			}
			case QUIT_ZONE: {
				try {
					client_Socket.end()
					console.log('[+] Quit successfully')
				}
				catch (err) {
					console.log(`[-] ${err}`)
				}
				finally {
					JOIN_NB = 0
					break
				}
			}
			default: {
				print()
			}
		}
	}
	else {
		data = data.toString()
		switch (action) {
			case JOIN_ZONE: {
				let MASTER_IP = data.substr(0, data.indexOf(':'))
				let MASTER_PORT = data.substr(data.indexOf(':') + 1)
				try {
					client_Socket = new Net.Socket()
					client_Socket.on('error', err => {
						JOIN_NB = 0
						console.log(`[-] ${err}`)
					})
					client_Socket.on('end', () => {
						JOIN_NB = 0
						console.log('[*] I Am Not Trusted')
					})
					client_Socket.connect({ port: MASTER_PORT, host: MASTER_IP }, () => {
						console.log('[+] Master Found')
						client_Socket.write(`Public Key:${CLIENT_KEY_PAIR.publicKey}`)

						client_Socket.on('data', chunk => {
							chunk = chunk.toString()
							if (chunk.search('Public Key') == 0) {
								master_Public_Key = chunk.substr(chunk.indexOf(':') + 1)
								console.log('[+] Sending Join Request')

								let msg = asy_crypto.encrypt(`${JOIN_REQUEST_C}Details`, master_Public_Key, CLIENT_KEY_PAIR.secretKey)
								client_Socket.write(msg.data + ' ' + msg.nonce)
							}
							else {
								try {
									let encryptedData = chunk.substr(0, chunk.indexOf(' '))
									let encryptedNonce = chunk.substr(chunk.indexOf(' ') + 1)
									let decrypted = asy_crypto.decrypt(encryptedData, encryptedNonce, master_Public_Key, CLIENT_KEY_PAIR.secretKey)
									decrypted = decrypted.toString()

									switch (decrypted[0]) {
										case CLIENT_ID_C: {
											CLIENT_ID = decrypted.substr(1)
											break
										}
										case ZONE_ID_C: {
											ZONE_ID = decrypted.substr(1)
											break
										}
										case CH1_MAIN_ROOT_C: {
											CH1_MAIN_ROOT = last_Ch1_Checked_Root = decrypted.substr(1)
											break
										}
										case CH2_SHARED_ROOT_C: {
											Ch2_Shared_Root = decrypted.substr(1)
											break
										}
										case CH2_SIDE_KEY_C: {
											Ch2_Side_Key = decrypted.substr(1)
											break
										}
										case EXECLUSIVE_KEY_C: {
											execlusive_Key = decrypted.substr(1)
											break
										}
										case JOIN_NB_C: {
											JOIN_NB = decrypted.substr(1)
											break
										}
										case CURRENT_CLIENT_CH_SIDE_KEY_C: {
											current_Client_Ch_Side_Key = decrypted.substr(1)

											Ch_Current_State = Mam.init(IOTA, SEED, 1, 0, 'restricted', IOTA.utils.toTrytes(current_Client_Ch_Side_Key))
											publishOnTheTangle('Starting Client *' + CLIENT_ID + '* Channel', Ch_Current_State)
											Ch_Main_Root = Ch_Current_State.channel.next_root
											publishOnTheTangle('Starting Client *' + CLIENT_ID + '* Channel', Ch_Current_State)

											let msg = asy_crypto.encrypt(CLIENT_CH_MAIN_ROOT_C + Ch_Main_Root, master_Public_Key, CLIENT_KEY_PAIR.secretKey)
											client_Socket.write(msg.data + ' ' + msg.nonce)

											console.log('[+] Joined Successfully')
											break
										}
										case RETRIEVE_EXECLUSIVE_KEY_C: {
											let requested_Execlusive_key = decrypted.substr(1)
											let key = crypto.scryptSync(requested_Execlusive_key, 'salt', 24)
											let decipher = crypto.createDecipheriv(ALGORTIHM, key, IV)
											let decryptedData = decipher.update(encrypted_Zone_Data, 'hex', 'utf8')
											decryptedData += decipher.final('utf8')

											PEER_CH1_MAIN_ROOT = decryptedData.substring('Peer Channel 1 Main Root: '.length, decryptedData.indexOf('Peer Channel 2 Shared Root:') - 1)
											PEER_CH2_SHARED_ROOT = decryptedData.substring(decryptedData.indexOf('Peer Channel 2 Shared Root:') + 'Peer Channel 2 Shared Root: '.length, decryptedData.indexOf('Peer Channel 2 Side Key:') - 1)
											PEER_CH2_SIDE_KEY = decryptedData.substring(decryptedData.indexOf('Peer Channel 2 Side Key:') + 'Peer Channel 2 Side Key: '.length)
											console.log('[+] Enter client number')
											getZoneClients(PEER_CH1_MAIN_ROOT).then(zoneClients => {
												console.log('************ Zone Client IDs ************')
												for (let i = 1; i <= zoneClients.length; i++) {
													console.log(i + '- ' + zoneClients[i - 1])
												}
												console.log('*****************************************')
												action = GET_EXTENDED_ZONE_CLIENT_DATA
											}).catch(err => {
												console.log('[-] You are not joined yet')
											})
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
			case GET_MY_ZONE_CLIENT_DATA: {
				checkChannelInformation().then(() => getClientData(CH1_MAIN_ROOT, Ch2_Shared_Root, Ch2_Side_Key, Number(data)))
				break
			}
			case FIND_EXTENDED_ZONE_CLIENT_DATA: {
				console.log('[+] Fetching ..')
				fetchZoneExeclusiveKeyNumber(data).then((execlusive_Key_Number) => {
					console.log('[+] Zone found')
					console.log('[+] Sending Retrieve Execlusive Key Request')
					let msg = asy_crypto.encrypt(RETRIEVE_EXECLUSIVE_KEY_C + execlusive_Key_Number, master_Public_Key, CLIENT_KEY_PAIR.secretKey)
					client_Socket.write(msg.data + ' ' + msg.nonce)
				}).catch(err => {
					console.log('[-] This zone does not trust you')
				})
				break
			}
			case GET_EXTENDED_ZONE_CLIENT_DATA: {
				getClientData(PEER_CH1_MAIN_ROOT, PEER_CH2_SHARED_ROOT, PEER_CH2_SIDE_KEY, Number(data))
				break
			}
		}
		action = null
	}
})

async function fetchZoneExeclusiveKeyNumber(ZoneID) {
	let execlusive_Key_Number = -1
	try {
		await Mam.fetch(CH1_MAIN_ROOT, 'private', null, data => {
			let ch_Data = JSON.parse(IOTA.utils.fromTrytes(data))
			if (ch_Data.indexOf('Extended ZoneID:') == 0 && ch_Data.indexOf(ZoneID.substr(0, 60)) == 17) {
				execlusive_Key_Number = ch_Data.substring(ch_Data.indexOf('Execlusive Key Number: ') + 'Execlusive Key Number: '.length, ch_Data.indexOf('Encrypted :') - 1)
				encrypted_Zone_Data = ch_Data.substring((ch_Data.indexOf('Encrypted : ') + 'Encrypted : '.length))
			}
		})
	}
	catch (err) { console.log(`[-] ${err}`) }
	return new Promise((resolve, reject) => {
		if (execlusive_Key_Number == -1) reject()
		else resolve(execlusive_Key_Number)
	})
}

async function checkChannelInformation() {
	try {
		var encrypted_new_Info
		let resp = await Mam.fetch(last_Ch1_Checked_Root, 'private', null, data => {
			let ch_Data = JSON.parse(IOTA.utils.fromTrytes(data))

			if (ch_Data.indexOf('Revoke Notification, New Channel Info:') == 0)
				encrypted_new_Info = ch_Data.substr(ch_Data.indexOf(':') + 2)
		})

		last_Ch1_Checked_Root = resp.nextRoot
		if (encrypted_new_Info != undefined) {
			let key = crypto.scryptSync(execlusive_Key, 'salt', 24)
			let decipher = crypto.createDecipheriv(ALGORTIHM, key, IV)
			let decrypted = decipher.update(encrypted_new_Info, 'hex', 'utf8')
			decrypted += decipher.final('utf8')

			let new_Client_Ch_Side_Key = decrypted.substring(decrypted.indexOf('Current Client Channel Side Key: ') + 'Current Client Channel Side Key: '.length, decrypted.indexOf('Channel 2 Shared Root:') - 1)
			if (new_Client_Ch_Side_Key != current_Client_Ch_Side_Key) {
				current_Client_Ch_Side_Key = new_Client_Ch_Side_Key
				Ch2_Shared_Root = decrypted.substring(decrypted.indexOf('Channel 2 Shared Root:') + 'Channel 2 Shared Root: '.length, decrypted.indexOf('Channel 2 Side Key:') - 1)
				Ch2_Side_Key = decrypted.substring(decrypted.indexOf('Channel 2 Side Key:') + 'Channel 2 Side Key: '.length)

				publishOnTheTangle('Updated', Ch_Current_State)
				Ch2_Current_State = Mam.changeMode(Ch_Current_State, 'restricted', IOTA.utils.toTrytes(current_Client_Ch_Side_Key))
				console.log('[+] You are newly updated')
			}
			else {
				console.log('[+] You are already updated')
			}
		}
		else {
			console.log('[+] You are already updated')
		}
	} catch (err) {
		console.log('[*] You are not joined yet or you are in an old zone')
	}

}

async function getClientData(CH1_MAIN_ROOT, Ch2_Shared_Root, Ch2_Side_Key, clientNumber) {
	let i = 0
	await Mam.fetch(CH1_MAIN_ROOT, 'private', null, data => {
		let ch_Data = JSON.parse(IOTA.utils.fromTrytes(data))

		if (i < clientNumber && ch_Data.indexOf('Client ID:') == 0) i++

		if (i == clientNumber) {
			i++
			client_Merkle_Root = ch_Data.substring(ch_Data.indexOf('Merkle Root:') + 13, ch_Data.indexOf('Join Number:') - 1)
			client_Join_Nb = ch_Data.substring(ch_Data.indexOf('Join Number:') + 13)
		}
	})

	i = 0
	let client_Ch_Side_Keys = []

	await Mam.fetch(Ch2_Shared_Root, 'restricted', IOTA.utils.toTrytes(Ch2_Side_Key), data => {
		let ch_Data = JSON.parse(IOTA.utils.fromTrytes(data))
		if (i < client_Join_Nb) i++
		if (i == client_Join_Nb) client_Ch_Side_Keys.push(ch_Data)
	})

	i = 0

	console.log('********************* START *********************')
	try {
		while (true) {
			await Mam.fetchSingle(client_Merkle_Root, 'restricted', IOTA.utils.toTrytes(client_Ch_Side_Keys[i])).then(data => {
				console.log('******************************************')
				console.log(JSON.parse(IOTA.utils.fromTrytes(data.payload)))
				client_Merkle_Root = data.nextRoot
				if (JSON.parse(IOTA.utils.fromTrytes(data.payload)) == 'Updated') i++
			})
		}
	}
	catch (err) {
		console.log('********************* END *********************')
	}
}

async function getZoneClients(CH1_MAIN_ROOT) {
	let zoneClients = []

	await Mam.fetch(CH1_MAIN_ROOT, 'private', null, data => {
		let ch_Data = JSON.parse(IOTA.utils.fromTrytes(data))
		ch_Data.indexOf('Client ID:') == 0 ? zoneClients.push(ch_Data.substr(ch_Data.indexOf('Client ID:') + 11, 10)) : 0
	})

	return new Promise((resolve, reject) => {
		if (zoneClients.length == 0) reject()
		else resolve(zoneClients)
	})

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
	console.log('*************************************')
	console.log('Choose Your Option: 1 -> 7')
	console.log('*************************************')
	console.log('1- Join a Zone')
	console.log('2- Share Random Data')
	console.log('3- Show Clients in my zone')
	console.log('4- Get Data of a Client in my Zone')
	console.log('5- Get Data of a Client in Extended Zone')
	console.log('6- Show Client Information')
	console.log('7- Quit the Zone')
	console.log('*************************************')
	console.log()
}