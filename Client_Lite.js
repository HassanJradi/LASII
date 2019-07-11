const Net = require('net')
const crypto = require('crypto')
const asy_crypto = require('asymmetric-crypto')
const iota = require('iota.lib.js')
const Mam = require('./mam.node.js')
const ArgumentParser = require('argparse').ArgumentParser

var parser = new ArgumentParser({
	addHelp: true,
	description: 'Client Lite'
})

parser.addArgument(
	['-a', '--address'],
	{
		help: 'Master IP',
		defaultValue: 'localhost'
	}
)

parser.addArgument(
	['-p', '--port'],
	{
		help: 'Master Port',
		defaultValue: '1234'
	}
)

const JOIN_REQUEST_C = 'a'
const CLIENT_ID_C = 'b'
const EXECLUSIVE_KEY_C = 'c'
const CURRENT_CLIENT_CH_SIDE_KEY_C = 'e'
const CLIENT_CH_MAIN_ROOT_C = 'f'
const CH1_MAIN_ROOT_C = 'j'

const IOTA = new iota({ provider: `http://192.168.1.70:10101` })
const SEED = randomSeedGenerator()
const CLIENT_KEY_PAIR = asy_crypto.keyPair()
const ALGORTIHM = 'aes-192-cbc'
const IV = Buffer.alloc(16, 0)

let CLIENT_ID
var client_Socket
var Ch_Current_State
var master_Public_Key
var current_Client_Ch_Side_Key
var last_Ch1_Checked_Root
var execlusive_Key

let MASTER_IP = parser.parseArgs().address
let MASTER_PORT = parser.parseArgs().port

try {
	client_Socket = new Net.Socket()
	client_Socket.on('error', err => {
		console.log(`[-] ${err}`)
	})
	client_Socket.on('end', () => {
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
						case CH1_MAIN_ROOT_C: {
							last_Ch1_Checked_Root = decrypted.substr(1)
							break
						}
						case EXECLUSIVE_KEY_C: {
							execlusive_Key = decrypted.substr(1)
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

							console.log('\n***********************************************************************************************************************************************************************\n')
							console.log('\t\t\t\t\t\t\t\t\tClient ID: ' + CLIENT_ID)
							console.log('\n***********************************************************************************************************************************************************************\n')
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

setInterval(shareRandomData, 5 * 1000)

function shareRandomData() {
	checkChannelInformation().then(() => {
		publishOnTheTangle((Math.random() * 100).toString().substr(3, 10), Ch_Current_State).then(promise => {
			if (promise != undefined)
				console.log('[+] Shared Successfully\n\n')
		})
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
		console.log(`[-] ${err}`)
	}

}
let i = 0
async function publishOnTheTangle(toPublish, Ch_State) {
	try {
		if (i < 2) i++
		else
			console.log('[+] Sharing Data: ' + toPublish)
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
