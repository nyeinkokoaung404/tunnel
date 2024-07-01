// @ts-ignore
import { connect } from 'cloudflare:sockets';

// How to generate your own UUID:
// [Windows] Press "Win + R", input cmd and run:  Powershell -NoExit -Command "[guid]::NewGuid()"
let userID = 'bbd4cd4b-616c-4431-83db-66ae98f39e17';

const proxyIPs = ['cdn.xn--b6gac.eu.org', 'cdn-all.xn--b6gac.eu.org', 'workers.cloudflare.cyou'];

// if you want to use ipv6 or single proxyIP, please add comment at this line and remove comment at the next line
let proxyIP = proxyIPs[Math.floor(Math.random() * proxyIPs.length)];
// use single proxyIP instead of random
// let proxyIP = 'cdn.xn--b6gac.eu.org';
// ipv6 proxyIP example remove comment to use
// let proxyIP = "[2a01:4f8:c2c:123f:64:5:6810:c55a]"

let dohURL = 'https://sky.rethinkdns.com/1:-Pf_____9_8A_AMAIgE8kMABVDDmKOHTAKg='; // https://cloudflare-dns.com/dns-query or https://dns.google/dns-query

// Set the preferred address API interface
let addressesapi = [
	'https://raw.githubusercontent.com/nyeinkokoaung404/tunnel/main/ipv4.txt', 
];

// Set the preferred address, the default port number is 443, and TLS subscription generation
let addresses = [
	'icook.tw:443#t.me/NKKA404',//Official preferred domain name
	//'cloudflare.cfgo.cc:443#YouTube',
	'visa.com:443#t.me/nkka_404'
];

let autoaddress = [
	'icook.tw:443',
	'cloudflare.cfgo.cc:443',
	'visa.com:443'
];

let FileName = 'ansoncloud8.github.io';
let tagName = 'telegram/@nkka404'
let SUBUpdateTime = 6;
let total = 99;//PB
//let timestamp = now;
let timestamp = 4102329600000;//2099-12-31
const regex = /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|\[.*\]):?(\d+)?#?(.*)?$/;

// Fake uuid and hostname, used to send to the configuration generation service
let fakeUserID = generateUUID();
let fakeHostName = generateRandomString();

let sub = 'worker.amcloud.filegear-sg.me';// Built-in preferred subscription generator, you can build it yourself
let subconverter = 'url.v1.mk';// Clash subscription conversion backend, currently using Feiyang's subscription conversion function. Comes with fake uuid and host subscription。
let subconfig = "https://raw.githubusercontent.com/ansoncloud8/ACL4SSR/main/Clash/config/ACL4SSR_Online_Full_MultiMode.ini"; //Subscription Profile


if (!isValidUUID(userID)) {
	throw new Error('uuid is invalid');
}

export default {
	/**
	 * @param {import("@cloudflare/workers-types").Request} request
	 * @param {{UUID: string, PROXYIP: string, DNS_RESOLVER_URL: string, NODE_ID: int, API_HOST: string, API_TOKEN: string}} env
	 * @param {import("@cloudflare/workers-types").ExecutionContext} ctx
	 * @returns {Promise<Response>}
	 */
	async fetch(request, env, ctx) {
		// uuid_validator(request);
		try {
			let expire = Math.floor(timestamp / 1000);
			let UD = Math.floor(((timestamp - Date.now()) / timestamp * 99 * 1099511627776 * 1024) / 2);
			const url = new URL(request.url);
			const uuid = url.searchParams.get('uuid') ? url.searchParams.get('uuid').toLowerCase() : "null";

			sub = env.SUB || sub;
			userID = env.UUID || userID;
			proxyIP = env.PROXYIP || proxyIP;
			dohURL = env.DNS_RESOLVER_URL || dohURL;
			let userID_Path = userID;
			if (userID.includes(',')) {
				userID_Path = userID.split(',')[0];
			}

			if (env.ADDRESSESAPI){
				addressesapi = [];
				addressesapi = await ADD(env.ADDRESSESAPI);
			} 		
			
			const upgradeHeader = request.headers.get('Upgrade');
			if (!upgradeHeader || upgradeHeader !== 'websocket') {
				switch (url.pathname) {
					case `/cf`: {
						return new Response(JSON.stringify(request.cf, null, 4), {
							status: 200,
							headers: {
								"Content-Type": "application/json;charset=utf-8",
							},
						});
					}
					case `/404`: {
						const vlessConfig = getVLESSConfig(userID, request.headers.get('Host'));
						return new Response(`${vlessConfig}`, {
							status: 200,
							headers: {
								"Content-Type": "text/html; charset=utf-8",
							}
						});
					};
					case `/sub/${userID_Path}`: {
						const url = new URL(request.url);
						const searchParams = url.searchParams;
						const format = searchParams.get('format') ? searchParams.get('format').toLowerCase() : null;
						const dq = searchParams.get('dq') ? searchParams.get('dq') : null;
						const btoa_not = searchParams.get('btoa') ? searchParams.get('btoa').toLowerCase() : null;
						const vlessSubConfig = createVLESSSub(userID, request.headers.get('Host'), format, dq);

						// Construct and return response object
						if (format === 'qx') {
							return new Response(vlessSubConfig, {
								status: 200,
								headers: {
									"Content-Type": "text/plain;charset=utf-8",
								}
							});
						} else if (btoa_not === 'btoa') {
							return new Response(vlessSubConfig, {
								status: 200,
								headers: {
									"Content-Type": "text/plain;charset=utf-8",
								}
							});
						} else {
							return new Response(btoa(vlessSubConfig), {
								status: 200,
								headers: {
									"Content-Type": "text/plain;charset=utf-8",
								}
							});
						}
					};
					case `/bestip/${uuid}`: {
						const newAddressesapi = await getAddressesapi(addressesapi);
						// const vlessSubConfig = createVlessBestIpSub(userID, request.headers.get('Host'), newAddressesapi,'format');
						//Take Random
						fakeUserID = uuid;
						fakeHostName = url.searchParams.get('host') ? url.searchParams.get('host').toLowerCase() : request.headers.get('Host');
						const format = url.searchParams.get('format') ? url.searchParams.get('format').toLowerCase() : "null";
						const vlessSubConfig = createVlessBestIpSub(fakeUserID, fakeHostName, newAddressesapi, format);
						const btoa_not = url.searchParams.get('btoa') ? url.searchParams.get('btoa').toLowerCase() : null;
						
					    if (btoa_not === 'btoa') {
							return new Response(vlessSubConfig, {
								status: 200,
								headers: {
									"Content-Type": "text/plain;charset=utf-8",
								}
							});
						}else {
							const base64Response = btoa(vlessSubConfig); // Re-encode to Base64
							const response = new Response(base64Response, {
								headers: {
									// "Content-Disposition": `attachment; filename*=utf-8''${encodeURIComponent(FileName)}; filename=${FileName}`,
									"content-type": "text/plain; charset=utf-8",
									"Profile-Update-Interval": `${SUBUpdateTime}`,
									"Subscription-Userinfo": `upload=${UD}; download=${UD}; total=${total}; expire=${expire}`,
								},
							});
							return response;
						}
					};
					case `/sub/bestip/${userID_Path}`: {
						const tls = true;
						// If the default domain name is used, change it to a workers domain name, and the subscriber will add a proxy
						const hostName = request.headers.get('Host');
						const userAgentHeader = request.headers.get('User-Agent');
						const userAgent = userAgentHeader ? userAgentHeader.toLowerCase() : "null";
						const format = url.searchParams.get('format') ? url.searchParams.get('format').toLowerCase() : "null";
						if (hostName.includes(".workers.dev")) {
							fakeHostName = `${fakeHostName}.${generateRandomString()}${generateRandomNumber()}.workers.dev`;
						} else if (hostName.includes(".pages.dev")) {
							fakeHostName = `${fakeHostName}.${generateRandomString()}${generateRandomNumber()}.pages.dev`;
						} else if (hostName.includes("worker") || hostName.includes("notls") || tls == false) {
							fakeHostName = `notls.${fakeHostName}${generateRandomNumber()}.net`;
						} else {
							fakeHostName = `${fakeHostName}.${generateRandomNumber()}.xyz`
						}
						let content = "";
						let suburl = "";
						let isBase64 = false;
						if ((userAgent.includes('clash') && !userAgent.includes('nekobox')) || format === 'clash') {
							suburl = `https://${subconverter}/sub?target=clash&url=https%3A%2F%2F${hostName}/bestip/${fakeUserID}%3Fhost%3D${fakeHostName}%26uuid%3D${fakeUserID}&insert=false&config=${encodeURIComponent(subconfig)}%26proxyip%3D${proxyIP}&emoji=true&list=false&tfo=false&scv=true&fdn=false&sort=false&new_name=true`;
						} else if ((userAgent.includes('sing-box') || userAgent.includes('singbox')) || format === 'singbox') {
							suburl = `https://${subconverter}/sub?target=singbox&url=https%3A%2F%2F${hostName}/bestip/${fakeUserID}%3Fhost%3D${fakeHostName}%26uuid%3D${fakeUserID}&insert=false&config=${encodeURIComponent(subconfig)}%26proxyip%3D${proxyIP}&emoji=true&list=false&tfo=false&scv=true&fdn=false&sort=false&new_name=true`;
						} else if (format === 'qx') {
							const newAddressesapi = await getAddressesapi(addressesapi);
							const vlessSubConfig = createVlessBestIpSub(userID, request.headers.get('Host'), newAddressesapi, format);
							return new Response(vlessSubConfig, {
								headers: {
									// "Content-Disposition": `attachment; filename*=utf-8''${encodeURIComponent(FileName)}; filename=${FileName}`,
									"content-type": "text/plain; charset=utf-8",
									"Profile-Update-Interval": `${SUBUpdateTime}`,
									"Subscription-Userinfo": `upload=${UD}; download=${UD}; total=${total}; expire=${expire}`,
								},
							});
						} else {
							suburl = `https://${sub}/bestip/${fakeUserID}?host=${fakeHostName}&uuid=${fakeUserID}&proxyip=${proxyIP}`;
							isBase64 = true;
						}
						try {
							const response = await fetch(suburl, {
								headers: {
									'User-Agent': 'ansoncloud8.github.io'
								}
							});
							content = await response.text();
							const result = revertFakeInfo(content, userID_Path, hostName, isBase64);

							// content.replace(new RegExp(fakeUserID, 'g'), userID)
							return new Response(result, {
								headers: {
									// "Content-Disposition": `attachment; filename*=utf-8''${encodeURIComponent(FileName)}; filename=${FileName}`,
									"content-type": "text/plain; charset=utf-8",
									"Profile-Update-Interval": `${SUBUpdateTime}`,
									"Subscription-Userinfo": `upload=${UD}; download=${UD}; total=${total}; expire=${expire}`,
								},
							});
						} catch (error) {
							console.error('Error fetching content:', error);
							return `Error fetching content: ${error.message}`;
						}
					};
					default:
						// return new Response('Not found', { status: 404 });
						//Change the home page to an nginx disguise page
						return new Response(await nginx(), {
							headers: {
								'Content-Type': 'text/html; charset=UTF-8',
								'referer': 'https://www.google.com/search?q=ansoncloud8.github.io',
							},
						});

					// For any other path, reverse proxy to 'ramdom website' and return the original response, caching it in the process
					// const randomHostname = cn_hostnames[Math.floor(Math.random() * cn_hostnames.length)];
					// const newHeaders = new Headers(request.headers);
					// newHeaders.set('cf-connecting-ip', '1.2.3.4');
					// newHeaders.set('x-forwarded-for', '1.2.3.4');
					// newHeaders.set('x-real-ip', '1.2.3.4');
					// newHeaders.set('referer', 'https://www.google.com/search?q=ansoncloud8.github.io');
					// // Use fetch to proxy the request to 15 different domains
					// const proxyUrl = 'https://' + randomHostname + url.pathname + url.search;
					// let modifiedRequest = new Request(proxyUrl, {
					// 	method: request.method,
					// 	headers: newHeaders,
					// 	body: request.body,
					// 	redirect: 'manual',
					// });
					// const proxyResponse = await fetch(modifiedRequest, { redirect: 'manual' });
					// // Check for 302 or 301 redirect status and return an error response
					// if ([301, 302].includes(proxyResponse.status)) {
					// 	return new Response(`Redirects to ${randomHostname} are not allowed.`, {
					// 		status: 403,
					// 		statusText: 'Forbidden',
					// 	});
					// }
					// // Return the response from the proxy server
					// return proxyResponse;
				}
			} else {
				return await vlessOverWSHandler(request);
			}
		} catch (err) {
			/** @type {Error} */ let e = err;
			return new Response(e.toString());
		}
	},
};

export async function uuid_validator(request) {
	const hostname = request.headers.get('Host');
	const currentDate = new Date();

	const subdomain = hostname.split('.')[0];
	const year = currentDate.getFullYear();
	const month = String(currentDate.getMonth() + 1).padStart(2, '0');
	const day = String(currentDate.getDate()).padStart(2, '0');

	const formattedDate = `${year}-${month}-${day}`;

	// const daliy_sub = formattedDate + subdomain
	const hashHex = await hashHex_f(subdomain);
	// subdomain string contains timestamps utc and uuid string TODO.
	console.log(hashHex, subdomain, formattedDate);
}

export async function hashHex_f(string) {
	const encoder = new TextEncoder();
	const data = encoder.encode(string);
	const hashBuffer = await crypto.subtle.digest('SHA-256', data);
	const hashArray = Array.from(new Uint8Array(hashBuffer));
	const hashHex = hashArray.map(byte => byte.toString(16).padStart(2, '0')).join('');
	return hashHex;
}

/**
 * Handles VLESS over WebSocket requests by creating a WebSocket pair, accepting the WebSocket connection, and processing the VLESS header.
 * @param {import("@cloudflare/workers-types").Request} request The incoming request object.
 * @returns {Promise<Response>} A Promise that resolves to a WebSocket response object.
 */
async function vlessOverWSHandler(request) {
	const webSocketPair = new WebSocketPair();
	const [client, webSocket] = Object.values(webSocketPair);
	webSocket.accept();

	let address = '';
	let portWithRandomLog = '';
	let currentDate = new Date();
	const log = (/** @type {string} */ info, /** @type {string | undefined} */ event) => {
		console.log(`[${currentDate} ${address}:${portWithRandomLog}] ${info}`, event || '');
	};
	const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';

	const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);

	/** @type {{ value: import("@cloudflare/workers-types").Socket | null}}*/
	let remoteSocketWapper = {
		value: null,
	};
	let udpStreamWrite = null;
	let isDns = false;

	// ws --> remote
	readableWebSocketStream.pipeTo(new WritableStream({
		async write(chunk, controller) {
			if (isDns && udpStreamWrite) {
				return udpStreamWrite(chunk);
			}
			if (remoteSocketWapper.value) {
				const writer = remoteSocketWapper.value.writable.getWriter()
				await writer.write(chunk);
				writer.releaseLock();
				return;
			}

			const {
				hasError,
				message,
				portRemote = 443,
				addressRemote = '',
				rawDataIndex,
				vlessVersion = new Uint8Array([0, 0]),
				isUDP,
			} = processVlessHeader(chunk, userID);
			address = addressRemote;
			portWithRandomLog = `${portRemote} ${isUDP ? 'udp' : 'tcp'} `;
			if (hasError) {
				// controller.error(message);
				throw new Error(message); // cf seems has bug, controller.error will not end stream
			}

			// If UDP and not DNS port, close it
			if (isUDP && portRemote !== 53) {
				throw new Error('UDP proxy only enabled for DNS which is port 53');
				// cf seems has bug, controller.error will not end stream
			}

			if (isUDP && portRemote === 53) {
				isDns = true;
			}

			// ["version", "附加信息长度 N"]
			const vlessResponseHeader = new Uint8Array([vlessVersion[0], 0]);
			const rawClientData = chunk.slice(rawDataIndex);

			// TODO: support udp here when cf runtime has udp support
			if (isDns) {
				const { write } = await handleUDPOutBound(webSocket, vlessResponseHeader, log);
				udpStreamWrite = write;
				udpStreamWrite(rawClientData);
				return;
			}
			handleTCPOutBound(remoteSocketWapper, addressRemote, portRemote, rawClientData, webSocket, vlessResponseHeader, log);
		},
		close() {
			log(`readableWebSocketStream is close`);
		},
		abort(reason) {
			log(`readableWebSocketStream is abort`, JSON.stringify(reason));
		},
	})).catch((err) => {
		log('readableWebSocketStream pipeTo error', err);
	});

	return new Response(null, {
		status: 101,
		webSocket: client,
	});
}

/**
 * Handles outbound TCP connections.
 *
 * @param {any} remoteSocket
 * @param {string} addressRemote The remote address to connect to.
 * @param {number} portRemote The remote port to connect to.
 * @param {Uint8Array} rawClientData The raw client data to write.
 * @param {import("@cloudflare/workers-types").WebSocket} webSocket The WebSocket to pass the remote socket to.
 * @param {Uint8Array} vlessResponseHeader The VLESS response header.
 * @param {function} log The logging function.
 * @returns {Promise<void>} The remote socket.
 */
async function handleTCPOutBound(remoteSocket, addressRemote, portRemote, rawClientData, webSocket, vlessResponseHeader, log,) {

	/**
	 * Connects to a given address and port and writes data to the socket.
	 * @param {string} address The address to connect to.
	 * @param {number} port The port to connect to.
	 * @returns {Promise<import("@cloudflare/workers-types").Socket>} A Promise that resolves to the connected socket.
	 */
	async function connectAndWrite(address, port) {
		/** @type {import("@cloudflare/workers-types").Socket} */
		const tcpSocket = connect({
			hostname: address,
			port: port,
		});
		remoteSocket.value = tcpSocket;
		log(`connected to ${address}:${port}`);
		const writer = tcpSocket.writable.getWriter();
		await writer.write(rawClientData); // first write, nomal is tls client hello
		writer.releaseLock();
		return tcpSocket;
	}

	/**
	 * Retries connecting to the remote address and port if the Cloudflare socket has no incoming data.
	 * @returns {Promise<void>} A Promise that resolves when the retry is complete.
	 */
	async function retry() {
		const tcpSocket = await connectAndWrite(proxyIP || addressRemote, portRemote)
		tcpSocket.closed.catch(error => {
			console.log('retry tcpSocket closed error', error);
		}).finally(() => {
			safeCloseWebSocket(webSocket);
		})
		remoteSocketToWS(tcpSocket, webSocket, vlessResponseHeader, null, log);
	}

	const tcpSocket = await connectAndWrite(addressRemote, portRemote);

	// when remoteSocket is ready, pass to websocket
	// remote--> ws
	remoteSocketToWS(tcpSocket, webSocket, vlessResponseHeader, retry, log);
}

/**
 * Creates a readable stream from a WebSocket server, allowing for data to be read from the WebSocket.
 * @param {import("@cloudflare/workers-types").WebSocket} webSocketServer The WebSocket server to create the readable stream from.
 * @param {string} earlyDataHeader The header containing early data for WebSocket 0-RTT.
 * @param {(info: string)=> void} log The logging function.
 * @returns {ReadableStream} A readable stream that can be used to read data from the WebSocket.
 */
function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
	let readableStreamCancel = false;
	const stream = new ReadableStream({
		start(controller) {
			webSocketServer.addEventListener('message', (event) => {
				const message = event.data;
				controller.enqueue(message);
			});

			webSocketServer.addEventListener('close', () => {
				safeCloseWebSocket(webSocketServer);
				controller.close();
			});

			webSocketServer.addEventListener('error', (err) => {
				log('webSocketServer has error');
				controller.error(err);
			});
			const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
			if (error) {
				controller.error(error);
			} else if (earlyData) {
				controller.enqueue(earlyData);
			}
		},

		pull(controller) {
			// if ws can stop read if stream is full, we can implement backpressure
			// https://streams.spec.whatwg.org/#example-rs-push-backpressure
		},

		cancel(reason) {
			log(`ReadableStream was canceled, due to ${reason}`)
			readableStreamCancel = true;
			safeCloseWebSocket(webSocketServer);
		}
	});

	return stream;
}

// https://xtls.github.io/development/protocols/vless.html
// https://github.com/zizifn/excalidraw-backup/blob/main/v2ray-protocol.excalidraw

/**
 * Processes the VLESS header buffer and returns an object with the relevant information.
 * @param {ArrayBuffer} vlessBuffer The VLESS header buffer to process.
 * @param {string} userID The user ID to validate against the UUID in the VLESS header.
 * @returns {{
 *  hasError: boolean,
 *  message?: string,
 *  addressRemote?: string,
 *  addressType?: number,
 *  portRemote?: number,
 *  rawDataIndex?: number,
 *  vlessVersion?: Uint8Array,
 *  isUDP?: boolean
 * }} An object with the relevant information extracted from the VLESS header buffer.
 */
function processVlessHeader(vlessBuffer, userID) {
	if (vlessBuffer.byteLength < 24) {
		return {
			hasError: true,
			message: 'invalid data',
		};
	}

	const version = new Uint8Array(vlessBuffer.slice(0, 1));
	let isValidUser = false;
	let isUDP = false;
	const slicedBuffer = new Uint8Array(vlessBuffer.slice(1, 17));
	const slicedBufferString = stringify(slicedBuffer);
	// check if userID is valid uuid or uuids split by , and contains userID in it otherwise return error message to console
	const uuids = userID.includes(',') ? userID.split(",") : [userID];
	// uuid_validator(hostName, slicedBufferString);


	// isValidUser = uuids.some(userUuid => slicedBufferString === userUuid.trim());
	isValidUser = uuids.some(userUuid => slicedBufferString === userUuid.trim()) || uuids.length === 1 && slicedBufferString === uuids[0].trim();

	console.log(`userID: ${slicedBufferString}`);

	if (!isValidUser) {
		return {
			hasError: true,
			message: 'invalid user',
		};
	}

	const optLength = new Uint8Array(vlessBuffer.slice(17, 18))[0];
	//skip opt for now

	const command = new Uint8Array(
		vlessBuffer.slice(18 + optLength, 18 + optLength + 1)
	)[0];

	// 0x01 TCP
	// 0x02 UDP
	// 0x03 MUX
	if (command === 1) {
		isUDP = false;
	} else if (command === 2) {
		isUDP = true;
	} else {
		return {
			hasError: true,
			message: `command ${command} is not support, command 01-tcp,02-udp,03-mux`,
		};
	}
	const portIndex = 18 + optLength + 1;
	const portBuffer = vlessBuffer.slice(portIndex, portIndex + 2);
	// port is big-Endian in raw data etc 80 == 0x005d
	const portRemote = new DataView(portBuffer).getUint16(0);

	let addressIndex = portIndex + 2;
	const addressBuffer = new Uint8Array(
		vlessBuffer.slice(addressIndex, addressIndex + 1)
	);

	// 1–> ipv4  addressLength =4
	// 2–> domain name addressLength=addressBuffer[1]
	// 3–> ipv6  addressLength =16
	const addressType = addressBuffer[0];
	let addressLength = 0;
	let addressValueIndex = addressIndex + 1;
	let addressValue = '';
	switch (addressType) {
		case 1:
			addressLength = 4;
			addressValue = new Uint8Array(
				vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)
			).join('.');
			break;
		case 2:
			addressLength = new Uint8Array(
				vlessBuffer.slice(addressValueIndex, addressValueIndex + 1)
			)[0];
			addressValueIndex += 1;
			addressValue = new TextDecoder().decode(
				vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)
			);
			break;
		case 3:
			addressLength = 16;
			const dataView = new DataView(
				vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)
			);
			// 2001:0db8:85a3:0000:0000:8a2e:0370:7334
			const ipv6 = [];
			for (let i = 0; i < 8; i++) {
				ipv6.push(dataView.getUint16(i * 2).toString(16));
			}
			addressValue = ipv6.join(':');
			// seems no need add [] for ipv6
			break;
		default:
			return {
				hasError: true,
				message: `invild  addressType is ${addressType}`,
			};
	}
	if (!addressValue) {
		return {
			hasError: true,
			message: `addressValue is empty, addressType is ${addressType}`,
		};
	}

	return {
		hasError: false,
		addressRemote: addressValue,
		addressType,
		portRemote,
		rawDataIndex: addressValueIndex + addressLength,
		vlessVersion: version,
		isUDP,
	};
}


/**
 * Converts a remote socket to a WebSocket connection.
 * @param {import("@cloudflare/workers-types").Socket} remoteSocket The remote socket to convert.
 * @param {import("@cloudflare/workers-types").WebSocket} webSocket The WebSocket to connect to.
 * @param {ArrayBuffer | null} vlessResponseHeader The VLESS response header.
 * @param {(() => Promise<void>) | null} retry The function to retry the connection if it fails.
 * @param {(info: string) => void} log The logging function.
 * @returns {Promise<void>} A Promise that resolves when the conversion is complete.
 */
async function remoteSocketToWS(remoteSocket, webSocket, vlessResponseHeader, retry, log) {
	// remote--> ws
	let remoteChunkCount = 0;
	let chunks = [];
	/** @type {ArrayBuffer | null} */
	let vlessHeader = vlessResponseHeader;
	let hasIncomingData = false; // check if remoteSocket has incoming data
	await remoteSocket.readable
		.pipeTo(
			new WritableStream({
				start() {
				},
				/**
				 *
				 * @param {Uint8Array} chunk
				 * @param {*} controller
				 */
				async write(chunk, controller) {
					hasIncomingData = true;
					remoteChunkCount++;
					if (webSocket.readyState !== WS_READY_STATE_OPEN) {
						controller.error(
							'webSocket.readyState is not open, maybe close'
						);
					}
					if (vlessHeader) {
						webSocket.send(await new Blob([vlessHeader, chunk]).arrayBuffer());
						vlessHeader = null;
					} else {
						// console.log(`remoteSocketToWS send chunk ${chunk.byteLength}`);
						// seems no need rate limit this, CF seems fix this??..
						// if (remoteChunkCount > 20000) {
						// 	// cf one package is 4096 byte(4kb),  4096 * 20000 = 80M
						// 	await delay(1);
						// }
						webSocket.send(chunk);
					}
				},
				close() {
					log(`remoteConnection!.readable is close with hasIncomingData is ${hasIncomingData}`);
					// safeCloseWebSocket(webSocket); // no need server close websocket frist for some case will casue HTTP ERR_CONTENT_LENGTH_MISMATCH issue, client will send close event anyway.
				},
				abort(reason) {
					console.error(`remoteConnection!.readable abort`, reason);
				},
			})
		)
		.catch((error) => {
			console.error(
				`remoteSocketToWS has exception `,
				error.stack || error
			);
			safeCloseWebSocket(webSocket);
		});

	// seems is cf connect socket have error,
	// 1. Socket.closed will have error
	// 2. Socket.readable will be close without any data coming
	if (hasIncomingData === false && retry) {
		log(`retry`)
		retry();
	}
}

/**
 * Decodes a base64 string into an ArrayBuffer.
 * @param {string} base64Str The base64 string to decode.
 * @returns {{earlyData: ArrayBuffer|null, error: Error|null}} An object containing the decoded ArrayBuffer or null if there was an error, and any error that occurred during decoding or null if there was no error.
 */
function base64ToArrayBuffer(base64Str) {
	if (!base64Str) {
		return { earlyData: null, error: null };
	}
	try {
		// go use modified Base64 for URL rfc4648 which js atob not support
		base64Str = base64Str.replace(/-/g, '+').replace(/_/g, '/');
		const decode = atob(base64Str);
		const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
		return { earlyData: arryBuffer.buffer, error: null };
	} catch (error) {
		return { earlyData: null, error };
	}
}

/**
 * Checks if a given string is a valid UUID.
 * Note: This is not a real UUID validation.
 * @param {string} uuid The string to validate as a UUID.
 * @returns {boolean} True if the string is a valid UUID, false otherwise.
 */
function isValidUUID(uuid) {
	const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
	return uuidRegex.test(uuid);
}

const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;
/**
 * Closes a WebSocket connection safely without throwing exceptions.
 * @param {import("@cloudflare/workers-types").WebSocket} socket The WebSocket connection to close.
 */
function safeCloseWebSocket(socket) {
	try {
		if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
			socket.close();
		}
	} catch (error) {
		console.error('safeCloseWebSocket error', error);
	}
}

const byteToHex = [];

for (let i = 0; i < 256; ++i) {
	byteToHex.push((i + 256).toString(16).slice(1));
}

function unsafeStringify(arr, offset = 0) {
	return (byteToHex[arr[offset + 0]] + byteToHex[arr[offset + 1]] + byteToHex[arr[offset + 2]] + byteToHex[arr[offset + 3]] + "-" + byteToHex[arr[offset + 4]] + byteToHex[arr[offset + 5]] + "-" + byteToHex[arr[offset + 6]] + byteToHex[arr[offset + 7]] + "-" + byteToHex[arr[offset + 8]] + byteToHex[arr[offset + 9]] + "-" + byteToHex[arr[offset + 10]] + byteToHex[arr[offset + 11]] + byteToHex[arr[offset + 12]] + byteToHex[arr[offset + 13]] + byteToHex[arr[offset + 14]] + byteToHex[arr[offset + 15]]).toLowerCase();
}

function stringify(arr, offset = 0) {
	const uuid = unsafeStringify(arr, offset);
	if (!isValidUUID(uuid)) {
		throw TypeError("Stringified UUID is invalid");
	}
	return uuid;
}


/**
 * Handles outbound UDP traffic by transforming the data into DNS queries and sending them over a WebSocket connection.
 * @param {import("@cloudflare/workers-types").WebSocket} webSocket The WebSocket connection to send the DNS queries over.
 * @param {ArrayBuffer} vlessResponseHeader The VLESS response header.
 * @param {(string) => void} log The logging function.
 * @returns {{write: (chunk: Uint8Array) => void}} An object with a write method that accepts a Uint8Array chunk to write to the transform stream.
 */
async function handleUDPOutBound(webSocket, vlessResponseHeader, log) {

	let isVlessHeaderSent = false;
	const transformStream = new TransformStream({
		start(controller) {

		},
		transform(chunk, controller) {
			// udp message 2 byte is the the length of udp data
			// TODO: this should have bug, beacsue maybe udp chunk can be in two websocket message
			for (let index = 0; index < chunk.byteLength;) {
				const lengthBuffer = chunk.slice(index, index + 2);
				const udpPakcetLength = new DataView(lengthBuffer).getUint16(0);
				const udpData = new Uint8Array(
					chunk.slice(index + 2, index + 2 + udpPakcetLength)
				);
				index = index + 2 + udpPakcetLength;
				controller.enqueue(udpData);
			}
		},
		flush(controller) {
		}
	});

	// only handle dns udp for now
	transformStream.readable.pipeTo(new WritableStream({
		async write(chunk) {
			const resp = await fetch(dohURL, // dns server url
				{
					method: 'POST',
					headers: {
						'content-type': 'application/dns-message',
					},
					body: chunk,
				})
			const dnsQueryResult = await resp.arrayBuffer();
			const udpSize = dnsQueryResult.byteLength;
			// console.log([...new Uint8Array(dnsQueryResult)].map((x) => x.toString(16)));
			const udpSizeBuffer = new Uint8Array([(udpSize >> 8) & 0xff, udpSize & 0xff]);
			if (webSocket.readyState === WS_READY_STATE_OPEN) {
				log(`doh success and dns message length is ${udpSize}`);
				if (isVlessHeaderSent) {
					webSocket.send(await new Blob([udpSizeBuffer, dnsQueryResult]).arrayBuffer());
				} else {
					webSocket.send(await new Blob([vlessResponseHeader, udpSizeBuffer, dnsQueryResult]).arrayBuffer());
					isVlessHeaderSent = true;
				}
			}
		}
	})).catch((error) => {
		log('dns udp has error' + error)
	});

	const writer = transformStream.writable.getWriter();

	return {
		/**
		 *
		 * @param {Uint8Array} chunk
		 */
		write(chunk) {
			writer.write(chunk);
		}
	};
}

async function ADD(envadd) {
	var addtext = envadd.replace(/[	|"'\r\n]+/g, ',').replace(/,+/g, ',');	// Replace spaces, double quotes, single quotes, and newline characters with commas
	//console.log(addtext);
	if (addtext.charAt(0) == ',') addtext = addtext.slice(1);
	if (addtext.charAt(addtext.length - 1) == ',') addtext = addtext.slice(0, addtext.length - 1);
	const add = addtext.split(',');
	// console.log(add);
	return add;
}

async function getAddressesapi(api) {
	if (!api || api.length === 0) {
		return [];
	}

	let newapi = "";

	// Create an AbortController object to control the cancellation of the fetch request
	const controller = new AbortController();

	const timeout = setTimeout(() => {
		controller.abort(); // Cancel all requests
	}, 2000); // Triggered after 2 seconds

	try {
		// Use Promise.allSettled to wait for all API requests to complete, regardless of success or failure
// Traverse the api array and initiate a fetch request for each API address
		const responses = await Promise.allSettled(api.map(apiUrl => fetch(apiUrl, {
			method: 'get',
			headers: {
				'Accept': 'text/html,application/xhtml+xml,application/xml;',
				'User-Agent': 'ansoncloud8.github.io'
			},
			signal: controller.signal // Add an AbortController semaphore to the fetch request so that the request can be canceled if needed.
		}).then(response => response.ok ? response.text() : Promise.reject())));

		// Iterate through all responses
		for (const response of responses) {
			// Check if the response status is'fulfilled'，The request is completed successfully
			if (response.status === 'fulfilled') {
				// Get the content of the response
				const content = await response.value;
				newapi += content + '\n';
			}
		}
	} catch (error) {
		console.error(error);
	} finally {
		// Regardless of success or failure, the set timeout timer is cleared at the end
		clearTimeout(timeout);
	}

	const newAddressesapi = await ADD(newapi);

	// Return the processed result
	return newAddressesapi;
}


function generateRandomString() {
	let minLength = 2;
	let maxLength = 3;
	let length = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
	let characters = 'abcdefghijklmnopqrstuvwxyz';
	let result = '';
	for (let i = 0; i < length; i++) {
		result += characters[Math.floor(Math.random() * characters.length)];
	}
	return result;
}

function generateUUID() {
	let uuid = '';
	for (let i = 0; i < 32; i++) {
		let num = Math.floor(Math.random() * 16);
		if (num < 10) {
			uuid += num;
		} else {
			uuid += String.fromCharCode(num + 55);
		}
	}
	return uuid.replace(/(.{8})(.{4})(.{4})(.{4})(.{12})/, '$1-$2-$3-$4-$5').toLowerCase();
}

function generateRandomNumber() {
	let minNum = 100000;
	let maxNum = 999999;
	return Math.floor(Math.random() * (maxNum - minNum + 1)) + minNum;
}

function revertFakeInfo(content, userID, hostName, isBase64) {
	if (isBase64) content = atob(content);//Base64coding
	content = content.replace(new RegExp(fakeUserID, 'g'), userID).replace(new RegExp(fakeHostName, 'g'), hostName);
	if (isBase64) content = btoa(content);//Base64coding
	return content;
}

/**
 *
 * @param {string} userID - single or comma separated userIDs
 * @param {string | null} hostName
 * @returns {string}
 */
function getVLESSConfig(userIDs, hostName) {
	const commonUrlPart = `:443?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2048#${hostName}`;
	const hashSeparator = "################################################################";

	// Split the userIDs into an array
	const userIDArray = userIDs.split(",");

	// Prepare output string for each userID
	const output = userIDArray.map((userID) => {
		const vlessMain = 'vless://' + userID + '@' + hostName + commonUrlPart;
		const vlessSec = 'vless://' + userID + '@' + proxyIP + commonUrlPart;
		return `################################################################
Telegram Channel!
t.me/nkka_404
---------------------------------------------------------------
Contact to developer
t.me/nkka404
---------------------------------------------------------------
Developed by 4̷ ̷ ̷4̷
################################################################
<h2>UUID: ${userID}</h2>\n<button onclick='copyToClipboard("${userID}")'><i class="fa fa-clipboard"></i> Copy UUID</button>
---------------------------------------------------------------
💠V2ray Default IP💠
---------------------------------------------------------------
${vlessMain}
<button onclick='copyToClipboard("${vlessMain}")'><i class="fa fa-clipboard"></i> Copy vlessMain</button>
---------------------------------------------------------------
💠V2ray With Best IP💠
---------------------------------------------------------------
${vlessSec}
<button onclick='copyToClipboard("${vlessSec}")'><i class="fa fa-clipboard"></i> Copy vlessSec</button>
---------------------------------------------------------------
💠Clash-Meta💠
---------------------------------------------------------------
- type: vless
  name: ${hostName}
  server: ${hostName}
  port: 443
  uuid: ${userID}
  network: ws
  tls: true
  udp: false
  sni: ${hostName}
  client-fingerprint: chrome
  ws-opts:
  path: "/?ed=2048"
  headers:
    host: ${hostName}
---------------------------------------------------------------
################################################################
`;
	}).join('\n');
	const sublink = `https://${hostName}/sub/${userIDArray[0]}`
	const subbestip = `https://${hostName}/bestip/${userIDArray[0]}?uuid=${userIDArray[0]}`;
	const singboxlink = `https://${hostName}/sub/bestip/${userIDArray[0]}?format=singbox&uuid=${fakeUserID}`;
	const quantumultxlink = `https://${hostName}/sub/bestip/${userIDArray[0]}?format=qx&uuid=${fakeUserID}`;
	const clashlink = `https://${hostName}/sub/bestip/${userIDArray[0]}?format=clash&uuid=${fakeUserID}`;
	// Prepare header string

	// Prepare header string
	const header = `
<p align='center'><img src='https://github.com/nyeinkokoaung404/onlyforyou/blob/480a5b3bcc7f7862c6a1f69a61c34f4b9bf4dcdf/assets/onlyforyouall.png?raw=true' alt='' width="150" height="150" style='margin-bottom: -0px;'>
<b style='font-size: 15px;'>Welcome! This function generates configuration for 404 protocol. If you found this useful, please join our Telegram channel for more:</b>
<b style='font-size: 15px;'>ONLY/:FORYOU&ALL</b>
<a href='https://t.me/Pmttg' style="color: #fff;font-size: 15px;background-color: #5cb85c;" target='_blank'>Click To Join Telegram Channel</a>
<div oninput="generateShellCode()" class="row g-2 mt-2">
<div class="form-control">
<a href='${subbestip}' target='_blank'>VLESS node subscription connection (V2rayU, V2rayN and other tools) preferred IP</a><br>
<button onclick='copyToClipboard("${subbestip}")'><i class="fa fa-clipboard"></i> Copy Vless Node Subscription</button><br>
<a href='https://t.me/nkka404' style="color: #fff;font-size: 10px;background-color: #f90083;" target='_blank'>xxxxxxxxxxxxxxxxxxxxxxxxx</a>
<button type="reset" onclick="window.open('https://apps.apple.com/app/id6446814690')" class="button">V2BOX VPN(Apple IOS)</button>
<a href='https://t.me/nkka404' style="color: #fff;font-size: 10px;background-color: #f90083;" target='_blank'>xxxxxxxxxxxxxxxxxxxxxxxxx</a>
<button type="reset" onclick="window.open('https://play.google.com/store/apps/details?id=com.v2ray.ang')" class="button">V2RayNG VPN(Android)</button></div></p>`;
	// HTML Head with CSS and FontAwesome library
	const htmlHead = `
  <head>
	<title>tunnel: VLESS configuration</title>
	<meta name='description' content='This is a tool for generating VLESS protocol configurations. Give us a star on GitHub https://ansoncloud8.github.io if you found it useful!'>
	<style>
	body {
	  font-family: Arial, sans-serif;
	  background-color: #f0f0f0;
	  color: #333;
	  padding: 10px;
	}

	a {
	  color: #1a0dab;
	  text-decoration: none;
	}
	img {
	  max-width: 100%;
	  height: auto;
	}

	pre {
	  white-space: pre-wrap;
	  word-wrap: break-word;
	  background-color: #fff;
	  border: 1px solid #ddd;
	  padding: 10px;
	  margin: 10px 0;
	}
	/* Dark mode */
	@media (prefers-color-scheme: dark) {
	  body {
		background-color: #333;
		color: #f0f0f0;
	  }

	  a {
		color: #9db4ff;
	  }

	  pre {
		background-color: #282a36;
		border-color: #6272a4;
	  }
	}
	</style>

	<!-- Add FontAwesome library -->
	<link rel='stylesheet' href='https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css'>
  </head>
  `;

	// Join output with newlines, wrap inside <html> and <body>
	return `
  <html>
  ${htmlHead}
  <body>
  <pre style='background-color: transparent; border: none;'>${header}</pre>
  <pre>${output}</pre>
  </body>
  <script>
	function copyToClipboard(text) {
	  navigator.clipboard.writeText(text)
		.then(() => {
		  alert("Copied to clipboard");
		})
		.catch((err) => {
		  console.error("Failed to copy to clipboard:", err);
		});
	}
  </script>
  </html>`;
}

let portSet_http = new Set([80, 8080, 8880, 2052, 2086, 2095, 2082]);
let portSet_https = new Set([443, 8443, 2053, 2096, 2087, 2083]);

function createVLESSSub(userID_Path, hostName, format, dq) {
	const userIDArray = userID_Path.includes(',') ? userID_Path.split(',') : [userID_Path];
	const commonUrlPart_http = `?encryption=none&security=none&fp=random&type=ws&host=${hostName}&path=%2F%3Fed%3D2048#`;
	const commonUrlPart_https = `?encryption=none&security=tls&sni=${hostName}&fp=random&type=ws&host=${hostName}&path=%2F%3Fed%3D2048#`;
	//trojan
	const trojan_http = `?alpn=http%2F1.1&security=none&fp=random&type=ws&host=${hostName}&path=%2F%3Fed%3D2048#`;
	const trojan_https = `?alpn=http%2F1.1&security=tls&sni=${hostName}&fp=random&type=ws&host=${hostName}&path=%2F%3Fed%3D2048#`;
//const trojanLink = `trojan://${密码}@${address}:${port}?security=tls&sni=${sni}&alpn=http%2F1.1&fp=randomized&type=ws&host=${伪装域名}&path=${encodeURIComponent(最终路径)}#${encodeURIComponent(addressid + 节点备注)}`;

	const output = userIDArray.flatMap((userID) => {
		if (format === 'qx') {
			var host = hostName.split('.').slice(1).join('.');
			const httpsConfigurations = Array.from(portSet_https).flatMap((port) => {
				if(dq){
					let tag = '📶 CF_' + port;
					//🇸🇬 SG：စင်္ကာပူ 🇭🇰 HK：ဟောင်ကောင် 🇰🇷 KR：တောင်ကိုရီးယား 🇯🇵 JP：ဂျပန် 🇬🇧 GB：ယူကေ 🇺🇸 US：ယူအက်စ်အေ 🇼🇸 TW：ထိုင်ဝမ်
					if (dq === 'SG') {
						tag = '🇸🇬 SG_' + port;
					} else if (dq === 'HK') {
						tag = '🇭🇰 HK_' + port;
					} else if (dq === 'KR') {
						tag = '🇰🇷 KR_' + port;
					} else if (dq === 'JP') {
						tag = '🇯🇵 JP_' + port;
					} else if (dq === 'GB') {
						tag = '🇬🇧 GB_' + port;
					} else if (dq === 'US') {
						tag = '🇺🇸 US_' + port;
					} else if (dq === 'TW') {
						tag = '🇼🇸 TW_' + port;
					} 
					const sgHttps = 'vless=' + dq.toLowerCase() + '.' + port + '.' + host + ':' + port + ',method=none,password=' + userID + ',obfs=wss,obfs-uri=/?ed=2048,obfs-host=' + hostName + ',tls-verification=true,tls-host=' + hostName + ',fast-open=false,udp-relay=false,tag=' + tag;
					return [sgHttps];
				}
				const sgHttps = 'vless=sg.' + port + '.' + host + ':' + port + ',method=none,password=' + userID + ',obfs=wss,obfs-uri=/?ed=2048,obfs-host=' + hostName + ',tls-verification=true,tls-host=' + hostName + ',fast-open=false,udp-relay=false,tag=🇸🇬 SG_' + port;
				const hkHttps = 'vless=hk.' + port + '.' + host + ':' + port + ',method=none,password=' + userID + ',obfs=wss,obfs-uri=/?ed=2048,obfs-host=' + hostName + ',tls-verification=true,tls-host=' + hostName + ',fast-open=false,udp-relay=false,tag=🇭🇰 HK_' + port;
				const krHttps = 'vless=kr.' + port + '.' + host + ':' + port + ',method=none,password=' + userID + ',obfs=wss,obfs-uri=/?ed=2048,obfs-host=' + hostName + ',tls-verification=true,tls-host=' + hostName + ',fast-open=false,udp-relay=false,tag=🇰🇷 KR_' + port;
				const jpHttps = 'vless=jp.' + port + '.' + host + ':' + port + ',method=none,password=' + userID + ',obfs=wss,obfs-uri=/?ed=2048,obfs-host=' + hostName + ',tls-verification=true,tls-host=' + hostName + ',fast-open=false,udp-relay=false,tag=🇯🇵 JP_' + port;
				const usHttps = 'vless=us.' + port + '.' + host + ':' + port + ',method=none,password=' + userID + ',obfs=wss,obfs-uri=/?ed=2048,obfs-host=' + hostName + ',tls-verification=true,tls-host=' + hostName + ',fast-open=false,udp-relay=false,tag=🇺🇸 US_' + port;
				const twHttps = 'vless=tw.' + port + '.' + host + ':' + port + ',method=none,password=' + userID + ',obfs=wss,obfs-uri=/?ed=2048,obfs-host=' + hostName + ',tls-verification=true,tls-host=' + hostName + ',fast-open=false,udp-relay=false,tag=🇼🇸 TW_' + port;
				const cfHttps = 'vless=cf.' + port + '.' + host + ':' + port + ',method=none,password=' + userID + ',obfs=wss,obfs-uri=/?ed=2048,obfs-host=' + hostName + ',tls-verification=true,tls-host=' + hostName + ',fast-open=false,udp-relay=false,tag=📶 CF_' + port;
				return [sgHttps, hkHttps, krHttps, jpHttps, usHttps, twHttps, cfHttps];
			});
			
			return [...httpsConfigurations];
		} else if (format === 'trojan') {
			const httpConfigurations = Array.from(portSet_http).flatMap((port) => {
				if (!hostName.includes('pages.dev')) {
					const urlPart = tagName + ` (${hostName}-HTTP-${port})`;
					const vlessMainHttp = 'trojan://' + userID + '@' + hostName + ':' + port + trojan_http + urlPart;
					return autoaddress.flatMap((proxyIP) => {
						const vlessSecHttp = 'trojan://' + userID + '@' + proxyIP + ':' + port + trojan_https + urlPart + '-' + proxyIP;
						return [vlessMainHttp, vlessSecHttp];
					});
				}
				return [];
			});

			const httpsConfigurations = Array.from(portSet_https).flatMap((port) => {
				const urlPart = tagName + ` (${hostName}-HTTPS-${port})`;
				const vlessMainHttps = 'trojan://' + userID + '@' + hostName + ':' + port + trojan_http + urlPart;
				return autoaddress.flatMap((proxyIP) => {
					const vlessSecHttps = 'trojan://' + userID + '@' + proxyIP + ':' + port + trojan_https + urlPart + '-' + proxyIP;
					return [vlessMainHttps, vlessSecHttps];
				});
			});

			return [...httpConfigurations, ...httpsConfigurations];
			
		}else {
			const httpConfigurations = Array.from(portSet_http).flatMap((port) => {
				if (!hostName.includes('pages.dev')) {
					const urlPart = tagName + ` (${hostName}-HTTP-${port})`;
					const vlessMainHttp = 'vless://' + userID + '@' + hostName + ':' + port + commonUrlPart_http + urlPart;
					return autoaddress.flatMap((proxyIP) => {
						const vlessSecHttp = 'vless://' + userID + '@' + proxyIP + ':' + port + commonUrlPart_http + urlPart + '-' + proxyIP;
						return [vlessMainHttp, vlessSecHttp];
					});
				}
				return [];
			});

			const httpsConfigurations = Array.from(portSet_https).flatMap((port) => {
				const urlPart = tagName + ` (${hostName}-HTTPS-${port})`;
				const vlessMainHttps = 'vless://' + userID + '@' + hostName + ':' + port + commonUrlPart_https + urlPart;
				return autoaddress.flatMap((proxyIP) => {
					const vlessSecHttps = 'vless://' + userID + '@' + proxyIP + ':' + port + commonUrlPart_https + urlPart + '-' + proxyIP;
					return [vlessMainHttps, vlessSecHttps];
				});
			});

			return [...httpConfigurations, ...httpsConfigurations];
		}
	});

	return output.join('\n');
}

function createVlessBestIpSub(userID_Path, hostName, newAddressesapi, format) {

	addresses = addresses.concat(newAddressesapi);
	// Use Set object to remove duplicates
	const uniqueAddresses = [...new Set(addresses)];

	const responseBody = uniqueAddresses.map((address, i) => {
		let port = "443";
		let addressid = address;
		let dq = tagName;

		const match = addressid.match(regex);
		if (!match) {
			if (address.includes(':') && address.includes('#')) {
				const parts = address.split(':');
				address = parts[0];
				const subParts = parts[1].split('#');
				port = subParts[0];
				addressid = subParts[1];
			} else if (address.includes(':')) {
				const parts = address.split(':');
				address = parts[0];
				port = parts[1];
			} else if (address.includes('#')) {
				const parts = address.split('#');
				address = parts[0];
				addressid = parts[1];
			}

			if (addressid.includes(':')) {
				addressid = addressid.split(':')[0];
			}
		} else {
			address = match[1];
			port = match[2] || port;
			addressid = match[3] || address;
		}
		dq = addressid + '_' + i;
		//🇸🇬 SG: Singapore 🇭🇰 HK: Hong Kong 🇰🇷 KR: South Korea 🇯🇵 JP: Japan 🇬🇧 GB: United Kingdom 🇺🇸 US: United States 🇼🇸 TW: Taiwan
		if (addressid.includes('AM')) {
			addressid = addressid;
			dq = addressid;
		} else if (addressid === 'SG') {
			addressid = '🇸🇬 SG_' + i;
		} else if (addressid === 'HK') {
			addressid = '🇭🇰 HK_' + i;
		} else if (addressid === 'KR') {
			addressid = '🇰🇷 KR_' + i;
		} else if (addressid === 'JP') {
			addressid = '🇯🇵 JP_' + i;
		} else if (addressid === 'GB') {
			addressid = '🇬🇧 GB_' + i;
		} else if (addressid === 'US') {
			addressid = '🇺🇸 US_' + i;
		} else if (addressid === 'TW') {
			addressid = '🇼🇸 TW_' + i;
		} else if (addressid === 'CF') {
			addressid = '📶 ' + addressid + '_' + i;
		} else {
			addressid = '📶 ' + addressid + '_' + i;
			dq = tagName+ '_' + i;
		}
		
		let vlessLink = `vless://${userID_Path}@${address}:${port}?encryption=none&security=tls&sni=${hostName}&fp=random&type=ws&host=${hostName}&path=&path=%2F%3Fed%3D2048#${dq}`;
		if (port === '80' || port === '8080' || port === '8880' || port === '2052' || port === '2086' || port === '2095' || port === '2082' ) {
			vlessLink = `vless://${userID_Path}@${address}:${port}?encryption=none&security=&fp=random&type=ws&host=${hostName}&path=&path=%2F%3Fed%3D2048#${dq}`;
		}
		
		if (format === 'qx') {
			//80, 8080, 8880, 2052, 2086, 2095, 2082
			//443, 8443, 2053, 2096, 2087, 2083
			if (port === '80' || port === '8080' || port === '8880' || port === '2052' || port === '2086' || port === '2095' || port === '2082' ) {
				vlessLink = `vless=${address}:${port},method=none,password=${userID_Path},obfs=ws,obfs-uri=/?ed=2048,obfs-host=${hostName},fast-open=false,udp-relay=false,tag=${addressid}`;
			}else{
				vlessLink = `vless=${address}:${port},method=none,password=${userID_Path},obfs=wss,obfs-uri=/?ed=2048,obfs-host=${hostName},tls-verification=true,tls-host=${hostName},fast-open=false,udp-relay=false,tag=${addressid}`;
			}
		}
		//trojan
		if (format === 'trojan') {
			if (port === '80' || port === '8080' || port === '8880' || port === '2052' || port === '2086' || port === '2095' || port === '2082' ) {
				vlessLink = `trojan://${userID_Path}@${address}:${port}?alpn=http%2F1.1&security=tls&sni=${hostName}&fp=random&type=ws&host=${hostName}&path=&path=%2F%3Fed%3D2048#${dq}`;
			}else{
				vlessLink = `trojan://${userID_Path}@${address}:${port}?alpn=http%2F1.1&security=&fp=random&type=ws&host=${hostName}&path=&path=%2F%3Fed%3D2048#${dq}`;
			}
		}
		

		return vlessLink;
	}).join('\n');
	return responseBody;
}


async function nginx() {
	const text = `
	<!DOCTYPE html>
	<html>
	<head>
	<title>Welcome to 404</title>
	<style>
		body {
			width: 35em;
			margin: 0 auto;
			font-family: Tahoma, Verdana, Arial, sans-serif;
		}
	</style>
	</head>
	<body>
	<h1>Welcome to 4̷ ̷ ̷4̷!</h1>
	<p align='center'><img src='https://github.com/nyeinkokoaung404/onlyforyou/blob/480a5b3bcc7f7862c6a1f69a61c34f4b9bf4dcdf/assets/onlyforyouall.png?raw=true' alt='' width="150" height="150" style='margin-bottom: -0px;'>
	<b style='font-size: 15px;'>Welcome! This function generates configuration for 404 protocol. If you found this useful, please join our Telegram channel for more:</b>
	<b style='font-size: 15px;'>ONLY/:FORYOU&ALL</b>
	<p>If you see this page, web server is successfully installed and
	working. Further configuration is required.</p>

	<p>For online documentation and support please refer to
	<a href="http://t.me/nkka_404/">Telegram Channel</a>.<br/>

	<p><em>Thank you for using 🤪🤪.</em></p>
	</body>
	</html>
	`
	return text;
}