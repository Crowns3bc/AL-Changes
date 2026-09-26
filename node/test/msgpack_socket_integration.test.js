"use strict";

const assert = require("node:assert/strict");
const http = require("node:http");
const test = require("node:test");
const vm = require("node:vm");
const { Server } = require("socket.io");
const { io: connect } = require("socket.io-client");
const { RawFrame, createParser } = require("../json_parser");
const { load, read } = require("./helpers/server_vm");
const parserModule = require("../msgpack_parser");
const browserParser = require("../../js/socket.io-msgpack-parser.min.js");

function once(socket, event) {
	return new Promise((resolve, reject) => {
		const timeout = setTimeout(() => reject(new Error(`timed out waiting for ${event}`)), 3000);
		socket.once(event, (...args) => {
			clearTimeout(timeout);
			resolve(args);
		});
	});
}

test("shared fan-out and full entity packets reach JSON, polling and MessagePack clients", async (context) => {
	const httpServer = http.createServer();
	const c = vm.createContext({});
	const source = read("node/server.js");
	vm.runInContext(
		source.slice(source.indexOf("var socket_deflate ="), source.indexOf("var io = new SocketIOServer")),
		c,
	);
	const legacy = new Server(httpServer, { path: "/ws1/", parser: createParser(), perMessageDeflate: c.socket_deflate });
	const compact = new Server(httpServer, {
		path: "/ws1-msgpack/",
		transports: ["websocket"],
		maxHttpBufferSize: 64 * 1024,
		parser: parserModule.createParser({ maxPacketBytes: 64 * 1024 }),
		perMessageDeflate: c.socket_deflate,
	});
	c.game_ios = [legacy, compact];
	load(c, "node/server_functions.js", ["collect_fanout", "emit_fanout"]);
	const clients = [];
	context.after(() => {
		for (const client of clients) client.close();
		legacy.close();
		compact.close();
		httpServer.close();
	});
	for (const [index, server] of c.game_ios.entries()) {
		server.on("connection", (socket) => {
			socket.al_server_index = index;
			socket.on("echo", (value, acknowledge) => acknowledge(value));
		});
	}

	await new Promise((resolve) => httpServer.listen(0, "127.0.0.1", resolve));
	const address = `http://127.0.0.1:${httpServer.address().port}`;
	const legacyClient = connect(address, { path: "/ws1/", transports: ["websocket"], forceNew: true });
	const compactClient = connect(address, {
		path: "/ws1-msgpack/",
		transports: ["websocket"],
		parser: browserParser,
		forceNew: true,
	});
	const pollingClient = connect(address, { path: "/ws1/", transports: ["polling"], forceNew: true });
	const excludedClient = connect(address, { path: "/ws1/", transports: ["websocket"], forceNew: true });
	clients.push(legacyClient, compactClient, pollingClient, excludedClient);

	await Promise.all(clients.map((client) => once(client, "connect")));
	assert.match(legacyClient.io.engine.transport.ws.extensions, /permessage-deflate/);
	assert.match(compactClient.io.engine.transport.ws.extensions, /permessage-deflate/);
	const legacyAck = new Promise((resolve) => legacyClient.emit("echo", { transport: "json" }, resolve));
	const compactAck = new Promise((resolve) => compactClient.emit("echo", { transport: "msgpack" }, resolve));
	assert.deepEqual(await legacyAck, { transport: "json" });
	assert.deepEqual(await compactAck, { transport: "msgpack" });

	const legacyNotice = once(legacyClient, "notice");
	const compactNotice = once(compactClient, "notice");
	for (const server of [legacy, compact]) server.emit("notice", "shared");
	assert.deepEqual(await legacyNotice, ["shared"]);
	assert.deepEqual(await compactNotice, ["shared"]);

	let fanout,
		unexpected = 0;
	excludedClient.on("entities", () => unexpected++);
	for (const [server, client] of [
		[legacy, legacyClient],
		[compact, compactClient],
		[legacy, pollingClient],
	]) {
		fanout = c.collect_fanout(fanout, { socket: server.of("/").sockets.get(client.id) });
	}
	const value = {
		type: "xy",
		in: "main",
		map: "main",
		monsters: [],
		players: Array.from({ length: 150 }, (_, i) => ({
			id: `Peer${i}`,
			ctype: "mage",
			x: i,
			y: 0,
			hp: 100,
			moving: true,
			going_x: 300,
			going_y: 0,
			move_num: 1,
			s: {},
		})),
	};
	const deliveries = [legacyClient, compactClient, pollingClient].map((client) => once(client, "entities"));
	const barrier = once(excludedClient, "barrier");
	c.emit_fanout(fanout, "entities", new RawFrame(undefined, JSON.stringify(value)));
	legacy.emit("barrier");
	for (const delivery of await Promise.all(deliveries)) assert.deepEqual(delivery, [value]);
	await barrier;
	assert.equal(unexpected, 0, "grouped broadcasts must not widen the recipient set");
});
