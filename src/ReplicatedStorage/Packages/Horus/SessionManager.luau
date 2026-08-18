--!optimize 2
--!native

--[[

	Horus | A Framework Module with a lot of security layers to make your life easier
	Inspired on @CrusherFire Module Loader
	Heavily modified by @3xp0x3d

	All rights reserved © 2026, framework only available with a valid license gave by @3xp0x3d.

	DO NOT DISTIBRUTE.

]]

local Cryptography = require("@game/ReplicatedStorage/Packages/Cryptography")
local Bindable = require("./_Index/Bindable")

local MlKEM = Cryptography.Verification.MlKEM
local AES = Cryptography.Encryption.AES
local CSPRNG = Cryptography.Utilities.CSPRNG
local HKDF = Cryptography.Hashing.HKDF
local SHA256 = Cryptography.Hashing.SHA2.SHA256

local RunService = game:GetService("RunService")
local ReplicatedStorage = game:GetService("ReplicatedStorage")
local Players = game:GetService("Players")

local isServer = RunService:IsServer()

local HANDSHAKE_REMOTE_NAME = "__HorusHandshake"
local AES_KEY_LENGTH = 32
local NONCE_LENGTH = 12
local HKDF_BLOCK_SIZE = 64  
local HKDF_HASH_LENGTH = 32 

local INFO_AES_KEY = buffer.fromstring("HorusAESKey")
local INFO_BASE_NONCE = buffer.fromstring("HorusBaseNonce")

export type Session = {
	AESKey: buffer,
	BaseNonce: buffer,
	SendSeq: number,
	RecvSeq: number,
}

local serverSessions: { [Player]: Session } = {}
local pendingSecretKeys: { [Player]: buffer } = {}
local handshakeRatelimit: { [Player]: number } = {}
local clientSession: Session? = nil
local sessionReadySignal = Bindable.new()

local function deriveSessionKeys(sharedSecret: buffer, player: Player): (buffer, buffer)
	local salt = buffer.fromstring(tostring(player.UserId))

	local aesKey = HKDF(
		sharedSecret,
		salt,
		INFO_AES_KEY,
		AES_KEY_LENGTH,
		SHA256,
		HKDF_BLOCK_SIZE,
		HKDF_HASH_LENGTH
	)

	local baseNonce = HKDF(
		sharedSecret,
		salt,
		INFO_BASE_NONCE,
		NONCE_LENGTH,
		SHA256,
		HKDF_BLOCK_SIZE,
		HKDF_HASH_LENGTH
	)

	return aesKey, baseNonce
end

local function deriveNonce(baseNonce: buffer, seqId: number): buffer
	local nonce = buffer.create(NONCE_LENGTH)
	buffer.copy(nonce, 0, baseNonce, 0, 8)
	local baseWord = buffer.readu32(baseNonce, 8)
	buffer.writeu32(nonce, 8, bit32.bxor(baseWord, seqId))
	return nonce
end

local function scrubBuffer(buf: buffer)
	buffer.fill(buf, 0, 0, buffer.len(buf))
end

local SessionManager = {}

function SessionManager:GetSession(player: Player?): Session?
	if isServer then
		if player then
			return serverSessions[player]
		end
		return nil
	else
		return clientSession
	end
end

function SessionManager:WaitForSession(player: Player?): Session
	local session = self:GetSession(player)
	while not session do
		sessionReadySignal:Wait()
		session = self:GetSession(player)
	end
	return session
end

function SessionManager:Encrypt(session: Session, serializedData: buffer): (number, buffer, buffer)
	local seqId = session.SendSeq
	session.SendSeq += 1

	local nonce = deriveNonce(session.BaseNonce, seqId)
	local ciphertext, tag = AES.Encrypt(serializedData, session.AESKey, nonce)

	return seqId, ciphertext, tag
end

function SessionManager:Decrypt(session: Session, seqId: number, ciphertext: buffer, tag: buffer): (boolean, buffer?)
	if seqId <= session.RecvSeq then
		return false, nil
	end

	local nonce = deriveNonce(session.BaseNonce, seqId)
	local success, plaintext = AES.Decrypt(ciphertext, session.AESKey, nonce, tag)

	if success and plaintext then
		session.RecvSeq = seqId
		return true, plaintext
	end

	return false, nil
end

if isServer then
	local handshakeRemote = Instance.new("RemoteFunction")
	handshakeRemote.Name = HANDSHAKE_REMOTE_NAME
	handshakeRemote.Parent = ReplicatedStorage

	handshakeRemote.OnServerInvoke = function(player: Player, ciphertext: buffer?): any
		if serverSessions[player] then
			warn(`[Horus] Handshake rejected: {player.Name} already has an active session`)
			return false
		end

		local now = os.clock()
		local lastAttempt = handshakeRatelimit[player] or 0
		if now - lastAttempt < 1 then
			warn(`[Horus] Handshake rate limit exceeded for {player.Name}`)
			return false
		end
		handshakeRatelimit[player] = now

		if ciphertext == nil then
			local publicKey, secretKey = MlKEM.MLKEM_768.GenerateKeys()
			pendingSecretKeys[player] = secretKey
			return publicKey
		end

		if typeof(ciphertext) ~= "buffer" then
			warn(`[Horus] Invalid ciphertext type from {player.Name}: {typeof(ciphertext)}`)
			return false
		end

		local secretKey = pendingSecretKeys[player]
		if not secretKey then
			warn(`[Horus] No pending keypair for {player.Name}`)
			return false
		end

		local ok, sharedSecret = pcall(MlKEM.MLKEM_768.Decapsulate, ciphertext, secretKey)
		if not ok or not sharedSecret then
			warn(`[Horus] Decapsulation failed for {player.Name}`)
			pendingSecretKeys[player] = nil
			return false
		end

		scrubBuffer(secretKey)
		pendingSecretKeys[player] = nil

		local aesKey, baseNonce = deriveSessionKeys(sharedSecret, player)
		scrubBuffer(sharedSecret)

		serverSessions[player] = {
			AESKey = aesKey,
			BaseNonce = baseNonce,
			SendSeq = 0,
			RecvSeq = -1,
		}

		sessionReadySignal:Fire()
		return true
	end

	Players.PlayerRemoving:Connect(function(player: Player)
		local session = serverSessions[player]
		if session then
			scrubBuffer(session.AESKey)
			scrubBuffer(session.BaseNonce)
			serverSessions[player] = nil
		end

		local pending = pendingSecretKeys[player]
		if pending then
			scrubBuffer(pending)
			pendingSecretKeys[player] = nil
		end

		handshakeRatelimit[player] = nil
	end)

else
	task.spawn(function()
		local handshakeRemote = ReplicatedStorage:WaitForChild(HANDSHAKE_REMOTE_NAME, 30)
		if not handshakeRemote or not handshakeRemote:IsA("RemoteFunction") then
			warn("[Horus] Failed to find handshake RemoteFunction")
			return
		end

		local publicKey = (handshakeRemote :: RemoteFunction):InvokeServer(nil)
		if not publicKey or typeof(publicKey) ~= "buffer" then
			warn("[Horus] Handshake Phase 1 failed: invalid public key response")
			return
		end

		local message = CSPRNG.RandomBytes(32)
		local ok, ciphertext, sharedSecret = pcall(function()
			return MlKEM.MLKEM_768.Encapsulate(message, publicKey)
		end)

		if not ok or not ciphertext or not sharedSecret then
			warn("[Horus] ML-KEM encapsulation failed")
			return
		end

		local success = (handshakeRemote :: RemoteFunction):InvokeServer(ciphertext)
		if success ~= true then
			warn("[Horus] Handshake Phase 2 failed: server rejected ciphertext")
			return
		end

		local aesKey, baseNonce = deriveSessionKeys(sharedSecret, Players.LocalPlayer)
		scrubBuffer(sharedSecret)

		clientSession = {
			AESKey = aesKey,
			BaseNonce = baseNonce,
			SendSeq = 0,
			RecvSeq = -1,
		}

		sessionReadySignal:Fire()
	end)
end

return SessionManager
