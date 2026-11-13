package cryptoutil

// DeriveMCPSessionKey derives the HMAC-SHA256 key that signs MCP session IDs
// (Mcp-Session-Id) from the deployment root secret, so every replica accepts
// a session another replica issued.
func DeriveMCPSessionKey(root []byte) []byte {
	return hkdfSHA256(root, []byte("citadel/mcp/salt/v1"), []byte("citadel-mcp-session-v1"), 32)
}
