# Multi-Agent Audit Trail System

Comprehensive provenance tracking that logs every decision, tool call, and data access across agent swarms with cryptographic verification for regulatory compliance.

## Features

- **Event Logging** - Logs every decision, tool call, and data access
- **Chain Hashing** - Cryptographic linking of events for tamper detection
- **Digital Signatures** - HMAC signing of all audit events
- **Chain Verification** - Verify integrity of audit trail
- **Session Management** - Track agent sessions from start to end
- **Search & Query** - Search events by agent, action, date range

## Installation

```bash
npm install
npm run build
```

## Usage

```bash
npm start
```

## API Endpoints

- `POST /session/start` - Start a new agent session
- `POST /session/end` - End an agent session
- `POST /audit/log` - Log an audit event
- `POST /audit/log/batch` - Batch log events
- `GET /session/:sessionId/events` - Get session events
- `GET /session/:sessionId/verify` - Verify chain integrity
- `GET /audit/stats` - Get audit statistics
- `POST /audit/search` - Search events

## Example

```bash
# Start session
curl -X POST http://localhost:3001/session/start \
  -H "Content-Type: application/json" \
  -d '{"agentId": "agent-001"}'

# Log event
curl -X POST http://localhost:3001/audit/log \
  -H "Content-Type: application/json" \
  -d '{
    "sessionId": "session-uuid",
    "agentId": "agent-001",
    "action": "decision",
    "details": {
      "decision": "Approve transaction",
      "confidence": 0.95,
      "reasoning": "Transaction matches normal pattern"
    }
  }'

# Verify chain
curl http://localhost:3001/session/session-uuid/verify
```

## License

MIT
