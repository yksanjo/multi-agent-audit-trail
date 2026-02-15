/**
 * Multi-Agent Audit Trail System
 * 
 * Comprehensive provenance tracking that logs every decision, tool call,
 * and data access across agent swarms with cryptographic verification
 * for regulatory compliance.
 */

import express from 'express';
import { v4 as uuidv4 } from 'uuid';
import crypto from 'crypto';
import signale from 'signale';

export interface AuditEvent {
  id: string;
  timestamp: string;
  agentId: string;
  sessionId: string;
  action: 'decision' | 'tool_call' | 'data_access' | 'message' | 'error';
  details: {
    type?: string;
    input?: any;
    output?: any;
    tool?: string;
    resource?: string;
    decision?: string;
    confidence?: number;
    reasoning?: string;
    metadata?: Record<string, any>;
  };
  parentEventId?: string;
  chainHash: string;
  signature?: string;
}

export interface AgentSession {
  id: string;
  agentId: string;
  startedAt: string;
  endedAt?: string;
  status: 'active' | 'completed' | 'terminated';
  events: AuditEvent[];
}

export interface ChainVerification {
  valid: boolean;
  brokenAt?: string;
  totalEvents: number;
  verifiedEvents: number;
}

class MultiAgentAuditTrail {
  private app: express.Application;
  private sessions: Map<string, AgentSession>;
  private eventChain: Map<string, string>; // eventId -> chainHash

  constructor() {
    this.app = express();
    this.sessions = new Map();
    this.eventChain = new Map();
    this.setupMiddleware();
    this.setupRoutes();
  }

  private setupMiddleware(): void {
    this.app.use(express.json());
  }

  private setupRoutes(): void {
    // Health check
    this.app.get('/health', (req, res) => {
      res.json({ status: 'healthy', timestamp: new Date().toISOString() });
    });

    // Start a new agent session
    this.app.post('/session/start', (req, res) => {
      const { agentId } = req.body;
      if (!agentId) {
        return res.status(400).json({ error: 'agentId is required' });
      }

      const sessionId = uuidv4();
      const session: AgentSession = {
        id: sessionId,
        agentId,
        startedAt: new Date().toISOString(),
        status: 'active',
        events: []
      };

      this.sessions.set(sessionId, session);
      
      res.json({
        sessionId,
        agentId,
        status: 'active',
        startedAt: session.startedAt
      });
    });

    // End an agent session
    this.app.post('/session/end', (req, res) => {
      const { sessionId } = req.body;
      const session = this.sessions.get(sessionId);

      if (!session) {
        return res.status(404).json({ error: 'Session not found' });
      }

      session.status = 'completed';
      session.endedAt = new Date().toISOString();

      res.json({
        sessionId,
        status: 'completed',
        endedAt: session.endedAt,
        totalEvents: session.events.length
      });
    });

    // Log an audit event
    this.app.post('/audit/log', (req, res) => {
      const { sessionId, agentId, action, details, parentEventId } = req.body;

      if (!sessionId || !agentId || !action) {
        return res.status(400).json({ 
          error: 'sessionId, agentId, and action are required' 
        });
      }

      // Get or create session
      let session = this.sessions.get(sessionId);
      if (!session) {
        session = {
          id: sessionId,
          agentId,
          startedAt: new Date().toISOString(),
          status: 'active',
          events: []
        };
        this.sessions.set(sessionId, session);
      }

      // Get previous chain hash
      const previousHash = session.events.length > 0
        ? session.events[session.events.length - 1].chainHash
        : 'genesis';

      // Create event with chain hash
      const eventId = uuidv4();
      const chainHash = this.computeChainHash(eventId, previousHash, details);

      const event: AuditEvent = {
        id: eventId,
        timestamp: new Date().toISOString(),
        agentId,
        sessionId,
        action,
        details,
        parentEventId,
        chainHash
      };

      // Sign the event
      event.signature = this.signEvent(event);

      session.events.push(event);
      this.eventChain.set(eventId, chainHash);

      res.json({
        eventId,
        sessionId,
        timestamp: event.timestamp,
        chainHash,
        chainLength: session.events.length
      });
    });

    // Batch log events
    this.app.post('/audit/log/batch', (req, res) => {
      const { events } = req.body;

      if (!Array.isArray(events)) {
        return res.status(400).json({ error: 'Events must be an array' });
      }

      const results = [];
      for (const eventData of events) {
        const { sessionId, agentId, action, details, parentEventId } = eventData;
        
        let session = this.sessions.get(sessionId);
        if (!session) {
          session = {
            id: sessionId,
            agentId,
            startedAt: new Date().toISOString(),
            status: 'active',
            events: []
          };
          this.sessions.set(sessionId, session);
        }

        const previousHash = session.events.length > 0
          ? session.events[session.events.length - 1].chainHash
          : 'genesis';

        const eventId = uuidv4();
        const chainHash = this.computeChainHash(eventId, previousHash, details);

        const event: AuditEvent = {
          id: eventId,
          timestamp: new Date().toISOString(),
          agentId,
          sessionId,
          action,
          details,
          parentEventId,
          chainHash
        };

        event.signature = this.signEvent(event);
        session.events.push(event);
        this.eventChain.set(eventId, chainHash);

        results.push({ eventId, chainHash });
      }

      res.json({ results, totalLogged: results.length });
    });

    // Get session events
    this.app.get('/session/:sessionId/events', (req, res) => {
      const { sessionId } = req.params;
      const { limit, offset } = req.query;
      const session = this.sessions.get(sessionId);

      if (!session) {
        return res.status(404).json({ error: 'Session not found' });
      }

      const events = session.events.slice(
        Number(offset) || 0,
        (Number(limit) || 100) + (Number(offset) || 0)
      );

      res.json({
        sessionId,
        totalEvents: session.events.length,
        events
      });
    });

    // Verify chain integrity
    this.app.get('/session/:sessionId/verify', (req, res) => {
      const { sessionId } = req.params;
      const session = this.sessions.get(sessionId);

      if (!session) {
        return res.status(404).json({ error: 'Session not found' });
      }

      const verification = this.verifyChain(session.events);

      res.json({
        sessionId,
        verification
      });
    });

    // Get audit statistics
    this.app.get('/audit/stats', (req, res) => {
      let totalSessions = 0;
      let activeSessions = 0;
      let totalEvents = 0;

      for (const session of this.sessions.values()) {
        totalSessions++;
        if (session.status === 'active') activeSessions++;
        totalEvents += session.events.length;
      }

      res.json({
        totalSessions,
        activeSessions,
        totalEvents,
        timestamp: new Date().toISOString()
      });
    });

    // Search events
    this.app.post('/audit/search', (req, res) => {
      const { sessionId, agentId, action, startDate, endDate } = req.query;
      
      const results: AuditEvent[] = [];
      
      for (const session of this.sessions.values()) {
        // Filter by session
        if (sessionId && session.id !== sessionId) continue;
        
        for (const event of session.events) {
          // Filter by agent
          if (agentId && event.agentId !== agentId) continue;
          
          // Filter by action
          if (action && event.action !== action) continue;
          
          // Filter by date range
          const eventTime = new Date(event.timestamp).getTime();
          if (startDate && eventTime < new Date(startDate as string).getTime()) continue;
          if (endDate && eventTime > new Date(endDate as string).getTime()) continue;
          
          results.push(event);
        }
      }

      res.json({
        results,
        total: results.length
      });
    });
  }

  /**
   * Compute chain hash for event linking
   */
  private computeChainHash(eventId: string, previousHash: string, details: any): string {
    const data = `${eventId}:${previousHash}:${JSON.stringify(details)}`;
    return crypto.createHash('sha256').update(data).digest('hex');
  }

  /**
   * Sign event with HMAC (in production, use asymmetric keys)
   */
  private signEvent(event: AuditEvent): string {
    const data = `${event.id}:${event.timestamp}:${event.chainHash}`;
    return crypto
      .createHmac('sha256', 'audit-secret-key')
      .update(data)
      .digest('hex');
  }

  /**
   * Verify chain integrity
   */
  private verifyChain(events: AuditEvent[]): ChainVerification {
    if (events.length === 0) {
      return { valid: true, totalEvents: 0, verifiedEvents: 0 };
    }

    let previousHash = 'genesis';

    for (const event of events) {
      // Verify chain link
      const expectedHash = this.computeChainHash(
        event.id,
        previousHash,
        event.details
      );

      if (event.chainHash !== expectedHash) {
        return {
          valid: false,
          brokenAt: event.id,
          totalEvents: events.length,
          verifiedEvents: events.indexOf(event)
        };
      }

      // Verify signature
      const expectedSignature = this.signEvent(event);
      if (event.signature !== expectedSignature) {
        return {
          valid: false,
          brokenAt: `signature_verification_failed:${event.id}`,
          totalEvents: events.length,
          verifiedEvents: events.indexOf(event)
        };
      }

      previousHash = event.chainHash;
    }

    return {
      valid: true,
      totalEvents: events.length,
      verifiedEvents: events.length
    };
  }

  public async start(port: number = 3001): Promise<void> {
    return new Promise((resolve) => {
      this.app.listen(port, () => {
        signale.success(`Multi-Agent Audit Trail running on port ${port}`);
        signale.info('Available endpoints:');
        signale.info('  POST /session/start - Start agent session');
        signale.info('  POST /session/end - End agent session');
        signale.info('  POST /audit/log - Log audit event');
        signale.info('  POST /audit/log/batch - Batch log events');
        signale.info('  GET /session/:sessionId/events - Get session events');
        signale.info('  GET /session/:sessionId/verify - Verify chain integrity');
        signale.info('  GET /audit/stats - Get audit statistics');
        signale.info('  POST /audit/search - Search events');
        resolve();
      });
    });
  }
}

// Run if executed directly
if (require.main === module) {
  const auditTrail = new MultiAgentAuditTrail();
  auditTrail.start(3001).catch(signale.error);
}

export default MultiAgentAuditTrail;
