import {
  CallToolRequestSchema,
  ErrorCode,
  ListToolsRequestSchema,
  McpError,
  type CallToolResult,
  type ToolAnnotations,
} from '@modelcontextprotocol/sdk/types.js';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';

export interface ToolDefinition {
  title?: string;
  description?: string;
  inputSchema: Record<string, unknown>;
  outputSchema?: Record<string, unknown>;
  annotations?: ToolAnnotations;
}

/**
 * What a handler knows about the call beyond its arguments.
 *
 * Only what a *streamed* answer needs: whether the caller asked to be kept
 * informed, and the channel to inform them on. Nothing here is authorization —
 * the broker decides that, on the far side of every upstream call.
 */
export interface ToolCallContext {
  /** Set when the caller attached `_meta.progressToken` and wants progress. */
  progressToken?: string | number;
  /** Send one server→client notification on the connection this call arrived on. */
  sendNotification: (notification: {
    method: string;
    params?: Record<string, unknown>;
  }) => Promise<void>;
}

type ToolHandler<Args extends Record<string, unknown> = Record<string, unknown>> = (
  args: Args,
  signal: AbortSignal,
  context: ToolCallContext,
) => CallToolResult | Promise<CallToolResult>;

interface ToolEntry {
  definition: ToolDefinition;
  parse?: (args: Record<string, unknown>) => Record<string, unknown>;
  handler: ToolHandler;
}

export interface RegisteredProtocolTool {
  remove(): void;
}

/** Convert a Zod object shape into its advertised JSON Schema and validator. */
export function zodToolInput(shape: z.ZodRawShape): Pick<ToolEntry, 'parse'> & {
  inputSchema: Record<string, unknown>;
} {
  const schema = z.object(shape);
  return {
    inputSchema: z.toJSONSchema(schema) as Record<string, unknown>,
    parse: (args) => schema.parse(args) as Record<string, unknown>,
  };
}

/**
 * Small protocol-level registry for MCP tools.
 *
 * The high-level SDK converts tool schemas from Zod. Upstream MCP schemas are
 * already JSON Schema and must be relayed byte-for-byte, so tools/list and
 * tools/call live at this lower layer. The call handler passes only
 * `params.arguments`; request context (including the agent Authorization
 * header) can never be mistaken for upstream arguments.
 */
export class ProtocolToolRegistry {
  private readonly tools = new Map<string, ToolEntry>();

  constructor(private readonly server: McpServer) {
    server.server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: [...this.tools].map(([name, entry]) => ({
        name,
        ...entry.definition,
      })),
    }));
    server.server.setRequestHandler(CallToolRequestSchema, async (request, extra) => {
      const entry = this.tools.get(request.params.name);
      if (!entry) {
        throw new McpError(
          ErrorCode.InvalidParams,
          `Tool ${request.params.name} not found`,
        );
      }
      const supplied = request.params.arguments ?? {};
      const progressToken = request.params._meta?.progressToken;
      const context: ToolCallContext = {
        ...(typeof progressToken === 'string' || typeof progressToken === 'number'
          ? { progressToken }
          : {}),
        // Bound to this request's own connection by the SDK, so a
        // notification cannot be delivered to a session that did not ask.
        sendNotification: (notification) =>
          extra.sendNotification(notification as Parameters<typeof extra.sendNotification>[0]),
      };
      try {
        const args = entry.parse ? entry.parse(supplied) : supplied;
        return await entry.handler(args, extra.signal, context);
      } catch (error) {
        if (error instanceof z.ZodError) {
          throw new McpError(
            ErrorCode.InvalidParams,
            `Invalid arguments for tool ${request.params.name}: ${error.message}`,
          );
        }
        throw error;
      }
    });
  }

  register<Args extends Record<string, unknown> = Record<string, unknown>>(
    name: string,
    definition: ToolDefinition,
    handler: ToolHandler<Args>,
    parse?: (args: Record<string, unknown>) => Args,
  ): RegisteredProtocolTool {
    if (this.tools.has(name)) throw new Error(`Tool ${name} is already registered`);
    this.tools.set(name, {
      definition,
      handler: handler as ToolHandler,
      parse: parse as ToolEntry['parse'],
    });
    this.server.sendToolListChanged();
    return {
      remove: () => {
        if (this.tools.delete(name)) this.server.sendToolListChanged();
      },
    };
  }
}
