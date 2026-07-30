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

type ToolHandler<Args extends Record<string, unknown> = Record<string, unknown>> = (
  args: Args,
  signal: AbortSignal,
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
      try {
        const args = entry.parse ? entry.parse(supplied) : supplied;
        return await entry.handler(args, extra.signal);
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
