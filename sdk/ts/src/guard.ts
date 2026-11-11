import { CerberusClient, CerberusError, ErrDenied } from "./client.js";

export type ToolFn<T = any> = (args: any) => Promise<T> | T;
export type ToolRunner<T = any> = (tool: string, args: any) => Promise<T> | T;

export class GuardedExecutor {
  private client: CerberusClient;

  constructor(client: CerberusClient) {
    if (!client) {
      throw new CerberusError("cerberus: guard has null or undefined client");
    }
    this.client = client;
  }

  async execute<T = any>(tool: string, args: any, fn: ToolFn<T>): Promise<T> {
    const dec = await this.client.decideTool(tool, args);
    if (!dec.allowed()) {
      throw new ErrDenied(dec.rule_id, dec.reason);
    }

    const effectiveArgs =
      dec.masked_args !== undefined && dec.masked_args !== null ? dec.masked_args : args;

    return await fn(effectiveArgs);
  }

  wrap<T = any>(next: ToolRunner<T>): ToolRunner<T> {
    return async (tool: string, args: any): Promise<T> => {
      return this.execute(tool, args, (guardedArgs) => next(tool, guardedArgs));
    };
  }
}
