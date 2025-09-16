/**
 * debugAdapter.ts implements the Debug Adapter protocol and integrates it with
 * the lnav debugger.
 */

import {
    Logger, logger,
    LoggingDebugSession,
    Thread, StackFrame, Scope, Source,
    InitializedEvent, StoppedEvent,
    Handles,
    Variable,
} from '@vscode/debugadapter';
import { DebugProtocol } from '@vscode/debugprotocol';
import * as vscode from 'vscode';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as http from 'http';
import { v4 as uuidv4 } from 'uuid';
import { exec } from 'child_process';

import { outputChannel } from './extension';


interface VariablePair {
    expr: string,
    value: string,
}

interface LogMapping {
    srcRef: SourceRef,
    variables: Array<VariablePair>,
}

interface SourceRef {
    sourcePath: string,
    lineNumber: number,
    column: number,
    name: string,
}

interface ViewStates {
    log: string,
    text: string,
}

interface PollInput {
    last_event_id: number,
    view_states: ViewStates,
}

interface ILaunchRequestArguments extends DebugProtocol.LaunchRequestArguments {
    logFile: string;
}

interface IAttachRequestArguments extends DebugProtocol.LaunchRequestArguments {
    // the port number of an lnav instance
    port: number;
    // the API key used to communicate with lnav
    apiKey: string;
}

const getThreadIdsScript = `
;SELECT log_time AS curr_time FROM all_logs WHERE log_line = log_msg_line() LIMIT 1
;SELECT rowid, thread_id FROM all_thread_ids WHERE $curr_time BETWEEN earliest AND latest;
:write-json-to -
`;

const nextLineScript = `
;SELECT log_line AS curr_line, log_thread_id AS curr_thread_id
   FROM all_logs
  WHERE log_line = log_msg_line()
;SELECT log_line AS next_line
   FROM all_logs
  WHERE log_line > $curr_line AND
        log_msg_src IS NOT NULL AND
        log_thread_id IS $curr_thread_id
  ORDER BY log_line ASC
  LIMIT 1;
;SELECT raise_error('No further log messages from this thread') WHERE $next_line IS NULL;
;UPDATE lnav_views SET selection = $next_line WHERE name = 'log';
`

const prevLineScript = `
;SELECT log_line AS curr_line, log_thread_id AS curr_thread_id
   FROM all_logs
  WHERE log_line = log_msg_line()
;SELECT log_line AS prev_line
   FROM all_logs
  WHERE log_line < $curr_line AND
        log_thread_id IS $curr_thread_id AND
        log_msg_src IS NOT NULL
  ORDER BY log_line DESC
  LIMIT 1;
;SELECT raise_error('No previous log messages from this thread') WHERE $prev_line IS NULL;
;UPDATE lnav_views SET selection = $prev_line WHERE name = 'log';
`

function getDebuggerInfo(args: IAttachRequestArguments, path: string): Promise<any> {
    const timeoutMs = 10000;
    const retryDelayMs = 1000;
    const startTime = Date.now();

    function attempt(): Promise<any> {
        return new Promise((resolve, reject) => {
            const options: http.RequestOptions = {
                hostname: 'localhost',
                port: args.port,
                path: path,
                method: 'GET',
                headers: {
                    'X-Api-Key': args.apiKey,
                }
            };

            const req = http.request(options, (res) => {
                let responseData = '';
                res.on('data', (chunk) => responseData += chunk);
                res.on('end', () => resolve(JSON.parse(responseData)));
            });

            req.on('error', (e) => reject(e));
            req.end();
        });
    }

    function retry(): Promise<any> {
        return attempt().catch((err) => {
            if (Date.now() - startTime < timeoutMs) {
                return new Promise((resolve) =>
                    setTimeout(resolve, retryDelayMs)
                ).then(retry);
            }
            throw err;
        });
    }

    return retry();
}

class ExecError extends Error {
    reason: string;
    help: string;

    constructor(message: string, reason: string = "", help: string = "") {
        super(message);
        this.reason = reason;
        this.help = help;
        Object.setPrototypeOf(this, ExecError.prototype);
    }
}

function sendDebuggerCommand(args: IAttachRequestArguments, path: string, data: string): Promise<any> {
    return new Promise((resolve, reject) => {
        const options: http.RequestOptions = {
            hostname: 'localhost',
            port: args.port,
            path: path,
            method: 'POST',
            headers: {
                'X-Api-Key': args.apiKey,
                'Content-Type': path == '/exec' ? 'text/x-lnav-script' : 'application/json',
                'Content-Length': Buffer.byteLength(data)
            }
        };

        const req = http.request(options, (res) => {
            let isError = (res.statusCode && (res.statusCode < 200 || res.statusCode >= 400));
            let responseData = '';
            res.on('data', (chunk) => responseData += chunk);
            res.on('end', () => {
                outputChannel.appendLine(`response: ${responseData}`);
                if (isError) {
                    const contentType = res.headers['content-type'];
                    if (contentType && contentType.includes('application/json')) {
                        try {
                            const errobj = JSON.parse(responseData);
                            const execerr = new ExecError(errobj.msg, errobj.reason, errobj.help);
                            return reject(execerr);
                        } catch (e) {
                            return reject(new Error(responseData));
                        }
                    }
                    return reject(new Error(responseData));
                }
                if (responseData != '') {
                    return resolve(JSON.parse(responseData));
                } else {
                    return resolve([]);
                }
            });
        });

        req.on('error', (e) => reject(e));
        req.write(data);
        req.end();
    });
}

export class DebugSession extends LoggingDebugSession {
    private _breakPoints = new Map<string, DebugProtocol.Breakpoint[]>();
    private _variableHandles = new Handles<'locals'>();
    private _attachArgs: IAttachRequestArguments = { port: 0, apiKey: "" };
    private _pollInput: PollInput = { last_event_id: 0, view_states: { log: "", text: "" } };
    private _mapping?: LogMapping = undefined;
    private _currentThreadId?: number = undefined;

    /**
     * Create a new debug adapter to use with a debug session.
     */
    public constructor() {
        super("lnav-dap.txt");

        this.setDebuggerLinesStartAt1(true);
        this.setDebuggerColumnsStartAt1(true);

        outputChannel.appendLine("Starting up...");
    }

    private pollLnav() {
        outputChannel.appendLine(`pollLnav: last_event_id=${this._pollInput.last_event_id}, view_states=${JSON.stringify(this._pollInput.view_states)}`);
        const prevViewStates = { ...this._pollInput.view_states };

        sendDebuggerCommand(this._attachArgs as IAttachRequestArguments, '/poll', JSON.stringify(this._pollInput))
            .then((input: PollInput) => {
                outputChannel.appendLine(`pollLnav: ${JSON.stringify(input)}`);
                this._pollInput = input;

                // Only send StoppedEvent if PollInput has changed
                if (input.last_event_id !== this._pollInput.last_event_id ||
                    input.view_states.log !== prevViewStates.log ||
                    input.view_states.text !== prevViewStates.text
                ) {
                    let event: DebugProtocol.StoppedEvent = new StoppedEvent('pause');
                    event.body.allThreadsStopped = true;
                    this.sendEvent(event);
                }

                this.pollLnav();
            });
    }

    protected disconnectRequest(response: DebugProtocol.DisconnectResponse, args: DebugProtocol.DisconnectArguments, request?: DebugProtocol.Request): void {
        outputChannel.appendLine(`disconnectRequest suspend: ${args.suspendDebuggee}, terminate: ${args.terminateDebuggee}`);
        if (args.terminateDebuggee) {
            sendDebuggerCommand(this._attachArgs, '/exec', ':quit')
                .finally(() => {
                    this.sendResponse(response);
                });
        } else {
            this.sendResponse(response);
        }
    }

    protected terminateRequest(response: DebugProtocol.TerminateResponse, args: DebugProtocol.TerminateArguments, request?: DebugProtocol.Request): void {
        outputChannel.appendLine(`terminateRequest`);
        sendDebuggerCommand(this._attachArgs, '/exec', ':quit')
            .finally(() => {
                this.sendResponse(response);
            });
    }

    /**
     * The 'initialize' request is the first request called by the frontend
     * to interrogate the features the debug adapter provides.
     */
    protected initializeRequest(response: DebugProtocol.InitializeResponse, args: DebugProtocol.InitializeRequestArguments): void {
        outputChannel.appendLine(`initializeRequest: ${JSON.stringify(args)}`);

        response.body = response.body || {};
        response.body.supportsStepBack = true;
        // response.body.supportsBreakpointLocationsRequest = true;
        response.body.supportTerminateDebuggee = true;

        this.sendResponse(response);
        this.sendEvent(new InitializedEvent());
    }

    protected setBreakPointsRequest(response: DebugProtocol.SetBreakpointsResponse, args: DebugProtocol.SetBreakpointsArguments) {
        outputChannel.appendLine(`setBreakPointsRequest ${JSON.stringify(args)}`);

        const bpPath = args.source.path as string;
        // TODO handle lines?
        const bps = args.breakpoints || [];
        this._breakPoints.set(bpPath, new Array<DebugProtocol.Breakpoint>());
        bps.forEach((sourceBp) => {
            let bps = this._breakPoints.get(bpPath) || [];
            bps.push({ line: sourceBp.line, verified: true });
        });
        const breakpoints = this._breakPoints.get(bpPath) || [];
        response.body = {
            breakpoints: breakpoints
        };

        if (breakpoints.length > 0) {
            this.sendEvent(new StoppedEvent('breakpoint'));
        }
        return this.sendResponse(response);
    }

    protected attachRequest(response: DebugProtocol.AttachResponse, args: IAttachRequestArguments) {
        outputChannel.appendLine(`attachRequest ${JSON.stringify(args)}`);

        // make sure to 'Stop' the buffered logging if 'trace' is not set
        logger.setup(Logger.LogLevel.Verbose, false);

        this._attachArgs = args;

        getDebuggerInfo(args, '/version').then((info) => {
            outputChannel.appendLine(`lnav version: ${info.version}`);
            this.sendResponse(response);
            outputChannel.appendLine(`sending StoppedEvent`);
            // Build ':add-source-path <workspace-path>' for each workspace folder
            const workspaceFolders = vscode.workspace.workspaceFolders ?? [];
            const addSourcePathArgs = workspaceFolders
                .map(folder => `:add-source-path ${folder.uri.fsPath}\n`)
                .join('\n');
            sendDebuggerCommand(this._attachArgs as IAttachRequestArguments, '/exec', addSourcePathArgs)
                .then(() => {
                    outputChannel.appendLine(`added source paths: ${addSourcePathArgs}`);
                    this.pollLnav();
                });
        }).catch((err) => {
            outputChannel.appendLine(`error getting lnav version: ${err}`);
            this.sendErrorResponse(response, 3000, `Error connecting to lnav instance: ${err}`);
        });
    }

    protected launchRequest(response: DebugProtocol.LaunchResponse, args: ILaunchRequestArguments) {
        outputChannel.appendLine(`launchRequest ${JSON.stringify(args)}`);

        exec('lnav -V', (error, stdout, stderr) => {
            if (error) {
                vscode.window.showErrorMessage('lnav not found in PATH. Please install lnav >= 0.14.');
                return;
            }
            const match = stdout.match(/(\d+\.\d+)/);
            if (!match || parseFloat(match[1]) < 0.14) {
                // vscode.window.showErrorMessage(`lnav version 0.14 or higher required. Found: ${stdout.trim()}`);
                this.sendErrorResponse(response, 3000, `lnav version 0.14 or higher required. Found: ${stdout.trim()}`);
                return;
            }

            const tempFilePath = path.join(os.tmpdir(), `lnav-launch-${uuidv4()}.json`);
            const writeInfoArg = `-c '|lnav-write-external-access-info-to ${tempFilePath}'`;
            const apiKey = uuidv4();

            // Create and show a new terminal, then run a command
            const terminal = vscode.window.createTerminal({ name: `lnav debug ${path.basename(args.logFile)}` });
            terminal.show();
            terminal.sendText(`exec lnav -d /tmp/vscode-lnav.err -c ':external-access 0 ${apiKey}' ${writeInfoArg} ${args.logFile}`);
            vscode.commands.executeCommand('workbench.action.terminal.moveToEditor');

            // Poll for tempFilePath creation, read and parse it
            const timeoutMs = 10000;
            const pollIntervalMs = 250;
            const startTime = Date.now();
            let port: number | undefined = undefined;

            const pollForFile = () => {
                if (fs.existsSync(tempFilePath)) {
                    try {
                        const fileContent = fs.readFileSync(tempFilePath, 'utf8');
                        const info = JSON.parse(fileContent);
                        port = info.port;
                        fs.unlinkSync(tempFilePath);
                    } catch (err) {
                        outputChannel.appendLine(`Error reading/parsing temp file: ${err}`);
                    }
                }
                if (port !== undefined) {
                    this.attachRequest(response, { port, apiKey });
                } else if (Date.now() - startTime < timeoutMs) {
                    setTimeout(pollForFile, pollIntervalMs);
                } else {
                    outputChannel.appendLine(`Timeout waiting for lnav info file: ${tempFilePath}`);
                    this.sendErrorResponse(response, 3001, `Timeout waiting for lnav info file`);
                }
            };

            pollForFile();
        });
    }

    protected threadsRequest(response: DebugProtocol.ThreadsResponse): void {
        outputChannel.appendLine(`threadsRequest`);

        sendDebuggerCommand(this._attachArgs as IAttachRequestArguments, '/exec', getThreadIdsScript)
            .then((rows) => {
                outputChannel.appendLine(`got thread ids: ${JSON.stringify(rows)}`);
                if (rows.length === 0) {
                    response.body = {
                        threads: [
                            new Thread(0, "main"),
                        ]
                    };
                } else {
                    response.body = {
                        threads: rows.map((row: any) => {
                            return new Thread(row.rowid, row.thread_id);
                        })
                    };
                }
                this.sendResponse(response);
            });
    }

    protected continueRequest(response: DebugProtocol.ContinueResponse, args: DebugProtocol.ContinueArguments): void {
        outputChannel.appendLine(`continueRequest ${JSON.stringify(args)}`);

        this.sendEvent(new StoppedEvent('breakpoint'));
        this.sendResponse(response);
    }

    protected reverseContinueRequest(response: DebugProtocol.ReverseContinueResponse, args: DebugProtocol.ReverseContinueArguments): void {
        outputChannel.appendLine(`reverseContinueRequest ${JSON.stringify(args)}`);

        this.sendEvent(new StoppedEvent('breakpoint'));
        this.sendResponse(response);
    }

    protected nextRequest(response: DebugProtocol.NextResponse, args: DebugProtocol.NextArguments): void {
        outputChannel.appendLine(`nextRequest ${JSON.stringify(args)}`);
        sendDebuggerCommand(this._attachArgs, '/exec', nextLineScript)
            .then(() => {
                outputChannel.appendLine(`stepped to next line`);
                response.success = true;
                this.sendResponse(response);
            })
            .catch((err) => {
                if (err instanceof ExecError) {
                    this.sendErrorResponse(response, 3002, err.message);
                } else {
                    outputChannel.appendLine(`error stepping to next line: ${err}`);
                    this.sendErrorResponse(response, 3002, `Error stepping to next line: ${err}`);
                }
            });
    }

    protected stepBackRequest(response: DebugProtocol.StepBackResponse, args: DebugProtocol.StepBackArguments): void {
        outputChannel.appendLine(`stepBackRequest ${JSON.stringify(args)}`);
        sendDebuggerCommand(this._attachArgs, '/exec', prevLineScript)
            .then(() => {
                outputChannel.appendLine(`stepped back one line`);
                response.success = true;
                this.sendResponse(response);
            })
            .catch((err) => {
                outputChannel.appendLine(`error stepping to previous line: ${err}`);
                this.sendErrorResponse(response, 3002, `Error stepping to previous line: ${err}`);
            });
    }

    private buildStackFrame(index: number, srcRef?: SourceRef): StackFrame {
        let name = "???";
        let lineNumber = -1;
        let sourceName = "???";
        let sourcePath = "???";

        if (srcRef !== null && srcRef !== undefined) {
            name = srcRef.name;
            lineNumber = srcRef.lineNumber;
            const codeSrcPath = path.parse(srcRef.sourcePath);
            sourceName = codeSrcPath.base;
            sourcePath = srcRef.sourcePath;
        }

        return new StackFrame(
            index,
            name,
            new Source(sourceName, sourcePath),
            this.convertDebuggerLineToClient(lineNumber)
        );
    }

    protected stackTraceRequest(response: DebugProtocol.StackTraceResponse, args: DebugProtocol.StackTraceArguments): void {
        outputChannel.appendLine(`stackTraceRequest ${JSON.stringify(args)}`);

        const getCurrLineScript = `
;SELECT
    CASE thread_id
      WHEN '' THEN NULL
      ELSE thread_id
    END AS curr_thread_id
  FROM all_thread_ids
  WHERE rowid = ${args.threadId}
;SELECT *
   FROM all_logs
  WHERE log_line <= log_msg_line() AND
        log_thread_id IS $curr_thread_id
  ORDER BY log_line DESC
  LIMIT 1
:write-json-to -
`;

        sendDebuggerCommand(this._attachArgs as IAttachRequestArguments, '/exec', getCurrLineScript)
            .then((row) => {
                outputChannel.appendLine(`got current line: ${JSON.stringify(row)}`);
                let row0 = row[0];

                const srcRef: SourceRef = {
                    sourcePath: row[0].log_msg_src.file,
                    lineNumber: row[0].log_msg_src.line,
                    name: row[0].log_msg_src.name,
                    column: 1,
                };
                this._mapping = {
                    srcRef: srcRef,
                    variables: row0.log_msg_values.map((element: { expr: string, value: string }) => {
                        let retval: VariablePair = { expr: element.expr, value: element.value };
                        return retval;
                    }),
                };
                let index = 0;
                const currentFrame = this.buildStackFrame(index++, srcRef);
                const stack: StackFrame[] = [currentFrame];

                response.body = {
                    stackFrames: stack,
                    totalFrames: stack.length
                };

                this.sendResponse(response);
            });
    }

    protected scopesRequest(response: DebugProtocol.ScopesResponse, args: DebugProtocol.ScopesArguments): void {
        outputChannel.appendLine(`scopesRequest ${JSON.stringify(args)}`);

        response.body = {
            scopes: [
                new Scope("Locals", this._variableHandles.create('locals'), false),
            ]
        };
        this.sendResponse(response);
    }

    protected variablesRequest(response: DebugProtocol.VariablesResponse, args: DebugProtocol.VariablesArguments, request?: DebugProtocol.Request): void {
        outputChannel.appendLine(`variablesRequest ${JSON.stringify(args)}`);

        let vs: DebugProtocol.Variable[] = [];

        const v = this._variableHandles.get(args.variablesReference);
        if (this._mapping !== undefined) {
            for (let pair of this._mapping.variables) {
                vs.push({
                    name: pair.expr,
                    value: pair.value,
                    variablesReference: 0
                });
            }
        }

        response.body = {
            variables: vs
        };
        this.sendResponse(response);
    }
}
