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
    ThreadEvent,
    ProgressStartEvent,
    ProgressEndEvent,
    ProgressUpdateEvent,
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
    task_states: Array<number>,
}

interface ExtError {
    error: string,
    source: string,
    help: string,
}

interface ExtPogress {
    id: string,
    status: 'idle' | 'working',
    current_step: string,
    completed: number,
    total: number,
    messages: Array<ExtError>,
}

interface PollResult {
    next_input: PollInput,
    background_tasks: Array<ExtPogress>
}

interface FindBreakpointResult {
    bpids: Array<number>,
    thread_id: number,
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

const createBreakpointTableScript = `
;DROP TABLE IF EXISTS vscode_breakpoints
;CREATE TABLE IF NOT EXISTS vscode_breakpoints (
    pattern TEXT PRIMARY KEY,
    path TEXT,
    breakpoint_id INTEGER,
    condition TEXT
)
`;

const deleteBreakpointsScript = `
;DELETE FROM vscode_breakpoints WHERE path = $headers ->> '$.x-source-file'
`;

const findBreakpointIdScript = `
;SELECT (SELECT json_group_array(breakpoint_id) FROM vscode_breakpoints WHERE log_body REGEXP pattern) AS bpids,
        (SELECT rowid FROM all_thread_ids WHERE ifnull(log_thread_id, '') = thread_id) AS thread_id
   FROM all_logs
  WHERE log_line = log_msg_line()
;SELECT json($bpids) AS bpids, $thread_id AS thread_id
:write-json-to -
`;

const getThreadIdsScript = `
;SELECT log_time AS curr_time FROM all_logs WHERE log_line = log_msg_line() LIMIT 1
;SELECT rowid,
        CASE thread_id
          WHEN '' THEN 'untitled'
          ELSE thread_id
        END AS thread_id
   FROM all_thread_ids
  WHERE $curr_time BETWEEN earliest AND latest;
:write-json-to -
`;

function encodeValueForHeader(value: string): string {
    return Buffer.from(value).toString('base64')
}

function getDebuggerInfo(args: IAttachRequestArguments, path: string): Promise<any> {
    const timeoutMs = 10000;
    const retryDelayMs = 1000;
    const startTime = Date.now();

    function attempt(): Promise<any> {
        return new Promise((resolve, reject) => {
            outputChannel.info(`get debug args: ${JSON.stringify(args)}`);
            const options: http.RequestOptions = {
                hostname: 'localhost',
                port: args.port,
                path: path,
                method: 'GET',
                headers: {
                    'X-Api-Key': encodeValueForHeader(args.apiKey),
                }
            };

            const req = http.request(options, (res) => {
                outputChannel.info(`get debug info res: ${res.statusCode}`);
                let isError = (res.statusCode && (res.statusCode < 200 || res.statusCode >= 400));
                let responseData = '';
                res.on('data', (chunk) => responseData += chunk);
                res.on('end', () => {
                    if (isError) {
                        return reject(new Error(responseData));
                    }
                    resolve(JSON.parse(responseData))
                });
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

function sendDebuggerCommand(
    args: IAttachRequestArguments,
    path: string,
    data: string,
    headers?: Record<string, string> | Map<string, string>
): Promise<any> {
    return new Promise((resolve, reject) => {
        const defaultHeaders: Record<string, string> = {
            'X-Api-Key': encodeValueForHeader(args.apiKey),
            'Content-Type': path == '/exec' ? 'text/x-lnav-script' : 'application/json',
            'Content-Length': Buffer.byteLength(data).toString()
        };

        // convert Map to plain object if needed
        let providedHeaders: Record<string, string> = {};
        if (headers) {
            if (headers instanceof Map) {
                providedHeaders = Object.fromEntries(headers.entries());
            } else {
                providedHeaders = headers;
            }
        }

        const mergedHeaders = { ...defaultHeaders, ...providedHeaders };

        const options: http.RequestOptions = {
            hostname: 'localhost',
            port: args.port,
            path: path,
            method: 'POST',
            headers: mergedHeaders
        };

        const req = http.request(options, (res) => {
            let isError = (res.statusCode && (res.statusCode < 200 || res.statusCode >= 400));
            let responseData = '';
            res.on('data', (chunk) => responseData += chunk);
            res.on('end', () => {
                outputChannel.info(`response to request for: ${path}`);
                outputChannel.info(`${data}`);
                outputChannel.info(`response: ${responseData}`);
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
    private _initArgs: DebugProtocol.InitializeRequestArguments | undefined;
    private _attachArgs: IAttachRequestArguments = { port: 0, apiKey: "" };
    private _pollInput: PollInput = { last_event_id: 0, view_states: { log: "", text: "" }, task_states: [] };
    private _mapping: Map<number, LogMapping> = new Map();
    private _variableHandles: Map<number, Handles<'locals'>> = new Map();
    private _variableToFrame: Map<number, number> = new Map();
    private _previousThreadIds: Set<number> = new Set();
    private _previousBackgroundTaskIds: Set<string> = new Set();
    private _attached = false;
    private _initialized = false;
    private _nextBreakpointId = 1;

    /**
     * Create a new debug adapter to use with a debug session.
     */
    public constructor() {
        super("lnav-dap.txt");

        this.setDebuggerLinesStartAt1(true);
        this.setDebuggerColumnsStartAt1(true);

        outputChannel.info("Starting up...");
    }

    private pollLnav() {
        outputChannel.info(`pollLnav: last_event_id=${this._pollInput.last_event_id}, view_states=${JSON.stringify(this._pollInput.view_states)}`);
        const prevViewStates = { ...this._pollInput.view_states };
        const prevTaskStates = this._pollInput.task_states;

        if (this._attached) {
            sendDebuggerCommand(this._attachArgs as IAttachRequestArguments, '/poll', JSON.stringify(this._pollInput))
                .then((pollResult: PollResult) => {
                    outputChannel.info(`pollLnav result: ${JSON.stringify(pollResult)}`);

                    // handle background task start/stop events
                    const latestBackgroundIds = new Set<string>();
                    for (const task of pollResult.background_tasks || []) {
                        latestBackgroundIds.add(task.id);
                    }
                    let task_ended = false;

                    if (this._initArgs?.supportsProgressReporting) {
                        // started tasks: in latest but not in previous
                        for (const task of pollResult.background_tasks || []) {
                            if (this._previousBackgroundTaskIds.has(task.id)) {
                                if (task.status == 'working') {
                                    outputChannel.info(`background task updated: ${task.id}`);
                                    let prog_event: DebugProtocol.ProgressUpdateEvent = new ProgressUpdateEvent(task.id, task.current_step);
                                    prog_event.body.percentage = task.completed * 100 / task.total;
                                    this.sendEvent(prog_event);
                                } else {
                                    outputChannel.info(`background task ended: ${task.id}`);
                                    this.sendEvent(new ProgressEndEvent(task.id));
                                    task_ended = true;
                                }
                            } else {
                                outputChannel.info(`background task started: ${task.id}`);
                                // Use current_step as title if available
                                const msg = task.current_step || 'background task';
                                let prog_event: DebugProtocol.ProgressStartEvent = new ProgressStartEvent(task.id, 'lnav initialization', msg);
                                prog_event.body.percentage = task.completed * 100 / task.total;
                                this.sendEvent(prog_event);
                            }
                        }
                    }

                    if (!this._initialized && task_ended) {
                        this._initialized = true;
                        this.sendEvent(new InitializedEvent());
                        //let event: DebugProtocol.StoppedEvent = new StoppedEvent('pause');
                        //event.body.allThreadsStopped = true;
                        //this.sendEvent(event);
                    }

                    // update previous background task ids
                    this._previousBackgroundTaskIds = latestBackgroundIds;

                    this._pollInput = pollResult.next_input;
                    // Only send StoppedEvent if PollInput has changed
                    if (this._initialized &&
                        (pollResult.next_input.view_states.log !== prevViewStates.log ||
                            pollResult.next_input.view_states.text !== prevViewStates.text ||
                            task_ended)
                    ) {
                        sendDebuggerCommand(this._attachArgs, '/exec', findBreakpointIdScript)
                            .then((res: Array<FindBreakpointResult>) => {
                                outputChannel.info(`stop breakpoints ${res}`);
                                let event: DebugProtocol.StoppedEvent = new StoppedEvent(
                                    (res.length > 0 && res[0].bpids.length > 0) ? 'breakpoint' : 'step');
                                if (res.length > 0) {
                                    event.body.threadId = res[0].thread_id;
                                    event.body.hitBreakpointIds = res[0].bpids;
                                    // event.body.preserveFocusHint = true;
                                }
                                event.body.allThreadsStopped = true;
                                outputChannel.info(`sending stopped event: ${JSON.stringify(event)}`);
                                this.sendEvent(event);
                                this.pollLnav();
                            })
                            .catch((err) => {
                                outputChannel.error(`poll failed ${err}`);
                                this.pollLnav();
                            });
                    } else {
                        this.pollLnav();
                    }
                })
                .catch((err) => {
                    outputChannel.error(`poll failed: ${err}`);
                });
        }
    }

    protected disconnectRequest(response: DebugProtocol.DisconnectResponse, args: DebugProtocol.DisconnectArguments, request?: DebugProtocol.Request): void {
        outputChannel.info(`disconnectRequest suspend: ${args.suspendDebuggee}, terminate: ${args.terminateDebuggee}`);
        this._attached = false;
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
        outputChannel.info(`terminateRequest`);
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
        outputChannel.info(`initializeRequest: ${JSON.stringify(args)}`);

        this._initArgs = args;
        response.body = response.body || {};
        response.body.supportsStepBack = true;
        // response.body.supportsBreakpointLocationsRequest = true;
        response.body.supportTerminateDebuggee = true;
        response.body.supportsConditionalBreakpoints = true;

        this.sendResponse(response);
    }

    protected setBreakPointsRequest(response: DebugProtocol.SetBreakpointsResponse, args: DebugProtocol.SetBreakpointsArguments): Promise<void> {
        outputChannel.info(`setBreakPointsRequest ${JSON.stringify(args)}`);

        const bpPath = args.source.path as string;
        // TODO handle lines?
        const bps = args.breakpoints || [];
        let bpsOut = new Array<DebugProtocol.Breakpoint>();
        let extraHeader = new Map<string, string>();
        extraHeader.set('X-Source-File', encodeValueForHeader(bpPath));
        const script = deleteBreakpointsScript.concat(bps.map((sourceBp) => {
            let bpid = this._nextBreakpointId;
            this._nextBreakpointId += 1;
            if (sourceBp.condition && sourceBp.condition.startsWith("/") && sourceBp.condition.endsWith("/")) {
                const condRegex = sourceBp.condition.slice(1, -1);
                extraHeader.set(`X-Bp-Cond${bpid}`, encodeValueForHeader(condRegex));
            }
            const populateBreakpointTableScript = `
;REPLACE INTO vscode_breakpoints
    SELECT sls.pattern,
           CAST (decode($headers ->> '$.x-source-file', 'base64') AS TEXT),
           ${bpid},
           CAST (decode($headers ->> ('$.x-bp-cond' || ${bpid}), 'base64') AS TEXT)
      FROM source_log_stmt(CAST(decode($headers ->> '$.x-source-file', 'base64') AS TEXT)) AS sls
     WHERE ${sourceBp.line} BETWEEN sls.begin_line AND sls.end_line
`;
            bpsOut.push({ id: bpid, line: sourceBp.line, verified: true });

            return populateBreakpointTableScript;
        }).join('\n'));

        response.body = {
            breakpoints: bpsOut,
        };
        outputChannel.info(`breakpoints: ${JSON.stringify(Object.fromEntries(extraHeader))} -> ${script}`);
        return sendDebuggerCommand(this._attachArgs as IAttachRequestArguments, '/exec', script, extraHeader)
            .then(() => {
                let event: DebugProtocol.StoppedEvent = new StoppedEvent('pause');
                event.body.allThreadsStopped = true;
                this.sendEvent(event);
                this.sendResponse(response);
            })
            .catch((err) => {
                outputChannel.error(`failed to set breakpoint: ${err}`);
                this.sendErrorResponse(response, 3002, err.message);
            });
    }

    protected attachRequest(response: DebugProtocol.AttachResponse, args: IAttachRequestArguments): Promise<void> {
        outputChannel.info(`attachRequest ${JSON.stringify(args)}`);

        // make sure to 'Stop' the buffered logging if 'trace' is not set
        logger.setup(Logger.LogLevel.Verbose, false);

        this._attachArgs = args;

        return getDebuggerInfo(args, '/version').then((info): Promise<void> => {
            this._attached = true;
            outputChannel.info(`lnav version: ${info.version}`);
            this.sendResponse(response);
            outputChannel.info(`starting poller`);
            this.pollLnav();
            // Build ':add-source-path <workspace-path>' for each workspace folder
            const workspaceFolders = vscode.workspace.workspaceFolders ?? [];
            const initScript = workspaceFolders
                .map(folder => `:add-source-path ${folder.uri.fsPath}\n`)
                .join('\n').concat(createBreakpointTableScript);
            outputChannel.info(`init script: ${initScript}`);
            return sendDebuggerCommand(this._attachArgs as IAttachRequestArguments, '/exec', initScript)
                .then(() => {
                });
        }).catch((err) => {
            outputChannel.error(`error getting lnav version: ${err}`);
            this.sendErrorResponse(response, 3000, `Error connecting to lnav instance: ${err}`);
        });
    }

    protected launchRequest(response: DebugProtocol.LaunchResponse, args: ILaunchRequestArguments) {
        outputChannel.info(`launchRequest ${JSON.stringify(args)}`);

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
            const writeInfoArg = `|lnav-write-external-access-info-to ${tempFilePath}`;
            const apiKey = uuidv4();

            let runArgs: DebugProtocol.RunInTerminalRequestArguments = {
                kind: "integrated", // "external",
                title: "lnav",
                cwd: ".",
                args: [
                    "exec",
                    "/usr/local/bin/lnav",
                    "-d", "/tmp/vscode-lnav.err",
                    "-c", `:external-access 0 ${apiKey}`,
                    "-c", writeInfoArg,
                    args.logFile,
                ],
            };
            this.runInTerminalRequest(runArgs, 600000, response => {
                outputChannel.info(`run resp ${JSON.stringify(response)}`);
            });

            if (false) {
                // Create and show a new terminal, then run a command
                const terminal = vscode.window.createTerminal({ name: `lnav debug ${path.basename(args.logFile)}` });
                terminal.show();
                terminal.sendText(`exec lnav -d /tmp/vscode-lnav.err -c ':external-access 0 ${apiKey}' ${writeInfoArg} ${args.logFile}`);
                // vscode.commands.executeCommand('workbench.action.terminal.moveToEditor');
            }
            // Poll for tempFilePath creation, read and parse it
            const timeoutMs = 10000;
            const pollIntervalMs = 250;
            const startTime = Date.now();
            let port: number | undefined = undefined;

            const pollForFile = () => {
                outputChannel.info(`Checking for port file: ${tempFilePath}`);
                if (fs.existsSync(tempFilePath)) {
                    try {
                        const fileContent = fs.readFileSync(tempFilePath, 'utf8');
                        const info = JSON.parse(fileContent);
                        port = info.port;
                        outputChannel.info(`Using port: ${port}`);
                        fs.unlinkSync(tempFilePath);
                    } catch (err) {
                        outputChannel.error(`Error reading/parsing temp file: ${err}`);
                    }
                }
                if (port !== undefined) {
                    this.attachRequest(response, { port, apiKey });
                } else if (Date.now() - startTime < timeoutMs) {
                    setTimeout(pollForFile, pollIntervalMs);
                } else {
                    outputChannel.info(`Timeout waiting for lnav info file: ${tempFilePath}`);
                    this.sendErrorResponse(response, 3001, `Timeout waiting for lnav info file`);
                }
            };

            this.sendResponse(response);
            pollForFile();
        });
    }

    protected threadsRequest(response: DebugProtocol.ThreadsResponse): Promise<void> {
        outputChannel.info(`threadsRequest`);

        this._mapping.clear();
        this._variableHandles.clear();
        this._variableToFrame.clear();
        // Fetch the latest threads from lnav
        return sendDebuggerCommand(this._attachArgs, '/exec', getThreadIdsScript)
            .then((threads: { rowid: number, thread_id: string }[]) => {
                const latestThreadIds = new Set<number>();
                const threadObjs: DebugProtocol.Thread[] = [];

                outputChannel.info(`got threads: ${JSON.stringify(threads)}`);
                for (const t of threads) {
                    latestThreadIds.add(t.rowid);
                    threadObjs.push(new Thread(t.rowid, t.thread_id));
                }

                // Threads that have started
                for (const id of latestThreadIds) {
                    if (!this._previousThreadIds.has(id)) {
                        outputChannel.info(`thread started: ${id}`);
                        this.sendEvent(new ThreadEvent('started', id));
                    }
                }

                // Threads that have exited
                for (const id of this._previousThreadIds) {
                    if (!latestThreadIds.has(id)) {
                        outputChannel.info(`thread exited: ${id}`);
                        this.sendEvent(new ThreadEvent('exited', id));
                    }
                }

                this._previousThreadIds = latestThreadIds;

                response.body = { threads: threadObjs };
                this.sendResponse(response);
            })
            .catch((err) => {
                outputChannel.info(`Error fetching threads: ${err}`);
                response.body = { threads: [] };
                this.sendResponse(response);
            });
    }

    protected continueRequest(response: DebugProtocol.ContinueResponse, args: DebugProtocol.ContinueArguments): void {
        outputChannel.info(`continueRequest ${JSON.stringify(args)}`);

        const continueScript = `
;SELECT thread_id AS curr_thread_id FROM all_thread_ids WHERE rowid = ${args.threadId}
;SELECT log_line AS next_line
   FROM all_logs
   LEFT JOIN vscode_breakpoints ON log_body REGEXP pattern AND (condition IS NULL OR log_body REGEXP condition)
  WHERE log_line > log_msg_line() AND
        log_msg_src IS NOT NULL AND
        log_thread_id IS $curr_thread_id AND
        pattern IS NOT NULL
  ORDER BY log_line ASC
  LIMIT 1
;SELECT raise_error('No further breakpoints found for this thread') WHERE $next_line IS NULL;
;UPDATE lnav_views SET selection = $next_line WHERE name = 'log';
`;

        sendDebuggerCommand(this._attachArgs, '/exec', continueScript)
            .then(() => {
                outputChannel.info(`continued to the next breakpoint`);
                response.success = true;
                this.sendResponse(response);
            })
            .catch((err) => {
                if (err instanceof ExecError) {
                    this.sendErrorResponse(response, 3002, err.message);
                } else {
                    outputChannel.error(`error stepping to next line: ${err}`);
                    this.sendErrorResponse(response, 3002, `Error stepping to next line: ${err}`);
                }
            });
    }

    protected reverseContinueRequest(response: DebugProtocol.ReverseContinueResponse, args: DebugProtocol.ReverseContinueArguments): void {
        outputChannel.info(`reverseContinueRequest ${JSON.stringify(args)}`);

        const reverseContinueScript = `
;SELECT thread_id AS curr_thread_id FROM all_thread_ids WHERE rowid = ${args.threadId}
;SELECT log_line AS prev_line
   FROM all_logs
   LEFT JOIN vscode_breakpoints ON log_body REGEXP pattern
  WHERE log_line < log_msg_line() AND
        log_msg_src IS NOT NULL AND
        log_thread_id IS $curr_thread_id AND
        pattern IS NOT NULL
  ORDER BY log_line ASC
  LIMIT 1
;SELECT raise_error('No previous breakpoints found for this thread') WHERE $prev_line IS NULL;
;UPDATE lnav_views SET selection = $prev_line WHERE name = 'log';
`;

        sendDebuggerCommand(this._attachArgs, '/exec', reverseContinueScript)
            .then(() => {
                outputChannel.info(`continued to the next breakpoint`);
                response.success = true;
                this.sendResponse(response);
            })
            .catch((err) => {
                if (err instanceof ExecError) {
                    this.sendErrorResponse(response, 3002, err.message);
                } else {
                    outputChannel.error(`error stepping to next line: ${err}`);
                    this.sendErrorResponse(response, 3002, `Error stepping to next line: ${err}`);
                }
            });
    }

    protected nextRequest(response: DebugProtocol.NextResponse, args: DebugProtocol.NextArguments): void {
        outputChannel.info(`nextRequest ${JSON.stringify(args)}`);

        const nextLineScript = `
;SELECT thread_id AS curr_thread_id FROM all_thread_ids WHERE rowid = ${args.threadId}
;SELECT log_line AS next_line
   FROM all_logs
  WHERE log_line > log_msg_line() AND
        log_msg_src IS NOT NULL AND
        log_thread_id IS $curr_thread_id
  ORDER BY log_line ASC
  LIMIT 1;
;SELECT raise_error('No further log messages from this thread') WHERE $next_line IS NULL;
;UPDATE lnav_views SET selection = $next_line WHERE name = 'log';
`;

        sendDebuggerCommand(this._attachArgs, '/exec', nextLineScript)
            .then(() => {
                outputChannel.info(`stepped to next line`);
                response.success = true;
                this.sendResponse(response);
            })
            .catch((err) => {
                if (err instanceof ExecError) {
                    this.sendErrorResponse(response, 3002, err.message);
                } else {
                    outputChannel.info(`error stepping to next line: ${err}`);
                    this.sendErrorResponse(response, 3002, `Error stepping to next line: ${err}`);
                }
            });
    }

    protected stepBackRequest(response: DebugProtocol.StepBackResponse, args: DebugProtocol.StepBackArguments): void {
        outputChannel.info(`stepBackRequest ${JSON.stringify(args)}`);

        const prevLineScript = `
;SELECT thread_id AS curr_thread_id FROM all_thread_ids WHERE rowid = ${args.threadId}
;SELECT log_line AS prev_line
   FROM all_logs
  WHERE log_line < log_msg_line() AND
        log_thread_id IS $curr_thread_id AND
        log_msg_src IS NOT NULL
  ORDER BY log_line DESC
  LIMIT 1;
;SELECT raise_error('No previous log messages from this thread') WHERE $prev_line IS NULL;
;UPDATE lnav_views SET selection = $prev_line WHERE name = 'log';
`;

        sendDebuggerCommand(this._attachArgs, '/exec', prevLineScript)
            .then(() => {
                outputChannel.info(`stepped back one line`);
                response.success = true;
                this.sendResponse(response);
            })
            .catch((err) => {
                outputChannel.info(`error stepping to previous line: ${err}`);
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

    protected stackTraceRequest(response: DebugProtocol.StackTraceResponse, args: DebugProtocol.StackTraceArguments): Promise<void> {
        outputChannel.info(`stackTraceRequest ${JSON.stringify(args)}`);

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

        return sendDebuggerCommand(this._attachArgs as IAttachRequestArguments, '/exec', getCurrLineScript)
            .then((row) => {
                outputChannel.info(`got current line: ${JSON.stringify(row)}`);
                let row0 = row[0];

                let srcRef: SourceRef | undefined;
                if (row0.log_msg_src) {
                    srcRef = {
                        sourcePath: row0.log_msg_src.file,
                        lineNumber: row0.log_msg_src.begin_line,
                        name: row0.log_msg_src.name.replace(/\s+/g, ' '),
                        column: 1,
                    };
                }
                let vars = new Array<VariablePair>;
                if (Array.isArray(row0.log_msg_values)) {
                    vars = row0.log_msg_values.map((element: { expr: string, value: string }) => {
                        let retval: VariablePair = { expr: element.expr, value: element.value };
                        return retval;
                    });
                }
                this._mapping.set(args.threadId, {
                    variables: vars,
                });
                const currentFrame = this.buildStackFrame(args.threadId, srcRef);
                const stack: StackFrame[] = [currentFrame];

                response.body = {
                    stackFrames: stack,
                    totalFrames: stack.length
                };
                outputChannel.info(`response ${JSON.stringify(response.body)}`);

                this.sendResponse(response);
            })
            .catch((err) => {
                outputChannel.error(`stack trace request failed: ${err}`);
                this.sendErrorResponse(response, 3002, err.message);
            });
    }

    protected scopesRequest(response: DebugProtocol.ScopesResponse, args: DebugProtocol.ScopesArguments): void {
        outputChannel.info(`scopesRequest ${JSON.stringify(args)}`);

        let handle = new Handles<'locals'>();
        let variablesReferenceId = handle.create('locals');
        this._variableHandles.set(args.frameId, handle);
        this._variableToFrame.set(variablesReferenceId, args.frameId);
        response.body = {
            scopes: [
                new Scope("Locals", variablesReferenceId, false),
            ]
        };
        this.sendResponse(response);
    }

    protected variablesRequest(response: DebugProtocol.VariablesResponse, args: DebugProtocol.VariablesArguments, request?: DebugProtocol.Request): void {
        outputChannel.info(`variablesRequest ${JSON.stringify(args)}`);

        let vs: DebugProtocol.Variable[] = [];

        let threadId = this._variableToFrame.get(args.variablesReference);
        outputChannel.info(`got thread id ${threadId}`)
        if (threadId !== undefined) {
            let vars = this._mapping.get(threadId)?.variables;
            if (vars !== undefined) {
                outputChannel.info(`got vars`);
                for (let pair of vars) {
                    outputChannel.info(`iterator`);
                    vs.push({
                        name: pair.expr,
                        value: pair.value,
                        variablesReference: 0
                    });
                }
            }
        }

        response.body = {
            variables: vs
        };
        this.sendResponse(response);
    }
}
