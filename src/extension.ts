/**
 * A "debugger" plug in for use with lnav.
 *
 * The extention serves as a Debug Adapater and implements the applicable
 * parts of the Debug Adapter Protocol for lnav.
 */

'use strict';

import * as vscode from 'vscode';
import { ProviderResult } from 'vscode';
import { DebugSession } from './debugAdapter';

const runMode: 'external' | 'server' | 'namedPipeServer' | 'inline' = 'inline';
const outputChannel = vscode.window.createOutputChannel("lnav", {log: true});

export { outputChannel }

export function activate(context: vscode.ExtensionContext) {
    // Register the command for selecting a log file
    context.subscriptions.push(
        vscode.commands.registerCommand('extension.lnav.selectLogFile', async () => {
            const uris = await vscode.window.showOpenDialog({
                canSelectMany: false,
                openLabel: 'Select log file',
                filters: {
                    'Log files': ['log', 'txt'],
                    'All files': ['*']
                }
            });
            if (uris && uris.length > 0) {
                return uris[0].fsPath;
            }
            return '';
        })
    );

    // The microsoft debug adapter extension had several ways of starting up, but the default inline method
    // seems easiest and so will focus on that initially. If there is need for other ways of starting, then
    // could look to the vscode-mock-debug for examples.
    switch (runMode) {
        case 'inline':
            // is there a way to do this in the package.json configuration instead?
            let factory = new InlineDebugAdapterFactory();
            context.subscriptions.push(vscode.debug.registerDebugAdapterDescriptorFactory('lnav', factory));
            break;

        default:
            throw new Error('Unsupported runMode ' + runMode);
    }
}

export function deactivate() {
    // nothing to do
}

class InlineDebugAdapterFactory implements vscode.DebugAdapterDescriptorFactory {
    createDebugAdapterDescriptor(_session: vscode.DebugSession): ProviderResult<vscode.DebugAdapterDescriptor> {
        return new vscode.DebugAdapterInlineImplementation(new DebugSession());
    }
}
