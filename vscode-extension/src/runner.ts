import { spawn } from 'child_process';

import { AnsedeReportEnvelope, parseReportPayload } from './protocol';


export interface RunScanOptions {
    executable: string;
    language: string;
    code: string;
    timeoutMs?: number;
}


export function runAnsedeScan(options: RunScanOptions): Promise<AnsedeReportEnvelope> {
    const timeoutMs = options.timeoutMs ?? 15_000;

    return new Promise((resolve, reject) => {
        const child = spawn(
            options.executable,
            ['--stdin', '--lang', options.language, '--format', 'json', '--fail-on', 'never'],
            { windowsHide: true },
        );

        let stdout = '';
        let stderr = '';
        let settled = false;

        const finish = (callback: () => void): void => {
            if (settled) {
                return;
            }
            settled = true;
            clearTimeout(timer);
            callback();
        };

        const timer = setTimeout(() => {
            child.kill();
            finish(() => reject(new Error(`ansede-static timed out after ${timeoutMs}ms`)));
        }, timeoutMs);

        child.stdout.setEncoding('utf8');
        child.stderr.setEncoding('utf8');

        child.stdout.on('data', (chunk: string) => {
            stdout += chunk;
        });
        child.stderr.on('data', (chunk: string) => {
            stderr += chunk;
        });

        child.on('error', (error: Error) => {
            const errorWithCode = error as NodeJS.ErrnoException;
            if (errorWithCode.code === 'ENOENT') {
                finish(() => reject(new Error(`ansede-static executable not found: ${options.executable}`)));
                return;
            }
            finish(() => reject(error));
        });

        child.on('close', (code: number | null) => {
            finish(() => {
                if (!stdout.trim()) {
                    const detail = stderr.trim() || `ansede-static exited with code ${code ?? 'unknown'}`;
                    reject(new Error(detail));
                    return;
                }
                try {
                    resolve(parseReportPayload(stdout));
                } catch (error) {
                    reject(error instanceof Error ? error : new Error(String(error)));
                }
            });
        });

        child.stdin.on('error', () => {
            // Ignore stdin shutdown races; close/error handlers above decide success.
        });
        child.stdin.end(options.code);
    });
}