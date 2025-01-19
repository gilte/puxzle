const { Worker } = require('worker_threads');
const readline = require('readline');

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
});

rl.question('Enter target hash: ', (targetHash) => {
    rl.question('Enter range start (hex): ', (rangeStart) => {
        rl.question('Enter range end (hex): ', (rangeEnd) => {
            rl.question('Enter min step value: ', (minStep) => {
                rl.question('Enter max step value: ', (maxStep) => {
                    try {
                        const startHex = BigInt(`0x${rangeStart}`);
                        const endHex = BigInt(`0x${rangeEnd}`);
                        const minStepBigInt = BigInt(minStep);
                        const maxStepBigInt = BigInt(maxStep);

                        if (startHex >= endHex) throw new Error("Range start must be less than range end.");
                        if (minStepBigInt <= 0n || maxStepBigInt <= 0n || minStepBigInt > maxStepBigInt) throw new Error("Invalid step values.");

                        const worker = new Worker('./worker.js');

                        worker.on('message', (message) => {
                            if (message.type === 'update') {
                                process.stdout.write(`${message.message}\r`);
                            } else if (message.type === 'found') {
                                console.log(`\nPrivate Key Found: ${message.privateKey}`);
                                worker.terminate();
                                rl.close();
                            } else if (message.type === 'finished') {
                                console.log(`\nSearch completed. ${message.message}`);
                                rl.close();
                            }
                        });

                        worker.on('error', (error) => {
                            console.error(`Error: ${error.message}`);
                            worker.terminate();
                            rl.close();
                        });

                        // Enviando mensagem sem o validationThreshold
                        worker.postMessage({
                            rangeStart,
                            rangeEnd,
                            targetHash,
                            minStep,
                            maxStep
                        });

                        console.log('Starting search...');
                    } catch (error) {
                        console.error(`Error: ${error.message}`);
                        rl.close();
                    }
                });
            });
        });
    });
});
