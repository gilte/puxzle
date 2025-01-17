const { Worker } = require('worker_threads');
const readline = require('readline');
const CryptoJS = require('./lib/crypto-js.min.js');
const elliptic = require('./lib/elliptic.min.js');

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
});

/**
 * Função para ler entrada do usuário de forma assíncrona.
 * @param {string} question - A pergunta a ser exibida para o usuário.
 * @returns {Promise<string>} - Retorna a resposta do usuário.
 */
function askQuestion(question) {
    return new Promise((resolve) => rl.question(question, resolve));
}

/**
 * Função principal para iniciar a busca de chaves privadas.
 */
async function startSearch() {
    try {
        const targetHash = await askQuestion('Enter target hash: ');
        const rangeStart = await askQuestion('Enter range start (hex): ');
        const rangeEnd = await askQuestion('Enter range end (hex): ');
        const minStep = await askQuestion('Enter min step value: ');
        const maxStep = await askQuestion('Enter max step value: ');

        const { startHex, endHex, minStepBigInt, maxStepBigInt } = validateInput(
            rangeStart,
            rangeEnd,
            minStep,
            maxStep
        );

        const totalRange = endHex - startHex;
        const validationThreshold = (totalRange * 10n) / 100n;

        const worker = new Worker('./worker.js');
        setupWorker(worker, targetHash, rangeStart, rangeEnd, minStep, maxStep, validationThreshold);

        console.log('Starting search...');
    } catch (error) {
        console.error(`Error: ${error.message}`);
        rl.close();
    }
}

/**
 * Valida as entradas fornecidas pelo usuário.
 * @param {string} rangeStart - Valor hexadecimal de início.
 * @param {string} rangeEnd - Valor hexadecimal de término.
 * @param {string} minStep - Passo mínimo.
 * @param {string} maxStep - Passo máximo.
 * @returns {Object} - Retorna os valores validados.
 */
function validateInput(rangeStart, rangeEnd, minStep, maxStep) {
    const startHex = BigInt(`0x${rangeStart}`);
    const endHex = BigInt(`0x${rangeEnd}`);
    const minStepBigInt = BigInt(minStep);
    const maxStepBigInt = BigInt(maxStep);

    if (startHex >= endHex) throw new Error('Range start must be less than range end.');
    if (minStepBigInt <= 0n || maxStepBigInt <= 0n || minStepBigInt > maxStepBigInt)
        throw new Error('Invalid step values.');

    return { startHex, endHex, minStepBigInt, maxStepBigInt };
}

/**
 * Configura o worker para realizar a busca.
 * @param {Worker} worker - Instância do worker.
 * @param {string} targetHash - Hash alvo.
 * @param {string} rangeStart - Valor hexadecimal de início.
 * @param {string} rangeEnd - Valor hexadecimal de término.
 * @param {string} minStep - Passo mínimo.
 * @param {string} maxStep - Passo máximo.
 * @param {BigInt} validationThreshold - Limite de validação.
 */
function setupWorker(worker, targetHash, rangeStart, rangeEnd, minStep, maxStep, validationThreshold) {
    worker.on('message', (message) => {
        if (message.type === 'update') {
            updateStatus(message.data);
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

    worker.postMessage({
        rangeStart,
        rangeEnd,
        targetHash,
        minStep,
        maxStep,
        validationThreshold: validationThreshold.toString(),
    });
}

/**
 * Atualiza o status da busca no terminal.
 * @param {Object} data - Dados a serem exibidos.
 */
function updateStatus(data) {
    const { targetHash, privateKeyHex, ripemd160Hash, rangeStart, rangeEnd, currentStep, randomStep } = data;

    process.stdout.write(`\x1b[2K\r`); // Limpa a linha e retorna ao início
    process.stdout.write(`
🌌 ============================ SEARCH STATUS ============================ 🌌
🔍 Target Hash:      ${targetHash}
🔑 Current Private Key (Hex): ${privateKeyHex}
🔗 Hash Generated:  ${ripemd160Hash}
🔄 Range Start:     ${rangeStart}
🔄 Range End:       ${rangeEnd}
🚀 Current Step:    ${currentStep}
🎲 Random Step:     ${randomStep}
🌌 ======================================================================= 🌌
`);
}

// Inicia a busca
startSearch();
