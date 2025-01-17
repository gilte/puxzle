const { parentPort, workerData } = require('worker_threads');
const CryptoJS = require('./lib/crypto-js.min.js');
const elliptic = require('./lib/elliptic.min.js');

parentPort.on('message', async (data) => {
    const { rangeStart, rangeEnd, targetHash, minStep, maxStep, validationThreshold } = data;
    const EC = elliptic.ec;
    const ec = new EC('secp256k1');

    const start = BigInt("0x" + rangeStart);
    const end = BigInt("0x" + rangeEnd);
    const curveN = BigInt("0x" + ec.curve.n.toString(16));
    const stepMin = BigInt(minStep);
    const stepMax = BigInt(maxStep);
    const validationThresholdBigInt = BigInt(validationThreshold);

    let currentStep = start;
    let keysTested = 0;
    let lastUpdateTime = Date.now();

    // Função para gerar um passo aleatório entre stepMin e stepMax
    function getRandomStep() {
        return BigInt(Math.floor(Math.random() * (Number(stepMax - stepMin) + 1)) + Number(stepMin));
    }

    while (currentStep <= end) {
        try {
            // Antes do limite de validação, apenas avança
            if (currentStep < validationThresholdBigInt) {
                currentStep += getRandomStep();

                if (keysTested % 1000n === 0n) {
                    parentPort.postMessage({
                        type: 'update',
                        message: `Skipping validation: current step = ${currentStep.toString(16).padStart(64, '0')}\n`,
                    });
                }
                continue;
            }

            // Após o limite, realiza a validação
            const privateKeyHex = currentStep.toString(16).padStart(64, '0');
            const keyPair = ec.keyFromPrivate(privateKeyHex);
            const publicKey = keyPair.getPublic(true, 'hex');

            // Hashing: SHA-256 seguido de RIPEMD-160
            const sha256Hash = CryptoJS.SHA256(CryptoJS.enc.Hex.parse(publicKey));
            const ripemd160Hash = CryptoJS.RIPEMD160(sha256Hash).toString();

            // Log da chave sendo testada
            process.stdout.write(String.fromCharCode(27) + '[2K' + String.fromCharCode(27) + '[0G');
            // Limpa a linha
            parentPort.postMessage({
                type: 'update',
                message: `
🌌 ============================ SEARCH STATUS ============================ 🌌
🔍 Target Hash:      ${targetHash}
🔑 Current Private Key (Hex): ${privateKeyHex}
🔗 Hash Generated:  ${ripemd160Hash}
🔄 Range Start:     ${rangeStart}
🔄 Range End:       ${rangeEnd}
🚀 Current Step:    ${currentStep.toString()}
🎲 Random Step:     ${getRandomStep().toString(10)}
🌌 ======================================================================= 🌌
                `,
            });

            if (ripemd160Hash === targetHash) {
                parentPort.postMessage({ type: 'found', privateKey: privateKeyHex });
                break;
            }

            keysTested++;

            // Atualiza a cada 1000 chaves testadas
            if (keysTested % 1000n === 0n) {
                const currentTime = Date.now();
                const elapsedTime = (currentTime - lastUpdateTime) / 1000; // Tempo em segundos
                const keysPerSecond = elapsedTime > 0 ? keysTested / elapsedTime : 0;

                parentPort.postMessage({
                    type: 'update',
                    message: `Keys per second: ${Math.round(keysPerSecond)}`,
                });

                lastUpdateTime = currentTime;
                keysTested = 0;
            }
        } catch (error) {
            parentPort.postMessage({
                type: 'error',
                message: `Error at step ${currentStep.toString(16).padStart(64, '0')}: ${error.message}`,
            });
        }

        currentStep += getRandomStep();

        // Reinicia ao atingir o final do intervalo, opcional
        if (currentStep > end) {
            currentStep = start;
            parentPort.postMessage({
                type: 'update',
                message: `Restarting search: current step reset to ${currentStep.toString(16).padStart(64, '0')}`,
            });
        }
    }

    parentPort.postMessage({ type: 'finished', message: 'Search completed.' });
});
