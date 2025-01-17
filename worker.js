const { parentPort, workerData } = require('worker_threads');
const CryptoJS = require('./lib/crypto-js.min.js');
const elliptic = require('./lib/elliptic.min.js');

/**
 * Função para gerar o hash a partir da chave pública (SHA256 -> RIPEMD160) e verificar se corresponde ao hash alvo.
 * @param {string} publicKeyHex - A chave pública em formato hexadecimal.
 * @param {string} targetHash - O hash alvo a ser encontrado.
 * @returns {boolean} - Retorna verdadeiro se o hash gerado a partir da chave pública corresponder ao hash alvo.
 */
function verifyHash(publicKeyHex, targetHash) {
    // Hashing: SHA-256 seguido de RIPEMD-160
    const sha256Hash = CryptoJS.SHA256(CryptoJS.enc.Hex.parse(publicKeyHex));
    const ripemd160Hash = CryptoJS.RIPEMD160(sha256Hash).toString(CryptoJS.enc.Hex);
    return ripemd160Hash === targetHash;
}

/**
 * Função que executa a busca da chave privada correspondente ao hash alvo.
 * @param {BigInt} rangeStart - O valor hexadecimal de início do intervalo.
 * @param {BigInt} rangeEnd - O valor hexadecimal de fim do intervalo.
 * @param {string} targetHash - O hash alvo a ser encontrado.
 * @param {BigInt} minStep - O valor mínimo do passo.
 * @param {BigInt} maxStep - O valor máximo do passo.
 */
function searchForPrivateKey(rangeStart, rangeEnd, targetHash, minStep, maxStep) {
    const EC = elliptic.ec;
    const ec = new EC('secp256k1');

    let currentStep = rangeStart;

    // A cada iteração, verificamos se o hash gerado pela chave pública corresponde ao hash alvo
    while (currentStep <= rangeEnd) {
        // Gera a chave privada em formato hexadecimal
        const privateKeyHex = currentStep.toString(16).padStart(64, '0');
        
        // Gerar chave pública a partir da chave privada
        const keyPair = ec.keyFromPrivate(privateKeyHex);
        const publicKey = keyPair.getPublic(true, 'hex');  // Chave pública comprimida em hexadecimal

        // Verifica se o hash gerado pela chave pública corresponde ao hash alvo
        if (verifyHash(publicKey, targetHash)) {
            // Envia a chave privada encontrada de volta para o main thread
            parentPort.postMessage({
                type: 'found',
                privateKey: privateKeyHex,
            });
            return; // Encerra a busca se a chave for encontrada
        }

        // A cada iteração, incrementamos o passo para gerar uma nova chave privada
        currentStep += BigInt(minStep + Math.floor(Math.random() * (Number(maxStep - minStep + 1))));
    }

    // Caso o intervalo seja percorrido sem sucesso, notificamos que a busca terminou
    parentPort.postMessage({
        type: 'finished',
        message: 'Search completed without finding a matching key.',
    });
}

/**
 * Função principal do Worker que gerencia a execução do processo de busca.
 */
function main() {
    const { rangeStart, rangeEnd, targetHash, minStep, maxStep } = workerData;

    // Inicia a busca pela chave privada correspondente ao hash alvo
    searchForPrivateKey(rangeStart, rangeEnd, targetHash, minStep, maxStep);
}

// Executa a função principal
main();
