const { buildPoseidon } = require("circomlibjs");
const { groth16 } = require("snarkjs");

async function poseidon(input) {
    let poseidon = await buildPoseidon()
    return poseidon.F.toObject(poseidon(input))
}

async function calcUser(password, salt) {
    return poseidon([password, salt]);
}

async function calcCertificate(user, attributes) {
    const newIn = [user].concat(attributes);
    return poseidon(newIn);
}

async function exportCallDataGroth16(input) {
    const { proof, publicSignals } = await groth16.fullProve(input, "./scripts/proofOfSuitability.wasm", "./scripts/groth16_final.zkey");

    const calldata = await groth16.exportSolidityCallData(proof, publicSignals);

    globalThis.curve_bn128.terminate(); // without this the execution never terminates (https://github.com/iden3/snarkjs/issues/152)

    //console.log(calldata);

    const argv = calldata.replace(/["[\]\s]/g, "").split(",");
    //.map((x) => BigInt(x).toString());
    //console.log(argv);

    return argv;
}

async function callData(password, userSalt, attributes, certificate, direction, minAttributes) {
    const INPUT = {
        password: password,
        userSalt: userSalt,
        attributes: attributes,
        certificate: certificate,
        direction: direction,
        minAttributes: minAttributes      
    };

    let proof;
    //let input;

    try {
        let dataResult = await exportCallDataGroth16(INPUT);
        proof = dataResult.slice(0, 8);
        //input = dataResult.slice(8, 13);
    } catch (error) {
        console.log(error);
        //window.alert("Wrong input");
    }

    return proof;
}

module.exports = {
    calcUser,
    calcCertificate,
    callData
};