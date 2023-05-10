const { calcUser, calcCertificate, callData } = require("./calculations.js");

async function main() {
    const [owner, verifier, user, challenger] = await ethers.getSigners();

    const verifierFactory = await ethers.getContractFactory("SuitabilityVerifier");
    const blockVerifyFactory = await ethers.getContractFactory("zkSuitability");

    const verifierContract = await verifierFactory.connect(owner).deploy();
    console.log("Verifier deployed to:", verifierContract.address);
    const blockVerify = await blockVerifyFactory.connect(owner).deploy(verifierContract.address, true);
    console.log("BlockVerify deployed to:", blockVerify.address);

    let tx = await blockVerify.connect(owner).addVerifier(verifier.address);
    let receipt = await tx.wait();
    console.log("Verifier added, tx:", receipt.transactionHash);

    const password = "123";
    const salt = "456";
    const userAttributes = ["1", "73", "600"];
    const userId = await calcUser(password, salt);
    console.log("User ID:", userId);
    const certificate = await calcCertificate(userId, userAttributes);
    console.log("Certificate:", certificate);
    tx = await blockVerify.connect(verifier).verifyUser(certificate, user.address);
    receipt = await tx.wait();
    console.log("User attributes verified, tx:", receipt.transactionHash);

    const challenge = "test";
    const direction = ["0", "0", "1"];
    const minAttributes = ["0", "70", "670"]; 
    tx = await blockVerify.connect(challenger).createChallenge(challenge, direction, minAttributes);
    receipt = await tx.wait();
    console.log("Challenge created, tx:", receipt.transactionHash);
    
    const proof = await callData(password, salt, userAttributes, certificate, direction, minAttributes);
    console.log("Proof:", proof);
    tx = await blockVerify.connect(user).respond(0, 1, proof); // challengeId = 0, verifierId = 1 (owner is also a verifier)
    receipt = await tx.wait();
    console.log("Response sent, tx:", receipt.transactionHash);
}

main()
    .then(() => process.exit(0))
    .catch((error) => {
        console.error(error);
        process.exit(1);
    });