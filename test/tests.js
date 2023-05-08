const { expect } = require("chai");
const { ethers } = require("hardhat");
const { loadFixture } = require("@nomicfoundation/hardhat-network-helpers");
const { calcUser, calcCertificate, callData } = require("../scripts/calculations.js");

describe("BlockVerify", function () {

  async function deployFixture() {

    const [owner, verifier, user, challenger] = await ethers.getSigners();

    const verifierFactory = await ethers.getContractFactory("SuitabilityVerifier");
    const blockVerifyFactory = await ethers.getContractFactory("zkSuitability");

    const verifierContract = await verifierFactory.deploy();
    const blockVerify = await blockVerifyFactory.deploy(verifierContract.address, true);

    return { owner, verifier, user, challenger, blockVerify };
  }

  async function userFixture() {

    const password = "123";
    const salt = "456";
    const userId = "19620391833206800292073497099357851348339828238212863168390691880932172496143";

    const userAttributes = ["1", "73", "750"];
    const userCertificate = "19291942765737016641315490180792170985811752680615714997126424296971201214309";

    const challenge = "test";
    const minAttributes = ["0", "70", "670"]; 

    return { password, salt, userId, userAttributes, userCertificate, challenge, minAttributes };
  }

  it("Owner adding a verifier", async function () {

    const { owner, verifier, blockVerify } = await loadFixture( deployFixture );

    expect(await blockVerify.verifiers(verifier.address)).to.equal(false);

    await blockVerify.connect(owner).addVerifier(verifier.address);

    expect(await blockVerify.verifiers(verifier.address)).to.equal(true);
  });

  it("User creating an identity", async function () {

    const { password, salt, userId } = await loadFixture( userFixture );
    const id = await calcUser(password, salt);

    expect(id).to.equal(userId);
  });

  it("Creating a certificate for the user", async function () {

    const { userId, userAttributes, userCertificate } = await loadFixture( userFixture );
    const certificate = await calcCertificate(userId, userAttributes);

    expect(certificate).to.equal(userCertificate);
  });

  it("Verifier posting a user certificate", async function () {

    const { owner, verifier, user, blockVerify } = await loadFixture( deployFixture );
    const { userCertificate } = await loadFixture( userFixture );

    await blockVerify.connect(owner).addVerifier(verifier.address);

    expect(await blockVerify.userCertificates(user.address, verifier.address)).to.equal(0);

    await blockVerify.connect(verifier).verifyUser(userCertificate, user.address);

    expect(await blockVerify.userCertificates(user.address, verifier.address)).to.equal(userCertificate);
  });

  it("Challenger posting a challenge", async function () {

    const { challenger, blockVerify } = await loadFixture( deployFixture );      
    const { challenge, minAttributes } = await loadFixture( userFixture );

    expect(await blockVerify.challengeNum()).to.equal(0);

    await blockVerify.connect(challenger).createChallenge(challenge, minAttributes);

    expect(await blockVerify.challengeNum()).to.equal(1);
    const retChallenge = await blockVerify.viewChallenge(0);
    expect(retChallenge['description']).to.equal(challenge);
    expect(retChallenge['minAttributes']).to.deep.equal(minAttributes);
    expect(retChallenge['responses']).to.deep.equal([]);
  });

  it("User responds to a challenge", async function () {
      
    const { owner, verifier, user, challenger, blockVerify } = await loadFixture( deployFixture );
    const { password, salt, userAttributes, userCertificate, challenge, minAttributes } = await loadFixture( userFixture );

    await blockVerify.connect(owner).addVerifier(verifier.address);
    await blockVerify.connect(verifier).verifyUser(userCertificate, user.address);
    await blockVerify.connect(challenger).createChallenge(challenge, minAttributes);

    const userId = await calcUser(password, salt);
    const certificate = await calcCertificate(userId, userAttributes);
    const proof = await callData(password, salt, userAttributes, certificate, minAttributes);

    const retChallengeBefore = await blockVerify.viewChallenge(0);
    expect(retChallengeBefore['responses']).to.deep.equal([]);

    await blockVerify.connect(user).respond(0, 1, proof); // challengeId = 0, verifierId = 1 (owner is also a verifier)

    const retChallengeAfter = await blockVerify.viewChallenge(0);
    expect(retChallengeAfter['responses']).to.deep.equal([user.address]);
  });
});