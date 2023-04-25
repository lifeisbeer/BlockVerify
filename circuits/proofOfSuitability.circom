pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";

// This is similar to a user id, this is done by the user, we do this so that the verifier cannot create user proofs
// The userSalt is necessary to prevent rainbow table attacks, but can be stored on chain
template CalculateUser() {
    signal input password;
    signal input userSalt;

    signal output user;

    component poseidon = Poseidon(2);

    poseidon.inputs[0] <== password;
    poseidon.inputs[1] <== userSalt;

    user <== poseidon.out;
}

// This is done by the verifier who verifies the attributes before issuing the "certificate" on chain
// Salt is not necessary here as we assume that the "user id" is kept secret, 
//  if this is revealed then an attacker might be able to guess user's attributes
// Attributes are numeric, but binary attributes can be represented as 0 (false) or 1 (true)
template CalculateCertificate(attrNum) {
    signal input user;
    signal input attributes[attrNum];

    signal output certificate;

    component poseidon = Poseidon(attrNum+1);

    poseidon.inputs[0] <== user;
    for (var i = 0; i < attrNum; i++) {
        poseidon.inputs[i+1] <== attributes[i];
    }     

    certificate <== poseidon.out;
}

// This is done by the user when they want to prove that they have certain attributes
template Suitability(attrNum) {
    // private inputs
    signal input password;
    signal input userSalt;
    signal input attributes[attrNum];

    // public inputs
    signal input certificate;
    signal input minAttributes[attrNum];

    // calculate user id
    component CalculateUser = CalculateUser();
    CalculateUser.password <== password;
    CalculateUser.userSalt <== userSalt;

    // calculate attributes and verify that they are at least the minimum attributes
    component CalculateCertificate = CalculateCertificate(attrNum);
    CalculateCertificate.user <== CalculateUser.user;

    component less[attrNum];
    for (var i = 0; i < attrNum; i++) {

        // constraint: minAttributes[i] <= attributes[i]
        less[i] = LessEqThan(10); // 10 bits, range: 0 - 1023
        less[i].in[0] <== minAttributes[i];
        less[i].in[1] <== attributes[i];
        less[i].out === 1; // 1 if minAttributes[i] <= attributes[i], 0 otherwise

        CalculateCertificate.attributes[i] <== attributes[i];
    }
    // verify that the certificate is correct
    CalculateCertificate.certificate === certificate;
}

component main {public [certificate, minAttributes]} = Suitability(3); // Certificate with 3 attributes