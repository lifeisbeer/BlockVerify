// SPDX-License-Identifier: GPL-3.0

pragma solidity >=0.8.2 <0.9.0;

import "./verifier.sol";

contract zkSuitability {

    SuitabilityVerifier public suitabilityVerifier;

    uint8 public constant ATTR_NUM = 3;

    address public immutable owner;
    mapping(address => bool) public verifiers;
    address[] public verifiersList;
    mapping(address => mapping(address => uint256)) public userCertificates; // user -> verifier -> certificate

    uint256 public challengeNum = 0;
    struct Challenge {
        string description;
        uint16[ATTR_NUM] minAttributes;
        address[] responses;
    }
    Challenge[] public challenges;

    event NewVerifier(address indexed verifier);
    event NewChallenge(uint256 indexed challengeNumber);
    event NewResponse(uint256 indexed challengeNumber, address responder, address verifier);

    error InvalidProof();

    modifier isOwner() {
        require(msg.sender == owner, "Caller is not owner");
        _;
    }
    modifier isVerifier() {
        require(verifiers[msg.sender], "Caller is not a verifier");
        _;
    }
    modifier isVerified(uint256 verifierId) {
        require(verifierId < verifiersList.length, "The selected verifier doesn't exist");
        require(userCertificates[msg.sender][verifiersList[verifierId]] > 0, "Caller is not verified by the selected verifier");
        _;
    }
    modifier isChallenge(uint256 challengeId) {
        require(challengeId < challengeNum, "The selected challenge doesn't exist");
        _;
    }

    constructor(address verAddress, bool alsoVerifier) {
        suitabilityVerifier = SuitabilityVerifier(verAddress);

        owner = msg.sender;

        if (alsoVerifier) {
            verifiers[msg.sender] = true;
            verifiersList.push(msg.sender);
            emit NewVerifier(msg.sender);
        }
    }

    function addVerifier(address verifier) public isOwner {
        verifiers[verifier] = true;
        verifiersList.push(verifier);
        emit NewVerifier(verifier);
    }

    function verifyUser(uint256 certificate, address user) public isVerifier {
        userCertificates[user][msg.sender] = certificate;
    }

    function createChallenge(
        string calldata description, 
        uint16[ATTR_NUM] calldata minAttributes
    ) public {
        challenges.push(Challenge(description, minAttributes, new address[](0)));
        emit NewChallenge(challengeNum);
        challengeNum += 1;
    }

    function viewChallenge(uint256 challengeId) 
        public 
        view 
        isChallenge(challengeId) 
        returns(Challenge memory)  
    {
        return challenges[challengeId];
    }

    function _verifyProof(
        uint256[ATTR_NUM+1] memory input,
        uint256[8] calldata proof
    ) 
        internal 
        view 
        returns (bool) 
    {
        return suitabilityVerifier.verifyProof(
            [proof[0], proof[1]],
            [[proof[2], proof[3]], [proof[4], proof[5]]],
            [proof[6], proof[7]],
            input
        );
    }

    function respond(
        uint256 challengeId, 
        uint256 verifierId,
        uint256[8] calldata proof
    ) 
        public 
        isVerified(verifierId)
        isChallenge(challengeId) 
    {
        uint256[ATTR_NUM+1] memory input;
        input[0] = userCertificates[msg.sender][verifiersList[verifierId]];
        for (uint8 i=0; i<ATTR_NUM; i++) {
            input[i+1] = challenges[challengeId].minAttributes[i];
        }

        bool outcome = _verifyProof(input, proof);

        if (!outcome) {
            revert InvalidProof();
        } else {
            challenges[challengeId].responses.push(msg.sender);
            emit NewResponse(challengeId, msg.sender, verifiersList[verifierId]);
        }         
    }
}