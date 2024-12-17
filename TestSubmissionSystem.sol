// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract TestSubmissionSystem {
    struct DID {
        string identifier;
        address owner;
        uint256 createdAt;
    }

    struct MetaData {
        string name;
        string email;
        string profilePicture;
        uint256 totalTestsSubmitted;
        uint256 lastTestScore;
    }

    struct Question {
        string text; // Question text
        string[4] answers; // Four possible answers
        uint8 correctAnswerIndex; // Index of the correct answer (0-3)
    }

    struct Test {
        string title; // Test title
        Question[] questions; // List of questions
        uint256 maxScore; // Maximum score for the test
        bool exists; // Check if the test exists
        uint256 deadline; // Test submission deadline (timestamp)
    }

    struct TestSubmission {
        uint256 testId;
        uint8[] answers; // Submitted answers
        uint256 grade; // Graded score
        uint256 submissionTime;
        bool graded; // If the test is graded
    }
    struct Credential {
        address issuer;
        string role;
        uint256 issueAt;
        bytes32 hashes;
    }

    // Mappings
    mapping(address => DID) private dids;
    mapping(address => string) private roles;
    mapping(address => string[]) private roleHistory;
    mapping(address => MetaData) private metadatas;
    mapping(address => Credential[]) private credentials;
    mapping(address => TestSubmission[]) private testSubmissions;
    mapping(uint256 => Test) private tests; // Tests by their ID
    uint256 private nextTestId; // Incremental test ID
    
    constructor() {
        roles[msg.sender] = "super admin";
        roleHistory[msg.sender].push("super admin");
    }

    // Events
    event DIDCreated(address indexed owner, string identifier);
    event SetMetaData(
        address indexed owner,
        string name,
        string email,
        string profilePicture
    );
    event RoleAssigned(address indexed user, string role);
    event RoleIssued(
        address indexed user,
        address receiver,
        string role,
        bytes32 hash
    );
    event TestCreated(uint256 indexed testId, string title, uint256 maxScore, uint256 deadline);
    event TestSubmitted(address indexed user, uint256 testId, uint256 grade);
    event TestGraded(address indexed user, uint256 testId, uint256 grade);

    // Modifiers
    modifier onlySuperAdmin() {
        require(
            keccak256(abi.encodePacked(roles[msg.sender])) == keccak256("super admin"),
            "Only super admin can perform this action"
        );
        _;
    }

    modifier onlyAdmin() {
        require(
            keccak256(abi.encodePacked(roles[msg.sender])) == keccak256("admin"),
            "Only admin can perform this action"
        );
        _;
    }

    modifier onlyStudent() {
        require(
            keccak256(abi.encodePacked(roles[msg.sender])) == keccak256("student"),
            "Only student can perform this action"
        );
        _;
    }

    // Assign roles
    function assignRole(address _user, string memory _role) public onlySuperAdmin {
        require(dids[msg.sender].owner != address(0), "Issuer must have a DID");
        require(bytes(_role).length > 0, "Role cannot be empty");

        // Validate role names
        require(
            keccak256(abi.encodePacked(_role)) == keccak256("admin") ||
                keccak256(abi.encodePacked(_role)) == keccak256("student"),
            "Invalid role"
        );

        roles[_user] = _role;
        roleHistory[_user].push(_role);
        emit RoleAssigned(_user, _role);
    }

    function issueRole(address _user, string memory _role) public onlySuperAdmin {
        require(dids[msg.sender].owner != address(0), "Issuer must have a DID");
        require(bytes(_role).length > 0, "Role cannot be empty");

        bytes32 roleHash = keccak256(
            abi.encodePacked(msg.sender, _user, _role, block.timestamp)
        );

        credentials[_user].push(
            Credential(msg.sender, _role, block.timestamp, roleHash)
        );

        roleHistory[_user].push(_role);

        emit RoleIssued(msg.sender, _user, _role, roleHash);
    }

    function createDID(string memory _identifier) public {
        require(bytes(_identifier).length > 0, "Identifier cannot be empty");
        require(dids[msg.sender].owner == address(0), "DID already exists");
        dids[msg.sender] = DID(_identifier, msg.sender, block.timestamp);
        emit DIDCreated(msg.sender, _identifier);
    }

    function getDID() public view returns (string memory) {
        require(
            dids[msg.sender].owner != address(0),
            "No DID found for this address"
        );

        return dids[msg.sender].identifier;
    }

    function setMetadata(
        string memory name,
        string memory email,
        string memory profilePicture
    ) public {
        require(
            dids[msg.sender].owner != address(0),
            "No DID found for this address"
        );
        require(bytes(name).length > 0, "Name cannot be empty");
        require(bytes(email).length > 0, "Email cannot be empty");
        require(
            bytes(profilePicture).length > 0,
            "Profile picture cannot be empty"
        );

        metadatas[msg.sender] = MetaData(name, email, profilePicture, 0, 0);

        emit SetMetaData(msg.sender, name, email, profilePicture);
    }

    function getMetadata() public view returns (MetaData memory) {
        require(dids[msg.sender].owner != address(0), "Data does not exist");
        return metadatas[msg.sender];
    }

    function getRole() public view returns (string[] memory) {
        require(
            dids[msg.sender].owner != address(0),
            "No DID found for this address"
        );
        require(roleHistory[msg.sender].length > 0, "No roles assigned yet");
        return roleHistory[msg.sender];
    }

    function verifyRole(
        address user,
        string memory role,
        address issuerAddress
    ) public view returns (bool) {
        require(
            dids[user].owner != address(0),
            "No DID found for this address"
        );
        require(
            bytes(roles[user]).length > 0,
            "User does not have any assigned roles"
        );

        bool roleMatches = keccak256(abi.encodePacked(roles[user])) ==
            keccak256(abi.encodePacked(role));
        bool issuerMatches = false;

        // Check the role issuer and the hash in the user's credentials
        for (uint256 i = 0; i < credentials[user].length; i++) {
            if (
                credentials[user][i].issuer == issuerAddress &&
                keccak256(abi.encodePacked(credentials[user][i].role)) ==
                keccak256(abi.encodePacked(role))
            ) {
                issuerMatches = true;
                break;
            }
        }

        return roleMatches && issuerMatches;
    }

    // Admin creates a test
    function createTest(
        string memory title,
        Question[] memory questions,
        uint256 deadline
    ) public onlyAdmin {
        require(bytes(title).length > 0, "Test title cannot be empty");
        require(questions.length > 0, "Questions are required");
        require(deadline > block.timestamp, "Deadline must be in the future");

        uint256 maxScore = questions.length;

        Test storage newTest = tests[nextTestId];
        newTest.title = title;
        newTest.exists = true;
        newTest.maxScore = maxScore;
        newTest.deadline = deadline;

        for (uint256 i = 0; i < questions.length; i++) {
            require(bytes(questions[i].text).length > 0, "Question text cannot be empty");
            require(questions[i].correctAnswerIndex < 4, "Invalid correct answer index");
            newTest.questions.push(questions[i]);
        }

        emit TestCreated(nextTestId, title, maxScore, deadline);
        nextTestId++;
    }

    // Students submit test answers
    function submitTest(uint256 testId, uint8[] memory answers) public onlyStudent {
        require(tests[testId].exists, "Test does not exist");
        require(block.timestamp <= tests[testId].deadline, "Test submission deadline has passed");
        require(answers.length == tests[testId].questions.length, "Answers count mismatch");

        uint256 grade = 0;
        for (uint256 i = 0; i < answers.length; i++) {
            if (answers[i] == tests[testId].questions[i].correctAnswerIndex) {
                grade++;
            }
        }

        testSubmissions[msg.sender].push(
            TestSubmission(testId, answers, grade, block.timestamp, true)
        );

        metadatas[msg.sender].totalTestsSubmitted++;
        metadatas[msg.sender].lastTestScore = grade;

        emit TestSubmitted(msg.sender, testId, grade);
    }

    // Admin views test submissions
    function gradeTest(address user, uint256 submissionIndex, uint256 grade) public onlyAdmin {
        require(submissionIndex < testSubmissions[user].length, "Invalid submission index");
        TestSubmission storage submission = testSubmissions[user][submissionIndex];
        require(!submission.graded, "Test already graded");

        submission.grade = grade;
        submission.graded = true;

        emit TestGraded(user, submission.testId, grade);
    }

    // Students view their submissions
    function getTestSubmissions() public view onlyStudent returns (TestSubmission[] memory) {
        return testSubmissions[msg.sender];
    }
}